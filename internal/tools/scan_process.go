package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/shirou/gopsutil/v3/process"
)

func registerScanProcess(s *server.MCPServer) {
	tool := mcp.NewTool("scan_process",
		mcp.WithDescription(
			"Deep-dive security scan of a process: SHA256 hash of the binary, "+
				"binary location analysis (suspicious paths: /tmp, Downloads, home dirs), "+
				"optional VirusTotal reputation lookup (requires intel.virustotal_api_key in config), "+
				"loaded modules (Linux/macOS only), and a consolidated list of suspicious signals. "+
				"Provide either pid or process_name.",
		),
		mcp.WithNumber("pid",
			mcp.Description("Exact PID to scan. Takes precedence over process_name."),
		),
		mcp.WithString("process_name",
			mcp.Description(
				"Case-insensitive substring match against running process names. "+
					"When multiple processes match, all are scanned.",
			),
		),
	)
	s.AddTool(tool, scanProcessHandler)
}

// scanReport is the output for a single process security scan.
type scanReport struct {
	PID              int32    `json:"pid"`
	Name             string   `json:"name"`
	BinaryPath       string   `json:"binary_path,omitempty"`
	SHA256           string   `json:"sha256,omitempty"`
	SHA256Error      string   `json:"sha256_error,omitempty"`
	BinarySizeBytes  int64    `json:"binary_size_bytes,omitempty"`
	IsSystemPath     bool     `json:"is_system_path"`
	LoadedModules    []string `json:"loaded_modules,omitempty"`
	VTDetections     int      `json:"vt_detections,omitempty"`     // number of AV engines flagging the hash
	VTTotal          int      `json:"vt_total,omitempty"`          // total engines scanned
	VTLookupError    string   `json:"vt_lookup_error,omitempty"`
	VTPermalink      string   `json:"vt_permalink,omitempty"`
	SuspiciousSignals []string `json:"suspicious_signals,omitempty"`
	ScannedAt        time.Time `json:"scanned_at"`
}

func scanProcessHandler(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.Params.Arguments

	var targetPID int32
	if v, ok := args["pid"].(float64); ok && v > 0 {
		targetPID = int32(v)
	}
	nameFilter, _ := args["process_name"].(string)

	if targetPID == 0 && nameFilter == "" {
		return errorResult("provide 'pid' or 'process_name'"), nil
	}

	procs, err := process.Processes()
	if err != nil {
		return errorResult(fmt.Sprintf("cannot list processes: %v", err)), nil
	}

	var matched []*process.Process
	for _, p := range procs {
		if targetPID > 0 && p.Pid == targetPID {
			matched = []*process.Process{p}
			break
		}
		if nameFilter != "" {
			name, _ := p.Name()
			if strings.Contains(strings.ToLower(name), strings.ToLower(nameFilter)) {
				matched = append(matched, p)
			}
		}
	}

	if len(matched) == 0 {
		return errorResult(fmt.Sprintf("no process found matching pid=%d name=%q", targetPID, nameFilter)), nil
	}

	vtKey := config.Get().Intel.VirusTotalAPIKey

	var reports []scanReport
	for _, p := range matched {
		reports = append(reports, buildScanReport(p, vtKey))
	}

	type response struct {
		ScannedAt       time.Time    `json:"scanned_at"`
		ProcessesFound  int          `json:"processes_found"`
		VTEnabled       bool         `json:"virustotal_enabled"`
		Processes       []scanReport `json:"processes"`
	}
	out, err := json.Marshal(response{
		ScannedAt:      time.Now().UTC(),
		ProcessesFound: len(reports),
		VTEnabled:      vtKey != "",
		Processes:      reports,
	})
	if err != nil {
		return errorResult("failed to encode response: " + err.Error()), nil
	}
	return mcp.NewToolResultText(string(out)), nil
}

func buildScanReport(p *process.Process, vtKey string) scanReport {
	r := scanReport{
		PID:       p.Pid,
		ScannedAt: time.Now().UTC(),
	}
	r.Name, _ = p.Name()
	r.BinaryPath, _ = p.Exe()
	r.IsSystemPath = isSystemPath(r.BinaryPath)

	// SHA256 hash of the binary on disk.
	if r.BinaryPath != "" {
		hash, size, err := hashFile(r.BinaryPath)
		if err != nil {
			r.SHA256Error = err.Error()
		} else {
			r.SHA256 = hash
			r.BinarySizeBytes = size
		}
	}

	// Loaded modules / memory-mapped shared libraries.
	r.LoadedModules = collectModules(p)

	// VirusTotal lookup (best-effort — never block the response).
	if vtKey != "" && r.SHA256 != "" {
		det, total, link, err := vtLookup(r.SHA256, vtKey)
		if err != nil {
			r.VTLookupError = err.Error()
		} else {
			r.VTDetections = det
			r.VTTotal = total
			r.VTPermalink = link
		}
	}

	// Derive suspicious signals.
	r.SuspiciousSignals = deriveSuspiciousSignals(r)
	return r
}

// hashFile computes the SHA256 of a file on disk.
// Returns hex-encoded hash, file size, and any error.
func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), fi.Size(), nil
}

// suspiciousPathPrefixes holds path prefixes that are anomalous for production
// binaries. /tmp, home directories, Downloads — all common dropper locations.
var suspiciousPathPrefixes = []string{
	"/tmp/", "/dev/shm/", "/var/tmp/",
	"/home/", "/Users/", // Linux / macOS home dirs
	"\\Temp\\", "\\AppData\\", "\\Downloads\\", // Windows
	"\\Users\\", // Windows user dirs
}

// systemPathPrefixes are trusted OS locations. Binaries here are considered
// system-managed and are exempt from binary-path scoring.
var systemPathPrefixes = []string{
	"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/",
	"/System/", "/Applications/", // macOS
	"C:\\Windows\\", "C:\\Program Files\\", "C:\\Program Files (x86)\\",
}

func isSystemPath(binaryPath string) bool {
	if binaryPath == "" {
		return false
	}
	for _, prefix := range systemPathPrefixes {
		if strings.HasPrefix(binaryPath, prefix) {
			return true
		}
	}
	return false
}

// collectModules returns the list of distinct shared-library paths loaded by
// the process. The actual implementation is OS-specific (see scan_process_unix.go
// and scan_process_windows.go).
func collectModules(p *process.Process) []string {
	return collectModulesUnix(p)
}

// vtResponse is a minimal subset of the VirusTotal v3 /files/{hash} response.
type vtResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
			} `json:"last_analysis_stats"`
			TypeDescription string `json:"type_description"`
		} `json:"attributes"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
	} `json:"data"`
}

// vtBaseURL is the VirusTotal v3 files endpoint. Override in tests to point
// at a local httptest server.
var vtBaseURL = "https://www.virustotal.com/api/v3/files/"

// vtLookup queries VirusTotal v3 for a SHA256 hash.
// Returns (malicious+suspicious detections, total engines, permalink, error).
func vtLookup(sha256hash, apiKey string) (detections, total int, permalink string, err error) {
	return vtLookupWithURL(vtBaseURL, sha256hash, apiKey)
}

// vtLookupWithURL is the testable core of vtLookup; baseURL allows tests to
// point at a local httptest server instead of the real VirusTotal endpoint.
func vtLookupWithURL(baseURL, sha256hash, apiKey string) (detections, total int, permalink string, err error) {
	req, err := http.NewRequest("GET", baseURL+sha256hash, nil)
	if err != nil {
		return 0, 0, "", fmt.Errorf("vtLookup: build request: %w", err)
	}
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, "", fmt.Errorf("vtLookup: HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// Hash not found in VT — either never submitted or very new.
		return 0, 0, "", nil
	}
	if resp.StatusCode != 200 {
		return 0, 0, "", fmt.Errorf("vtLookup: HTTP %d", resp.StatusCode)
	}

	var result vtResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, 0, "", fmt.Errorf("vtLookup: decode: %w", err)
	}

	stats := result.Data.Attributes.LastAnalysisStats
	detections = stats.Malicious + stats.Suspicious
	total = stats.Malicious + stats.Suspicious + stats.Undetected + stats.Harmless
	permalink = result.Data.Links.Self
	return detections, total, permalink, nil
}

// deriveSuspiciousSignals generates a list of human-readable signal strings
// based on the scan findings. These mirror the scoring signals in aggregate.go
// so the user can understand why a process is suspicious.
func deriveSuspiciousSignals(r scanReport) []string {
	var signals []string

	// Binary location.
	if r.BinaryPath != "" {
		bpLow := strings.ToLower(filepath.ToSlash(r.BinaryPath))
		for _, prefix := range suspiciousPathPrefixes {
			if strings.Contains(bpLow, strings.ToLower(filepath.ToSlash(prefix))) {
				signals = append(signals, fmt.Sprintf("binary_in_suspicious_path: %s", r.BinaryPath))
				break
			}
		}
	}
	if r.BinaryPath == "" {
		signals = append(signals, "binary_path_unavailable: process may be hiding or using memfd_create")
	}

	// SHA256 unavailable.
	if r.SHA256Error != "" {
		signals = append(signals, "hash_unavailable: "+r.SHA256Error)
	}

	// VirusTotal.
	if r.VTDetections > 0 {
		signals = append(signals, fmt.Sprintf("vt_positive: %d/%d engines flagged the binary", r.VTDetections, r.VTTotal))
	}

	// Suspicious module paths (injected DLLs, LD_PRELOAD artifacts, /tmp/.so).
	for _, mod := range r.LoadedModules {
		modLow := strings.ToLower(filepath.ToSlash(mod))
		for _, prefix := range suspiciousPathPrefixes {
			if strings.Contains(modLow, strings.ToLower(filepath.ToSlash(prefix))) {
				signals = append(signals, fmt.Sprintf("suspicious_module: %s", mod))
				break
			}
		}
	}

	return signals
}
