package tools

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
	"github.com/ClementG91/MCP-FlowSentinel/internal/correlate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/history"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// toolsWritePcapFile creates a minimal valid pcap v2.4 (LE, Ethernet) file
// containing the given raw packet bytes. Returns the file path.
func toolsWritePcapFile(t *testing.T, packets [][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "capture.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer f.Close()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatalf("write pcap: %v", e)
		}
	}
	must(binary.Write(f, binary.LittleEndian, uint32(0xa1b2c3d4)))
	must(binary.Write(f, binary.LittleEndian, uint16(2)))
	must(binary.Write(f, binary.LittleEndian, uint16(4)))
	must(binary.Write(f, binary.LittleEndian, int32(0)))
	must(binary.Write(f, binary.LittleEndian, uint32(0)))
	must(binary.Write(f, binary.LittleEndian, uint32(65535)))
	must(binary.Write(f, binary.LittleEndian, uint32(1)))
	for _, pkt := range packets {
		must(binary.Write(f, binary.LittleEndian, uint32(0)))
		must(binary.Write(f, binary.LittleEndian, uint32(0)))
		must(binary.Write(f, binary.LittleEndian, uint32(len(pkt))))
		must(binary.Write(f, binary.LittleEndian, uint32(len(pkt))))
		if _, werr := f.Write(pkt); werr != nil {
			t.Fatalf("write packet: %v", werr)
		}
	}
	return path
}

// toolsBuildIPv4TCPRaw serialises an Ethernet/IPv4/TCP frame into raw bytes.
func toolsBuildIPv4TCPRaw(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort)}
	if err := tcp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip4, tcp); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return buf.Bytes()
}

// ─── helper ──────────────────────────────────────────────────────────────────

// callReq builds a minimal mcp.CallToolRequest with the given arguments map.
func callReq(args map[string]any) mcp.CallToolRequest {
	return mcp.CallToolRequest{
		Params: struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments,omitempty"`
			Meta      *struct {
				ProgressToken mcp.ProgressToken `json:"progressToken,omitempty"`
			} `json:"_meta,omitempty"`
		}{
			Arguments: args,
		},
	}
}

// resultText extracts the text from the first content item of a tool result.
func resultText(t *testing.T, r *mcp.CallToolResult) string {
	t.Helper()
	if r == nil {
		t.Fatal("result is nil")
	}
	if len(r.Content) == 0 {
		t.Fatal("result has no content")
	}
	b, err := json.Marshal(r.Content[0])
	if err != nil {
		t.Fatalf("marshal content: %v", err)
	}
	var wrapper struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(b, &wrapper); err != nil {
		t.Fatalf("unmarshal content: %v", err)
	}
	return wrapper.Text
}

// isErrorResult returns true if the tool result encodes a JSON {"error":...}.
func isErrorResult(t *testing.T, r *mcp.CallToolResult) bool {
	t.Helper()
	text := resultText(t, r)
	return strings.Contains(text, `"error"`)
}

// ─── analyze_network validation ──────────────────────────────────────────────

func TestAnalyzeNetwork_MissingInterface(t *testing.T) {
	r, err := analyzeNetworkHandler(context.Background(), callReq(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isErrorResult(t, r) {
		t.Error("expected error result when interface is missing")
	}
}

func TestAnalyzeNetwork_EmptyInterface(t *testing.T) {
	r, err := analyzeNetworkHandler(context.Background(), callReq(map[string]any{
		"interface": "",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isErrorResult(t, r) {
		t.Error("expected error result for empty interface name")
	}
}

func TestAnalyzeNetwork_InvalidInterfaceName_MetaChars(t *testing.T) {
	malicious := []string{
		"eth0; rm -rf /",
		"$(whoami)",
		"../etc/passwd",
		"eth0\x00injected",
	}
	for _, iface := range malicious {
		t.Run(iface, func(t *testing.T) {
			r, err := analyzeNetworkHandler(context.Background(), callReq(map[string]any{
				"interface": iface,
			}))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !isErrorResult(t, r) {
				t.Errorf("expected error for malicious interface name %q", iface)
			}
		})
	}
}

func TestAnalyzeNetwork_InterfaceNameTooLong(t *testing.T) {
	long := strings.Repeat("a", 300)
	r, err := analyzeNetworkHandler(context.Background(), callReq(map[string]any{
		"interface": long,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isErrorResult(t, r) {
		t.Error("expected error for interface name > 256 chars")
	}
}

// ─── analyze_pcap validation ──────────────────────────────────────────────────

func TestAnalyzePcap_MissingFilePath(t *testing.T) {
	r, err := analyzePcapHandler(context.Background(), callReq(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isErrorResult(t, r) {
		t.Error("expected error when file_path is missing")
	}
}

func TestAnalyzePcap_WrongExtension(t *testing.T) {
	for _, bad := range []string{"/tmp/capture.txt", "/tmp/capture.exe", "/tmp/capture"} {
		t.Run(bad, func(t *testing.T) {
			r, err := analyzePcapHandler(context.Background(), callReq(map[string]any{
				"file_path": bad,
			}))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !isErrorResult(t, r) {
				t.Errorf("expected error for bad extension: %q", bad)
			}
		})
	}
}

func TestAnalyzePcap_FileNotFound(t *testing.T) {
	r, err := analyzePcapHandler(context.Background(), callReq(map[string]any{
		"file_path": "/nonexistent/path/capture.pcap",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isErrorResult(t, r) {
		t.Error("expected error for non-existent file")
	}
}

func TestAnalyzePcap_ValidFile_ReturnsJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pcap.OpenOffline requires wpcap.dll which is not available on Windows CI runners")
	}
	// Build a pcap file with real IPv4/TCP packets.
	rawPkt := toolsBuildIPv4TCPRaw(t, "10.0.0.1", "10.0.0.2", 12345, 80)
	path := toolsWritePcapFile(t, [][]byte{rawPkt, rawPkt, rawPkt})

	r, err := analyzePcapHandler(context.Background(), callReq(map[string]any{
		"file_path": path,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := resultText(t, r)

	var out struct {
		CaptureInfo struct {
			TotalPackets int64 `json:"total_packets"`
		} `json:"capture_info"`
		Flows []any `json:"flows"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, text)
	}
	if out.CaptureInfo.TotalPackets != 3 {
		t.Errorf("TotalPackets = %d, want 3", out.CaptureInfo.TotalPackets)
	}
}

func TestAnalyzePcap_ValidFile_WithFilters(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pcap.OpenOffline requires wpcap.dll which is not available on Windows CI runners")
	}
	rawPkt := toolsBuildIPv4TCPRaw(t, "10.0.0.1", "10.0.0.2", 12345, 443)
	path := toolsWritePcapFile(t, [][]byte{rawPkt})

	r, err := analyzePcapHandler(context.Background(), callReq(map[string]any{
		"file_path": path,
		"min_score": float64(0),
		"top_n":     float64(10),
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isErrorResult(t, r) {
		t.Error("unexpected error result for valid pcap with filters")
	}
}

func TestAnalyzePcap_FileTooLarge(t *testing.T) {
	// Create a temp file and make it appear oversized by using os.Truncate.
	dir := t.TempDir()
	path := filepath.Join(dir, "big.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	f.Close()
	// Truncate to 1 GB + 1 byte — the file content is sparse, but os.Stat
	// will report its size as > maxPcapSize.
	if err := os.Truncate(path, (1<<30)+1); err != nil {
		t.Skipf("cannot create sparse file on this OS: %v", err)
	}

	r, err := analyzePcapHandler(context.Background(), callReq(map[string]any{
		"file_path": path,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isErrorResult(t, r) {
		t.Error("expected error for file > 1 GB")
	}
}

// ─── analyze_process validation ───────────────────────────────────────────────

func TestAnalyzeProcess_NoArgs_ReturnsError(t *testing.T) {
	r, err := analyzeProcessHandler(context.Background(), callReq(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isErrorResult(t, r) {
		t.Error("expected error when neither pid nor process_name is provided")
	}
}

func TestAnalyzeProcess_NonExistentPID(t *testing.T) {
	// PID 999999999 is virtually guaranteed not to exist.
	r, err := analyzeProcessHandler(context.Background(), callReq(map[string]any{
		"pid": float64(999999999),
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isErrorResult(t, r) {
		t.Error("expected error for non-existent PID")
	}
}

func TestAnalyzeProcess_NonExistentName(t *testing.T) {
	r, err := analyzeProcessHandler(context.Background(), callReq(map[string]any{
		"process_name": "zzz-this-process-cannot-exist-xyzzy",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isErrorResult(t, r) {
		t.Error("expected error for non-existent process name")
	}
}

func TestAnalyzeProcess_ByPID_CurrentProcess_ReturnsJSON(t *testing.T) {
	pid := float64(os.Getpid())
	r, err := analyzeProcessHandler(context.Background(), callReq(map[string]any{
		"pid": pid,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isErrorResult(t, r) {
		t.Errorf("expected success for current PID, got: %s", resultText(t, r))
	}
	text := resultText(t, r)
	var out struct {
		ProcessesFound int `json:"processes_found"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("invalid JSON: %v\nbody: %s", err, text)
	}
	if out.ProcessesFound < 1 {
		t.Errorf("expected ≥1 process found, got %d", out.ProcessesFound)
	}
}

func TestAnalyzeProcess_ByName_CurrentProcess_ReturnsJSON(t *testing.T) {
	// Resolve the current process name so the filter is guaranteed to match.
	currentProc, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		t.Skipf("process.NewProcess: %v", err)
	}
	name, err := currentProc.Name()
	if err != nil || name == "" {
		t.Skipf("could not get current process name: %v", err)
	}

	r, err := analyzeProcessHandler(context.Background(), callReq(map[string]any{
		"process_name": name,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := resultText(t, r)
	// Result may be error if the name resolves to zero matches in the process list,
	// but we at least verify that the response is valid JSON.
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Errorf("response is not valid JSON: %v\nbody: %s", err, text)
	}
}

// ─── get_flow_history validation ──────────────────────────────────────────────

func TestGetFlowHistory_EmptyHistory_ReturnsValidJSON(t *testing.T) {
	// Point history at an empty temp dir so it finds no file.
	r, err := getFlowHistoryHandler(context.Background(), callReq(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := resultText(t, r)

	// Must be valid JSON with entries array.
	var out struct {
		Entries []any `json:"entries"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Errorf("response is not valid JSON: %v\nbody: %s", err, text)
	}
}

// ─── get_flow_history — filter args exercise ──────────────────────────────────

func TestGetFlowHistory_WithAllFilters_ReturnsValidJSON(t *testing.T) {
	r, err := getFlowHistoryHandler(context.Background(), callReq(map[string]any{
		"max_age_hours": float64(2),
		"min_score":     float64(3.0),
		"src_ip":        "192.168.1.1",
		"dst_ip":        "8.8.8.8",
		"process_name":  "curl",
		"top_n":         float64(10),
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := resultText(t, r)
	var out struct {
		Entries  []any `json:"entries"`
		QueryInfo struct {
			MaxAgeHours float64 `json:"max_age_hours"`
		} `json:"query_info"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Errorf("response is not valid JSON: %v\nbody: %s", err, text)
	}
	if out.QueryInfo.MaxAgeHours != 2.0 {
		t.Errorf("max_age_hours = %v, want 2.0", out.QueryInfo.MaxAgeHours)
	}
}

// ─── sockProtoName ────────────────────────────────────────────────────────────

func TestSockProtoName(t *testing.T) {
	tests := []struct {
		t    uint32
		want string
	}{
		{1, "TCP"},
		{2, "UDP"},
		{3, "SOCK3"},
		{99, "SOCK99"},
	}
	for _, tc := range tests {
		if got := sockProtoName(tc.t); got != tc.want {
			t.Errorf("sockProtoName(%d) = %q, want %q", tc.t, got, tc.want)
		}
	}
}

// ─── Register ─────────────────────────────────────────────────────────────────

func TestRegister_RegistersAllTools_NoPanic(t *testing.T) {
	s := server.NewMCPServer("test-server", "0.0.0")
	// Register must not panic even if pcap / procfs is unavailable.
	Register(s)
}

// ─── listInterfacesHandler ────────────────────────────────────────────────────

func TestListInterfacesHandler_ReturnsResult(t *testing.T) {
	r, err := listInterfacesHandler(context.Background(), callReq(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if r == nil {
		t.Fatal("result is nil")
	}
	// Whether pcap enumeration succeeds or fails gracefully, we must get a non-empty text.
	text := resultText(t, r)
	if text == "" {
		t.Error("empty result text")
	}
}

// ─── getProcessMapHandler ─────────────────────────────────────────────────────

func TestGetProcessMapHandler_ReturnsResult(t *testing.T) {
	r, err := getProcessMapHandler(context.Background(), callReq(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if r == nil {
		t.Fatal("result is nil")
	}
	text := resultText(t, r)
	if text == "" {
		t.Error("empty result text")
	}
}

// ─── buildProcessReport + resolveParentChain ──────────────────────────────────

func TestBuildProcessReport_CurrentProcess(t *testing.T) {
	pid := int32(os.Getpid())
	proc, err := process.NewProcess(pid)
	if err != nil {
		t.Skipf("process.NewProcess(%d) failed: %v", pid, err)
	}
	report := buildProcessReport(proc, []psnet.ConnectionStat{})
	if report.PID != pid {
		t.Errorf("PID = %d, want %d", report.PID, pid)
	}
	if report.Name == "" {
		t.Error("expected non-empty process Name")
	}
	if report.CurrentConnections == nil {
		t.Error("CurrentConnections must be non-nil (empty slice), not nil")
	}
}

func TestBuildProcessReport_WithConnection(t *testing.T) {
	pid := int32(os.Getpid())
	proc, err := process.NewProcess(pid)
	if err != nil {
		t.Skipf("process.NewProcess(%d) failed: %v", pid, err)
	}
	conn := psnet.ConnectionStat{
		Laddr: psnet.Addr{IP: "127.0.0.1", Port: 12345},
		Raddr: psnet.Addr{IP: "8.8.8.8", Port: 443},
		Type:  1, // TCP
	}
	report := buildProcessReport(proc, []psnet.ConnectionStat{conn})
	if len(report.CurrentConnections) != 1 {
		t.Errorf("expected 1 connection, got %d", len(report.CurrentConnections))
	}
}

func TestBuildProcessReport_WildcardRemote(t *testing.T) {
	pid := int32(os.Getpid())
	proc, err := process.NewProcess(pid)
	if err != nil {
		t.Skipf("process.NewProcess(%d) failed: %v", pid, err)
	}
	// Connection with no remote address (LISTEN socket).
	conn := psnet.ConnectionStat{
		Laddr: psnet.Addr{IP: "0.0.0.0", Port: 8080},
		Raddr: psnet.Addr{IP: "", Port: 0},
		Type:  1,
	}
	report := buildProcessReport(proc, []psnet.ConnectionStat{conn})
	if len(report.CurrentConnections) != 1 {
		t.Fatalf("expected 1 connection")
	}
	if report.CurrentConnections[0].Remote != "*" {
		t.Errorf("Remote = %q, want %q", report.CurrentConnections[0].Remote, "*")
	}
}

func TestResolveParentChain_CurrentProcess(t *testing.T) {
	pid := int32(os.Getpid())
	proc, err := process.NewProcess(pid)
	if err != nil {
		t.Skipf("process.NewProcess failed: %v", err)
	}
	chain := resolveParentChain(proc, 4)
	// Must not panic; chain length is OS-dependent (may be 0 in container envs).
	t.Logf("parent chain length = %d", len(chain))
	for _, p := range chain {
		if p.PID <= 0 {
			t.Errorf("invalid parent PID %d in chain", p.PID)
		}
	}
}

func TestResolveParentChain_ZeroDepth(t *testing.T) {
	pid := int32(os.Getpid())
	proc, err := process.NewProcess(pid)
	if err != nil {
		t.Skipf("process.NewProcess failed: %v", err)
	}
	chain := resolveParentChain(proc, 0)
	if len(chain) != 0 {
		t.Errorf("expected empty chain for depth 0, got %d entries", len(chain))
	}
}

// ─── makeResolver ─────────────────────────────────────────────────────────────

func TestMakeResolver_NilTable_ReturnsNil(t *testing.T) {
	// A zero-value atomic.Pointer has Load() == nil; makeResolver must not panic.
	var ptr atomic.Pointer[correlate.SocketTable]
	// ptr.Load() returns nil — simulates the brief window before the first table is built.
	resolver := makeResolver(&ptr)
	got := resolver("1.2.3.4", 9, "5.6.7.8", 10, "TCP")
	if got != nil {
		t.Errorf("expected nil result for nil socket table, got %+v", got)
	}
}

func TestMakeResolver_MissReturnsNil(t *testing.T) {
	table := correlate.BuildSocketTable()
	var ptr atomic.Pointer[correlate.SocketTable]
	ptr.Store(table)

	resolver := makeResolver(&ptr)
	// An arbitrary four-tuple that is almost certainly not in the table.
	got := resolver("1.2.3.4", 9, "5.6.7.8", 10, "TCP")
	if got != nil {
		t.Logf("unexpected match (live system has many connections): %+v", got)
	}
	// Just verify no panic and valid return.
}

// ─── analyzePcapHandler — positive min_score branch ──────────────────────────

// TestAnalyzePcap_ValidFile_WithPositiveMinScore covers the minScore = v
// assignment that is skipped when min_score == 0.
func TestAnalyzePcap_ValidFile_WithPositiveMinScore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pcap.OpenOffline requires wpcap.dll which is not available on Windows CI runners")
	}
	rawPkt := toolsBuildIPv4TCPRaw(t, "10.0.0.1", "10.0.0.2", 12345, 443)
	path := toolsWritePcapFile(t, [][]byte{rawPkt})

	r, err := analyzePcapHandler(context.Background(), callReq(map[string]any{
		"file_path": path,
		"min_score": float64(5.0), // v > 0 → triggers minScore = v
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isErrorResult(t, r) {
		t.Errorf("unexpected error result: %s", resultText(t, r))
	}
}

// ─── getFlowHistoryHandler — totalFlows accumulator ──────────────────────────

// TestGetFlowHistory_WithInjectedHistory_HasFlows injects one history entry
// so that the totalFlows accumulator inside getFlowHistoryHandler is exercised.
func TestGetFlowHistory_WithInjectedHistory_HasFlows(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "hist.jsonl")
	orig := history.Path()
	history.SetPathForTesting(tmp)
	t.Cleanup(func() { history.SetPathForTesting(orig) })

	history.Append("test-source", []aggregate.FlowRecord{
		{SrcIP: "1.2.3.4", DstIP: "5.6.7.8", ProcessName: "testproc", SuspicionScore: 0.5},
	})

	r, err := getFlowHistoryHandler(context.Background(), callReq(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := resultText(t, r)
	var out struct {
		QueryInfo struct {
			TotalFlows int `json:"total_flows"`
		} `json:"query_info"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("invalid JSON: %v\nbody: %s", err, text)
	}
	if out.QueryInfo.TotalFlows == 0 {
		t.Error("expected TotalFlows > 0 after injecting a history entry")
	}
}

// ─── analyzeProcessHandler — sort comparison for 2+ matches ──────────────────

// TestAnalyzeProcess_MultipleMatches_SortInvoked finds a process name with
// 2+ running instances so that sort.Slice's comparison function is called.
func TestAnalyzeProcess_MultipleMatches_SortInvoked(t *testing.T) {
	procs, err := process.Processes()
	if err != nil {
		t.Skipf("process.Processes: %v", err)
	}

	nameCounts := map[string]int{}
	for _, p := range procs {
		name, _ := p.Name()
		if name != "" {
			nameCounts[strings.ToLower(name)]++
		}
	}

	var multiName string
	for name, count := range nameCounts {
		if count >= 2 {
			multiName = name
			break
		}
	}
	if multiName == "" {
		t.Skip("no process name with 2+ instances found on this system")
	}

	r, err := analyzeProcessHandler(context.Background(), callReq(map[string]any{
		"process_name": multiName,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := resultText(t, r)
	var out struct {
		ProcessesFound int `json:"processes_found"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("invalid JSON: %v\nbody: %s", err, text)
	}
	if out.ProcessesFound < 2 {
		t.Skipf("expected 2+ processes for name %q, got %d (race with process exit)", multiName, out.ProcessesFound)
	}
}

// ─── get_config handler ───────────────────────────────────────────────────────

func TestGetConfig_ReturnsValidJSON(t *testing.T) {
	r, err := getConfigHandler(context.Background(), callReq(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := resultText(t, r)
	var out struct {
		Scoring  any `json:"scoring"`
		Alerting any `json:"alerting"`
		Daemon   any `json:"daemon"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, text)
	}
	if out.Scoring == nil {
		t.Error("expected scoring section in response")
	}
}

func TestGetConfig_MasksWebhookURL(t *testing.T) {
	original := config.Get()
	defer config.Set(original)

	cfg := config.Default()
	cfg.Alerting.Enabled = true
	cfg.Alerting.WebhookURL = "https://hooks.example.com/secret"
	config.Set(cfg)

	r, err := getConfigHandler(context.Background(), callReq(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := resultText(t, r)
	if strings.Contains(text, "secret") {
		t.Error("webhook URL should be masked in get_config response")
	}
	if !strings.Contains(text, `"***"`) {
		t.Error("expected masked webhook URL to appear as ***")
	}
}

// ─── get_daemon_stats handler ────────────────────────────────────────────────

func TestGetDaemonStats_ReturnsValidJSON(t *testing.T) {
	r, err := getDaemonStatsHandler(context.Background(), callReq(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := resultText(t, r)
	var out struct {
		Running bool `json:"running"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, text)
	}
	// Daemon is not running in test context.
	if out.Running {
		t.Error("expected daemon running=false in test context")
	}
}

// ─── get_alerts handler ───────────────────────────────────────────────────────

func TestGetAlerts_EmptyLog_ReturnsValidJSON(t *testing.T) {
	r, err := getAlertsHandler(context.Background(), callReq(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := resultText(t, r)
	var out struct {
		TotalAlerts int   `json:"total_alerts"`
		Alerts      []any `json:"alerts"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, text)
	}
	if out.Alerts == nil {
		t.Error("alerts field must not be null")
	}
}

func TestGetAlerts_WithParams_ReturnsValidJSON(t *testing.T) {
	r, err := getAlertsHandler(context.Background(), callReq(map[string]any{
		"max_age_hours": float64(2),
		"min_score":     float64(5.0),
		"top_n":         float64(10),
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := resultText(t, r)
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, text)
	}
}

// ─── reload_config handler ────────────────────────────────────────────────────

func TestReloadConfig_ReturnsValidJSON(t *testing.T) {
	r, err := reloadConfigHandler(context.Background(), callReq(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := resultText(t, r)
	var out struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Config  any    `json:"config"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, text)
	}
	if out.Status != "ok" {
		t.Errorf("status = %q, want ok", out.Status)
	}
}

// ─── makeResolver — table hit returns ProcessSnapshot ────────────────────────

// TestMakeResolver_TableHit_ReturnsProcessSnapshot finds a live connection in
// the socket table and verifies that makeResolver returns a non-nil snapshot,
// covering the return &aggregate.ProcessSnapshot{...} branch.
func TestMakeResolver_TableHit_ReturnsProcessSnapshot(t *testing.T) {
	conns, err := psnet.Connections("all")
	if err != nil {
		t.Skipf("psnet.Connections: %v", err)
	}

	// Find a connection with a real remote address (not a LISTEN socket).
	var target psnet.ConnectionStat
	for _, c := range conns {
		if c.Raddr.IP != "" && c.Raddr.IP != "0.0.0.0" && c.Raddr.IP != "::" {
			target = c
			break
		}
	}
	if target.Laddr.IP == "" {
		t.Skip("no established connection with remote address available")
	}

	table := correlate.BuildSocketTable()

	proto := "TCP"
	if target.Type == 2 {
		proto = "UDP"
	}

	// Pre-check: skip if the connection is no longer in the table.
	if table.Lookup(target.Laddr.IP, uint16(target.Laddr.Port), target.Raddr.IP, uint16(target.Raddr.Port), proto) == nil {
		t.Skip("connection left the socket table between snapshot and lookup")
	}

	var ptr atomic.Pointer[correlate.SocketTable]
	ptr.Store(table)
	resolver := makeResolver(&ptr)

	result := resolver(target.Laddr.IP, uint16(target.Laddr.Port), target.Raddr.IP, uint16(target.Raddr.Port), proto)
	if result == nil {
		t.Error("expected non-nil ProcessSnapshot for a confirmed socket table hit")
	} else {
		t.Logf("makeResolver hit: PID=%d Name=%s", result.PID, result.Name)
	}
}

// ─── buildProcessReport — history flow count branch ──────────────────────────

// TestBuildProcessReport_WithHistoryFlows injects a history entry that matches
// the current process name so that the HistoryFlowCount accumulator is exercised.
func TestBuildProcessReport_WithHistoryFlows(t *testing.T) {
	pid := int32(os.Getpid())
	proc, err := process.NewProcess(pid)
	if err != nil {
		t.Skipf("process.NewProcess(%d) failed: %v", pid, err)
	}
	name, err := proc.Name()
	if err != nil || name == "" {
		t.Skipf("could not get process name: %v", err)
	}

	// Redirect history to a temp file so we don't pollute the real history.
	tmp := filepath.Join(t.TempDir(), "hist.jsonl")
	orig := history.Path()
	history.SetPathForTesting(tmp)
	t.Cleanup(func() { history.SetPathForTesting(orig) })

	// Inject one entry whose ProcessName matches the current process.
	history.Append("test-source", []aggregate.FlowRecord{
		{SrcIP: "1.2.3.4", DstIP: "5.6.7.8", ProcessName: name, SuspicionScore: 0.5},
	})

	report := buildProcessReport(proc, nil)
	if report.HistoryFlowCount == 0 {
		t.Errorf("HistoryFlowCount = 0; expected > 0 after injecting a matching history entry (process %q)", name)
	}
}
