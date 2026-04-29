// domrep.go — domain reputation lookups against community threat-intel feeds.
// Supports URLhaus plain-text URL lists (hostname extraction) and ThreatFox
// domain CSV exports. Lookups check exact domain and one parent-domain level.
package intel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// domRepEntry records the source and descriptive label for a domain hit.
type domRepEntry struct {
	Source string `json:"source"`
	Label  string `json:"label"`
}

// domRepState holds the live reputation database.
type domRepState struct {
	domains map[string]domRepEntry // lowercase domain → entry
}

var (
	domRepMu   sync.RWMutex
	domRepLive = &domRepState{domains: make(map[string]domRepEntry)}
)

// domRepCachePath is the on-disk JSON cache for domain reputation data.
var domRepCachePath string

func init() {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = os.TempDir()
	}
	domRepCachePath = filepath.Join(home, ".cache", "mcp-flowsentinel", "domrep.json")
	loadDomRepFromDisk()
}

// DomRepLookup checks whether domain (or its immediate parent) is blocklisted.
// Returns the label and true on a match; empty string and false otherwise.
// Lookup is case-insensitive and strips trailing dots.
func DomRepLookup(domain string) (string, bool) {
	if domain == "" {
		return "", false
	}
	d := strings.ToLower(strings.TrimSuffix(domain, "."))

	domRepMu.RLock()
	defer domRepMu.RUnlock()

	if e, ok := domRepLive.domains[d]; ok {
		return e.Source + ": " + e.Label, true
	}
	// Check parent domain (strip leftmost label).
	if idx := strings.Index(d, "."); idx >= 0 && idx < len(d)-1 {
		parent := d[idx+1:]
		if e, ok := domRepLive.domains[parent]; ok {
			return e.Source + ": " + e.Label, true
		}
	}
	return "", false
}

// DomRepSize returns the number of entries in the live database.
func DomRepSize() int {
	domRepMu.RLock()
	defer domRepMu.RUnlock()
	return len(domRepLive.domains)
}

// UpdateDomRep fetches the given URLs (and optional localFile) and atomically
// replaces the live domain reputation database. Individual URL failures are
// logged and skipped rather than aborting the whole update, matching the
// resilience behaviour of UpdateIPRep.
func UpdateDomRep(urls []string, localFile string) error {
	domains := make(map[string]domRepEntry)

	if localFile != "" {
		f, err := os.Open(localFile)
		if err != nil {
			log.Printf("domrep: local file %q: %v", localFile, err)
		} else {
			parseDomRepText(f, "local", domains)
			f.Close()
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	var lastErr error
	for _, u := range urls {
		resp, err := client.Get(u) //nolint:noctx
		if err != nil {
			log.Printf("domrep: fetch %q: %v", u, err)
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			log.Printf("domrep: fetch %q: HTTP %d", u, resp.StatusCode)
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		src := domRepSourceLabel(u)
		if strings.Contains(strings.ToLower(u), "threatfox") {
			parseDomRepThreatFox(resp.Body, src, domains)
		} else {
			parseDomRepText(resp.Body, src, domains)
		}
		resp.Body.Close()
	}

	if len(domains) == 0 {
		if lastErr != nil {
			return fmt.Errorf("domrep: all sources failed, last error: %w", lastErr)
		}
		return fmt.Errorf("domrep: no entries parsed from sources")
	}

	saveDomRepToDisk(domains)

	domRepMu.Lock()
	domRepLive = &domRepState{domains: domains}
	domRepMu.Unlock()

	log.Printf("domrep: loaded %d domains", len(domains))
	return nil
}

// parseDomRepText handles plain-text lists where each non-comment line is
// either a full URL (http/https — hostname is extracted) or a bare domain.
func parseDomRepText(r io.Reader, source string, dst map[string]domRepEntry) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var host string
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			u, err := url.Parse(line)
			if err != nil || u.Hostname() == "" {
				continue
			}
			host = strings.ToLower(u.Hostname())
		} else {
			// Treat as bare domain; skip if it contains a space or slash.
			if strings.ContainsAny(line, " \t/") {
				continue
			}
			host = strings.ToLower(line)
		}
		if host == "" {
			continue
		}
		if _, exists := dst[host]; !exists {
			dst[host] = domRepEntry{Source: source, Label: "malware distribution"}
		}
	}
}

// parseDomRepThreatFox parses ThreatFox CSV domain exports.
// Expected line format (quoted CSV): "id","ioc_value","ioc_type","threat_type","malware",...
// Lines starting with '#' are comments.
func parseDomRepThreatFox(r io.Reader, source string, dst map[string]domRepEntry) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Split on comma, respecting quoted fields minimally.
		fields := splitCSVLine(line)
		if len(fields) < 3 {
			continue
		}
		// Field 1 = ioc_value (domain), field 2 = ioc_type
		iocType := strings.ToLower(strings.Trim(fields[2], `" `))
		if iocType != "domain" && iocType != "url" {
			continue
		}
		domain := strings.ToLower(strings.Trim(fields[1], `" `))
		if domain == "" {
			continue
		}
		// For URL ioc_type, extract hostname.
		if iocType == "url" {
			u, err := url.Parse(domain)
			if err != nil || u.Hostname() == "" {
				continue
			}
			domain = u.Hostname()
		}
		malware := ""
		if len(fields) > 4 {
			malware = strings.Trim(fields[4], `" `)
		}
		label := "malware C2"
		if malware != "" {
			label = malware
		}
		if _, exists := dst[domain]; !exists {
			dst[domain] = domRepEntry{Source: source, Label: label}
		}
	}
}

// splitCSVLine splits a CSV line on commas, handling simple double-quoted fields.
func splitCSVLine(line string) []string {
	var fields []string
	inQuote := false
	start := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inQuote = !inQuote
		case ',':
			if !inQuote {
				fields = append(fields, line[start:i])
				start = i + 1
			}
		}
	}
	fields = append(fields, line[start:])
	return fields
}

// domRepSourceLabel maps a feed URL to a short source identifier.
func domRepSourceLabel(feedURL string) string {
	lower := strings.ToLower(feedURL)
	switch {
	case strings.Contains(lower, "urlhaus"):
		return "urlhaus"
	case strings.Contains(lower, "threatfox"):
		return "threatfox"
	case strings.Contains(lower, "openphish"):
		return "openphish"
	default:
		return "custom_url"
	}
}

// saveDomRepToDisk persists the domain map to the cache file (atomic rename).
func saveDomRepToDisk(domains map[string]domRepEntry) {
	data, err := json.Marshal(domains)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(domRepCachePath), 0o700); err != nil {
		return
	}
	tmp := domRepCachePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, domRepCachePath)
}

// loadDomRepFromDisk reads a previously saved domain reputation cache.
func loadDomRepFromDisk() {
	data, err := os.ReadFile(domRepCachePath)
	if err != nil {
		return
	}
	var domains map[string]domRepEntry
	if err := json.Unmarshal(data, &domains); err != nil {
		return
	}
	domRepMu.Lock()
	domRepLive = &domRepState{domains: domains}
	domRepMu.Unlock()
	log.Printf("domrep: restored %d domains from disk cache (updated %s ago)",
		len(domains), time.Since(domRepLastUpdated()).Round(time.Minute))
}

// domRepLastUpdated returns the modification time of the cache file, or zero.
func domRepLastUpdated() time.Time {
	fi, err := os.Stat(domRepCachePath)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}
