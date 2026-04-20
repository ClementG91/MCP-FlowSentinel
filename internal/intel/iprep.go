// iprep.go — IP reputation blocklist for known C2 infrastructure.
//
// Loads plain-text IP/CIDR blocklists from remote threat-intelligence feeds
// (Feodo Tracker, Emerging Threats) and an optional local file. Lookups are
// O(1) for exact IP matches and O(N-CIDRs) for CIDR ranges (N ≤ a few hundred).
//
// Supported sources:
//   - Feodo Tracker:      https://feodotracker.abuse.ch/downloads/ipblocklist.txt
//   - Emerging Threats:   https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
//   - Any newline-delimited file of IPs and/or CIDRs (comments start with '#').
package intel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ipRepEntry records why an IP is considered malicious.
type ipRepEntry struct {
	Source string `json:"source"`
	Label  string `json:"label"` // e.g. "C2 server", "botnet tracker"
}

// ipRepState holds the current reputation database.
type ipRepState struct {
	exact  map[string]ipRepEntry // exact IP string → entry
	ranges []ipRepRange          // CIDR ranges
}

type ipRepRange struct {
	net   *net.IPNet
	entry ipRepEntry
}

// ipRepCacheEntry is the on-disk format for one IP or CIDR.
type ipRepCacheEntry struct {
	CIDR   string `json:"cidr"`
	Source string `json:"source"`
	Label  string `json:"label"`
}

type ipRepCacheFile struct {
	UpdatedAt time.Time         `json:"updated_at"`
	Entries   []ipRepCacheEntry `json:"entries"`
}

var (
	ipRepMu        sync.RWMutex
	ipRepLive      = &ipRepState{exact: make(map[string]ipRepEntry)}
	ipRepCachePath string
)

func init() {
	home, _ := os.UserHomeDir()
	ipRepCachePath = filepath.Join(home, ".cache", "mcp-flowsentinel", "iprep.json")
	loadIPRepFromDisk()
}

// IPRepLookup returns (label, true) when ip is on a known C2/botnet blocklist,
// or ("", false) otherwise. Safe for concurrent use.
func IPRepLookup(ip string) (label string, ok bool) {
	if ip == "" {
		return "", false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}

	ipRepMu.RLock()
	state := ipRepLive
	ipRepMu.RUnlock()

	// Exact match first (O(1))
	if e, found := state.exact[ip]; found {
		return e.Label, true
	}
	// CIDR ranges (O(N) but N is small — ≤ a few hundred typical ranges)
	for _, r := range state.ranges {
		if r.net.Contains(parsed) {
			return r.entry.Label, true
		}
	}
	return "", false
}

// IPRepSize returns the number of exact IPs + CIDR ranges currently loaded.
func IPRepSize() int {
	ipRepMu.RLock()
	state := ipRepLive
	ipRepMu.RUnlock()
	return len(state.exact) + len(state.ranges)
}

// UpdateIPRep fetches all provided URLs and merges them into the in-memory
// reputation database. A local file (plain-text) is loaded first. Safe to call
// from a background goroutine.
//
// File format: one IP or CIDR per line; lines starting with '#' are comments.
// Example:
//
//	# Feodo Tracker C2 IPs
//	185.220.101.1
//	10.0.0.0/8
func UpdateIPRep(urls []string, localFile string) error {
	newExact := make(map[string]ipRepEntry)
	var newRanges []ipRepRange

	ingest := func(r io.Reader, source, label string) {
		parseIPRepStream(r, source, label, newExact, &newRanges)
	}

	if localFile != "" {
		if f, err := os.Open(localFile); err == nil {
			ingest(f, "local", "local blocklist")
			f.Close()
		} else {
			log.Printf("iprep: local file %q: %v", localFile, err)
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	var lastErr error
	for _, url := range urls {
		resp, err := client.Get(url) //nolint:noctx
		if err != nil {
			log.Printf("iprep: fetch %q: %v", url, err)
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			log.Printf("iprep: fetch %q: HTTP %d", url, resp.StatusCode)
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		src, lbl := ipRepSourceLabel(url)
		ingest(resp.Body, src, lbl)
		resp.Body.Close()
	}

	total := len(newExact) + len(newRanges)
	if total == 0 {
		if lastErr != nil {
			return fmt.Errorf("iprep update: all sources failed, last error: %w", lastErr)
		}
		return nil
	}

	newState := &ipRepState{exact: newExact, ranges: newRanges}
	ipRepMu.Lock()
	ipRepLive = newState
	ipRepMu.Unlock()

	log.Printf("iprep: loaded %d exact IPs + %d CIDR ranges", len(newExact), len(newRanges))
	saveIPRepToDisk(newExact, newRanges)
	return nil
}

// ─── Private helpers ──────────────────────────────────────────────────────────

func parseIPRepStream(r io.Reader, source, label string, exact map[string]ipRepEntry, ranges *[]ipRepRange) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip optional trailing comment after whitespace.
		if idx := strings.IndexByte(line, ' '); idx > 0 {
			line = line[:idx]
		}
		if idx := strings.IndexByte(line, '\t'); idx > 0 {
			line = line[:idx]
		}
		e := ipRepEntry{Source: source, Label: label}
		if strings.Contains(line, "/") {
			_, cidr, err := net.ParseCIDR(line)
			if err == nil {
				*ranges = append(*ranges, ipRepRange{net: cidr, entry: e})
			}
		} else {
			ip := net.ParseIP(line)
			if ip != nil {
				exact[ip.String()] = e
			}
		}
	}
}

func saveIPRepToDisk(exact map[string]ipRepEntry, ranges []ipRepRange) {
	dir := filepath.Dir(ipRepCachePath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		log.Printf("iprep: cannot create cache dir: %v", err)
		return
	}
	var entries []ipRepCacheEntry
	for ip, e := range exact {
		entries = append(entries, ipRepCacheEntry{CIDR: ip, Source: e.Source, Label: e.Label})
	}
	for _, r := range ranges {
		entries = append(entries, ipRepCacheEntry{CIDR: r.net.String(), Source: r.entry.Source, Label: r.entry.Label})
	}
	cache := ipRepCacheFile{UpdatedAt: time.Now().UTC(), Entries: entries}
	data, err := json.Marshal(cache)
	if err != nil {
		return
	}
	if err := os.WriteFile(ipRepCachePath, data, 0o640); err != nil {
		log.Printf("iprep: write cache: %v", err)
	}
}

func loadIPRepFromDisk() {
	data, err := os.ReadFile(ipRepCachePath)
	if err != nil {
		return
	}
	var cache ipRepCacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		log.Printf("iprep: corrupt cache — ignored: %v", err)
		return
	}
	newExact := make(map[string]ipRepEntry)
	var newRanges []ipRepRange
	for _, c := range cache.Entries {
		e := ipRepEntry{Source: c.Source, Label: c.Label}
		if strings.Contains(c.CIDR, "/") {
			_, cidr, err := net.ParseCIDR(c.CIDR)
			if err == nil {
				newRanges = append(newRanges, ipRepRange{net: cidr, entry: e})
			}
		} else {
			ip := net.ParseIP(c.CIDR)
			if ip != nil {
				newExact[ip.String()] = e
			}
		}
	}
	total := len(newExact) + len(newRanges)
	if total == 0 {
		return
	}
	ipRepMu.Lock()
	ipRepLive = &ipRepState{exact: newExact, ranges: newRanges}
	ipRepMu.Unlock()
	log.Printf("iprep: restored %d entries from disk cache (updated %s ago)",
		total, time.Since(cache.UpdatedAt).Round(time.Minute))
}

func ipRepSourceLabel(url string) (source, label string) {
	switch {
	case strings.Contains(url, "feodotracker"):
		return "feodo", "Feodo Tracker C2"
	case strings.Contains(url, "emergingthreats"):
		return "et", "Emerging Threats blocklist"
	case strings.Contains(url, "abuse.ch"):
		return "abuse.ch", "abuse.ch blocklist"
	default:
		return "custom_url", "threat intelligence blocklist"
	}
}
