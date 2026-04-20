// hassh_feed.go — dynamic HASSH threat-intel feed for the capture package.
//
// The feed is loaded from:
//  1. A local custom CSV file (highest priority)
//  2. Remote URLs (CSV format: hash,description) — refreshed periodically
//  3. A disk cache (~/.cache/mcp-flowsentinel/hassh_feed.json) used across restarts
//
// A public CSV HASSH feed does not yet exist with the same coverage as abuse.ch
// JA3, but the mechanism is in place so operators can supply their own lists and
// consume any future community feed.
//
// All lookups are non-blocking. The feed map is swapped atomically under a
// write lock; scorers hold only the read lock for a single map lookup.
package capture

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// hasshFeedEntry is a single entry from a remote or local HASSH feed.
type hasshFeedEntry struct {
	Hash        string `json:"hash"`
	Description string `json:"description"`
	Source      string `json:"source"`
}

// hasshFeedCache is the on-disk persistence format.
type hasshFeedCache struct {
	UpdatedAt time.Time        `json:"updated_at"`
	Entries   []hasshFeedEntry `json:"entries"`
}

var (
	hasshFeedMu        sync.RWMutex
	hasshFeedEntries   map[string]hasshFeedEntry // lower-case hash → entry
	hasshFeedCachePath string
)

func init() {
	home, _ := os.UserHomeDir()
	hasshFeedCachePath = filepath.Join(home, ".cache", "mcp-flowsentinel", "hassh_feed.json")
	hasshFeedEntries = make(map[string]hasshFeedEntry)
	loadHasshFeedFromDisk()
}

// LookupHASHWithFeed checks the hash against:
//  1. The built-in knownBadHasshHashes map
//  2. The dynamically-loaded threat feed
//
// This is the primary lookup used in the scoring hot-path and is safe for
// concurrent use.
func LookupHASHWithFeed(hash string) (family string, ok bool) {
	if hash == "" {
		return "", false
	}
	normalized := strings.ToLower(hash)

	// 1. Built-in static list (read-only after init — no lock needed)
	if desc, found := knownBadHasshHashes[normalized]; found {
		return desc, true
	}

	// 2. Dynamic feed (read lock only — does not block concurrent scoring)
	hasshFeedMu.RLock()
	e, found := hasshFeedEntries[normalized]
	hasshFeedMu.RUnlock()
	if found {
		return e.Description, true
	}

	return "", false
}

// UpdateHasshFeed fetches all provided URLs, merges them with the local file,
// and persists the result. Safe to call from a background goroutine.
//
// URL/file format: CSV with at least 2 columns — hash (32-char MD5 hex), description.
// Lines starting with '#' are treated as comments and skipped.
func UpdateHasshFeed(urls []string, localFile string) error {
	newEntries := make(map[string]hasshFeedEntry)

	// Local file takes priority over remote URLs.
	if localFile != "" {
		if err := loadHasshCSVFile(localFile, "local", newEntries); err != nil {
			log.Printf("hasshfeed: local file %q: %v", localFile, err)
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	var lastErr error
	for _, url := range urls {
		source := hasshSourceLabel(url)
		if err := fetchHasshCSV(client, url, source, newEntries); err != nil {
			log.Printf("hasshfeed: fetch %q failed: %v", url, err)
			lastErr = err
		}
	}

	if len(newEntries) == 0 {
		if lastErr != nil {
			return fmt.Errorf("hassh feed update: all sources failed, last error: %w", lastErr)
		}
		return nil
	}

	// Atomically replace the live feed map.
	hasshFeedMu.Lock()
	hasshFeedEntries = newEntries
	hasshFeedMu.Unlock()

	log.Printf("hasshfeed: loaded %d entries", len(newEntries))
	saveHasshFeedToDisk(newEntries)
	return nil
}

// HasshFeedSize returns the number of entries loaded from the dynamic feed.
func HasshFeedSize() int {
	hasshFeedMu.RLock()
	n := len(hasshFeedEntries)
	hasshFeedMu.RUnlock()
	return n
}

// ─── Private helpers ──────────────────────────────────────────────────────────

func fetchHasshCSV(client *http.Client, url, source string, dst map[string]hasshFeedEntry) error {
	resp, err := client.Get(url) //nolint:noctx // explicit timeout set on client
	if err != nil {
		return fmt.Errorf("GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return parseHasshCSV(resp.Body, source, dst)
}

func loadHasshCSVFile(path, source string, dst map[string]hasshFeedEntry) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return parseHasshCSV(f, source, dst)
}

// parseHasshCSV reads a CSV where each non-comment line has:
//
//	column 0: HASSH MD5 hash (32 hex chars)
//	column 1: description / tool name
func parseHasshCSV(r io.Reader, source string, dst map[string]hasshFeedEntry) error {
	scanner := bufio.NewScanner(r)
	parsed := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.ReplaceAll(line, `"`, "")
		parts := strings.SplitN(line, ",", 3)
		if len(parts) < 2 {
			continue
		}
		hash := strings.ToLower(strings.TrimSpace(parts[0]))
		if len(hash) != 32 {
			continue
		}
		desc := strings.TrimSpace(parts[1])
		if desc == "" {
			desc = "offensive SSH tool (" + source + ")"
		}
		dst[hash] = hasshFeedEntry{Hash: hash, Description: desc, Source: source}
		parsed++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if parsed == 0 {
		return fmt.Errorf("no valid entries found")
	}
	return nil
}

func saveHasshFeedToDisk(entries map[string]hasshFeedEntry) {
	dir := filepath.Dir(hasshFeedCachePath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		log.Printf("hasshfeed: cannot create cache dir %q: %v", dir, err)
		return
	}
	list := make([]hasshFeedEntry, 0, len(entries))
	for _, e := range entries {
		list = append(list, e)
	}
	cache := hasshFeedCache{UpdatedAt: time.Now().UTC(), Entries: list}
	data, err := json.Marshal(cache)
	if err != nil {
		log.Printf("hasshfeed: marshal error: %v", err)
		return
	}
	if err := os.WriteFile(hasshFeedCachePath, data, 0o640); err != nil {
		log.Printf("hasshfeed: write cache %q: %v", hasshFeedCachePath, err)
	}
}

func loadHasshFeedFromDisk() {
	data, err := os.ReadFile(hasshFeedCachePath)
	if err != nil {
		return
	}
	var cache hasshFeedCache
	if err := json.Unmarshal(data, &cache); err != nil {
		log.Printf("hasshfeed: corrupt cache %q — ignored: %v", hasshFeedCachePath, err)
		return
	}
	if len(cache.Entries) == 0 {
		return
	}
	m := make(map[string]hasshFeedEntry, len(cache.Entries))
	for _, e := range cache.Entries {
		m[strings.ToLower(e.Hash)] = e
	}
	hasshFeedMu.Lock()
	hasshFeedEntries = m
	hasshFeedMu.Unlock()
	log.Printf("hasshfeed: restored %d entries from disk cache (updated %s ago)",
		len(m), time.Since(cache.UpdatedAt).Round(time.Minute))
}

func hasshSourceLabel(url string) string {
	switch {
	case strings.Contains(url, "salesforce"):
		return "salesforce"
	case strings.Contains(url, "abuse.ch"):
		return "abuse.ch"
	default:
		return "custom_url"
	}
}
