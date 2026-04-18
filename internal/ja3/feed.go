// Package ja3 — feed.go provides a dynamic threat-intel feed for JA3 hashes.
//
// The feed is loaded from:
//  1. Remote URLs (CSV format: hash,description) — refreshed periodically
//  2. A local custom CSV file (same format)
//  3. A disk cache (~/.cache/mcp-flowsentinel/ja3_feed.json) used across restarts
//
// All lookups are non-blocking: the feed map is protected by a read-write mutex
// and callers in the scoring hot-path only hold the read lock for a map lookup.
package ja3

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

// feedEntry represents a single entry loaded from a remote or local feed.
type feedEntry struct {
	Hash        string `json:"hash"`
	Description string `json:"description"`
	Source      string `json:"source"` // "abuse.ch", "local", "custom_url"
}

// feedCache is the on-disk representation persisted between restarts.
type feedCache struct {
	UpdatedAt time.Time   `json:"updated_at"`
	Entries   []feedEntry `json:"entries"`
}

var (
	feedMu      sync.RWMutex
	feedEntries map[string]feedEntry // lower-case hash → entry
	feedCachePath string
)

func init() {
	home, _ := os.UserHomeDir()
	feedCachePath = filepath.Join(home, ".cache", "mcp-flowsentinel", "ja3_feed.json")
	feedEntries = make(map[string]feedEntry)
	loadFeedFromDisk()
}

// LookupWithFeed checks the hash against:
//  1. The built-in knownBadHashes map
//  2. The dynamically-loaded threat feed
//  3. The caller-supplied extra hashes from config
//
// This replaces LookupWithCustom in the scoring hot-path.
// The function is safe for concurrent use.
func LookupWithFeed(hash string, extraHashes []string) (family string, ok bool) {
	if hash == "" {
		return "", false
	}
	normalized := strings.ToLower(hash)

	// 1. Built-in static list (no lock needed — read-only after init)
	if desc, found := knownBadHashes[normalized]; found {
		return desc, true
	}

	// 2. Dynamic feed (read lock only — won't block concurrent scorers)
	feedMu.RLock()
	e, found := feedEntries[normalized]
	feedMu.RUnlock()
	if found {
		return e.Description, true
	}

	// 3. Config-supplied custom hashes
	return lookupCustom(normalized, extraHashes)
}

// lookupCustom is the lower-level check against caller-supplied hashes.
// Accepts an already-normalized (lower-case) hash.
func lookupCustom(normalized string, extraHashes []string) (string, bool) {
	for _, entry := range extraHashes {
		parts := strings.SplitN(entry, ":", 2)
		if strings.ToLower(strings.TrimSpace(parts[0])) == normalized {
			if len(parts) > 1 && parts[1] != "" {
				return parts[1], true
			}
			return "custom threat indicator", true
		}
	}
	return "", false
}

// UpdateFeed fetches all provided URLs, merges them into the in-memory feed,
// and persists the result to the disk cache. An optional local file path (CSV)
// is merged before the remote URLs. Safe to call from a background goroutine.
//
// URL format: CSV with at least 2 columns — hash, description.
// Lines starting with '#' are treated as comments and skipped.
// abuse.ch format: "JA3 MD5 Fingerprint","Description","Reference"
func UpdateFeed(urls []string, localFile string) error {
	newEntries := make(map[string]feedEntry)

	// Load local file first (highest priority for overrides)
	if localFile != "" {
		if err := loadCSVFile(localFile, "local", newEntries); err != nil {
			log.Printf("ja3feed: local file %q: %v", localFile, err)
		}
	}

	// Fetch remote URLs
	client := &http.Client{Timeout: 30 * time.Second}
	var lastErr error
	for _, url := range urls {
		source := sourceLabel(url)
		if err := fetchCSV(client, url, source, newEntries); err != nil {
			log.Printf("ja3feed: fetch %q failed: %v", url, err)
			lastErr = err
		}
	}

	if len(newEntries) == 0 {
		if lastErr != nil {
			return fmt.Errorf("ja3 feed update: all sources failed, last error: %w", lastErr)
		}
		return nil
	}

	// Atomically replace the live feed
	feedMu.Lock()
	feedEntries = newEntries
	feedMu.Unlock()

	log.Printf("ja3feed: loaded %d entries", len(newEntries))

	// Persist to disk for next restart
	saveFeedToDisk(newEntries)
	return nil
}

// FeedSize returns the number of entries currently loaded from the dynamic feed.
func FeedSize() int {
	feedMu.RLock()
	n := len(feedEntries)
	feedMu.RUnlock()
	return n
}

// ─── Private helpers ──────────────────────────────────────────────────────────

func fetchCSV(client *http.Client, url, source string, dst map[string]feedEntry) error {
	resp, err := client.Get(url) //nolint:noctx // explicit timeout set on client
	if err != nil {
		return fmt.Errorf("GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return parseCSV(resp.Body, source, dst)
}

func loadCSVFile(path, source string, dst map[string]feedEntry) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return parseCSV(f, source, dst)
}

// parseCSV reads a CSV stream where each non-comment line has at minimum:
//
//	column 0: JA3 MD5 hash (32 hex chars)
//	column 1: description / malware family
//
// abuse.ch format uses quoted fields; plain CSV also accepted.
func parseCSV(r io.Reader, source string, dst map[string]feedEntry) error {
	scanner := bufio.NewScanner(r)
	parsed := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip surrounding quotes (abuse.ch wraps fields in double-quotes)
		line = strings.ReplaceAll(line, `"`, "")
		parts := strings.SplitN(line, ",", 3)
		if len(parts) < 2 {
			continue
		}
		hash := strings.ToLower(strings.TrimSpace(parts[0]))
		if len(hash) != 32 {
			continue // not a valid MD5 hex string
		}
		desc := strings.TrimSpace(parts[1])
		if desc == "" {
			desc = "threat indicator (" + source + ")"
		}
		dst[hash] = feedEntry{Hash: hash, Description: desc, Source: source}
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

func saveFeedToDisk(entries map[string]feedEntry) {
	dir := filepath.Dir(feedCachePath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		log.Printf("ja3feed: cannot create cache dir %q: %v", dir, err)
		return
	}

	list := make([]feedEntry, 0, len(entries))
	for _, e := range entries {
		list = append(list, e)
	}
	cache := feedCache{UpdatedAt: time.Now().UTC(), Entries: list}
	data, err := json.Marshal(cache)
	if err != nil {
		log.Printf("ja3feed: marshal error: %v", err)
		return
	}
	if err := os.WriteFile(feedCachePath, data, 0o640); err != nil {
		log.Printf("ja3feed: write cache %q: %v", feedCachePath, err)
	}
}

func loadFeedFromDisk() {
	data, err := os.ReadFile(feedCachePath)
	if err != nil {
		return // cache miss — will be populated on first UpdateFeed call
	}
	var cache feedCache
	if err := json.Unmarshal(data, &cache); err != nil {
		log.Printf("ja3feed: corrupt cache %q — ignored: %v", feedCachePath, err)
		return
	}
	if len(cache.Entries) == 0 {
		return
	}
	m := make(map[string]feedEntry, len(cache.Entries))
	for _, e := range cache.Entries {
		m[strings.ToLower(e.Hash)] = e
	}
	feedMu.Lock()
	feedEntries = m
	feedMu.Unlock()
	log.Printf("ja3feed: restored %d entries from disk cache (updated %s ago)",
		len(m), time.Since(cache.UpdatedAt).Round(time.Minute))
}

// sourceLabel returns a short human-readable label for a URL.
func sourceLabel(url string) string {
	switch {
	case strings.Contains(url, "abuse.ch"):
		return "abuse.ch"
	case strings.Contains(url, "salesforce"):
		return "salesforce"
	default:
		return "custom_url"
	}
}
