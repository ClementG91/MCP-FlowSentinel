// Package history persists analyzed flow records to a rolling 24-hour JSONL
// file at ~/.cache/mcp-flowsentinel/history.jsonl, allowing AI clients to
// query past capture sessions and correlate activity over time.
package history

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
)

const pruneEvery = 5 // run pruneOld after every N appends

// currentSchemaVersion is incremented whenever the Entry or FlowRecord schema
// changes in a backward-incompatible way. Readers treat v=0 (missing field) as
// a legacy entry written before schema versioning was introduced.
const currentSchemaVersion = 1

// Entry is one history record: a batch of flows from a single capture session.
type Entry struct {
	SchemaVersion int                    `json:"v,omitempty"` // 0 = legacy (pre-versioning), 1 = current
	Timestamp     time.Time              `json:"timestamp"`
	Source        string                 `json:"source"` // e.g. "live:eth0" or "pcap:/path/to/file"
	FlowCount     int                    `json:"flow_count"`
	Flows         []aggregate.FlowRecord `json:"flows"`
}

// QueryOpts controls what history.Query returns.
type QueryOpts struct {
	MaxAge      time.Duration // 0 → defaults to 24 h
	MinScore    float64       // 0 → all scores
	SrcIP       string        // "" → any source IP
	DstIP       string        // "" → any destination IP
	ProcessName string        // "" → any process; case-insensitive substring match
	TopN        int           // 0 → unlimited
}

// indexEntry maps a JSONL line's timestamp to its byte offset in histPath.
// The slice is kept sorted by Timestamp ascending so binary search can find
// the start offset for any time-range query in O(log n).
type indexEntry struct {
	ts     time.Time
	offset int64
}

var (
	mu          sync.Mutex
	histPath    string
	appendCount int64
	// offsetIndex is an in-memory index over the history JSONL file.
	// Protected by mu. Populated lazily on first Query and updated on Append.
	offsetIndex []indexEntry
)

func init() {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	dir := filepath.Join(home, ".cache", "mcp-flowsentinel")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		dir = os.TempDir()
	}
	histPath = filepath.Join(dir, "history.jsonl")
}

// Append persists a batch of flows to the history file.
// source is a human-readable label such as "live:eth0" or "pcap:/tmp/cap.pcap".
// Errors are silently swallowed — history is best-effort and must never break
// the main capture pipeline.
func Append(source string, flows []aggregate.FlowRecord) {
	if len(flows) == 0 {
		return
	}

	entry := Entry{
		SchemaVersion: currentSchemaVersion,
		Timestamp:     time.Now().UTC(),
		Source:        source,
		FlowCount:     len(flows),
		Flows:         flows,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	mu.Lock()
	f, err := os.OpenFile(histPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		mu.Unlock()
		return
	}
	// Record the offset of the new line before writing.
	offset, _ := f.Seek(0, 2) // seek to end = current file size
	f.WriteString(string(data) + "\n")
	f.Close()
	// Append to in-memory index (always sorted: new entries have the latest ts).
	offsetIndex = append(offsetIndex, indexEntry{ts: entry.Timestamp, offset: offset})
	mu.Unlock()

	// Prune old entries periodically to prevent unbounded file growth.
	if atomic.AddInt64(&appendCount, 1)%pruneEvery == 0 {
		go pruneOld()
	}
}

// Query reads the history file and returns entries that match opts.
// When the in-memory offset index is populated it seeks directly to the
// first entry that could fall within the requested time window, skipping
// any earlier bytes entirely (O(log n) seek vs O(n) full scan).
func Query(opts QueryOpts) ([]Entry, error) {
	if opts.MaxAge <= 0 {
		opts.MaxAge = time.Duration(config.Get().History.MaxAgeHours) * time.Hour
	}
	cutoff := time.Now().Add(-opts.MaxAge)

	mu.Lock()
	defer mu.Unlock()

	f, err := os.Open(histPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// If the index is empty (e.g. after a restart or prune) rebuild it from
	// the file so subsequent queries benefit from O(log n) seeks.
	if len(offsetIndex) == 0 {
		buildIndex(f) // ignore error — fall back to full scan
	}

	// Binary-search the index for the first entry whose timestamp >= cutoff.
	// Step back one entry as a safety margin for timestamp precision.
	startOffset := int64(0)
	if n := len(offsetIndex); n > 0 {
		lo, hi := 0, n
		for lo < hi {
			mid := (lo + hi) / 2
			if offsetIndex[mid].ts.Before(cutoff) {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		if lo > 0 {
			startOffset = offsetIndex[lo-1].offset
		}
	}
	// Always seek explicitly: buildIndex leaves the cursor at EOF.
	f.Seek(startOffset, 0)

	var results []Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

	for scanner.Scan() {
		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.Timestamp.Before(cutoff) {
			continue
		}

		filtered := filterFlows(entry.Flows, opts)
		if len(filtered) == 0 {
			continue
		}
		entry.Flows = filtered
		entry.FlowCount = len(filtered)
		results = append(results, entry)
	}

	return results, scanner.Err()
}

// buildIndex rebuilds the offsetIndex by scanning through the open history file.
// The file position is reset to 0 before scanning and left at EOF after.
// Must be called with mu held.
func buildIndex(f *os.File) error {
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	offsetIndex = offsetIndex[:0]
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	var offset int64
	for scanner.Scan() {
		line := scanner.Bytes()
		var entry Entry
		if err := json.Unmarshal(line, &entry); err == nil {
			offsetIndex = append(offsetIndex, indexEntry{ts: entry.Timestamp, offset: offset})
		}
		offset += int64(len(line)) + 1 // +1 for the '\n'
	}
	return scanner.Err()
}

// Path returns the absolute path of the history file for diagnostics.
func Path() string { return histPath }

// filterFlows applies QueryOpts filters to a slice of flows.
func filterFlows(flows []aggregate.FlowRecord, opts QueryOpts) []aggregate.FlowRecord {
	processFilter := strings.ToLower(opts.ProcessName)
	var out []aggregate.FlowRecord
	for _, f := range flows {
		if opts.MinScore > 0 && f.SuspicionScore < opts.MinScore {
			continue
		}
		if opts.SrcIP != "" && f.SrcIP != opts.SrcIP {
			continue
		}
		if opts.DstIP != "" && f.DstIP != opts.DstIP {
			continue
		}
		if processFilter != "" && !strings.Contains(strings.ToLower(f.ProcessName), processFilter) {
			continue
		}
		out = append(out, f)
	}
	// Sort by suspicion score descending before applying TopN so the caller
	// always receives the highest-risk flows, regardless of JSONL order.
	sort.Slice(out, func(i, j int) bool {
		return out[i].SuspicionScore > out[j].SuspicionScore
	})
	if opts.TopN > 0 && len(out) > opts.TopN {
		out = out[:opts.TopN]
	}
	return out
}

// SetPathForTesting overrides the history file path and resets all state.
// Must only be called from tests — not safe for concurrent use with Append/Query.
func SetPathForTesting(path string) {
	mu.Lock()
	defer mu.Unlock()
	histPath = path
	atomic.StoreInt64(&appendCount, 0)
	offsetIndex = offsetIndex[:0]
}

// pruneOld rewrites the history file removing entries older than maxAge.
// Also prunes to last 12 h when the file exceeds maxFileSize.
func pruneOld() {
	mu.Lock()
	defer mu.Unlock()

	fi, err := os.Stat(histPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("history: prune stat error: %v", err)
		}
		return
	}

	hcfg := config.Get().History
	age := time.Duration(hcfg.MaxAgeHours) * time.Hour
	if fi.Size() > int64(hcfg.MaxSizeMB)*1024*1024 {
		age = time.Duration(hcfg.PruneToHours) * time.Hour
	}
	cutoff := time.Now().Add(-age)

	f, err := os.Open(histPath)
	if err != nil {
		log.Printf("history: prune open error: %v", err)
		return
	}

	var keep [][]byte
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil || entry.Timestamp.After(cutoff) {
			cp := make([]byte, len(line))
			copy(cp, line)
			keep = append(keep, cp)
		}
	}
	f.Close()

	dir := filepath.Dir(histPath)
	tmp, err := os.CreateTemp(dir, ".history-prune-*")
	if err != nil {
		log.Printf("history: prune create temp: %v", err)
		return
	}
	w := bufio.NewWriter(tmp)
	for _, line := range keep {
		w.Write(line)
		w.WriteByte('\n')
	}
	w.Flush()
	tmp.Close()
	if err := os.Rename(tmp.Name(), histPath); err != nil {
		log.Printf("history: prune rename: %v", err)
		os.Remove(tmp.Name())
		return
	}
	// The file has been rewritten — invalidate the offset index so the next
	// Query rebuilds it from the new file.
	offsetIndex = offsetIndex[:0]
}
