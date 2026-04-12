// Package history persists analyzed flow records to a rolling 24-hour JSONL
// file at ~/.cache/mcp-flowsentinel/history.jsonl, allowing AI clients to
// query past capture sessions and correlate activity over time.
package history

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
)

const (
	maxAge     = 24 * time.Hour
	maxFileSize = 50 * 1024 * 1024 // 50 MB — prune more aggressively above this
	pruneEvery  = 5                 // run pruneOld after every N appends
)

// Entry is one history record: a batch of flows from a single capture session.
type Entry struct {
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"` // e.g. "live:eth0" or "pcap:/path/to/file"
	FlowCount int                    `json:"flow_count"`
	Flows     []aggregate.FlowRecord `json:"flows"`
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

var (
	mu          sync.Mutex
	histPath    string
	appendCount int64
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
		Timestamp: time.Now().UTC(),
		Source:    source,
		FlowCount: len(flows),
		Flows:     flows,
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
	f.WriteString(string(data) + "\n")
	f.Close()
	mu.Unlock()

	// Prune old entries periodically to prevent unbounded file growth.
	if atomic.AddInt64(&appendCount, 1)%pruneEvery == 0 {
		go pruneOld()
	}
}

// Query reads the history file and returns entries that match opts.
func Query(opts QueryOpts) ([]Entry, error) {
	if opts.MaxAge <= 0 {
		opts.MaxAge = maxAge
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

// SetPathForTesting overrides the history file path.
// Must only be called from tests — not safe for concurrent use with Append/Query.
func SetPathForTesting(path string) {
	mu.Lock()
	defer mu.Unlock()
	histPath = path
	atomic.StoreInt64(&appendCount, 0)
}

// pruneOld rewrites the history file removing entries older than maxAge.
// Also prunes to last 12 h when the file exceeds maxFileSize.
func pruneOld() {
	mu.Lock()
	defer mu.Unlock()

	fi, err := os.Stat(histPath)
	if err != nil {
		return
	}

	age := maxAge
	if fi.Size() > maxFileSize {
		age = 12 * time.Hour
	}
	cutoff := time.Now().Add(-age)

	f, err := os.Open(histPath)
	if err != nil {
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
		return
	}
	w := bufio.NewWriter(tmp)
	for _, line := range keep {
		w.Write(line)
		w.WriteByte('\n')
	}
	w.Flush()
	tmp.Close()
	os.Rename(tmp.Name(), histPath)
}
