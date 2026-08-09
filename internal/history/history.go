// Package history persists analyzed flow records to a rolling 24-hour JSONL
// file at ~/.cache/mcp-flowsentinel/history.jsonl, allowing AI clients to
// query past capture sessions and correlate activity over time.
package history

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
)

const (
	pruneEvery         = 5        // run pruneOld after every N appends
	maxHistoryLineSize = 64 << 20 // bound memory use and keep JSONL scanners readable
)

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
// Persistence remains best-effort for callers, but errors are returned so the
// capture pipeline can report data loss instead of silently claiming success.
func Append(source string, flows []aggregate.FlowRecord) error {
	if len(flows) == 0 {
		return nil
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
		return fmt.Errorf("marshal history entry: %w", err)
	}
	if len(data) > maxHistoryLineSize {
		return fmt.Errorf("history entry is %d bytes, limit is %d", len(data), maxHistoryLineSize)
	}

	mu.Lock()
	defer mu.Unlock()
	f, err := os.OpenFile(histPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open history: %w", err)
	}
	// Record the offset of the new line before writing.
	offset, err := f.Seek(0, 2) // seek to end = current file size
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("seek history: %w", err)
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("append history: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close history: %w", err)
	}
	// Append to in-memory index (always sorted: new entries have the latest ts).
	offsetIndex = append(offsetIndex, indexEntry{ts: entry.Timestamp, offset: offset})

	// Prune old entries periodically to prevent unbounded file growth.
	if atomic.AddInt64(&appendCount, 1)%pruneEvery == 0 {
		go pruneOld()
	}
	return nil
}

// Query reads the history file and returns entries that match opts.
// When the in-memory offset index is populated it seeks directly to the
// first entry that could fall within the requested time window, skipping
// any earlier bytes entirely (O(log n) seek vs O(n) full scan).
// If CompressRotated is enabled, rotated daily gzip files are also consulted
// whenever the requested time window spans more than today.
func Query(opts QueryOpts) ([]Entry, error) {
	if opts.MaxAge <= 0 {
		opts.MaxAge = time.Duration(config.Get().History.MaxAgeHours) * time.Hour
	}
	cutoff := time.Now().Add(-opts.MaxAge)

	mu.Lock()
	defer mu.Unlock()

	f, err := os.Open(histPath)
	if os.IsNotExist(err) {
		if config.Get().History.CompressRotated {
			results, queryErr := queryCompressedFiles(cutoff, opts)
			if queryErr != nil {
				return nil, queryErr
			}
			sort.Slice(results, func(i, j int) bool {
				return results[i].Timestamp.Before(results[j].Timestamp)
			})
			return results, nil
		}
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
	if _, err := f.Seek(startOffset, 0); err != nil {
		return nil, fmt.Errorf("seek history query: %w", err)
	}

	var results []Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), maxHistoryLineSize)

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
	if err := scanner.Err(); err != nil {
		return results, err
	}

	// Also search rotated daily gzip files when the window spans multiple days.
	if config.Get().History.CompressRotated {
		compressed, err := queryCompressedFiles(cutoff, opts)
		if err != nil {
			return results, err
		}
		results = append(results, compressed...)
		sort.Slice(results, func(i, j int) bool {
			return results[i].Timestamp.Before(results[j].Timestamp)
		})
	}

	return results, nil
}

// queryCompressedFiles scans rotated history_YYYY-MM-DD.jsonl.gz files for
// entries matching opts. Must be called with mu held.
func queryCompressedFiles(cutoff time.Time, opts QueryOpts) ([]Entry, error) {
	dir := filepath.Dir(histPath)
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rotated history directory: %w", err)
	}

	var results []Entry
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if !strings.HasPrefix(name, "history_") || !strings.HasSuffix(name, ".jsonl.gz") {
			continue
		}
		// Parse the date embedded in the filename to skip obviously out-of-range files.
		datePart := strings.TrimSuffix(strings.TrimPrefix(name, "history_"), ".jsonl.gz")
		fileDate, err := time.Parse("2006-01-02", datePart)
		if err != nil {
			continue
		}
		// Entire day ended before the cutoff — nothing in this file is useful.
		endOfDay := time.Date(fileDate.Year(), fileDate.Month(), fileDate.Day()+1, 0, 0, 0, 0, time.UTC)
		if endOfDay.Before(cutoff) {
			continue
		}

		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return results, fmt.Errorf("open rotated history %s: %w", name, err)
		}
		gr, err := gzip.NewReader(f)
		if err != nil {
			_ = f.Close()
			return results, fmt.Errorf("open rotated history %s: %w", name, err)
		}
		scanner := bufio.NewScanner(gr)
		scanner.Buffer(make([]byte, 64*1024), maxHistoryLineSize)
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
		if err := scanner.Err(); err != nil {
			_ = gr.Close()
			_ = f.Close()
			return results, fmt.Errorf("scan rotated history %s: %w", name, err)
		}
		if err := gr.Close(); err != nil {
			_ = f.Close()
			return results, fmt.Errorf("close rotated history %s: %w", name, err)
		}
		if err := f.Close(); err != nil {
			return results, fmt.Errorf("close rotated history file %s: %w", name, err)
		}
	}
	return results, nil
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
	scanner.Buffer(make([]byte, 64*1024), maxHistoryLineSize)
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

// RecurrenceKey returns the canonical string key for a flow tuple.
// Exported so callers can construct matching keys without duplicating format.
func RecurrenceKey(srcIP, dstIP string, dstPort uint16, proto string) string {
	return srcIP + "\x00" + dstIP + "\x00" + strconv.FormatUint(uint64(dstPort), 10) + "\x00" + proto
}

// RecurrenceMap returns a map from RecurrenceKey to the number of distinct
// capture windows that contained a matching flow within the lookback period.
// Each Entry is counted at most once per flow key (duplicate flows in the same
// window are deduplicated). Used for slow-and-low C2 detection.
func RecurrenceMap(since time.Time) map[string]int {
	mu.Lock()
	defer mu.Unlock()

	counts := make(map[string]int)
	f, err := os.Open(histPath)
	if os.IsNotExist(err) {
		if config.Get().History.CompressRotated {
			addCompressedRecurrences(counts, since)
		}
		return counts
	}
	if err != nil {
		log.Printf("history: recurrence open: %v", err)
		return counts
	}
	defer f.Close()

	if len(offsetIndex) == 0 {
		buildIndex(f) //nolint:errcheck
	}
	startOffset := int64(0)
	if n := len(offsetIndex); n > 0 {
		lo, hi := 0, n
		for lo < hi {
			mid := (lo + hi) / 2
			if offsetIndex[mid].ts.Before(since) {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		if lo > 0 {
			startOffset = offsetIndex[lo-1].offset
		}
	}
	if _, err := f.Seek(startOffset, 0); err != nil {
		return nil
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), maxHistoryLineSize)
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		if e.Timestamp.Before(since) {
			continue
		}
		seen := make(map[string]struct{}, len(e.Flows))
		for _, fl := range e.Flows {
			k := RecurrenceKey(fl.SrcIP, fl.DstIP, fl.DstPort, fl.Protocol)
			if _, dup := seen[k]; !dup {
				seen[k] = struct{}{}
				counts[k]++
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("history: recurrence scan error: %v", err)
	}
	if config.Get().History.CompressRotated {
		addCompressedRecurrences(counts, since)
	}
	return counts
}

// addCompressedRecurrences augments counts with rotated history. Must be called
// with mu held. Corrupt files are logged and skipped so recurrence scoring can
// continue from the healthy history that remains.
func addCompressedRecurrences(counts map[string]int, since time.Time) {
	dir := filepath.Dir(histPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("history: recurrence read rotated directory: %v", err)
		return
	}
	for _, de := range entries {
		name := de.Name()
		if de.IsDir() || !strings.HasPrefix(name, "history_") || !strings.HasSuffix(name, ".jsonl.gz") {
			continue
		}
		datePart := strings.TrimSuffix(strings.TrimPrefix(name, "history_"), ".jsonl.gz")
		fileDate, err := time.Parse("2006-01-02", datePart)
		if err != nil || fileDate.Add(24*time.Hour).Before(since) {
			continue
		}
		path := filepath.Join(dir, name)
		f, err := os.Open(path)
		if err != nil {
			log.Printf("history: recurrence open %s: %v", path, err)
			continue
		}
		gr, err := gzip.NewReader(f)
		if err != nil {
			_ = f.Close()
			log.Printf("history: recurrence gzip %s: %v", path, err)
			continue
		}
		scanner := bufio.NewScanner(gr)
		scanner.Buffer(make([]byte, 64*1024), maxHistoryLineSize)
		for scanner.Scan() {
			var e Entry
			if json.Unmarshal(scanner.Bytes(), &e) != nil || e.Timestamp.Before(since) {
				continue
			}
			addEntryRecurrences(counts, e)
		}
		if err := scanner.Err(); err != nil {
			log.Printf("history: recurrence scan %s: %v", path, err)
		}
		_ = gr.Close()
		_ = f.Close()
	}
}

func addEntryRecurrences(counts map[string]int, e Entry) {
	seen := make(map[string]struct{}, len(e.Flows))
	for _, fl := range e.Flows {
		k := RecurrenceKey(fl.SrcIP, fl.DstIP, fl.DstPort, fl.Protocol)
		if _, dup := seen[k]; !dup {
			seen[k] = struct{}{}
			counts[k]++
		}
	}
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
// When CompressRotated is enabled, yesterday's entries are moved to a
// per-day gzip file before pruning.
func pruneOld() {
	mu.Lock()
	defer mu.Unlock()

	// Rotate old entries into compressed daily files first, so they are
	// preserved even after the hot file is trimmed.
	rotateOldEntriesToGzip()

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
	var keepBytes int64
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), maxHistoryLineSize)
	for scanner.Scan() {
		line := scanner.Bytes()
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil || entry.Timestamp.After(cutoff) {
			cp := make([]byte, len(line))
			copy(cp, line)
			keep = append(keep, cp)
			keepBytes += int64(len(cp) + 1)
		}
	}
	if err := scanner.Err(); err != nil {
		_ = f.Close()
		log.Printf("history: prune scan error: %v", err)
		return
	}
	if err := f.Close(); err != nil {
		log.Printf("history: prune close error: %v", err)
		return
	}

	// Enforce MaxSizeMB as a hard cap by dropping the oldest retained entries.
	maxBytes := int64(hcfg.MaxSizeMB) * 1024 * 1024
	for maxBytes > 0 && keepBytes > maxBytes && len(keep) > 0 {
		keepBytes -= int64(len(keep[0]) + 1)
		keep = keep[1:]
	}

	dir := filepath.Dir(histPath)
	tmp, err := os.CreateTemp(dir, ".history-prune-*")
	if err != nil {
		log.Printf("history: prune create temp: %v", err)
		return
	}
	w := bufio.NewWriter(tmp)
	for _, line := range keep {
		if _, err := w.Write(line); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
			log.Printf("history: prune write: %v", err)
			return
		}
		if err := w.WriteByte('\n'); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
			log.Printf("history: prune newline: %v", err)
			return
		}
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		log.Printf("history: prune flush: %v", err)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		log.Printf("history: prune close temp: %v", err)
		return
	}
	if err := replaceFileSafely(tmp.Name(), histPath); err != nil {
		log.Printf("history: prune rename: %v", err)
		_ = os.Remove(tmp.Name())
		return
	}
	// The file has been rewritten — invalidate the offset index so the next
	// Query rebuilds it from the new file.
	offsetIndex = offsetIndex[:0]
}

// rotateOldEntriesToGzip moves entries from history.jsonl that are older than
// the start of today UTC into per-day history_YYYY-MM-DD.jsonl.gz files.
// Old compressed files beyond MaxRotatedDays are deleted.
// Must be called with mu held.
func rotateOldEntriesToGzip() {
	hcfg := config.Get().History
	if !hcfg.CompressRotated {
		return
	}

	now := time.Now().UTC()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	f, err := os.Open(histPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("history: rotate open: %v", err)
		}
		return
	}

	// Partition entries: today stays in the hot file; older entries go to gzip.
	var todayLines [][]byte
	perDay := make(map[string][][]byte)
	var orderedDays []string // insertion order for deterministic output

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), maxHistoryLineSize)
	for scanner.Scan() {
		raw := scanner.Bytes()
		cp := make([]byte, len(raw))
		copy(cp, raw)

		var entry Entry
		if err := json.Unmarshal(raw, &entry); err != nil || entry.Timestamp.IsZero() {
			todayLines = append(todayLines, cp) // keep unparseable lines
			continue
		}
		if entry.Timestamp.UTC().Before(todayStart) {
			day := entry.Timestamp.UTC().Format("2006-01-02")
			if _, ok := perDay[day]; !ok {
				orderedDays = append(orderedDays, day)
			}
			perDay[day] = append(perDay[day], cp)
		} else {
			todayLines = append(todayLines, cp)
		}
	}
	if err := scanner.Err(); err != nil {
		_ = f.Close()
		log.Printf("history: rotate scan: %v", err)
		return
	}
	if err := f.Close(); err != nil {
		log.Printf("history: rotate close: %v", err)
		return
	}

	if len(perDay) == 0 {
		return // nothing to rotate
	}

	dir := filepath.Dir(histPath)

	// Merge each day's entries into its compressed file.
	for _, day := range orderedDays {
		gzPath := filepath.Join(dir, "history_"+day+".jsonl.gz")
		if err := mergeIntoGzip(gzPath, perDay[day]); err != nil {
			log.Printf("history: rotate write %s: %v", gzPath, err)
			return // abort; leave hot file untouched
		}
	}

	// Rewrite the hot file with today's entries only.
	tmp, err := os.CreateTemp(dir, ".history-rotate-*")
	if err != nil {
		log.Printf("history: rotate create temp: %v", err)
		return
	}
	bw := bufio.NewWriter(tmp)
	for _, line := range todayLines {
		if _, err := bw.Write(line); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
			log.Printf("history: rotate write: %v", err)
			return
		}
		if err := bw.WriteByte('\n'); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
			log.Printf("history: rotate newline: %v", err)
			return
		}
	}
	if err := bw.Flush(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		log.Printf("history: rotate flush: %v", err)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		log.Printf("history: rotate close temp: %v", err)
		return
	}
	if err := replaceFileSafely(tmp.Name(), histPath); err != nil {
		log.Printf("history: rotate rename: %v", err)
		_ = os.Remove(tmp.Name())
		return
	}
	offsetIndex = offsetIndex[:0]

	// Delete compressed files older than MaxRotatedDays.
	if hcfg.MaxRotatedDays > 0 {
		purgeCutoff := now.AddDate(0, 0, -hcfg.MaxRotatedDays)
		des, err := os.ReadDir(dir)
		if err != nil {
			log.Printf("history: purge read directory: %v", err)
			return
		}
		for _, de := range des {
			if de.IsDir() {
				continue
			}
			name := de.Name()
			if !strings.HasPrefix(name, "history_") || !strings.HasSuffix(name, ".jsonl.gz") {
				continue
			}
			datePart := strings.TrimSuffix(strings.TrimPrefix(name, "history_"), ".jsonl.gz")
			t, err := time.Parse("2006-01-02", datePart)
			if err != nil {
				continue
			}
			if t.Before(purgeCutoff) {
				if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
					log.Printf("history: purge %s: %v", name, err)
				}
			}
		}
	}
}

// mergeIntoGzip reads any existing lines from a gzip file, appends newLines,
// and atomically rewrites the file. This ensures idempotent daily rotation.
func mergeIntoGzip(path string, newLines [][]byte) error {
	var existing [][]byte
	seen := make(map[string]struct{})
	if ef, err := os.Open(path); err == nil {
		gr, gerr := gzip.NewReader(ef)
		if gerr == nil {
			scanner := bufio.NewScanner(gr)
			scanner.Buffer(make([]byte, 64*1024), maxHistoryLineSize)
			for scanner.Scan() {
				raw := scanner.Bytes()
				cp := make([]byte, len(raw))
				copy(cp, raw)
				existing = append(existing, cp)
				seen[string(cp)] = struct{}{}
			}
			if err := scanner.Err(); err != nil {
				_ = gr.Close()
				_ = ef.Close()
				return fmt.Errorf("scan existing gzip: %w", err)
			}
			if err := gr.Close(); err != nil {
				_ = ef.Close()
				return fmt.Errorf("close existing gzip: %w", err)
			}
		} else {
			_ = ef.Close()
			return fmt.Errorf("open existing gzip: %w", gerr)
		}
		if err := ef.Close(); err != nil {
			return fmt.Errorf("close existing gzip file: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("open existing gzip file: %w", err)
	}

	all := existing
	for _, line := range newLines {
		if _, duplicate := seen[string(line)]; duplicate {
			continue
		}
		seen[string(line)] = struct{}{}
		all = append(all, line)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".history-gz-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	gz, err := gzip.NewWriterLevel(tmp, gzip.BestCompression)
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("gzip writer: %w", err)
	}
	bw := bufio.NewWriter(gz)
	for _, line := range all {
		if _, err := bw.Write(line); err != nil {
			_ = gz.Close()
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
			return fmt.Errorf("write gzip: %w", err)
		}
		if err := bw.WriteByte('\n'); err != nil {
			_ = gz.Close()
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
			return fmt.Errorf("write gzip newline: %w", err)
		}
	}
	if err := bw.Flush(); err != nil {
		gz.Close()
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("flush: %w", err)
	}
	if err := gz.Close(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("gzip close: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("close temp: %w", err)
	}
	if err := replaceFileSafely(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// replaceFileSafely uses a direct atomic rename where the platform supports
// replacing an existing destination. On Windows it falls back to a recoverable
// backup-and-swap sequence and restores the original if installation fails.
func replaceFileSafely(tempPath, dstPath string) error {
	if err := os.Rename(tempPath, dstPath); err == nil {
		return nil
	}

	backup, err := os.CreateTemp(filepath.Dir(dstPath), ".history-backup-*")
	if err != nil {
		return fmt.Errorf("create replacement backup: %w", err)
	}
	backupPath := backup.Name()
	if err := backup.Close(); err != nil {
		_ = os.Remove(backupPath)
		return fmt.Errorf("close replacement backup: %w", err)
	}
	if err := os.Remove(backupPath); err != nil {
		return fmt.Errorf("prepare replacement backup: %w", err)
	}
	if err := os.Rename(dstPath, backupPath); err != nil {
		return fmt.Errorf("backup destination: %w", err)
	}
	if err := os.Rename(tempPath, dstPath); err != nil {
		if restoreErr := os.Rename(backupPath, dstPath); restoreErr != nil {
			return fmt.Errorf("replace destination: %w (restore failed: %v; backup retained at %s)", err, restoreErr, backupPath)
		}
		return fmt.Errorf("replace destination: %w (original restored)", err)
	}
	if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove replacement backup %s: %w", backupPath, err)
	}
	return nil
}
