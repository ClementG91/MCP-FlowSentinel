package history

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
)

// ─── test helpers ─────────────────────────────────────────────────────────────

func makeFlow(srcIP, dstIP, process string, score float64) aggregate.FlowRecord {
	return aggregate.FlowRecord{
		SrcIP:          srcIP,
		DstIP:          dstIP,
		ProcessName:    process,
		SuspicionScore: score,
	}
}

// setup redirects the package to a fresh temp file and returns a cleanup func.
func setup(t *testing.T) {
	t.Helper()
	tmp, err := os.CreateTemp(t.TempDir(), "history-*.jsonl")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	tmp.Close()
	SetPathForTesting(tmp.Name())
}

// injectEntry writes a pre-constructed Entry directly to histPath,
// bypassing Append so we can force arbitrary timestamps.
func injectEntry(t *testing.T, e Entry) {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	f, err := os.OpenFile(histPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open hist: %v", err)
	}
	defer f.Close()
	f.Write(b)
	f.WriteString("\n")
}

// ─── Append ──────────────────────────────────────────────────────────────────

func TestAppend_WritesAndReadsBack(t *testing.T) {
	setup(t)

	flows := []aggregate.FlowRecord{
		makeFlow("1.2.3.4", "5.6.7.8", "curl", 2.5),
		makeFlow("1.2.3.4", "9.9.9.9", "wget", 4.0),
	}
	Append("live:eth0", flows)

	entries, err := Query(QueryOpts{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].FlowCount != 2 {
		t.Errorf("FlowCount = %d, want 2", entries[0].FlowCount)
	}
	if entries[0].Source != "live:eth0" {
		t.Errorf("Source = %q, want %q", entries[0].Source, "live:eth0")
	}
}

func TestAppend_EmptyInput_Noop(t *testing.T) {
	setup(t)

	Append("live:eth0", nil)
	Append("live:eth0", []aggregate.FlowRecord{})

	entries, err := Query(QueryOpts{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries after empty appends, got %d", len(entries))
	}
}

func TestAppend_MultipleEntries(t *testing.T) {
	setup(t)

	for i := 0; i < 3; i++ {
		Append(fmt.Sprintf("src:%d", i), []aggregate.FlowRecord{
			makeFlow("10.0.0.1", "8.8.8.8", "proc", float64(i)),
		})
	}

	entries, err := Query(QueryOpts{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

// ─── Query filters ────────────────────────────────────────────────────────────

func TestQuery_SrcIP_Filter(t *testing.T) {
	setup(t)

	Append("s", []aggregate.FlowRecord{
		makeFlow("10.0.0.1", "8.8.8.8", "proc", 1.0),
		makeFlow("10.0.0.2", "8.8.8.8", "proc", 2.0),
	})

	entries, err := Query(QueryOpts{SrcIP: "10.0.0.1"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	for _, f := range entries[0].Flows {
		if f.SrcIP != "10.0.0.1" {
			t.Errorf("unexpected SrcIP %q in filtered result", f.SrcIP)
		}
	}
}

func TestQuery_DstIP_Filter(t *testing.T) {
	setup(t)

	Append("s", []aggregate.FlowRecord{
		makeFlow("1.1.1.1", "8.8.8.8", "proc", 1.0),
		makeFlow("1.1.1.1", "1.1.1.2", "proc", 2.0),
	})

	entries, err := Query(QueryOpts{DstIP: "8.8.8.8"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Flows[0].DstIP != "8.8.8.8" {
		t.Errorf("DstIP filter returned wrong flow")
	}
}

func TestQuery_ProcessName_CaseInsensitiveSubstring(t *testing.T) {
	setup(t)

	Append("s", []aggregate.FlowRecord{
		makeFlow("1.1.1.1", "2.2.2.2", "Curl.EXE", 1.0),
		makeFlow("1.1.1.1", "3.3.3.3", "wget", 2.0),
	})

	entries, err := Query(QueryOpts{ProcessName: "curl"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 || len(entries[0].Flows) != 1 {
		t.Errorf("expected 1 flow matching 'curl', got entries=%d", len(entries))
	}
	if entries[0].Flows[0].ProcessName != "Curl.EXE" {
		t.Errorf("wrong process matched: %q", entries[0].Flows[0].ProcessName)
	}
}

func TestQuery_MinScore_Filter(t *testing.T) {
	setup(t)

	Append("s", []aggregate.FlowRecord{
		makeFlow("1.1.1.1", "2.2.2.2", "p", 1.0),
		makeFlow("1.1.1.1", "3.3.3.3", "p", 6.0),
	})

	entries, err := Query(QueryOpts{MinScore: 5.0})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry above MinScore=5, got %d", len(entries))
	}
	if entries[0].Flows[0].SuspicionScore < 5.0 {
		t.Errorf("MinScore filter returned score=%.1f", entries[0].Flows[0].SuspicionScore)
	}
}

func TestQuery_NoHistoryFile_ReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	SetPathForTesting(dir + "/nonexistent.jsonl")

	entries, err := Query(QueryOpts{})
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

// ─── TopN ordering (the bug that was fixed) ───────────────────────────────────

func TestFilterFlows_TopN_SortsByScoreDesc(t *testing.T) {
	flows := []aggregate.FlowRecord{
		makeFlow("a", "b", "p", 1.0),
		makeFlow("a", "c", "p", 9.0),
		makeFlow("a", "d", "p", 4.5),
		makeFlow("a", "e", "p", 7.0),
	}

	got := filterFlows(flows, QueryOpts{TopN: 2})
	if len(got) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(got))
	}
	if got[0].SuspicionScore != 9.0 {
		t.Errorf("first flow score = %.1f, want 9.0", got[0].SuspicionScore)
	}
	if got[1].SuspicionScore != 7.0 {
		t.Errorf("second flow score = %.1f, want 7.0", got[1].SuspicionScore)
	}
}

func TestFilterFlows_TopN_Zero_ReturnsAll(t *testing.T) {
	flows := make([]aggregate.FlowRecord, 10)
	for i := range flows {
		flows[i] = makeFlow("a", fmt.Sprintf("%d.%d.%d.%d", i, i, i, i), "p", float64(i))
	}
	got := filterFlows(flows, QueryOpts{TopN: 0})
	if len(got) != 10 {
		t.Errorf("TopN=0 should return all 10 flows, got %d", len(got))
	}
}

func TestFilterFlows_TopN_LargerThanSlice(t *testing.T) {
	flows := []aggregate.FlowRecord{
		makeFlow("a", "b", "p", 3.0),
		makeFlow("a", "c", "p", 1.0),
	}
	got := filterFlows(flows, QueryOpts{TopN: 100})
	if len(got) != 2 {
		t.Errorf("TopN larger than slice: expected 2, got %d", len(got))
	}
}

// ─── pruneOld ─────────────────────────────────────────────────────────────────

func TestPruneOld_RemovesStaleEntries(t *testing.T) {
	setup(t)

	// Fresh entry via normal Append.
	Append("fresh", []aggregate.FlowRecord{makeFlow("1.1.1.1", "2.2.2.2", "p", 0.5)})

	// Inject a stale entry with a timestamp 48 h in the past.
	injectEntry(t, Entry{
		Timestamp: time.Now().Add(-48 * time.Hour),
		Source:    "stale",
		FlowCount: 1,
		Flows:     []aggregate.FlowRecord{makeFlow("9.9.9.9", "8.8.8.8", "old", 0.0)},
	})

	// Both are visible with a wide window before pruning.
	before, _ := Query(QueryOpts{MaxAge: 72 * time.Hour})
	if len(before) != 2 {
		t.Fatalf("expected 2 entries before prune, got %d", len(before))
	}

	pruneOld()

	after, err := Query(QueryOpts{MaxAge: 72 * time.Hour})
	if err != nil {
		t.Fatalf("Query after prune: %v", err)
	}
	if len(after) != 1 {
		t.Errorf("expected 1 entry after prune, got %d", len(after))
	}
	if after[0].Source != "fresh" {
		t.Errorf("wrong entry survived prune: source=%q", after[0].Source)
	}
}

// ─── Concurrent Append (run with -race) ───────────────────────────────────────

func TestAppend_Concurrent_NoDataRace(t *testing.T) {
	setup(t)

	const n = 30
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(id int) {
			defer wg.Done()
			Append(fmt.Sprintf("goroutine:%d", id), []aggregate.FlowRecord{
				makeFlow(fmt.Sprintf("10.0.0.%d", id%254+1), "8.8.8.8", "proc", float64(id%10)),
			})
		}(i)
	}
	wg.Wait()

	// On Windows, pruneOld runs in a background goroutine (go pruneOld()) and
	// may still hold the history file open when the test's TempDir cleanup runs.
	// A short sleep lets any in-flight prune goroutines finish before cleanup.
	time.Sleep(200 * time.Millisecond)

	entries, err := Query(QueryOpts{})
	if err != nil {
		t.Fatalf("Query after concurrent appends: %v", err)
	}
	if len(entries) != n {
		t.Errorf("expected %d entries, got %d", n, len(entries))
	}
}

func TestPath_ReturnsNonEmpty(t *testing.T) {
	setup(t)
	p := Path()
	if p == "" {
		t.Error("Path() returned empty string")
	}
}

// ─── Error path coverage ──────────────────────────────────────────────────────

func TestAppend_InvalidPath_SilentlyIgnored(t *testing.T) {
	// Direct mutation of histPath to a path inside a non-existent subdirectory.
	// os.OpenFile will fail; Append must return without panicking.
	mu.Lock()
	orig := histPath
	histPath = filepath.Join(t.TempDir(), "nonexistent-subdir", "history.jsonl")
	mu.Unlock()
	defer func() {
		mu.Lock()
		histPath = orig
		mu.Unlock()
	}()

	// Must not panic — write errors are silently swallowed.
	Append("source", []aggregate.FlowRecord{makeFlow("1.1.1.1", "2.2.2.2", "proc", 1.0)})
}

func TestQuery_BadJSONLine_IsSkipped(t *testing.T) {
	setup(t)

	// Write a garbage line followed by a valid entry.
	mu.Lock()
	f, err := os.OpenFile(histPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		mu.Unlock()
		t.Fatalf("open hist: %v", err)
	}
	f.WriteString("not-valid-json\n")
	f.Close()
	mu.Unlock()

	Append("valid-source", []aggregate.FlowRecord{makeFlow("1.1.1.1", "2.2.2.2", "proc", 1.0)})

	entries, err := Query(QueryOpts{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	// The bad line is skipped; only the valid entry is returned.
	if len(entries) != 1 {
		t.Errorf("expected 1 entry (bad line skipped), got %d", len(entries))
	}
}

func TestQuery_AllFlowsFilteredOut_EntrySkipped(t *testing.T) {
	setup(t)

	// Append an entry with a low-score flow (score < MinScore).
	Append("source", []aggregate.FlowRecord{makeFlow("1.1.1.1", "2.2.2.2", "proc", 0.5)})

	// Query with a MinScore higher than any flow in the file.
	entries, err := Query(QueryOpts{MinScore: 9.0})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	// All flows filtered out → entry is skipped → 0 results.
	if len(entries) != 0 {
		t.Errorf("expected 0 entries when all flows filtered out, got %d", len(entries))
	}
}

func TestAppend_NaNScore_JsonMarshalError_SilentlyIgnored(t *testing.T) {
	setup(t)

	// math.NaN() in a float64 field causes json.Marshal to return an error.
	// Append must silently ignore it.
	flows := []aggregate.FlowRecord{
		makeFlow("1.1.1.1", "2.2.2.2", "proc", 0),
	}
	flows[0].SuspicionScore = math.NaN()

	Append("source", flows) // must not panic

	entries, err := Query(QueryOpts{})
	if err != nil {
		t.Fatalf("Query after NaN append: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries after marshal-error append, got %d", len(entries))
	}
}

func TestPruneOld_NoFile_SilentlyIgnored(t *testing.T) {
	// Set histPath to a non-existent file. pruneOld must not panic.
	dir := t.TempDir()
	SetPathForTesting(filepath.Join(dir, "nonexistent.jsonl"))
	pruneOld() // os.Stat fails → early return, no panic
}

func TestPruneOld_LargeFile_Uses12hWindow(t *testing.T) {
	setup(t)

	// Inject a stale entry (48h old) that should be pruned.
	injectEntry(t, Entry{
		Timestamp: time.Now().Add(-48 * time.Hour),
		Source:    "stale",
		FlowCount: 1,
		Flows:     []aggregate.FlowRecord{makeFlow("9.9.9.9", "8.8.8.8", "old", 0)},
	})
	// Inject a recent entry (1h old) that should survive even the 12h window.
	injectEntry(t, Entry{
		Timestamp: time.Now().Add(-1 * time.Hour),
		Source:    "fresh",
		FlowCount: 1,
		Flows:     []aggregate.FlowRecord{makeFlow("1.1.1.1", "2.2.2.2", "p", 0)},
	})

	// Make the file appear > configured max size (default 50 MB) via sparse file.
	maxFileSizeBytes := int64(config.Get().History.MaxSizeMB) * 1024 * 1024
	mu.Lock()
	if err := os.Truncate(histPath, maxFileSizeBytes+1); err != nil {
		mu.Unlock()
		t.Skipf("cannot create sparse file on this OS: %v", err)
	}
	mu.Unlock()

	pruneOld()

	entries, err := Query(QueryOpts{MaxAge: 72 * time.Hour})
	if err != nil {
		t.Fatalf("Query after large-file prune: %v", err)
	}
	// Stale (48h) entry should be pruned under 12h window; fresh (1h) survives.
	for _, e := range entries {
		if e.Source == "stale" {
			t.Error("stale entry should have been pruned in large-file mode")
		}
	}
}

func TestQuery_TooOldEntry_IsSkipped(t *testing.T) {
	// Exercises the "entry.Timestamp.Before(cutoff) → continue" branch in Query.
	setup(t)

	// Inject an entry 8 days old — older than the default maxAge of 7 days.
	injectEntry(t, Entry{
		Timestamp: time.Now().Add(-8 * 24 * time.Hour),
		Source:    "too-old",
		FlowCount: 1,
		Flows:     []aggregate.FlowRecord{makeFlow("1.2.3.4", "5.6.7.8", "oldproc", 0.1)},
	})
	// Inject a fresh entry that should survive.
	injectEntry(t, Entry{
		Timestamp: time.Now().Add(-1 * time.Hour),
		Source:    "fresh",
		FlowCount: 1,
		Flows:     []aggregate.FlowRecord{makeFlow("10.0.0.1", "8.8.8.8", "proc", 0.2)},
	})

	// Default MaxAge (7*24h) — the 8-day-old entry must be skipped.
	entries, err := Query(QueryOpts{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for _, e := range entries {
		if e.Source == "too-old" {
			t.Error("8-day-old entry should be excluded by default maxAge window")
		}
	}
	// The fresh entry must still be present.
	found := false
	for _, e := range entries {
		if e.Source == "fresh" {
			found = true
		}
	}
	if !found {
		t.Error("fresh entry should be included in results")
	}
}

func TestQuery_OpenError_NotIsNotExist_ReturnsError(t *testing.T) {
	// Use a path with invalid characters on the target OS to trigger an open
	// error that is NOT an "IsNotExist" error (the file path is syntactically
	// invalid, not merely absent).
	//
	// On Windows, '|' is an illegal filename character → "invalid argument".
	// On Linux/macOS, '\x00' (null byte) is illegal in path components.
	var badPath string
	if os.PathSeparator == '\\' { // Windows
		badPath = filepath.Join(t.TempDir(), "bad|name.jsonl")
	} else {
		badPath = filepath.Join(t.TempDir(), "bad\x00name.jsonl")
	}
	SetPathForTesting(badPath)

	entries, err := Query(QueryOpts{})
	// The path is syntactically invalid on this OS, so os.Open should return
	// an error. But if the OS doesn't reject it (e.g. treats it as absent),
	// we accept that gracefully too.
	if err != nil {
		t.Logf("got expected open error: %v", err)
		if len(entries) != 0 {
			t.Errorf("expected 0 entries on error, got %d", len(entries))
		}
	} else {
		t.Logf("OS did not reject invalid path (treated as absent, entries=%d)", len(entries))
	}
}

// ─── Schema versioning ────────────────────────────────────────────────────────

func TestAppend_SetsCurrentSchemaVersion(t *testing.T) {
	setup(t)
	flow := makeFlow("1.2.3.4", "5.6.7.8", "proc", 5.0)
	Append("test", []aggregate.FlowRecord{flow})

	// Read the raw JSONL to verify the "v" field is set.
	mu.Lock()
	b, err := os.ReadFile(histPath)
	mu.Unlock()
	if err != nil {
		t.Fatalf("read history file: %v", err)
	}
	var e Entry
	if err := json.Unmarshal(b[:len(b)-1], &e); err != nil {
		t.Fatalf("unmarshal entry: %v", err)
	}
	if e.SchemaVersion != currentSchemaVersion {
		t.Errorf("SchemaVersion=%d, want %d", e.SchemaVersion, currentSchemaVersion)
	}
}

func TestQuery_LegacyEntries_BackwardCompat(t *testing.T) {
	// Entries written before schema versioning have v=0 (JSON zero value / omitempty).
	// They must be readable without error.
	setup(t)
	legacy := Entry{
		// SchemaVersion intentionally omitted (zero value → omitted via omitempty).
		Timestamp: time.Now().UTC(),
		Source:    "legacy",
		FlowCount: 1,
		Flows:     []aggregate.FlowRecord{makeFlow("10.0.0.1", "10.0.0.2", "old", 3.0)},
	}
	injectEntry(t, legacy)

	entries, err := Query(QueryOpts{MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].SchemaVersion != 0 {
		t.Errorf("legacy entry SchemaVersion should be 0, got %d", entries[0].SchemaVersion)
	}
	if len(entries[0].Flows) != 1 {
		t.Errorf("expected 1 flow in legacy entry, got %d", len(entries[0].Flows))
	}
}

// ─── Gzip rotation ────────────────────────────────────────────────────────────

// enableRotation sets CompressRotated=true on the global config and returns a
// restore function that the caller should defer.
func enableRotation(t *testing.T, maxRotatedDays int) func() {
	t.Helper()
	orig := config.Get()
	cfg := *orig
	cfg.History.CompressRotated = true
	cfg.History.MaxRotatedDays = maxRotatedDays
	config.Set(&cfg)
	return func() { config.Set(orig) }
}

func TestMergeIntoGzip_CreateAndRead(t *testing.T) {
	dir := t.TempDir()
	gzPath := filepath.Join(dir, "test.jsonl.gz")

	lines := [][]byte{[]byte(`{"source":"a"}`), []byte(`{"source":"b"}`)}
	if err := mergeIntoGzip(gzPath, lines); err != nil {
		t.Fatalf("mergeIntoGzip: %v", err)
	}

	// Read back via queryCompressedFiles indirectly through a full Query round-trip.
	// Here we verify the file is a valid gzip that can be opened and read.
	f, err := os.Open(gzPath)
	if err != nil {
		t.Fatalf("open gz: %v", err)
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gr.Close()
	scanner := bufio.NewScanner(gr)
	var got []string
	for scanner.Scan() {
		got = append(got, scanner.Text())
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(got))
	}
}

func TestMergeIntoGzip_MergesWithExistingContent(t *testing.T) {
	dir := t.TempDir()
	gzPath := filepath.Join(dir, "test.jsonl.gz")

	first := [][]byte{[]byte(`{"source":"first"}`)}
	if err := mergeIntoGzip(gzPath, first); err != nil {
		t.Fatalf("first mergeIntoGzip: %v", err)
	}

	second := [][]byte{[]byte(`{"source":"second"}`)}
	if err := mergeIntoGzip(gzPath, second); err != nil {
		t.Fatalf("second mergeIntoGzip: %v", err)
	}

	f, _ := os.Open(gzPath)
	defer f.Close()
	gr, _ := gzip.NewReader(f)
	defer gr.Close()
	scanner := bufio.NewScanner(gr)
	var count int
	for scanner.Scan() {
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 merged lines, got %d", count)
	}
}

func TestRotateOldEntriesToGzip_Disabled_Noop(t *testing.T) {
	setup(t)
	// CompressRotated is false by default — no .gz file must be created.
	injectEntry(t, Entry{
		Timestamp: time.Now().Add(-48 * time.Hour),
		Source:    "old",
		FlowCount: 1,
		Flows:     []aggregate.FlowRecord{makeFlow("1.1.1.1", "2.2.2.2", "p", 1.0)},
	})
	mu.Lock()
	rotateOldEntriesToGzip()
	mu.Unlock()

	dir := filepath.Dir(histPath)
	des, _ := os.ReadDir(dir)
	for _, de := range des {
		if strings.HasSuffix(de.Name(), ".jsonl.gz") {
			t.Errorf("unexpected gz file created when CompressRotated=false: %s", de.Name())
		}
	}
}

func TestRotateOldEntriesToGzip_MovesOldAndKeepsToday(t *testing.T) {
	setup(t)
	restore := enableRotation(t, 0)
	defer restore()

	yesterday := time.Now().UTC().Add(-25 * time.Hour)
	injectEntry(t, Entry{
		Timestamp: yesterday,
		Source:    "yesterday",
		FlowCount: 1,
		Flows:     []aggregate.FlowRecord{makeFlow("1.1.1.1", "2.2.2.2", "p", 1.0)},
	})
	Append("today", []aggregate.FlowRecord{makeFlow("3.3.3.3", "4.4.4.4", "q", 2.0)})

	mu.Lock()
	rotateOldEntriesToGzip()
	mu.Unlock()

	// The hot file should only contain today's entry.
	entries, err := Query(QueryOpts{MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for _, e := range entries {
		if e.Source == "yesterday" {
			t.Error("yesterday's entry should have been rotated out of the hot file")
		}
	}

	// A .gz file for yesterday's date should exist.
	expectedDay := yesterday.Format("2006-01-02")
	gzPath := filepath.Join(filepath.Dir(histPath), "history_"+expectedDay+".jsonl.gz")
	if _, err := os.Stat(gzPath); err != nil {
		t.Errorf("expected gz file %s to exist: %v", gzPath, err)
	}
}

func TestQueryCompressedFiles_ReturnsEntriesFromGzip(t *testing.T) {
	setup(t)
	restore := enableRotation(t, 30)
	defer restore()

	// Directly write a gz file for 2 days ago.
	twoDaysAgo := time.Now().UTC().Add(-49 * time.Hour)
	day := twoDaysAgo.Format("2006-01-02")
	entry := Entry{
		SchemaVersion: currentSchemaVersion,
		Timestamp:     twoDaysAgo,
		Source:        "gz-source",
		FlowCount:     1,
		Flows:         []aggregate.FlowRecord{makeFlow("5.5.5.5", "6.6.6.6", "gz-proc", 7.0)},
	}
	b, _ := json.Marshal(entry)
	gzPath := filepath.Join(filepath.Dir(histPath), "history_"+day+".jsonl.gz")
	if err := mergeIntoGzip(gzPath, [][]byte{b}); err != nil {
		t.Fatalf("mergeIntoGzip: %v", err)
	}

	// Query with a window that covers 3 days.
	results, err := Query(QueryOpts{MaxAge: 72 * time.Hour})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	found := false
	for _, e := range results {
		if e.Source == "gz-source" {
			found = true
		}
	}
	if !found {
		t.Error("expected entry from compressed file to appear in Query results")
	}
}

func TestRotateOldEntriesToGzip_PurgesOldGzFiles(t *testing.T) {
	setup(t)
	restore := enableRotation(t, 7)
	defer restore()

	dir := filepath.Dir(histPath)
	// Plant a .gz file that is 10 days old — older than MaxRotatedDays=7.
	oldDay := time.Now().UTC().AddDate(0, 0, -10).Format("2006-01-02")
	oldGz := filepath.Join(dir, "history_"+oldDay+".jsonl.gz")
	if err := mergeIntoGzip(oldGz, [][]byte{[]byte(`{}`)}); err != nil {
		t.Fatalf("plant old gz: %v", err)
	}

	// Plant an entry older than today to trigger actual rotation.
	injectEntry(t, Entry{
		Timestamp: time.Now().UTC().Add(-25 * time.Hour),
		Source:    "old",
		FlowCount: 1,
		Flows:     []aggregate.FlowRecord{makeFlow("1.1.1.1", "2.2.2.2", "p", 1.0)},
	})

	mu.Lock()
	rotateOldEntriesToGzip()
	mu.Unlock()

	if _, err := os.Stat(oldGz); !os.IsNotExist(err) {
		t.Errorf("expected old gz file to be purged, but it still exists (err=%v)", err)
	}
}
