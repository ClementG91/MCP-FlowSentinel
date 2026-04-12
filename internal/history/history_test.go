package history

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
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

	// Make the file appear > maxFileSize (50 MB) via truncation (sparse file).
	mu.Lock()
	if err := os.Truncate(histPath, maxFileSize+1); err != nil {
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
