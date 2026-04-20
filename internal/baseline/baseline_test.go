package baseline

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// resetGlobal wipes and re-initialises the global store for test isolation.
func resetGlobal() {
	global.mu.Lock()
	global.entries = make(map[string]*entry)
	global.cacheDir = ""
	global.mu.Unlock()
}

// ─── entry / Welford ─────────────────────────────────────────────────────────

func TestEntryWelford_SingleObservation(t *testing.T) {
	e := &entry{}
	e.observe(100)
	if e.N != 1 {
		t.Fatalf("N=%d want 1", e.N)
	}
	if e.MeanB != 100 {
		t.Fatalf("Mean=%f want 100", e.MeanB)
	}
	if e.M2B != 0 {
		t.Fatalf("M2=%f want 0", e.M2B)
	}
	if e.stddev() != 0 {
		t.Fatalf("stddev=%f want 0 for N<2", e.stddev())
	}
}

func TestEntryWelford_Mean(t *testing.T) {
	e := &entry{}
	for _, x := range []float64{10, 20, 30, 40, 50} {
		e.observe(x)
	}
	if math.Abs(e.MeanB-30) > 1e-9 {
		t.Fatalf("Mean=%.6f want 30", e.MeanB)
	}
}

func TestEntryWelford_Stddev(t *testing.T) {
	// population {2, 4, 4, 4, 5, 5, 7, 9} — sample stddev ≈ 2.0
	vals := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	e := &entry{}
	for _, v := range vals {
		e.observe(v)
	}
	// sample stddev = sqrt(32/7) ≈ 2.138
	want := 2.138
	got := e.stddev()
	if math.Abs(got-want) > 0.01 {
		t.Fatalf("stddev=%.4f want ~%.4f", got, want)
	}
}

func TestEntryZScore(t *testing.T) {
	e := &entry{}
	// Feed 10 identical values — stddev = 0 → zScore always 0.
	for i := 0; i < 10; i++ {
		e.observe(100)
	}
	if e.zScore(200) != 0 {
		t.Fatal("zScore with zero stddev should return 0")
	}
}

// ─── Stale ───────────────────────────────────────────────────────────────────

func TestEntryStale(t *testing.T) {
	e := &entry{LastSeen: time.Now().Add(-stalePeriod - time.Minute)}
	if !e.stale() {
		t.Fatal("entry should be stale")
	}
	e2 := &entry{LastSeen: time.Now()}
	if e2.stale() {
		t.Fatal("fresh entry should not be stale")
	}
}

// ─── AnomalyMultiplier ────────────────────────────────────────────────────────

func TestAnomalyMultiplier_NoBaseline(t *testing.T) {
	resetGlobal()
	m := AnomalyMultiplier("curl", 443, 1024)
	if m != 1.0 {
		t.Fatalf("multiplier=%f want 1.0 when no baseline", m)
	}
}

func TestAnomalyMultiplier_EmptyProcessName(t *testing.T) {
	resetGlobal()
	m := AnomalyMultiplier("", 80, 512)
	if m != 1.0 {
		t.Fatalf("multiplier=%f want 1.0 for empty process name", m)
	}
}

func TestAnomalyMultiplier_InsufficientData(t *testing.T) {
	resetGlobal()
	// Feed 4 observations — one short of minObservations (5).
	for i := 0; i < minObservations-1; i++ {
		Observe("curl", 443, 1024)
	}
	m := AnomalyMultiplier("curl", 443, 1024)
	if m != 1.0 {
		t.Fatalf("multiplier=%f want 1.0 when N < minObservations", m)
	}
}

func TestAnomalyMultiplier_NormalBehaviorDampened(t *testing.T) {
	resetGlobal()
	// Baseline: 100 KB per flow — tightly clustered.
	bytes := int64(100 * 1024)
	for i := 0; i < 20; i++ {
		Observe("curl", 443, bytes)
	}
	// Query at exactly the mean → Z ≈ 0 → multiplier = 0.7.
	m := AnomalyMultiplier("curl", 443, bytes)
	if m != 0.7 {
		t.Fatalf("multiplier=%f want 0.7 for Z≈0 (normal flow)", m)
	}
}

func TestAnomalyMultiplier_AnomalousLarge(t *testing.T) {
	resetGlobal()
	// Baseline: small flows ~1 KB with low variance.
	for i := 0; i < 20; i++ {
		Observe("agent", 8080, 1000+int64(i)) // 1000–1019 bytes
	}
	// Query at 100 MB — many σ above mean → multiplier = 1.8.
	m := AnomalyMultiplier("agent", 8080, 100*1024*1024)
	if m != 1.8 {
		t.Fatalf("multiplier=%f want 1.8 for highly anomalous flow", m)
	}
}

// ─── Observe ─────────────────────────────────────────────────────────────────

func TestObserve_UpdatesEntry(t *testing.T) {
	resetGlobal()
	Observe("python3", 4444, 512)
	Observe("python3", 4444, 1024)
	if Size() != 1 {
		t.Fatalf("size=%d want 1", Size())
	}
}

func TestObserve_CaseInsensitive(t *testing.T) {
	resetGlobal()
	Observe("Chrome", 443, 512)
	Observe("chrome", 443, 512)
	Observe("CHROME", 443, 512)
	if Size() != 1 {
		t.Fatalf("size=%d want 1 (case-insensitive key)", Size())
	}
}

// ─── Prune ────────────────────────────────────────────────────────────────────

func TestPrune_RemovesStaleEntries(t *testing.T) {
	resetGlobal()
	Observe("proc_a", 80, 1024)
	// Manually age the entry.
	global.mu.Lock()
	for _, e := range global.entries {
		e.LastSeen = time.Now().Add(-stalePeriod - time.Minute)
	}
	global.mu.Unlock()
	Observe("proc_b", 443, 2048) // fresh entry
	Prune()
	if Size() != 1 {
		t.Fatalf("size=%d want 1 after pruning stale entry", Size())
	}
}

// ─── Persist / Load ───────────────────────────────────────────────────────────

func TestPersistAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	resetGlobal()
	Init(tmpDir)

	for i := 0; i < 10; i++ {
		Observe("sshd", 22, int64(i*100))
	}
	if err := Persist(); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	// Reset and reload.
	resetGlobal()
	Init(tmpDir) // triggers load()

	// Verify the sshd baseline was restored.
	if Size() != 1 {
		t.Fatalf("size=%d want 1 after reload", Size())
	}
	// Observations: 0,100,200,...,900 → mean=450.
	// Querying at the mean gives Z=0 → Z < 1σ → multiplier = 0.7 (dampen normal).
	m := AnomalyMultiplier("sshd", 22, 450)
	if m != 0.7 {
		t.Fatalf("multiplier=%f want 0.7 after reload (query at mean)", m)
	}
}

func TestPersist_NoCacheDir(t *testing.T) {
	resetGlobal()
	// No cacheDir set — should be a no-op without error.
	if err := Persist(); err != nil {
		t.Fatalf("Persist with no cacheDir: %v", err)
	}
}

func TestLoad_CorruptFile(t *testing.T) {
	tmpDir := t.TempDir()
	resetGlobal()
	Init(tmpDir)
	// Write garbage.
	if err := os.WriteFile(filepath.Join(tmpDir, "baseline.json"), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Should not panic; store stays empty.
	load()
	if Size() != 0 {
		t.Fatalf("size=%d want 0 after corrupt load", Size())
	}
}

// ─── portStr ─────────────────────────────────────────────────────────────────

func TestPortStr(t *testing.T) {
	cases := []struct {
		in   uint16
		want string
	}{
		{0, "0"},
		{1, "1"},
		{80, "80"},
		{443, "443"},
		{65535, "65535"},
	}
	for _, c := range cases {
		got := portStr(c.in)
		if got != c.want {
			t.Errorf("portStr(%d)=%q want %q", c.in, got, c.want)
		}
	}
}
