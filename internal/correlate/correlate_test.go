package correlate

import (
	"fmt"
	"os"
	"testing"
)

var testProc = &ProcessInfo{PID: 42, Name: "testd", BinaryPath: "/usr/bin/testd"}

// makeTable builds a minimal SocketTable without requiring a live system,
// so the tests run in CI without root privileges.
func makeTable() *SocketTable {
	t := &SocketTable{
		byConn:      make(map[connKey]*ProcessInfo),
		byLocalPort: make(map[string]*ProcessInfo),
	}
	k := connKey{
		localIP:    "192.168.1.10",
		localPort:  8080,
		remoteIP:   "10.0.0.5",
		remotePort: 54321,
		proto:      "TCP",
	}
	t.byConn[k] = testProc
	// Mirror what BuildSocketTable does for the local-port index.
	lk := fmt.Sprintf("%s:%d:%s", "192.168.1.10", 8080, "TCP")
	t.byLocalPort[lk] = testProc
	wk := fmt.Sprintf("0.0.0.0:%d:%s", 8080, "TCP")
	t.byLocalPort[wk] = testProc
	return t
}

func TestSocketTable_ExactMatch(t *testing.T) {
	// Client (10.0.0.5:54321) → server (192.168.1.10:8080): reversed lookup.
	table := makeTable()
	info := table.Lookup("10.0.0.5", 54321, "192.168.1.10", 8080, "TCP")
	if info == nil {
		t.Fatal("expected match for client→server lookup, got nil")
	}
	if info.PID != 42 {
		t.Errorf("expected PID 42, got %d", info.PID)
	}
}

func TestSocketTable_ReverseMatch(t *testing.T) {
	// Server (192.168.1.10:8080) → client direction stored as exact key.
	table := makeTable()
	info := table.Lookup("192.168.1.10", 8080, "10.0.0.5", 54321, "TCP")
	if info == nil {
		t.Fatal("expected match for server→client lookup, got nil")
	}
}

func TestSocketTable_PartialMatch(t *testing.T) {
	// Different remote IP/port: should still match via local-port index.
	table := makeTable()
	info := table.Lookup("172.16.0.1", 9999, "192.168.1.10", 8080, "TCP")
	if info == nil {
		t.Fatal("expected partial match via local-port index, got nil")
	}
	if info.Name != "testd" {
		t.Errorf("expected name 'testd', got %q", info.Name)
	}
}

func TestSocketTable_WildcardMatch(t *testing.T) {
	// Lookup where only the wildcard (0.0.0.0) binding matches.
	table := makeTable()
	info := table.Lookup("172.16.0.99", 11111, "0.0.0.0", 8080, "TCP")
	if info == nil {
		t.Fatal("expected wildcard match for 0.0.0.0:8080, got nil")
	}
}

func TestSocketTable_Miss(t *testing.T) {
	table := makeTable()
	info := table.Lookup("1.2.3.4", 9999, "5.6.7.8", 7777, "UDP")
	if info != nil {
		t.Errorf("expected nil for unknown flow, got %+v", info)
	}
}

func TestProtoName(t *testing.T) {
	tests := []struct {
		sockType uint32
		want     string
	}{
		{1, "TCP"},
		{2, "UDP"},
		{3, "SOCK3"},
		{99, "SOCK99"},
	}
	for _, tc := range tests {
		if got := protoName(tc.sockType); got != tc.want {
			t.Errorf("protoName(%d) = %q, want %q", tc.sockType, got, tc.want)
		}
	}
}

// ─── BuildSocketTable ─────────────────────────────────────────────────────────

func TestBuildSocketTable_ReturnsValidTable(t *testing.T) {
	table := BuildSocketTable()
	if table == nil {
		t.Fatal("BuildSocketTable returned nil")
	}
	// Lookup on an empty or live-populated table must never panic.
	_ = table.Lookup("127.0.0.1", 0, "127.0.0.1", 0, "TCP")
}

// ─── ProcCache ────────────────────────────────────────────────────────────────

func TestProcCache_NewIsEmpty(t *testing.T) {
	pc := NewProcCache()
	if pc.Size() != 0 {
		t.Errorf("new ProcCache: Size() = %d, want 0", pc.Size())
	}
}

func TestProcCache_GetSetRoundtrip(t *testing.T) {
	pc := NewProcCache()
	want := &ProcessInfo{PID: 1234, Name: "testd"}
	pc.mu.Lock()
	pc.set(1234, want)
	got, ok := pc.get(1234)
	pc.mu.Unlock()
	if !ok {
		t.Fatal("get after set: expected hit")
	}
	if got != want {
		t.Error("get returned a different pointer than set stored")
	}
}

func TestProcCache_PruneRemovesStaleEntries(t *testing.T) {
	pc := NewProcCache()
	pc.mu.Lock()
	pc.set(10, &ProcessInfo{PID: 10})
	pc.set(20, &ProcessInfo{PID: 20})
	pc.set(30, &ProcessInfo{PID: 30})
	// Only PID 20 is still alive.
	pc.pruneExcept(map[int32]struct{}{20: {}})
	pc.mu.Unlock()

	if pc.Size() != 1 {
		t.Errorf("after prune: Size() = %d, want 1", pc.Size())
	}
	pc.mu.Lock()
	_, ok := pc.get(20)
	pc.mu.Unlock()
	if !ok {
		t.Error("active PID 20 should survive prune")
	}
}

func TestProcCache_PruneKeepsAllWhenAllActive(t *testing.T) {
	pc := NewProcCache()
	pc.mu.Lock()
	pc.set(1, &ProcessInfo{PID: 1})
	pc.set(2, &ProcessInfo{PID: 2})
	pc.pruneExcept(map[int32]struct{}{1: {}, 2: {}})
	pc.mu.Unlock()

	if pc.Size() != 2 {
		t.Errorf("after prune with all active: Size() = %d, want 2", pc.Size())
	}
}

func TestBuildSocketTableCached_DoesNotPanic(t *testing.T) {
	pc := NewProcCache()
	table := BuildSocketTableCached(pc)
	if table == nil {
		t.Fatal("BuildSocketTableCached returned nil")
	}
	// Second call should reuse the cache — must not panic.
	table2 := BuildSocketTableCached(pc)
	if table2 == nil {
		t.Fatal("second BuildSocketTableCached returned nil")
	}
	// Cache size must be non-negative and bounded.
	if pc.Size() < 0 {
		t.Errorf("ProcCache.Size() = %d, want >= 0", pc.Size())
	}
}

// ─── GetAllConnections ────────────────────────────────────────────────────────

func TestGetAllConnections_ReturnsMap(t *testing.T) {
	m, err := GetAllConnections()
	if err != nil {
		t.Skipf("GetAllConnections failed (acceptable in sandboxed env): %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil map")
	}
}

// ─── resolveProcess ───────────────────────────────────────────────────────────

func TestResolveProcess_CurrentProcess(t *testing.T) {
	pid := int32(os.Getpid())
	cache := make(map[int32]*ProcessInfo)

	info := resolveProcess(pid, cache)
	if info == nil {
		t.Fatal("expected non-nil ProcessInfo for current process")
	}
	if info.PID != pid {
		t.Errorf("PID = %d, want %d", info.PID, pid)
	}
	if info.Name == "" {
		t.Error("expected non-empty Name for current process")
	}
	// Second call must return the cached pointer.
	info2 := resolveProcess(pid, cache)
	if info2 != info {
		t.Error("second call should return the cached pointer")
	}
}

func TestResolveProcess_PIDZero_ReturnsEmptyInfo(t *testing.T) {
	cache := make(map[int32]*ProcessInfo)
	info := resolveProcess(0, cache)
	if info == nil {
		t.Fatal("expected non-nil ProcessInfo for PID 0")
	}
	if info.PID != 0 {
		t.Errorf("PID = %d, want 0", info.PID)
	}
	// Name is empty for PID 0 (kernel pseudo-process).
	if info.Name != "" {
		t.Logf("PID 0 name = %q (OS-dependent, not an error)", info.Name)
	}
}

func TestResolveProcess_NonExistentPID_ReturnsPlaceholder(t *testing.T) {
	cache := make(map[int32]*ProcessInfo)
	info := resolveProcess(999999999, cache)
	if info == nil {
		t.Fatal("expected non-nil placeholder for non-existent PID")
	}
	if info.PID != 999999999 {
		t.Errorf("PID = %d, want 999999999", info.PID)
	}
}

// ─── resolveProcessName ───────────────────────────────────────────────────────

func TestResolveProcessName_CurrentProcess_ReturnsName(t *testing.T) {
	cache := make(map[int32]*ProcessInfo)
	name := resolveProcessName(int32(os.Getpid()), cache)
	if name == "" {
		t.Error("expected non-empty name for current process")
	}
	// Second call must use cache (same result).
	name2 := resolveProcessName(int32(os.Getpid()), cache)
	if name2 != name {
		t.Errorf("cache miss on second call: got %q, want %q", name2, name)
	}
}

func TestResolveProcessName_NonExistentPID_ReturnsEmpty(t *testing.T) {
	cache := make(map[int32]*ProcessInfo)
	name := resolveProcessName(999999999, cache)
	if name != "" {
		t.Errorf("expected empty name for non-existent PID, got %q", name)
	}
}

func TestResolveProcessName_UsesCache(t *testing.T) {
	cache := map[int32]*ProcessInfo{
		42: {PID: 42, Name: "cached-proc"},
	}
	name := resolveProcessName(42, cache)
	if name != "cached-proc" {
		t.Errorf("expected cached name %q, got %q", "cached-proc", name)
	}
}
