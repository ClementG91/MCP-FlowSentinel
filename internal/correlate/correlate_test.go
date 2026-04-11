package correlate

import (
	"fmt"
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
