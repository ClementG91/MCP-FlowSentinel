package intel

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetIPRep() {
	ipRepMu.Lock()
	ipRepLive = &ipRepState{exact: make(map[string]ipRepEntry)}
	ipRepMu.Unlock()
}

// ─── IPRepLookup ──────────────────────────────────────────────────────────────

func TestIPRepLookup_EmptyAndInvalid(t *testing.T) {
	resetIPRep()
	if _, ok := IPRepLookup(""); ok {
		t.Fatal("empty IP should not match")
	}
	if _, ok := IPRepLookup("not-an-ip"); ok {
		t.Fatal("invalid IP should not match")
	}
}

func TestIPRepLookup_ExactMatch(t *testing.T) {
	resetIPRep()
	ipRepMu.Lock()
	ipRepLive.exact["185.220.101.1"] = ipRepEntry{Source: "test", Label: "C2 server"}
	ipRepMu.Unlock()

	label, ok := IPRepLookup("185.220.101.1")
	if !ok {
		t.Fatal("exact IP should match")
	}
	if label != "C2 server" {
		t.Errorf("label=%q want C2 server", label)
	}
	resetIPRep()
}

func TestIPRepLookup_CIDRMatch(t *testing.T) {
	resetIPRep()
	_, cidr, _ := net.ParseCIDR("10.20.0.0/16")
	ipRepMu.Lock()
	ipRepLive.ranges = append(ipRepLive.ranges, ipRepRange{
		net:   cidr,
		entry: ipRepEntry{Source: "test", Label: "botnet range"},
	})
	ipRepMu.Unlock()

	label, ok := IPRepLookup("10.20.1.2")
	if !ok {
		t.Fatal("IP inside CIDR range should match")
	}
	if label != "botnet range" {
		t.Errorf("label=%q want botnet range", label)
	}

	_, ok = IPRepLookup("10.21.0.1")
	if ok {
		t.Fatal("IP outside CIDR range should not match")
	}
	resetIPRep()
}

func TestIPRepLookup_NoMatch(t *testing.T) {
	resetIPRep()
	if _, ok := IPRepLookup("8.8.8.8"); ok {
		t.Fatal("unknown IP should not match empty database")
	}
}

// ─── parseIPRepStream ─────────────────────────────────────────────────────────

func TestParseIPRepStream_Mixed(t *testing.T) {
	input := `# comment line
185.220.101.1
10.0.0.0/8
invalid-line
192.168.1.1
`
	exact := make(map[string]ipRepEntry)
	var ranges []ipRepRange
	parseIPRepStream(strings.NewReader(input), "test", "label", exact, &ranges)

	if len(exact) != 2 {
		t.Fatalf("exact=%d want 2", len(exact))
	}
	if len(ranges) != 1 {
		t.Fatalf("ranges=%d want 1", len(ranges))
	}
}

func TestParseIPRepStream_TrailingComment(t *testing.T) {
	// Some Feodo lists append " # comment" after the IP.
	input := "185.220.101.1 # Emotet\n"
	exact := make(map[string]ipRepEntry)
	var ranges []ipRepRange
	parseIPRepStream(strings.NewReader(input), "test", "label", exact, &ranges)
	if len(exact) != 1 {
		t.Fatalf("exact=%d want 1 (should strip trailing comment)", len(exact))
	}
}

// ─── UpdateIPRep (HTTP mock) ──────────────────────────────────────────────────

func TestUpdateIPRep_HTTPMock(t *testing.T) {
	resetIPRep()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("# test blocklist\n203.0.113.42\n198.51.100.0/24\n"))
	}))
	defer srv.Close()

	if err := UpdateIPRep([]string{srv.URL}, ""); err != nil {
		t.Fatalf("UpdateIPRep: %v", err)
	}
	if IPRepSize() != 2 { // 1 exact + 1 CIDR
		t.Fatalf("size=%d want 2", IPRepSize())
	}
	if _, ok := IPRepLookup("203.0.113.42"); !ok {
		t.Fatal("exact IP from feed not found")
	}
	if _, ok := IPRepLookup("198.51.100.5"); !ok {
		t.Fatal("CIDR-matched IP from feed not found")
	}
	resetIPRep()
}

func TestUpdateIPRep_LocalFile(t *testing.T) {
	resetIPRep()
	tmp := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := os.WriteFile(tmp, []byte("203.0.113.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := UpdateIPRep(nil, tmp); err != nil {
		t.Fatalf("UpdateIPRep local: %v", err)
	}
	if _, ok := IPRepLookup("203.0.113.1"); !ok {
		t.Fatal("local file IP not found")
	}
	resetIPRep()
}

func TestUpdateIPRep_HTTPError(t *testing.T) {
	resetIPRep()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := UpdateIPRep([]string{srv.URL}, "")
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	resetIPRep()
}

// ─── Persist / Load ───────────────────────────────────────────────────────────

func TestIPRepPersistAndLoad(t *testing.T) {
	resetIPRep()
	tmpDir := t.TempDir()
	oldPath := ipRepCachePath
	ipRepCachePath = filepath.Join(tmpDir, "iprep.json")
	defer func() { ipRepCachePath = oldPath }()

	exact := map[string]ipRepEntry{
		"10.0.0.1": {Source: "test", Label: "C2"},
	}
	_, cidr, _ := net.ParseCIDR("192.168.0.0/16")
	ranges := []ipRepRange{{net: cidr, entry: ipRepEntry{Source: "test", Label: "internal"}}}
	saveIPRepToDisk(exact, ranges)

	resetIPRep()
	loadIPRepFromDisk()

	if IPRepSize() != 2 {
		t.Fatalf("size=%d want 2 after reload", IPRepSize())
	}
}

// ─── ipRepSourceLabel ─────────────────────────────────────────────────────────

func TestIPRepSourceLabel(t *testing.T) {
	cases := []struct {
		url     string
		wantSrc string
	}{
		{"https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "feodo"},
		{"https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", "et"},
		{"https://example.com/blocklist.txt", "custom_url"},
	}
	for _, c := range cases {
		src, _ := ipRepSourceLabel(c.url)
		if src != c.wantSrc {
			t.Errorf("url=%s: src=%q want %q", c.url, src, c.wantSrc)
		}
	}
}
