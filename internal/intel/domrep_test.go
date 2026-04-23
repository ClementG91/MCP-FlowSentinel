package intel

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetDomRep() {
	domRepMu.Lock()
	domRepLive = &domRepState{domains: make(map[string]domRepEntry)}
	domRepMu.Unlock()
}

// ─── DomRepLookup ─────────────────────────────────────────────────────────────

func TestDomRepLookup_Empty(t *testing.T) {
	resetDomRep()
	if _, ok := DomRepLookup(""); ok {
		t.Fatal("empty domain should not match")
	}
}

func TestDomRepLookup_ExactMatch(t *testing.T) {
	resetDomRep()
	domRepMu.Lock()
	domRepLive.domains["evil.com"] = domRepEntry{Source: "test", Label: "C2 server"}
	domRepMu.Unlock()

	label, ok := DomRepLookup("evil.com")
	if !ok {
		t.Fatal("exact domain should match")
	}
	if !strings.Contains(label, "C2 server") {
		t.Errorf("label=%q want 'C2 server'", label)
	}
	resetDomRep()
}

func TestDomRepLookup_SubdomainMatch(t *testing.T) {
	resetDomRep()
	domRepMu.Lock()
	domRepLive.domains["evil.com"] = domRepEntry{Source: "test", Label: "botnet"}
	domRepMu.Unlock()

	_, ok := DomRepLookup("sub.evil.com")
	if !ok {
		t.Fatal("subdomain should match parent domain")
	}
	_, ok = DomRepLookup("other.example.com")
	if ok {
		t.Fatal("unrelated domain should not match")
	}
	resetDomRep()
}

func TestDomRepLookup_CaseInsensitive(t *testing.T) {
	resetDomRep()
	domRepMu.Lock()
	domRepLive.domains["evil.com"] = domRepEntry{Source: "test", Label: "test"}
	domRepMu.Unlock()

	if _, ok := DomRepLookup("EVIL.COM"); !ok {
		t.Fatal("lookup should be case-insensitive")
	}
	resetDomRep()
}

func TestDomRepLookup_NoMatch(t *testing.T) {
	resetDomRep()
	if _, ok := DomRepLookup("clean.example.com"); ok {
		t.Fatal("unknown domain should not match empty database")
	}
}

// ─── parseDomRepText ──────────────────────────────────────────────────────────

func TestParseDomRepText_URLhaus(t *testing.T) {
	input := `# URLhaus feed
http://malware.example.com/payload.exe
https://c2.evil.org/checkin
invalid line with spaces
`
	dst := make(map[string]domRepEntry)
	parseDomRepText(strings.NewReader(input), "urlhaus", dst)
	if len(dst) != 2 {
		t.Fatalf("len=%d want 2", len(dst))
	}
	if _, ok := dst["malware.example.com"]; !ok {
		t.Error("malware.example.com not parsed")
	}
	if _, ok := dst["c2.evil.org"]; !ok {
		t.Error("c2.evil.org not parsed")
	}
}

func TestParseDomRepText_PlainDomains(t *testing.T) {
	input := "evil.com\nbad.org\n# comment\n\n"
	dst := make(map[string]domRepEntry)
	parseDomRepText(strings.NewReader(input), "local", dst)
	if len(dst) != 2 {
		t.Fatalf("len=%d want 2", len(dst))
	}
}

// ─── parseDomRepThreatFox ─────────────────────────────────────────────────────

func TestParseDomRepThreatFox_Valid(t *testing.T) {
	csv := `# ThreatFox export
"1","evil.com","domain","botnet_cc","AgentTesla","2024-01-01","2024-01-01"
"2","http://malware.org/c2","url","botnet_cc","Remcos","2024-01-01","2024-01-01"
"3","1.2.3.4","ip:port","botnet_cc","SomeRAT","2024-01-01","2024-01-01"
`
	dst := make(map[string]domRepEntry)
	parseDomRepThreatFox(strings.NewReader(csv), "threatfox", dst)
	if len(dst) != 2 {
		t.Fatalf("len=%d want 2 (domain + url, not ip)", len(dst))
	}
	if _, ok := dst["evil.com"]; !ok {
		t.Error("evil.com not found")
	}
	if _, ok := dst["malware.org"]; !ok {
		t.Error("malware.org from URL ioc not found")
	}
}

// ─── UpdateDomRep (HTTP mock) ─────────────────────────────────────────────────

func TestUpdateDomRep_HTTPMock(t *testing.T) {
	resetDomRep()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("# test\nhttp://evil.example.com/malware\n"))
	}))
	defer srv.Close()

	if err := UpdateDomRep([]string{srv.URL}, ""); err != nil {
		t.Fatalf("UpdateDomRep: %v", err)
	}
	if DomRepSize() == 0 {
		t.Fatal("feed should have entries after update")
	}
	if _, ok := DomRepLookup("evil.example.com"); !ok {
		t.Fatal("parsed domain not found after update")
	}
	resetDomRep()
}

func TestUpdateDomRep_LocalFile(t *testing.T) {
	resetDomRep()
	tmp := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(tmp, []byte("malicious.example.org\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := UpdateDomRep(nil, tmp); err != nil {
		t.Fatalf("UpdateDomRep local: %v", err)
	}
	if _, ok := DomRepLookup("malicious.example.org"); !ok {
		t.Fatal("local file domain not found")
	}
	resetDomRep()
}

func TestUpdateDomRep_HTTPError(t *testing.T) {
	resetDomRep()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	err := UpdateDomRep([]string{srv.URL}, "")
	if err == nil {
		t.Fatal("expected error for HTTP 403")
	}
	resetDomRep()
}
