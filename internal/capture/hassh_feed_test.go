package capture

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetHasshFeed() {
	hasshFeedMu.Lock()
	hasshFeedEntries = make(map[string]hasshFeedEntry)
	hasshFeedMu.Unlock()
}

// ─── LookupHASHWithFeed ───────────────────────────────────────────────────────

func TestLookupHASHWithFeed_EmptyHash(t *testing.T) {
	_, ok := LookupHASHWithFeed("")
	if ok {
		t.Fatal("empty hash should not match")
	}
}

func TestLookupHASHWithFeed_BuiltinStatic(t *testing.T) {
	// Paramiko is in the built-in map.
	desc, ok := LookupHASHWithFeed("b307ecfe3313e6a04c58bfdd13d91d4f")
	if !ok {
		t.Fatal("Paramiko HASSH should match built-in list")
	}
	if !strings.Contains(desc, "Paramiko") {
		t.Errorf("expected Paramiko in description, got %q", desc)
	}
}

func TestLookupHASHWithFeed_CaseInsensitive(t *testing.T) {
	_, ok := LookupHASHWithFeed("B307ECFE3313E6A04C58BFD D13D91D4F")
	// The hash with a space is invalid — should not match.
	if ok {
		t.Fatal("hash with embedded space should not match")
	}
	_, ok = LookupHASHWithFeed("B307ECFE3313E6A04C58BFDD13D91D4F")
	if !ok {
		t.Fatal("uppercase Paramiko hash should match (case-insensitive)")
	}
}

func TestLookupHASHWithFeed_DynamicFeed(t *testing.T) {
	resetHasshFeed()
	// Inject a fake feed entry directly.
	hasshFeedMu.Lock()
	hasshFeedEntries["aabbccddeeff00112233445566778899"] = hasshFeedEntry{
		Hash:        "aabbccddeeff00112233445566778899",
		Description: "TestTool",
		Source:      "test",
	}
	hasshFeedMu.Unlock()

	desc, ok := LookupHASHWithFeed("aabbccddeeff00112233445566778899")
	if !ok {
		t.Fatal("feed entry should match")
	}
	if desc != "TestTool" {
		t.Errorf("desc=%q want TestTool", desc)
	}
	resetHasshFeed()
}

// ─── parseHasshCSV ────────────────────────────────────────────────────────────

func TestParseHasshCSV_ValidLines(t *testing.T) {
	csv := `# comment
aabbccddeeff00112233445566778899,EvilTool
b307ecfe3313e6a04c58bfdd13d91d4f,Paramiko clone
`
	dst := make(map[string]hasshFeedEntry)
	if err := parseHasshCSV(strings.NewReader(csv), "test", dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dst) != 2 {
		t.Fatalf("len=%d want 2", len(dst))
	}
}

func TestParseHasshCSV_SkipsShortHashes(t *testing.T) {
	csv := "tooshort,EvilTool\naabbccddeeff00112233445566778899,GoodTool\n"
	dst := make(map[string]hasshFeedEntry)
	if err := parseHasshCSV(strings.NewReader(csv), "test", dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dst) != 1 {
		t.Fatalf("len=%d want 1", len(dst))
	}
}

func TestParseHasshCSV_EmptyFile(t *testing.T) {
	dst := make(map[string]hasshFeedEntry)
	err := parseHasshCSV(strings.NewReader("# only comments\n"), "test", dst)
	if err == nil {
		t.Fatal("empty CSV should return error")
	}
}

// ─── UpdateHasshFeed (HTTP mock) ──────────────────────────────────────────────

func TestUpdateHasshFeed_HTTPMock(t *testing.T) {
	resetHasshFeed()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("aabbccddeeff00112233445566778899,MockTool\n"))
	}))
	defer srv.Close()

	if err := UpdateHasshFeed([]string{srv.URL}, ""); err != nil {
		t.Fatalf("UpdateHasshFeed: %v", err)
	}
	if HasshFeedSize() != 1 {
		t.Fatalf("feed size=%d want 1", HasshFeedSize())
	}
	desc, ok := LookupHASHWithFeed("aabbccddeeff00112233445566778899")
	if !ok || desc != "MockTool" {
		t.Fatalf("lookup after update: ok=%v desc=%q", ok, desc)
	}
	resetHasshFeed()
}

func TestUpdateHasshFeed_LocalFile(t *testing.T) {
	resetHasshFeed()
	tmp := filepath.Join(t.TempDir(), "hassh.csv")
	content := "aabbccddeeff00112233445566778899,LocalTool\n"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := UpdateHasshFeed(nil, tmp); err != nil {
		t.Fatalf("UpdateHasshFeed local: %v", err)
	}
	_, ok := LookupHASHWithFeed("aabbccddeeff00112233445566778899")
	if !ok {
		t.Fatal("local file entry should be found")
	}
	resetHasshFeed()
}

func TestUpdateHasshFeed_HTTPError(t *testing.T) {
	resetHasshFeed()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	err := UpdateHasshFeed([]string{srv.URL}, "")
	if err == nil {
		t.Fatal("expected error for HTTP 403")
	}
	resetHasshFeed()
}
