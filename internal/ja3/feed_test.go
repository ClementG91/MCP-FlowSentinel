package ja3

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetFeed clears the in-memory feed for test isolation.
func resetFeed() {
	feedMu.Lock()
	feedEntries = make(map[string]feedEntry)
	feedMu.Unlock()
}

func TestLookupWithFeed_BuiltIn(t *testing.T) {
	resetFeed()
	// Cobalt Strike is in the built-in list
	desc, ok := LookupWithFeed("51c64c77e60f3980eea90869b68c58a8", nil)
	if !ok {
		t.Fatal("expected built-in hash to be found")
	}
	if !strings.Contains(strings.ToLower(desc), "cobalt") {
		t.Errorf("unexpected description: %q", desc)
	}
}

func TestLookupWithFeed_DynamicFeed(t *testing.T) {
	resetFeed()
	// Inject a test entry directly into the feed map.
	testHash := "aabbccdd11223344aabbccdd11223344"
	feedMu.Lock()
	feedEntries[testHash] = feedEntry{Hash: testHash, Description: "TestMalware", Source: "test"}
	feedMu.Unlock()

	desc, ok := LookupWithFeed(testHash, nil)
	if !ok {
		t.Fatal("expected dynamic feed entry to be found")
	}
	if desc != "TestMalware" {
		t.Errorf("expected TestMalware, got %q", desc)
	}
}

func TestLookupWithFeed_CustomExtra(t *testing.T) {
	resetFeed()
	hash := "deadbeefdeadbeefdeadbeefdeadbeef"
	extra := []string{hash + ":RedTeam Tool"}

	desc, ok := LookupWithFeed(hash, extra)
	if !ok {
		t.Fatal("expected custom extra hash to be found")
	}
	if desc != "RedTeam Tool" {
		t.Errorf("expected RedTeam Tool, got %q", desc)
	}
}

func TestLookupWithFeed_NotFound(t *testing.T) {
	resetFeed()
	_, ok := LookupWithFeed("00000000000000000000000000000000", nil)
	if ok {
		t.Fatal("expected miss for unknown hash")
	}
}

func TestLookupWithFeed_EmptyHash(t *testing.T) {
	resetFeed()
	_, ok := LookupWithFeed("", nil)
	if ok {
		t.Fatal("empty hash should return false")
	}
}

func TestUpdateFeed_FromHTTPServer(t *testing.T) {
	resetFeed()

	// Serve a fake CSV identical to abuse.ch format
	csv := `# JA3 Fingerprints
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","FakeMalware1","https://example.com"
"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","FakeMalware2","https://example.com"
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(csv))
	}))
	defer srv.Close()

	if err := UpdateFeed([]string{srv.URL}, ""); err != nil {
		t.Fatalf("UpdateFeed failed: %v", err)
	}

	desc, ok := LookupWithFeed("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
	if !ok {
		t.Fatal("expected feed hash to be found after update")
	}
	if desc != "FakeMalware1" {
		t.Errorf("unexpected description: %q", desc)
	}

	if FeedSize() < 2 {
		t.Errorf("expected at least 2 entries, got %d", FeedSize())
	}
}

func TestUpdateFeed_LocalFile(t *testing.T) {
	resetFeed()

	dir := t.TempDir()
	path := filepath.Join(dir, "custom.csv")
	content := "cccccccccccccccccccccccccccccccc,LocalToolA\ndddddddddddddddddddddddddddddddd,LocalToolB\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := UpdateFeed(nil, path); err != nil {
		t.Fatalf("UpdateFeed with local file failed: %v", err)
	}

	desc, ok := LookupWithFeed("cccccccccccccccccccccccccccccccc", nil)
	if !ok {
		t.Fatal("expected local file entry to be found")
	}
	if desc != "LocalToolA" {
		t.Errorf("unexpected description: %q", desc)
	}
}

func TestUpdateFeed_InvalidURL(t *testing.T) {
	resetFeed()
	// A completely unreachable URL should return an error but not panic.
	err := UpdateFeed([]string{"http://127.0.0.1:1"}, "")
	if err == nil {
		t.Error("expected error for unreachable URL")
	}
}

func TestUpdateFeed_DiskCacheRoundtrip(t *testing.T) {
	resetFeed()

	// Override cache path for test isolation
	dir := t.TempDir()
	origPath := feedCachePath
	feedCachePath = filepath.Join(dir, "ja3_feed.json")
	defer func() { feedCachePath = origPath }()

	testHash := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	feedMu.Lock()
	feedEntries[testHash] = feedEntry{Hash: testHash, Description: "CacheTest", Source: "test"}
	feedMu.Unlock()

	saveFeedToDisk(feedEntries)
	resetFeed()
	loadFeedFromDisk()

	desc, ok := LookupWithFeed(testHash, nil)
	if !ok {
		t.Fatal("expected entry to survive disk cache round-trip")
	}
	if desc != "CacheTest" {
		t.Errorf("unexpected description after reload: %q", desc)
	}
}

func TestParseCSV_SkipsShortHashes(t *testing.T) {
	input := strings.NewReader("short,description\naabbccddaabbccddaabbccddaabbccdd,valid\n")
	dst := make(map[string]feedEntry)
	if err := parseCSV(input, "test", dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dst) != 1 {
		t.Errorf("expected 1 valid entry, got %d", len(dst))
	}
	if _, ok := dst["aabbccddaabbccddaabbccddaabbccdd"]; !ok {
		t.Error("expected valid hash to be in dst")
	}
}

func TestParseCSV_EmptyStream(t *testing.T) {
	input := strings.NewReader("# comment only\n")
	dst := make(map[string]feedEntry)
	err := parseCSV(input, "test", dst)
	if err == nil {
		t.Error("expected error for empty/comment-only CSV")
	}
}

func TestFeedConcurrency(t *testing.T) {
	// Hammer LookupWithFeed from multiple goroutines while UpdateFeed runs.
	resetFeed()

	csv := "ffffffffffffffffffffffffffffffff,ConcurrentTest\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(csv))
	}))
	defer srv.Close()

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					LookupWithFeed("ffffffffffffffffffffffffffffffff", nil)
				}
			}
		}()
	}
	// Run several updates concurrently
	for i := 0; i < 5; i++ {
		_ = UpdateFeed([]string{srv.URL}, "")
	}
	close(done)
}
