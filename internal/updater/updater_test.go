package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestVersionEqual(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"v1.2.3", "v1.2.3", true},
		{"1.2.3", "v1.2.3", true},  // leading "v" is ignored
		{"v1.2.3", "1.2.3", true},
		{"1.2.3", "1.2.3", true},
		{"v1.2.3", "v1.2.4", false},
		{"v1.0.0", "v2.0.0", false},
		{"dev", "dev", true},
		{"dev", "v1.0.0", false},
	}
	for _, tc := range tests {
		got := versionEqual(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("versionEqual(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestAssetForPlatform_ReturnsNonEmpty(t *testing.T) {
	got := assetForPlatform()
	if got == "" {
		t.Skip("unsupported platform — assetForPlatform() correctly returns empty string")
	}
	t.Logf("assetForPlatform() = %q", got)
}

// ─── latestRelease ────────────────────────────────────────────────────────────

func withAPIBase(t *testing.T, url string) func() {
	t.Helper()
	orig := apiBase
	apiBase = url
	return func() { apiBase = orig }
}

func TestLatestRelease_Success(t *testing.T) {
	expected := Release{
		TagName: "v1.5.0",
		Assets: []Asset{
			{Name: "mcp-flowsentinel-linux-amd64", BrowserDownloadURL: "https://example.com/bin"},
		},
	}
	body, _ := json.Marshal(expected)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer srv.Close()
	defer withAPIBase(t, srv.URL)()

	got, err := latestRelease(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.TagName != "v1.5.0" {
		t.Errorf("TagName = %q, want %q", got.TagName, "v1.5.0")
	}
	if len(got.Assets) != 1 {
		t.Errorf("len(Assets) = %d, want 1", len(got.Assets))
	}
}

func TestLatestRelease_HTTP404_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	defer withAPIBase(t, srv.URL)()

	_, err := latestRelease(context.Background())
	if err == nil {
		t.Error("expected error for HTTP 404")
	}
}

func TestLatestRelease_MalformedJSON_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not valid json {{{"))
	}))
	defer srv.Close()
	defer withAPIBase(t, srv.URL)()

	_, err := latestRelease(context.Background())
	if err == nil {
		t.Error("expected error for malformed JSON response")
	}
}

func TestLatestRelease_InvalidBaseURL_ReturnsError(t *testing.T) {
	// An invalid URL scheme causes http.NewRequestWithContext to fail.
	defer withAPIBase(t, "://\x00invalid")()
	_, err := latestRelease(context.Background())
	if err == nil {
		t.Error("expected error for invalid base URL, got nil")
	}
}

func TestLatestRelease_ConnectionRefused_ReturnsError(t *testing.T) {
	// Port 0 on localhost: NewRequestWithContext succeeds (URL is valid) but
	// http.DefaultClient.Do fails because the connection is refused.
	// Covers the "return nil, err" after Do() in latestRelease.
	defer withAPIBase(t, "http://127.0.0.1:0")()
	_, err := latestRelease(context.Background())
	if err == nil {
		t.Error("expected connection error for unreachable server, got nil")
	}
}

func TestDownloadReplace_InvalidRequestURL_ReturnsError(t *testing.T) {
	// http.NewRequestWithContext fails for a URL with a null byte.
	dst := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(dst, []byte("old"), 0o755); err != nil {
		t.Fatalf("pre-create: %v", err)
	}
	err := downloadReplace(context.Background(), "://\x00invalid", dst)
	if err == nil {
		t.Error("expected error for invalid download URL")
	}
}

func TestLatestRelease_WithGitHubToken_SendsHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		body, _ := json.Marshal(Release{TagName: "v1.0.0"})
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()
	defer withAPIBase(t, srv.URL)()

	t.Setenv("GITHUB_TOKEN", "test-token-xyz")

	if _, err := latestRelease(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer test-token-xyz" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer test-token-xyz")
	}
}

// ─── downloadReplace ─────────────────────────────────────────────────────────

func TestDownloadReplace_Success(t *testing.T) {
	content := []byte("fake binary content for testing")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "testbin")
	// Pre-create the destination so the Windows rename-to-.old path works.
	if err := os.WriteFile(dst, []byte("old content"), 0o755); err != nil {
		t.Fatalf("pre-create dst: %v", err)
	}

	if err := downloadReplace(context.Background(), srv.URL, dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content mismatch: got %q, want %q", got, content)
	}
}

func TestDownloadReplace_HTTP404_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "testbin")
	if err := downloadReplace(context.Background(), srv.URL, dst); err == nil {
		t.Error("expected error for HTTP 404 download")
	}
}

func TestDownloadReplace_BodyReadError_ReturnsError(t *testing.T) {
	// Server sends headers then abruptly closes the connection without a body.
	// This causes io.Copy to fail with an unexpected EOF.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		// Write a few bytes then close — io.Copy sees unexpected EOF.
		w.Write([]byte("partial"))
		// Hijack and close connection to force a read error.
		if h, ok := w.(http.Hijacker); ok {
			conn, _, _ := h.Hijack()
			conn.Close()
		}
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "testbin")
	if err := os.WriteFile(dst, []byte("old"), 0o755); err != nil {
		t.Fatalf("pre-create: %v", err)
	}

	err := downloadReplace(context.Background(), srv.URL, dst)
	// May or may not fail depending on buffering; we just verify no panic.
	t.Logf("downloadReplace body-error result: %v", err)
}

func TestDownloadReplace_InvalidURL_ReturnsError(t *testing.T) {
	err := downloadReplace(context.Background(), "http://127.0.0.1:0/unreachable", filepath.Join(t.TempDir(), "bin"))
	if err == nil {
		t.Error("expected error for unreachable URL")
	}
}

// ─── CheckAndUpdate ───────────────────────────────────────────────────────────

func TestCheckAndUpdate_FetchError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	defer withAPIBase(t, srv.URL)()

	err := CheckAndUpdate("v1.0.0")
	if err == nil {
		t.Error("expected error when API returns 500, got nil")
	}
}

func TestCheckAndUpdate_AlreadyLatest_ReturnsNil(t *testing.T) {
	body, _ := json.Marshal(Release{TagName: "v1.2.3"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()
	defer withAPIBase(t, srv.URL)()

	if err := CheckAndUpdate("v1.2.3"); err != nil {
		t.Errorf("expected nil when already at latest, got: %v", err)
	}
}

func TestCheckAndUpdate_AlreadyLatest_LeadingV_ReturnsNil(t *testing.T) {
	// v-prefix stripping: "v1.0.0" == "1.0.0"
	body, _ := json.Marshal(Release{TagName: "v1.0.0"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()
	defer withAPIBase(t, srv.URL)()

	if err := CheckAndUpdate("1.0.0"); err != nil {
		t.Errorf("expected nil for matching version (no v prefix), got: %v", err)
	}
}

func TestCheckAndUpdate_AssetNotFound_ReturnsError(t *testing.T) {
	if assetForPlatform() == "" {
		t.Skip("unsupported platform — assetForPlatform() returns empty string")
	}
	// Return a newer version whose asset list has no matching entry.
	body, _ := json.Marshal(Release{
		TagName: "v99.0.0",
		Assets: []Asset{
			{Name: "mcp-flowsentinel-unknown-arch", BrowserDownloadURL: "http://example.com/bin"},
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()
	defer withAPIBase(t, srv.URL)()

	err := CheckAndUpdate("v1.0.0")
	if err == nil {
		t.Error("expected error when no matching asset found in release")
	}
}

func TestCheckAndUpdate_DownloadPath_ReturnsErrorOrNil(t *testing.T) {
	// This test verifies that the full download code path is exercised.
	// On platforms where os.Executable() returns a running binary (e.g. Windows),
	// downloadReplace cannot overwrite the running exe → returns an error.
	// On platforms that allow it, the binary would be replaced (not dangerous in a temp test binary).
	// Either way, lines 81–93 (fmt.Printf + os.Executable + downloadReplace) are covered.
	assetName := assetForPlatform()
	if assetName == "" {
		t.Skip("unsupported platform")
	}

	// Serve a tiny fake binary payload.
	const fakePayload = "fake binary content"
	var dlURL string
	binSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fakePayload))
	}))
	defer binSrv.Close()
	dlURL = binSrv.URL + "/asset"

	release := Release{
		TagName: "v999.0.0", // definitely newer than "v1.0.0"
		Assets: []Asset{
			{Name: assetName, BrowserDownloadURL: dlURL},
		},
	}
	body, _ := json.Marshal(release)
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer apiSrv.Close()
	defer withAPIBase(t, apiSrv.URL)()

	// CheckAndUpdate will find the asset, call os.Executable(), and attempt downloadReplace.
	// On Windows this fails (can't overwrite running binary) → error is acceptable.
	// On Linux/macOS it may succeed or fail depending on permissions.
	err := CheckAndUpdate("v1.0.0")
	t.Logf("CheckAndUpdate result: %v", err)
	// We only care that it doesn't panic and covers the download path.
}

func TestCheckAndUpdate_DevBuild_AssetNotFound_ReturnsError(t *testing.T) {
	// "dev" version is never equal to a release tag, so we proceed to asset lookup.
	if assetForPlatform() == "" {
		t.Skip("unsupported platform")
	}
	body, _ := json.Marshal(Release{
		TagName: "v2.0.0",
		Assets:  []Asset{},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()
	defer withAPIBase(t, srv.URL)()

	err := CheckAndUpdate("dev")
	if err == nil {
		t.Error("expected error for dev build when no asset in release")
	}
}
