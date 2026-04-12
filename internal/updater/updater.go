// Package updater checks for newer releases on GitHub and replaces the running
// binary in-place. It is intentionally dependency-free (stdlib only).
package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	repo    = "ClementG91/MCP-FlowSentinel"
	timeout = 30 * time.Second
)

// apiBase is a var so tests can point it at an httptest.Server.
var apiBase = "https://api.github.com"

// Release holds the fields we need from the GitHub Releases API.
type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Asset is a single downloadable file in a release.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// CheckAndUpdate fetches the latest release, compares it against current,
// and replaces the binary if a newer version is available.
// It prints status lines to stdout so the caller can remain simple.
func CheckAndUpdate(currentVersion string) error {
	fmt.Printf("Current version : %s\n", currentVersion)
	fmt.Printf("Checking GitHub : https://github.com/%s/releases\n\n", repo)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	release, err := latestRelease(ctx)
	if err != nil {
		return fmt.Errorf("could not fetch release info: %w", err)
	}

	fmt.Printf("Latest release  : %s\n", release.TagName)

	if versionEqual(currentVersion, release.TagName) {
		fmt.Println("\nYou are already on the latest version. Nothing to do.")
		return nil
	}

	if currentVersion == "dev" {
		fmt.Println("Running a dev build — will install the latest release binary.")
	}

	assetName := assetForPlatform()
	if assetName == "" {
		return fmt.Errorf("unsupported platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	var target *Asset
	for i := range release.Assets {
		if release.Assets[i].Name == assetName {
			target = &release.Assets[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("no asset named %q in release %s — please open an issue at https://github.com/%s/issues",
			assetName, release.TagName, repo)
	}

	fmt.Printf("\nDownloading %s ...\n", assetName)

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("cannot resolve symlinks: %w", err)
	}

	if err := downloadReplace(ctx, target.BrowserDownloadURL, exePath); err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	fmt.Printf("\nUpdated to %s. Restart the MCP server to apply.\n", release.TagName)
	return nil
}

// latestRelease calls the GitHub API and returns the latest release.
func latestRelease(ctx context.Context) (*Release, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", apiBase, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "mcp-flowsentinel-updater")
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	var r Release
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("malformed API response: %w", err)
	}
	return &r, nil
}

// downloadReplace downloads src, writes it to a temp file beside dst, then
// atomically renames it over dst.
func downloadReplace(ctx context.Context, src, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "mcp-flowsentinel-updater")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	// Write to a temp file in the same directory so the rename is atomic.
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".mcp-flowsentinel-update-*")
	if err != nil {
		return fmt.Errorf("cannot create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		// Clean up temp file if something went wrong.
		os.Remove(tmpName)
	}()

	const maxBinarySize = 100 << 20 // 100 MB — guard against infinite/huge responses
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, maxBinarySize)); err != nil {
		return fmt.Errorf("download interrupted: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Make executable.
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}

	// On Windows, we cannot rename over a running executable.
	// Rename the old binary to a .old file first, then rename the new one.
	if runtime.GOOS == "windows" {
		oldPath := dst + ".old"
		_ = os.Remove(oldPath) // ignore error if it doesn't exist
		if err := os.Rename(dst, oldPath); err != nil {
			return fmt.Errorf("cannot move old binary: %w", err)
		}
	}

	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("cannot replace binary: %w", err)
	}
	return nil
}

// assetForPlatform returns the GitHub release asset name for the current OS/arch.
func assetForPlatform() string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	switch goos {
	case "linux":
		switch goarch {
		case "amd64":
			return "mcp-flowsentinel-linux-amd64"
		case "arm64":
			return "mcp-flowsentinel-linux-arm64"
		}
	case "darwin":
		switch goarch {
		case "amd64":
			return "mcp-flowsentinel-darwin-amd64"
		case "arm64":
			return "mcp-flowsentinel-darwin-arm64"
		}
	case "windows":
		if goarch == "amd64" || goarch == "arm64" {
			return "mcp-flowsentinel-windows-amd64.exe"
		}
	}
	return ""
}

// versionEqual compares two version strings, ignoring a leading "v".
func versionEqual(a, b string) bool {
	return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}
