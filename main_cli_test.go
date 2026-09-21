package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/capture"
	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// cliEnv isolates the CLI from the host: config and webhook env overrides are
// cleared, the global config is restored, and every seam that would touch a
// live interface, the network or stdio fails the test unless replaced.
func cliEnv(t *testing.T) string {
	t.Helper()
	t.Setenv("FLOWSENTINEL_CONFIG", "")
	t.Setenv("FLOWSENTINEL_WEBHOOK_URL", "")

	origCfg := config.Get()
	origList, origCapture, origPriv := listInterfaces, capturePackets, checkPrivilegesFn
	origUpdate, origAlert, origDaemon, origServe := checkAndUpdate, fireTestAlert, runDaemonLoop, serveStdio
	t.Cleanup(func() {
		config.Set(origCfg)
		listInterfaces, capturePackets, checkPrivilegesFn = origList, origCapture, origPriv
		checkAndUpdate, fireTestAlert, runDaemonLoop, serveStdio = origUpdate, origAlert, origDaemon, origServe
	})

	listInterfaces = func() ([]capture.Interface, error) {
		t.Error("unexpected interface enumeration")
		return nil, errors.New("disabled in tests")
	}
	capturePackets = func(context.Context, string, string) (<-chan capture.PacketEvent, error) {
		t.Error("unexpected live capture")
		return nil, errors.New("disabled in tests")
	}
	checkPrivilegesFn = func(string) bool { return true }
	checkAndUpdate = func(string) error {
		t.Error("unexpected update")
		return errors.New("disabled in tests")
	}
	fireTestAlert = func(aggregate.FlowRecord) error {
		t.Error("unexpected webhook")
		return errors.New("disabled in tests")
	}
	runDaemonLoop = func(context.Context) error {
		t.Error("unexpected daemon loop")
		return errors.New("disabled in tests")
	}
	serveStdio = func(context.Context, *mcp.Server) error {
		t.Error("unexpected stdio session")
		return errors.New("disabled in tests")
	}
	return t.TempDir()
}

func writeConfig(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runCLI(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRun_HelpAndVersion(t *testing.T) {
	cliEnv(t)
	orig := version
	version = "v1.2.3-test"
	t.Cleanup(func() { version = orig })

	tests := []struct {
		args []string
		want string
	}{
		{[]string{"--help"}, "Usage:"},
		{[]string{"-h"}, "--init-config"},
		{[]string{"--version"}, "mcp-flowsentinel v1.2.3-test\n"},
		{[]string{"-v"}, "mcp-flowsentinel v1.2.3-test\n"},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			code, stdout, stderr := runCLI(tc.args...)
			if code != 0 || !strings.Contains(stdout, tc.want) || stderr != "" {
				t.Fatalf("run(%v) = %d, stdout %q, stderr %q", tc.args, code, stdout, stderr)
			}
		})
	}
}

func TestRun_CommandsWithoutConfigIgnoreInvalidConfig(t *testing.T) {
	dir := cliEnv(t)
	bad := writeConfig(t, dir, "not_a_field: true\n")

	code, stdout, _ := runCLI("--config", bad, "--version")
	if code != 0 || !strings.HasPrefix(stdout, "mcp-flowsentinel ") {
		t.Fatalf("--version with invalid config = %d, %q", code, stdout)
	}
}

func TestRun_Update(t *testing.T) {
	cliEnv(t)
	var gotVersion string
	checkAndUpdate = func(v string) error { gotVersion = v; return nil }
	if code, _, _ := runCLI("--update"); code != 0 || gotVersion != version {
		t.Fatalf("--update = %d with version %q, want 0 with %q", code, gotVersion, version)
	}

	checkAndUpdate = func(string) error { return errors.New("no provenance") }
	code, _, stderr := runCLI("--update")
	if code != 1 || !strings.Contains(stderr, "update error: no provenance") {
		t.Fatalf("failed --update = %d, stderr %q", code, stderr)
	}
}

func TestRun_InitConfig(t *testing.T) {
	dir := cliEnv(t)
	path := filepath.Join(dir, "new", "config.yaml")

	code, stdout, stderr := runCLI("--init-config", path)
	if code != 0 || !strings.Contains(stdout, "Config written to: "+path) {
		t.Fatalf("--init-config = %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("generated config does not load: %v", err)
	}

	code, _, stderr = runCLI("--init-config", path)
	if code != 1 || !strings.Contains(stderr, "init-config error") {
		t.Fatalf("--init-config over existing file = %d, stderr %q", code, stderr)
	}
}

func TestRun_ConfigErrors(t *testing.T) {
	dir := cliEnv(t)
	tests := map[string]string{
		"unknown field": "not_a_field: true\n",
		"invalid yaml":  "alerting: [\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, t.TempDir(), body)
			code, _, stderr := runCLI("--config", path, "--validate-config")
			if code != 1 || !strings.Contains(stderr, "config error:") {
				t.Fatalf("run = %d, stderr %q, want config error", code, stderr)
			}
		})
	}

	code, _, stderr := runCLI("--config", dir, "--validate-config")
	if code != 1 || !strings.Contains(stderr, "config error:") {
		t.Fatalf("directory as config = %d, stderr %q", code, stderr)
	}
}

func TestRun_ValidateConfig(t *testing.T) {
	dir := cliEnv(t)
	path := writeConfig(t, dir, "alerting:\n  enabled: true\n  webhook_url: https://hooks.example.com/flow\n  min_score_threshold: 5.5\n")

	code, stdout, stderr := runCLI("--validate-config", "--config", path)
	if code != 0 || !strings.Contains(stderr, "Config valid.") {
		t.Fatalf("--validate-config = %d, stderr %q", code, stderr)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, stdout)
	}
	if got["status"] != "ok" || got["loaded_from"] != path || got["alerting_enabled"] != true || got["min_score_threshold"] != 5.5 {
		t.Fatalf("--validate-config output = %v", got)
	}
}

func TestRun_UnknownCommandPrintsUsage(t *testing.T) {
	dir := cliEnv(t)
	cfg := filepath.Join(dir, "absent.yaml") // missing file: built-in defaults
	code, stdout, stderr := runCLI("--config", cfg, "--bogus")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "Usage:") {
		t.Fatalf("--bogus = %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestRun_TestAlert(t *testing.T) {
	dir := cliEnv(t)

	disabled := writeConfig(t, t.TempDir(), "alerting:\n  enabled: false\n")
	if code, _, stderr := runCLI("--config", disabled, "--test-alert"); code != 1 || !strings.Contains(stderr, "Alerting is disabled") {
		t.Fatalf("disabled alerting = %d, %q", code, stderr)
	}

	noURL := writeConfig(t, t.TempDir(), "alerting:\n  enabled: true\n")
	if code, _, stderr := runCLI("--config", noURL, "--test-alert"); code != 1 || !strings.Contains(stderr, "webhook_url is not set") {
		t.Fatalf("missing webhook = %d, %q", code, stderr)
	}

	enabled := writeConfig(t, dir, "alerting:\n  enabled: true\n  webhook_url: https://hooks.example.com/flow\n  min_score_threshold: 4\n")
	var sent aggregate.FlowRecord
	fireTestAlert = func(f aggregate.FlowRecord) error { sent = f; return nil }
	code, stdout, _ := runCLI("--config", enabled, "--test-alert")
	if code != 0 || !strings.Contains(stdout, "Test alert sent successfully") {
		t.Fatalf("test alert = %d, %q", code, stdout)
	}
	if sent.SuspicionScore != 5 || sent.RiskLevel != "TEST" || sent.DstIP != "203.0.113.42" {
		t.Fatalf("test alert flow = %+v", sent)
	}

	fireTestAlert = func(aggregate.FlowRecord) error { return errors.New("HTTP 500") }
	if code, _, stderr := runCLI("--config", enabled, "--test-alert"); code != 1 || !strings.Contains(stderr, "Test alert failed: HTTP 500") {
		t.Fatalf("failing webhook = %d, %q", code, stderr)
	}
}

func TestRun_StdioServer(t *testing.T) {
	dir := cliEnv(t)
	cfg := filepath.Join(dir, "absent.yaml") // missing file: built-in defaults
	var served *mcp.Server
	serveStdio = func(_ context.Context, s *mcp.Server) error { served = s; return nil }
	if code, stdout, _ := runCLI("--config", cfg); code != 0 || stdout != "" || served == nil {
		t.Fatalf("stdio mode = %d, stdout %q, served %v", code, stdout, served != nil)
	}

	serveStdio = func(context.Context, *mcp.Server) error { return errors.New("broken pipe") }
	if code, _, _ := runCLI("--config", cfg); code != 1 {
		t.Fatalf("stdio failure exit code = %d, want 1", code)
	}
}

func TestRun_DaemonStartsLoopAndServer(t *testing.T) {
	dir := cliEnv(t)
	cfg := filepath.Join(dir, "absent.yaml") // missing file: built-in defaults
	loopStarted := make(chan struct{})
	runDaemonLoop = func(ctx context.Context) error {
		close(loopStarted)
		<-ctx.Done()
		return errors.New("stopped")
	}
	serveStdio = func(context.Context, *mcp.Server) error {
		<-loopStarted
		return nil
	}
	if code, _, _ := runCLI("--config", cfg, "--daemon"); code != 0 {
		t.Fatalf("--daemon exit code = %d, want 0", code)
	}

	serveStdio = func(context.Context, *mcp.Server) error { return errors.New("closed") }
	runDaemonLoop = func(ctx context.Context) error { <-ctx.Done(); return nil }
	if code, _, _ := runCLI("--config", cfg, "--daemon"); code != 1 {
		t.Fatalf("--daemon with failing server = %d, want 1", code)
	}
}

func TestRun_Check(t *testing.T) {
	ifaces := []capture.Interface{
		{Name: "lo", Flags: []string{"loopback", "up"}, Addresses: []string{"127.0.0.1/8"}},
		{Name: "eth0", Description: "Test NIC", Flags: []string{"up"}},
	}
	packets := func(n int) func(context.Context, string, string) (<-chan capture.PacketEvent, error) {
		return func(_ context.Context, iface, filter string) (<-chan capture.PacketEvent, error) {
			if iface != "eth0" || filter != "" {
				return nil, errors.New("unexpected interface " + iface)
			}
			ch := make(chan capture.PacketEvent, n)
			for i := 0; i < n; i++ {
				ch <- capture.PacketEvent{}
			}
			close(ch)
			return ch, nil
		}
	}

	tests := []struct {
		name      string
		priv      bool
		list      func() ([]capture.Interface, error)
		capture   func(context.Context, string, string) (<-chan capture.PacketEvent, error)
		wantCode  int
		wantLines []string
	}{
		{
			name:      "all checks pass",
			priv:      true,
			list:      func() ([]capture.Interface, error) { return ifaces, nil },
			capture:   packets(3),
			wantLines: []string{"[OK] pcap available — 2 interface(s)", "eth0 (Test NIC)", "3 packet(s) observed", "All checks passed"},
		},
		{
			name:      "missing privileges",
			priv:      false,
			list:      func() ([]capture.Interface, error) { return ifaces, nil },
			capture:   packets(0),
			wantCode:  1,
			wantLines: []string{"Some checks failed"},
		},
		{
			name:      "pcap unavailable",
			priv:      true,
			list:      func() ([]capture.Interface, error) { return nil, errors.New("wpcap.dll not found") },
			wantCode:  1,
			wantLines: []string{"[FAIL] Could not list pcap interfaces: wpcap.dll not found", "npcap.com"},
		},
		{
			name: "capture fails",
			priv: true,
			list: func() ([]capture.Interface, error) { return ifaces, nil },
			capture: func(context.Context, string, string) (<-chan capture.PacketEvent, error) {
				return nil, errors.New("operation not permitted")
			},
			wantCode:  1,
			wantLines: []string{"[FAIL] Capture test failed: operation not permitted"},
		},
		{
			name: "loopback only falls back to first interface",
			priv: true,
			list: func() ([]capture.Interface, error) {
				return []capture.Interface{{Name: "eth0", Flags: []string{"loopback"}}}, nil
			},
			capture:   packets(1),
			wantLines: []string{"(no addresses)", `Testing live capture on "eth0"`, "All checks passed"},
		},
		{
			name:      "no interfaces",
			priv:      true,
			list:      func() ([]capture.Interface, error) { return nil, nil },
			wantLines: []string{"0 interface(s) found", "All checks passed"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := cliEnv(t)
			cfg := filepath.Join(dir, "absent.yaml") // missing file: built-in defaults
			checkPrivilegesFn = func(string) bool { return tc.priv }
			listInterfaces = tc.list
			if tc.capture != nil {
				capturePackets = tc.capture
			}
			code, stdout, _ := runCLI("--config", cfg, "--check")
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d\n%s", code, tc.wantCode, stdout)
			}
			for _, line := range tc.wantLines {
				if !strings.Contains(stdout, line) {
					t.Errorf("output missing %q:\n%s", line, stdout)
				}
			}
		})
	}
}
