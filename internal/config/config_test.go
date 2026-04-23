package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefault_AllFieldsPopulated(t *testing.T) {
	cfg := Default()

	if cfg.Scoring.BeaconingMinPackets != 5 {
		t.Errorf("BeaconingMinPackets = %d, want 5", cfg.Scoring.BeaconingMinPackets)
	}
	if cfg.Scoring.BeaconingStrongCV != 0.15 {
		t.Errorf("BeaconingStrongCV = %v, want 0.15", cfg.Scoring.BeaconingStrongCV)
	}
	if cfg.Capture.DefaultDurationSec != 5 {
		t.Errorf("DefaultDurationSec = %d, want 5", cfg.Capture.DefaultDurationSec)
	}
	if cfg.Capture.MaxDurationSec != 60 {
		t.Errorf("MaxDurationSec = %d, want 60", cfg.Capture.MaxDurationSec)
	}
	if cfg.History.MaxAgeHours != 24 {
		t.Errorf("MaxAgeHours = %d, want 24", cfg.History.MaxAgeHours)
	}
	if cfg.History.MaxSizeMB != 50 {
		t.Errorf("MaxSizeMB = %d, want 50", cfg.History.MaxSizeMB)
	}
	if cfg.Daemon.CaptureIntervalSec != 300 {
		t.Errorf("CaptureIntervalSec = %d, want 300", cfg.Daemon.CaptureIntervalSec)
	}
}

func TestGet_ReturnsNonNil(t *testing.T) {
	cfg := Get()
	if cfg == nil {
		t.Fatal("Get() returned nil")
	}
}

func TestSet_UpdatesGlobal(t *testing.T) {
	original := Get()
	defer Set(original)

	custom := Default()
	custom.Capture.DefaultDurationSec = 99
	Set(custom)

	if Get().Capture.DefaultDurationSec != 99 {
		t.Error("Set() did not update global config")
	}
}

func TestLoad_NoFile_UsesDefaults(t *testing.T) {
	original := Get()
	defer Set(original)

	cfg, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err != nil {
		t.Fatalf("Load with missing file: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load returned nil config")
	}
	if cfg.Capture.DefaultDurationSec != 5 {
		t.Errorf("DefaultDurationSec = %d, want 5", cfg.Capture.DefaultDurationSec)
	}
}

func TestLoad_ValidYAML_OverridesDefaults(t *testing.T) {
	original := Get()
	defer Set(original)

	yaml := `
capture:
  default_duration_seconds: 10
  max_duration_seconds: 120
  dns_timeout_ms: 500
  dns_workers: 10
scoring:
  beaconing_strong_cv: 0.10
  beaconing_possible_cv: 0.25
  beaconing_min_packets: 7
  dns_entropy_threshold: 4.0
  dns_label_len_threshold: 30
  scan_confirmed_destinations: 25
  scan_possible_destinations: 10
history:
  max_size_mb: 100
  max_age_hours: 48
  prune_to_hours: 24
daemon:
  capture_interval_seconds: 60
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Capture.DefaultDurationSec != 10 {
		t.Errorf("DefaultDurationSec = %d, want 10", cfg.Capture.DefaultDurationSec)
	}
	if cfg.Scoring.BeaconingStrongCV != 0.10 {
		t.Errorf("BeaconingStrongCV = %v, want 0.10", cfg.Scoring.BeaconingStrongCV)
	}
	if cfg.History.MaxSizeMB != 100 {
		t.Errorf("MaxSizeMB = %d, want 100", cfg.History.MaxSizeMB)
	}
}

// TestLoad_PartialConfig_DefaultsPreserved verifies that omitting numeric fields
// from a partial YAML config leaves the built-in defaults in place rather than
// overwriting them with 0 (the YAML zero-value problem).
func TestLoad_PartialConfig_DefaultsPreserved(t *testing.T) {
	original := Get()
	defer Set(original)

	// Only set alerting; every other section is omitted.
	yaml := `alerting:
  enabled: true
  webhook_url: "https://example.com/hook"
`
	path := filepath.Join(t.TempDir(), "partial.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	def := Default()
	if cfg.Scoring.BeaconingStrongCV != def.Scoring.BeaconingStrongCV {
		t.Errorf("BeaconingStrongCV = %v, want default %v", cfg.Scoring.BeaconingStrongCV, def.Scoring.BeaconingStrongCV)
	}
	if cfg.Capture.DefaultDurationSec != def.Capture.DefaultDurationSec {
		t.Errorf("DefaultDurationSec = %d, want default %d", cfg.Capture.DefaultDurationSec, def.Capture.DefaultDurationSec)
	}
	if cfg.History.MaxSizeMB != def.History.MaxSizeMB {
		t.Errorf("MaxSizeMB = %d, want default %d", cfg.History.MaxSizeMB, def.History.MaxSizeMB)
	}
	if cfg.Daemon.CaptureIntervalSec != def.Daemon.CaptureIntervalSec {
		t.Errorf("CaptureIntervalSec = %d, want default %d", cfg.Daemon.CaptureIntervalSec, def.Daemon.CaptureIntervalSec)
	}
	// Set fields should be applied.
	if !cfg.Alerting.Enabled {
		t.Error("Alerting.Enabled should be true")
	}
	if cfg.Alerting.WebhookURL != "https://example.com/hook" {
		t.Errorf("WebhookURL = %q, want https://example.com/hook", cfg.Alerting.WebhookURL)
	}
}

func TestValidate_DNSWorkersBounds(t *testing.T) {
	original := Get()
	defer Set(original)

	writeYAML := func(t *testing.T, yaml string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return path
	}

	// 201 workers → too many
	_, err := Load(writeYAML(t, "capture:\n  dns_workers: 201\n"))
	if err == nil {
		t.Error("dns_workers: 201 should return error")
	}

	// 200 workers → upper bound OK
	if _, err := Load(writeYAML(t, "capture:\n  dns_workers: 200\n")); err != nil {
		t.Errorf("dns_workers: 200 should be valid, got: %v", err)
	}

	// Negative DNS cache TTL
	_, err = Load(writeYAML(t, "capture:\n  dns_cache_ttl_seconds: -1\n"))
	if err == nil {
		t.Error("dns_cache_ttl_seconds: -1 should return error")
	}

	// Negative dedup window
	_, err = Load(writeYAML(t, "alerting:\n  deduplication_window_seconds: -1\n"))
	if err == nil {
		t.Error("deduplication_window_seconds: -1 should return error")
	}
}

func TestLoad_InvalidYAML_ReturnsError(t *testing.T) {
	original := Get()
	defer Set(original)

	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("capture: [invalid"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Error("Load with invalid YAML should return error")
	}
}

func TestLoad_InvalidValues_ReturnsError(t *testing.T) {
	original := Get()
	defer Set(original)

	tests := []struct {
		name string
		yaml string
	}{
		{"neg_strong_cv", "scoring:\n  beaconing_strong_cv: -0.1\n  beaconing_possible_cv: 0.3\n  beaconing_min_packets: 5\n  dns_entropy_threshold: 3.5\n  scan_confirmed_destinations: 20\n  scan_possible_destinations: 8\ncapture:\n  default_duration_seconds: 5\n  max_duration_seconds: 60\n  dns_timeout_ms: 200\n  dns_workers: 20\nhistory:\n  max_size_mb: 50\n  max_age_hours: 24\n  prune_to_hours: 12\ndaemon:\n  capture_interval_seconds: 300\n"},
		{"cv_order_wrong", "scoring:\n  beaconing_strong_cv: 0.5\n  beaconing_possible_cv: 0.3\n  beaconing_min_packets: 5\n  dns_entropy_threshold: 3.5\n  scan_confirmed_destinations: 20\n  scan_possible_destinations: 8\ncapture:\n  default_duration_seconds: 5\n  max_duration_seconds: 60\n  dns_timeout_ms: 200\n  dns_workers: 20\nhistory:\n  max_size_mb: 50\n  max_age_hours: 24\n  prune_to_hours: 12\ndaemon:\n  capture_interval_seconds: 300\n"},
		{"too_few_beaconing_packets", "scoring:\n  beaconing_strong_cv: 0.15\n  beaconing_possible_cv: 0.30\n  beaconing_min_packets: 1\n  dns_entropy_threshold: 3.5\n  scan_confirmed_destinations: 20\n  scan_possible_destinations: 8\ncapture:\n  default_duration_seconds: 5\n  max_duration_seconds: 60\n  dns_timeout_ms: 200\n  dns_workers: 20\nhistory:\n  max_size_mb: 50\n  max_age_hours: 24\n  prune_to_hours: 12\ndaemon:\n  capture_interval_seconds: 300\n"},
		{"scan_order_wrong", "scoring:\n  beaconing_strong_cv: 0.15\n  beaconing_possible_cv: 0.30\n  beaconing_min_packets: 5\n  dns_entropy_threshold: 3.5\n  scan_confirmed_destinations: 5\n  scan_possible_destinations: 10\ncapture:\n  default_duration_seconds: 5\n  max_duration_seconds: 60\n  dns_timeout_ms: 200\n  dns_workers: 20\nhistory:\n  max_size_mb: 50\n  max_age_hours: 24\n  prune_to_hours: 12\ndaemon:\n  capture_interval_seconds: 300\n"},
		{"neg_dns_entropy", "scoring:\n  beaconing_strong_cv: 0.15\n  beaconing_possible_cv: 0.30\n  beaconing_min_packets: 5\n  dns_entropy_threshold: -1\n  scan_confirmed_destinations: 20\n  scan_possible_destinations: 8\ncapture:\n  default_duration_seconds: 5\n  max_duration_seconds: 60\n  dns_timeout_ms: 200\n  dns_workers: 20\nhistory:\n  max_size_mb: 50\n  max_age_hours: 24\n  prune_to_hours: 12\ndaemon:\n  capture_interval_seconds: 300\n"},
		{"neg_default_duration", "scoring:\n  beaconing_strong_cv: 0.15\n  beaconing_possible_cv: 0.30\n  beaconing_min_packets: 5\n  dns_entropy_threshold: 3.5\n  scan_confirmed_destinations: 20\n  scan_possible_destinations: 8\ncapture:\n  default_duration_seconds: -1\n  max_duration_seconds: 60\n  dns_timeout_ms: 200\n  dns_workers: 20\nhistory:\n  max_size_mb: 50\n  max_age_hours: 24\n  prune_to_hours: 12\ndaemon:\n  capture_interval_seconds: 300\n"},
		{"max_less_than_default", "scoring:\n  beaconing_strong_cv: 0.15\n  beaconing_possible_cv: 0.30\n  beaconing_min_packets: 5\n  dns_entropy_threshold: 3.5\n  scan_confirmed_destinations: 20\n  scan_possible_destinations: 8\ncapture:\n  default_duration_seconds: 30\n  max_duration_seconds: 10\n  dns_timeout_ms: 200\n  dns_workers: 20\nhistory:\n  max_size_mb: 50\n  max_age_hours: 24\n  prune_to_hours: 12\ndaemon:\n  capture_interval_seconds: 300\n"},
		{"neg_dns_timeout", "scoring:\n  beaconing_strong_cv: 0.15\n  beaconing_possible_cv: 0.30\n  beaconing_min_packets: 5\n  dns_entropy_threshold: 3.5\n  scan_confirmed_destinations: 20\n  scan_possible_destinations: 8\ncapture:\n  default_duration_seconds: 5\n  max_duration_seconds: 60\n  dns_timeout_ms: -1\n  dns_workers: 20\nhistory:\n  max_size_mb: 50\n  max_age_hours: 24\n  prune_to_hours: 12\ndaemon:\n  capture_interval_seconds: 300\n"},
		{"neg_dns_workers", "scoring:\n  beaconing_strong_cv: 0.15\n  beaconing_possible_cv: 0.30\n  beaconing_min_packets: 5\n  dns_entropy_threshold: 3.5\n  scan_confirmed_destinations: 20\n  scan_possible_destinations: 8\ncapture:\n  default_duration_seconds: 5\n  max_duration_seconds: 60\n  dns_timeout_ms: 200\n  dns_workers: -1\nhistory:\n  max_size_mb: 50\n  max_age_hours: 24\n  prune_to_hours: 12\ndaemon:\n  capture_interval_seconds: 300\n"},
		{"neg_max_size_mb", "scoring:\n  beaconing_strong_cv: 0.15\n  beaconing_possible_cv: 0.30\n  beaconing_min_packets: 5\n  dns_entropy_threshold: 3.5\n  scan_confirmed_destinations: 20\n  scan_possible_destinations: 8\ncapture:\n  default_duration_seconds: 5\n  max_duration_seconds: 60\n  dns_timeout_ms: 200\n  dns_workers: 20\nhistory:\n  max_size_mb: -1\n  max_age_hours: 24\n  prune_to_hours: 12\ndaemon:\n  capture_interval_seconds: 300\n"},
		{"neg_max_age", "scoring:\n  beaconing_strong_cv: 0.15\n  beaconing_possible_cv: 0.30\n  beaconing_min_packets: 5\n  dns_entropy_threshold: 3.5\n  scan_confirmed_destinations: 20\n  scan_possible_destinations: 8\ncapture:\n  default_duration_seconds: 5\n  max_duration_seconds: 60\n  dns_timeout_ms: 200\n  dns_workers: 20\nhistory:\n  max_size_mb: 50\n  max_age_hours: -1\n  prune_to_hours: 12\ndaemon:\n  capture_interval_seconds: 300\n"},
		{"prune_exceeds_age", "scoring:\n  beaconing_strong_cv: 0.15\n  beaconing_possible_cv: 0.30\n  beaconing_min_packets: 5\n  dns_entropy_threshold: 3.5\n  scan_confirmed_destinations: 20\n  scan_possible_destinations: 8\ncapture:\n  default_duration_seconds: 5\n  max_duration_seconds: 60\n  dns_timeout_ms: 200\n  dns_workers: 20\nhistory:\n  max_size_mb: 50\n  max_age_hours: 12\n  prune_to_hours: 24\ndaemon:\n  capture_interval_seconds: 300\n"},
		{"neg_daemon_interval", "scoring:\n  beaconing_strong_cv: 0.15\n  beaconing_possible_cv: 0.30\n  beaconing_min_packets: 5\n  dns_entropy_threshold: 3.5\n  scan_confirmed_destinations: 20\n  scan_possible_destinations: 8\ncapture:\n  default_duration_seconds: 5\n  max_duration_seconds: 60\n  dns_timeout_ms: 200\n  dns_workers: 20\nhistory:\n  max_size_mb: 50\n  max_age_hours: 24\n  prune_to_hours: 12\ndaemon:\n  capture_interval_seconds: -1\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			_, err := Load(path)
			if err == nil {
				t.Errorf("Load(%s) should return validation error", tc.name)
			}
		})
	}
}

func TestLoad_EnvVarGeoIP_OverridesConfig(t *testing.T) {
	original := Get()
	defer Set(original)

	t.Setenv("GEOIP_CITY_DB", "/env/city.mmdb")
	t.Setenv("GEOIP_ASN_DB", "/env/asn.mmdb")

	cfg, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GeoIP.CityDB != "/env/city.mmdb" {
		t.Errorf("GeoIP.CityDB = %q, want /env/city.mmdb", cfg.GeoIP.CityDB)
	}
	if cfg.GeoIP.ASNDB != "/env/asn.mmdb" {
		t.Errorf("GeoIP.ASNDB = %q, want /env/asn.mmdb", cfg.GeoIP.ASNDB)
	}
}

func TestLoad_FlowSentinelConfigEnvVar(t *testing.T) {
	original := Get()
	defer Set(original)

	yaml := `capture:
  default_duration_seconds: 42
  max_duration_seconds: 60
  dns_timeout_ms: 200
  dns_workers: 20
scoring:
  beaconing_strong_cv: 0.15
  beaconing_possible_cv: 0.30
  beaconing_min_packets: 5
  dns_entropy_threshold: 3.5
  scan_confirmed_destinations: 20
  scan_possible_destinations: 8
history:
  max_size_mb: 50
  max_age_hours: 24
  prune_to_hours: 12
daemon:
  capture_interval_seconds: 300
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("FLOWSENTINEL_CONFIG", path)

	cfg, err := Load("") // empty path → will be overridden by env var
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Capture.DefaultDurationSec != 42 {
		t.Errorf("DefaultDurationSec = %d, want 42", cfg.Capture.DefaultDurationSec)
	}
}

func TestWriteDefault_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "config.yaml")

	if err := WriteDefault(path); err != nil {
		t.Fatalf("WriteDefault: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) == 0 {
		t.Error("WriteDefault produced empty file")
	}
}

func TestWriteDefault_ExistingFile_ReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := WriteDefault(path); err == nil {
		t.Error("WriteDefault should error when file already exists")
	}
}

func TestDefaultPath_NonEmpty(t *testing.T) {
	p := DefaultPath()
	if p == "" {
		t.Error("DefaultPath() returned empty string")
	}
}

func TestLoadedPath_AfterLoad_ReturnsPath(t *testing.T) {
	original := Get()
	defer Set(original)

	yaml := `capture:
  default_duration_seconds: 5
  max_duration_seconds: 60
  dns_timeout_ms: 200
  dns_workers: 20
scoring:
  beaconing_strong_cv: 0.15
  beaconing_possible_cv: 0.30
  beaconing_min_packets: 5
  dns_entropy_threshold: 3.5
  scan_confirmed_destinations: 20
  scan_possible_destinations: 8
history:
  max_size_mb: 50
  max_age_hours: 24
  prune_to_hours: 12
daemon:
  capture_interval_seconds: 300
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := LoadedPath(); got != path {
		t.Errorf("LoadedPath() = %q, want %q", got, path)
	}
}

func TestReload_ReappliesConfig(t *testing.T) {
	original := Get()
	defer Set(original)

	yaml := `capture:
  default_duration_seconds: 7
  max_duration_seconds: 60
  dns_timeout_ms: 200
  dns_workers: 20
scoring:
  beaconing_strong_cv: 0.15
  beaconing_possible_cv: 0.30
  beaconing_min_packets: 5
  dns_entropy_threshold: 3.5
  scan_confirmed_destinations: 20
  scan_possible_destinations: 8
history:
  max_size_mb: 50
  max_age_hours: 24
  prune_to_hours: 12
daemon:
  capture_interval_seconds: 300
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Mutate in memory — Reload should restore from file.
	cfg := Get()
	cfg.Capture.DefaultDurationSec = 99
	Set(cfg)

	reloaded, err := Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if reloaded.Capture.DefaultDurationSec != 7 {
		t.Errorf("after Reload, DefaultDurationSec = %d, want 7", reloaded.Capture.DefaultDurationSec)
	}
}

func TestCompiledExtraCmdlinePatterns_PopulatedOnLoad(t *testing.T) {
	original := Get()
	defer Set(original)

	yaml := `capture:
  default_duration_seconds: 5
  max_duration_seconds: 60
  dns_timeout_ms: 200
  dns_workers: 20
scoring:
  beaconing_strong_cv: 0.15
  beaconing_possible_cv: 0.30
  beaconing_min_packets: 5
  dns_entropy_threshold: 3.5
  scan_confirmed_destinations: 20
  scan_possible_destinations: 8
  extra_cmdline_patterns:
    - "(?i)mshta\\.exe"
    - "(?i)regsvr32"
history:
  max_size_mb: 50
  max_age_hours: 24
  prune_to_hours: 12
daemon:
  capture_interval_seconds: 300
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Scoring.CompiledExtraCmdlinePatterns) != 2 {
		t.Errorf("expected 2 compiled patterns, got %d", len(cfg.Scoring.CompiledExtraCmdlinePatterns))
	}
	if !cfg.Scoring.CompiledExtraCmdlinePatterns[0].MatchString("MSHTA.EXE") {
		t.Error("first pattern should match MSHTA.EXE (case-insensitive)")
	}
}

func TestCompiledExtraCmdlinePatterns_InvalidPatternReturnsError(t *testing.T) {
	cfg := Default()
	cfg.Scoring.ExtraCmdlinePatterns = []string{"(?i)valid", "[invalid"}
	err := compileScoringPatterns(cfg)
	if err == nil {
		t.Error("compileScoringPatterns should return error for invalid regex")
	}
	// No patterns should be compiled when an error occurs.
	if len(cfg.Scoring.CompiledExtraCmdlinePatterns) != 0 {
		t.Errorf("expected 0 compiled patterns on error, got %d", len(cfg.Scoring.CompiledExtraCmdlinePatterns))
	}
}

func TestLoad_InvalidRegex_ReturnsError(t *testing.T) {
	original := Get()
	defer Set(original)

	yaml := `capture:
  default_duration_seconds: 5
  max_duration_seconds: 60
  dns_timeout_ms: 200
  dns_workers: 20
scoring:
  beaconing_strong_cv: 0.15
  beaconing_possible_cv: 0.30
  beaconing_min_packets: 5
  dns_entropy_threshold: 3.5
  scan_confirmed_destinations: 20
  scan_possible_destinations: 8
  extra_cmdline_patterns:
    - "(?i)valid_pattern"
    - "[this is not valid regex"
history:
  max_size_mb: 50
  max_age_hours: 24
  prune_to_hours: 12
daemon:
  capture_interval_seconds: 300
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Error("Load with invalid regex should return error")
	}
	if !strings.Contains(err.Error(), "extra_cmdline_patterns") {
		t.Errorf("error should mention extra_cmdline_patterns, got: %v", err)
	}
}

func TestAlertingMinScoreThreshold_Validation(t *testing.T) {
	original := Get()
	defer Set(original)

	tests := []struct {
		name      string
		threshold float64
		wantErr   bool
	}{
		{"valid_zero", 0.0, false},
		{"valid_mid", 5.0, false},
		{"valid_max", 10.0, false},
		{"negative", -1.0, true},
		{"above_max", 11.0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			yamlContent := "capture:\n  default_duration_seconds: 5\n  max_duration_seconds: 60\n  dns_timeout_ms: 200\n  dns_workers: 20\nscoring:\n  beaconing_strong_cv: 0.15\n  beaconing_possible_cv: 0.30\n  beaconing_min_packets: 5\n  dns_entropy_threshold: 3.5\n  scan_confirmed_destinations: 20\n  scan_possible_destinations: 8\nhistory:\n  max_size_mb: 50\n  max_age_hours: 24\n  prune_to_hours: 12\ndaemon:\n  capture_interval_seconds: 300\nalerting:\n  min_score_threshold: " + formatFloat(tc.threshold) + "\n"
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			_, err := Load(path)
			if tc.wantErr && err == nil {
				t.Errorf("Load(%s) should return validation error for threshold %v", tc.name, tc.threshold)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Load(%s) returned unexpected error: %v", tc.name, err)
			}
		})
	}
}

func formatFloat(f float64) string {
	return fmt.Sprintf("%g", f)
}

// ─── DomRep config merge ──────────────────────────────────────────────────────

func TestLoad_DomRep_DefaultsDisabled(t *testing.T) {
	cfg := Default()
	if cfg.DomRep.Enabled {
		t.Error("DomRep should be disabled by default")
	}
	if len(cfg.DomRep.URLs) == 0 {
		t.Error("DomRep should have default URLs")
	}
	if cfg.DomRep.UpdateIntervalHours == 0 {
		t.Error("DomRep.UpdateIntervalHours should have a default")
	}
}

func TestLoad_DomRep_EnabledViaYAML(t *testing.T) {
	yaml := `
capture:
  default_duration_seconds: 5
  max_duration_seconds: 60
  dns_timeout_ms: 200
  dns_workers: 20
scoring:
  beaconing_strong_cv: 0.15
  beaconing_possible_cv: 0.30
  beaconing_min_packets: 5
  dns_entropy_threshold: 3.5
  scan_confirmed_destinations: 20
  scan_possible_destinations: 8
history:
  max_size_mb: 50
  max_age_hours: 24
  prune_to_hours: 12
daemon:
  capture_interval_seconds: 300
dom_rep:
  enabled: true
  update_interval_hours: 12
  local_file: "/tmp/domains.txt"
  urls:
    - https://custom.example.com/domains.txt
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.DomRep.Enabled {
		t.Error("DomRep.Enabled should be true")
	}
	if cfg.DomRep.UpdateIntervalHours != 12 {
		t.Errorf("DomRep.UpdateIntervalHours = %d, want 12", cfg.DomRep.UpdateIntervalHours)
	}
	if cfg.DomRep.LocalFile != "/tmp/domains.txt" {
		t.Errorf("DomRep.LocalFile = %q, want /tmp/domains.txt", cfg.DomRep.LocalFile)
	}
	if len(cfg.DomRep.URLs) != 1 || cfg.DomRep.URLs[0] != "https://custom.example.com/domains.txt" {
		t.Errorf("DomRep.URLs = %v, want single custom URL", cfg.DomRep.URLs)
	}
}

func TestLoad_DomRep_PartialOverride_DefaultURLsKept(t *testing.T) {
	// When dom_rep block only sets enabled=true without URLs, default URLs are preserved.
	yaml := `
capture:
  default_duration_seconds: 5
  max_duration_seconds: 60
  dns_timeout_ms: 200
  dns_workers: 20
scoring:
  beaconing_strong_cv: 0.15
  beaconing_possible_cv: 0.30
  beaconing_min_packets: 5
  dns_entropy_threshold: 3.5
  scan_confirmed_destinations: 20
  scan_possible_destinations: 8
history:
  max_size_mb: 50
  max_age_hours: 24
  prune_to_hours: 12
daemon:
  capture_interval_seconds: 300
dom_rep:
  enabled: true
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.DomRep.Enabled {
		t.Error("DomRep.Enabled should be true")
	}
	// Default URLs should still be present when not overridden.
	if len(cfg.DomRep.URLs) == 0 {
		t.Error("DomRep.URLs should fall back to defaults when not specified")
	}
}
