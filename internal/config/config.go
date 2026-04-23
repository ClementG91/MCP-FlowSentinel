// Package config loads, validates, and exposes the single runtime configuration
// for MCP-FlowSentinel. Values come from (lowest → highest priority):
//
//  1. Built-in defaults (matching previous hard-coded values)
//  2. YAML config file  (~/.config/mcp-flowsentinel/config.yaml or --config path)
//  3. Environment variables (GEOIP_CITY_DB, GEOIP_ASN_DB, FLOWSENTINEL_CONFIG)
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"gopkg.in/yaml.v3"
)

// ─── Structs ──────────────────────────────────────────────────────────────────

// Config is the root configuration object.
type Config struct {
	Scoring   ScoringConfig   `yaml:"scoring"`
	Capture   CaptureConfig   `yaml:"capture"`
	GeoIP     GeoIPConfig     `yaml:"geoip"`
	History   HistoryConfig   `yaml:"history"`
	Alerting  AlertingConfig  `yaml:"alerting"`
	Daemon    DaemonConfig    `yaml:"daemon"`
	JA3Feed   JA3FeedConfig   `yaml:"ja3_feed"`
	HasshFeed HasshFeedConfig `yaml:"hassh_feed"`
	IPRep     IPRepConfig     `yaml:"ip_rep"`
	DomRep    DomRepConfig    `yaml:"dom_rep"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Intel     IntelConfig     `yaml:"intel"`
}

// ScoringConfig controls every detection-engine threshold.
type ScoringConfig struct {
	// Beaconing
	BeaconingStrongCV    float64 `yaml:"beaconing_strong_cv"`
	BeaconingPossibleCV  float64 `yaml:"beaconing_possible_cv"`
	BeaconingMinPackets  int     `yaml:"beaconing_min_packets"`
	// BeaconingMinIntervalSec suppresses beaconing detection for flows whose
	// mean inter-packet interval is shorter than this threshold (seconds).
	// Useful to silence sub-100ms polling loops (NTP, MQTT) that have low CV
	// but are obviously not C2. Set to 0 to disable the guard entirely.
	// Default: 0 (disabled — score all intervals).
	BeaconingMinIntervalSec float64 `yaml:"beaconing_min_interval_seconds"`

	// DNS exfiltration
	DNSEntropyThreshold  float64 `yaml:"dns_entropy_threshold"`
	DNSLabelLenThreshold int     `yaml:"dns_label_len_threshold"`

	// Port-scan detection
	ScanConfirmedDests int `yaml:"scan_confirmed_destinations"`
	ScanPossibleDests  int `yaml:"scan_possible_destinations"`

	// Additive port lists (merged with built-in lists at runtime)
	ExtraBadPorts      []int `yaml:"extra_bad_ports"`
	ExtraStandardPorts []int `yaml:"extra_standard_ports"`

	// Additive path / cmdline / ASN / JA3 lists
	ExtraSuspiciousPaths []string `yaml:"extra_suspicious_paths"`
	ExtraCmdlinePatterns []string `yaml:"extra_cmdline_patterns"`
	ExtraHighRiskASNs    []string `yaml:"extra_high_risk_asns"`
	// ExtraJA3BadHashes adds custom malware JA3 fingerprints.
	// Format: "hash" (description defaults to "custom threat indicator")
	// or "hash:description" (e.g. "abc123:My internal red-team tool").
	ExtraJA3BadHashes []string `yaml:"extra_ja3_bad_hashes"`

	// ExemptedProcesses lists process names that bypass beaconing and
	// binary-path scoring. Useful for build systems, cron jobs, and
	// monitoring agents that exhibit beacon-like traffic patterns.
	ExemptedProcesses []string `yaml:"exempted_processes"`

	// DevToolProcesses lists additional process names to treat as developer
	// tools. Dev tools get a higher scan/NXDOMAIN threshold and skip QUIC
	// scoring. Built-in list covers node, python, go, docker, kubectl, etc.
	DevToolProcesses []string `yaml:"dev_tool_processes"`

	// DNS response analysis thresholds.
	// NXDomainStormThreshold is the minimum number of NXDOMAIN responses in a
	// single flow before it is flagged as a potential DGA/C2 NXDOMAIN storm.
	// Default: 5.
	NXDomainStormThreshold int `yaml:"nxdomain_storm_threshold"`
	// FastFluxTTLThreshold flags flows whose minimum observed DNS TTL is below
	// this value (seconds). Very low TTLs indicate fast-flux or DGA domains.
	// Default: 30.
	FastFluxTTLThreshold int `yaml:"fast_flux_ttl_threshold"`

	// AsymmetricUploadRatio flags flows where upload bytes exceed download bytes
	// by this factor, indicating potential data exfiltration.
	// Default: 10.0 (upload > 10× download triggers the signal).
	AsymmetricUploadRatio float64 `yaml:"asymmetric_upload_ratio"`

	// Kill-switches — set to true to silence a noisy signal entirely.
	DisableBinaryPathScoring       bool `yaml:"disable_binary_path_scoring"`
	DisableCmdlineScoring          bool `yaml:"disable_cmdline_scoring"`
	DisablePortScoring             bool `yaml:"disable_port_scoring"`
	DisableBeaconingScoring        bool `yaml:"disable_beaconing_scoring"`
	DisableDNSExfilScoring         bool `yaml:"disable_dns_exfil_scoring"`
	DisableGeoScoring              bool `yaml:"disable_geo_scoring"`
	DisableJA3Scoring              bool `yaml:"disable_ja3_scoring"`
	DisableReverseDNSScoring       bool `yaml:"disable_reverse_dns_scoring"`
	DisableSNIScoring              bool `yaml:"disable_sni_scoring"`
	DisableQUICScoring             bool `yaml:"disable_quic_scoring"`
	DisableLateralMovementScoring  bool `yaml:"disable_lateral_movement_scoring"`
	DisableProtocolAnomalyScoring  bool `yaml:"disable_protocol_anomaly_scoring"`
	DisableAsymmetricScoring       bool `yaml:"disable_asymmetric_scoring"`
	DisableHTTPScoring             bool `yaml:"disable_http_scoring"`
	DisableCertScoring             bool `yaml:"disable_cert_scoring"`

	// CompiledExtraCmdlinePatterns holds compiled versions of ExtraCmdlinePatterns.
	// Populated automatically after config load. Not serialized — use this
	// instead of ExtraCmdlinePatterns in hot paths to avoid per-flow compilation.
	CompiledExtraCmdlinePatterns []*regexp.Regexp `yaml:"-"`
}

// CaptureConfig controls packet-capture timing parameters.
type CaptureConfig struct {
	DefaultDurationSec int `yaml:"default_duration_seconds"`
	MaxDurationSec     int `yaml:"max_duration_seconds"`
	DNSTimeoutMS       int `yaml:"dns_timeout_ms"`
	DNSWorkers         int `yaml:"dns_workers"`
	// DNSCacheTTLSec is how long resolved (or negative) PTR results are reused.
	// 0 means use the built-in default (300 s). Takes effect on next restart.
	DNSCacheTTLSec int `yaml:"dns_cache_ttl_seconds"`
	// PacketBufferSize is the capacity of the in-process packet event channel.
	// Increase on high-throughput interfaces (> 100 Mbps) to reduce drops.
	// 0 means use the built-in default (4096). Must be between 256 and 65536.
	PacketBufferSize int `yaml:"packet_buffer_size"`
}

// GeoIPConfig points to MaxMind database files.
// Environment variables GEOIP_CITY_DB and GEOIP_ASN_DB always take precedence.
type GeoIPConfig struct {
	CityDB string `yaml:"city_db"`
	ASNDB  string `yaml:"asn_db"`
}

// HistoryConfig controls the rolling JSONL history file.
type HistoryConfig struct {
	MaxSizeMB    int `yaml:"max_size_mb"`
	MaxAgeHours  int `yaml:"max_age_hours"`
	PruneToHours int `yaml:"prune_to_hours"`
	// CompressRotated enables gzip compression of the previous day's history
	// when the rolling window advances past midnight. Compressed files are named
	// history_YYYY-MM-DD.jsonl.gz and kept for MaxRotatedDays days.
	// Default: false (no compression, single file as before).
	CompressRotated bool `yaml:"compress_rotated"`
	// MaxRotatedDays is how many compressed daily files to retain.
	// Older files are deleted automatically. Default: 7.
	MaxRotatedDays int `yaml:"max_rotated_days"`
}

// AlertingConfig enables optional webhook notifications for high-score flows.
type AlertingConfig struct {
	Enabled           bool    `yaml:"enabled"`
	WebhookURL        string  `yaml:"webhook_url"`
	MinScoreThreshold float64 `yaml:"min_score_threshold"`
	// DeduplicationWindowSec suppresses repeat alerts for the same flow within
	// this window. 0 means use the built-in default (300 s).
	DeduplicationWindowSec int `yaml:"deduplication_window_seconds"`
	// MaxAlertsPerMinute caps the webhook POST rate. 0 means unlimited.
	// Default: 60 (prevents bursts from saturating the receiving endpoint).
	MaxAlertsPerMinute int `yaml:"max_alerts_per_minute"`
	// WebhookSecret enables HMAC-SHA256 request signing when non-empty.
	// The X-FlowSentinel-Signature header will contain "sha256=<hex>".
	// The receiving endpoint should verify: HMAC-SHA256(secret, body).
	WebhookSecret string `yaml:"webhook_secret"`
}

// DaemonConfig controls the --daemon continuous-monitoring mode.
type DaemonConfig struct {
	// Interface is kept for backward compatibility. If Interfaces is empty
	// and Interface is non-empty, the daemon uses Interface as a single-element
	// list. Prefer Interfaces for new configurations.
	Interface  string   `yaml:"interface"`
	Interfaces []string `yaml:"interfaces"`
	BPFFilter  string   `yaml:"bpf_filter"`
	CaptureIntervalSec int `yaml:"capture_interval_seconds"`
}

// JA3FeedConfig controls the dynamic JA3 threat-intel feed.
type JA3FeedConfig struct {
	// Enabled controls whether the feed is fetched and used. Default: false.
	// When false, only the built-in static hash list and ExtraJA3BadHashes are used.
	Enabled bool `yaml:"enabled"`
	// UpdateIntervalHours is how often the remote feeds are refreshed. Default: 24.
	UpdateIntervalHours int `yaml:"update_interval_hours"`
	// URLs is the list of remote CSV feeds to fetch. Each URL must return a CSV
	// where column 0 is a 32-char MD5 hex hash and column 1 is a description.
	// The abuse.ch SSL blacklist format (quoted fields) is also accepted.
	URLs []string `yaml:"urls"`
	// LocalFile is an optional path to a local CSV file in the same format.
	// Entries from this file take priority over remote feeds.
	LocalFile string `yaml:"local_file"`
}

// HasshFeedConfig controls the dynamic HASSH threat-intel feed.
type HasshFeedConfig struct {
	// Enabled controls whether the feed is fetched and used. Default: false.
	Enabled bool `yaml:"enabled"`
	// UpdateIntervalHours is how often the remote feeds are refreshed. Default: 24.
	UpdateIntervalHours int `yaml:"update_interval_hours"`
	// URLs is the list of remote CSV feeds to fetch. Each must return a CSV
	// where column 0 is a 32-char MD5 hex hash and column 1 is a description.
	URLs []string `yaml:"urls"`
	// LocalFile is an optional path to a local CSV file (hash,description).
	LocalFile string `yaml:"local_file"`
}

// IPRepConfig controls the IP reputation blocklist feeds.
type IPRepConfig struct {
	// Enabled controls whether remote blocklists are fetched. Default: false.
	Enabled bool `yaml:"enabled"`
	// UpdateIntervalHours is how often the blocklists are refreshed. Default: 24.
	UpdateIntervalHours int `yaml:"update_interval_hours"`
	// URLs lists remote plain-text IP/CIDR blocklist sources.
	// Supported formats: Feodo Tracker, Emerging Threats, any newline-delimited list.
	URLs []string `yaml:"urls"`
	// LocalFile is an optional local plain-text file (one IP or CIDR per line).
	LocalFile string `yaml:"local_file"`
}

// DomRepConfig controls the domain reputation feed.
type DomRepConfig struct {
	// Enabled controls whether domain reputation lookups are active. Default: false.
	Enabled bool `yaml:"enabled"`
	// UpdateIntervalHours is how often remote feeds are refreshed. Default: 24.
	UpdateIntervalHours int `yaml:"update_interval_hours"`
	// URLs lists remote feeds. URLhaus text format and ThreatFox CSV are supported.
	URLs []string `yaml:"urls"`
	// LocalFile is an optional local file (one URL or domain per line).
	LocalFile string `yaml:"local_file"`
}

// IntelConfig holds external threat-intelligence API keys and settings.
type IntelConfig struct {
	// VirusTotalAPIKey enables VirusTotal file reputation lookups in scan_process.
	// When empty, VT lookups are skipped. Get a free key at virustotal.com.
	VirusTotalAPIKey string `yaml:"virustotal_api_key"`
}

// MetricsConfig controls the optional Prometheus metrics endpoint.
type MetricsConfig struct {
	// Enabled controls whether the /metrics HTTP server is started. Default: false.
	// When false, no port is opened and no prometheus dependency is initialised.
	Enabled bool `yaml:"enabled"`
	// ListenAddr is the TCP address for the metrics endpoint. Default: ":9200".
	ListenAddr string `yaml:"listen_addr"`
}

// ─── Defaults ─────────────────────────────────────────────────────────────────

// Default returns a Config populated with the built-in defaults.
// These match the values that were previously hard-coded throughout the codebase.
func Default() *Config {
	cfg := &Config{
		Scoring: ScoringConfig{
			BeaconingStrongCV:       0.15,
			BeaconingPossibleCV:     0.30,
			BeaconingMinPackets:     5,
			BeaconingMinIntervalSec: 0, // disabled by default; set > 0 to filter sub-N-second intervals
			DNSEntropyThreshold:     3.5,
			DNSLabelLenThreshold:    40,
			ScanConfirmedDests:      20,
			ScanPossibleDests:       8,
			NXDomainStormThreshold:  5,
			FastFluxTTLThreshold:    30,
			AsymmetricUploadRatio:   10.0,
		},
		Capture: CaptureConfig{
			DefaultDurationSec: 5,
			MaxDurationSec:     60,
			DNSTimeoutMS:       200,
			DNSWorkers:         20,
		},
		GeoIP: GeoIPConfig{},
		History: HistoryConfig{
			MaxSizeMB:    50,
			MaxAgeHours:  24,
			PruneToHours: 12,
		},
		Alerting: AlertingConfig{
			MinScoreThreshold:      7.0,
			DeduplicationWindowSec: 300,
			MaxAlertsPerMinute:     60,
		},
		Daemon: DaemonConfig{
			CaptureIntervalSec: 300,
		},
		JA3Feed: JA3FeedConfig{
			Enabled:             false,
			UpdateIntervalHours: 24,
			URLs: []string{
				"https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
			},
		},
		HasshFeed: HasshFeedConfig{
			Enabled:             false,
			UpdateIntervalHours: 24,
		},
		IPRep: IPRepConfig{
			Enabled:             false,
			UpdateIntervalHours: 24,
			URLs: []string{
				"https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
				"https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
			},
		},
		DomRep: DomRepConfig{
			Enabled:             false,
			UpdateIntervalHours: 24,
			URLs: []string{
				"https://urlhaus.abuse.ch/downloads/text/",
				"https://threatfox.abuse.ch/export/csv/domains/recent/",
			},
		},
		Metrics: MetricsConfig{
			Enabled:    false,
			ListenAddr: ":9200",
		},
	}
	// Default() is called with empty ExtraCmdlinePatterns so this never errors.
	_ = compileScoringPatterns(cfg)
	return cfg
}

// ─── Global singleton ─────────────────────────────────────────────────────────

var (
	global     *Config
	globalMu   sync.RWMutex
	lastPath   string
	lastPathMu sync.RWMutex
)

func init() {
	global = Default()
}

// Get returns the active global config. Always non-nil (returns defaults if
// Load has not been called).
func Get() *Config {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return global
}

// Set replaces the global config. Used by Load and by tests.
func Set(c *Config) {
	globalMu.Lock()
	global = c
	globalMu.Unlock()
}

// LoadedPath returns the config file path that was last successfully loaded.
// Empty string means no file was loaded (built-in defaults are in use).
func LoadedPath() string {
	lastPathMu.RLock()
	defer lastPathMu.RUnlock()
	return lastPath
}

// Reload re-reads the config from the last loaded path (or DefaultPath if no
// file was previously loaded). Useful for hot-reloading without restart.
func Reload() (*Config, error) {
	return Load(LoadedPath())
}

// ─── Merge ───────────────────────────────────────────────────────────────────

// mergeOverDefaults applies non-zero fields from override onto dst (which holds
// the built-in defaults). This avoids the YAML zero-value problem where omitted
// int/float fields are unmarshalled as 0 and silently clobber sensible defaults.
//
// Rules:
//   - int/float: override wins only when != 0
//   - string:    override wins when != ""
//   - bool:      override wins when true (defaults are all false, so true is always intentional)
//   - slices:    override replaces entirely when len > 0 (additive lists)
func mergeOverDefaults(dst, override *Config) {
	s := &dst.Scoring
	o := &override.Scoring
	if o.BeaconingStrongCV != 0 {
		s.BeaconingStrongCV = o.BeaconingStrongCV
	}
	if o.BeaconingPossibleCV != 0 {
		s.BeaconingPossibleCV = o.BeaconingPossibleCV
	}
	if o.BeaconingMinPackets != 0 {
		s.BeaconingMinPackets = o.BeaconingMinPackets
	}
	if o.BeaconingMinIntervalSec != 0 {
		s.BeaconingMinIntervalSec = o.BeaconingMinIntervalSec
	}
	if o.DNSEntropyThreshold != 0 {
		s.DNSEntropyThreshold = o.DNSEntropyThreshold
	}
	if o.DNSLabelLenThreshold != 0 {
		s.DNSLabelLenThreshold = o.DNSLabelLenThreshold
	}
	if o.ScanConfirmedDests != 0 {
		s.ScanConfirmedDests = o.ScanConfirmedDests
	}
	if o.ScanPossibleDests != 0 {
		s.ScanPossibleDests = o.ScanPossibleDests
	}
	if o.NXDomainStormThreshold != 0 {
		s.NXDomainStormThreshold = o.NXDomainStormThreshold
	}
	if o.FastFluxTTLThreshold != 0 {
		s.FastFluxTTLThreshold = o.FastFluxTTLThreshold
	}
	if o.AsymmetricUploadRatio != 0 {
		s.AsymmetricUploadRatio = o.AsymmetricUploadRatio
	}
	if len(o.ExtraBadPorts) > 0 {
		s.ExtraBadPorts = o.ExtraBadPorts
	}
	if len(o.ExtraStandardPorts) > 0 {
		s.ExtraStandardPorts = o.ExtraStandardPorts
	}
	if len(o.ExtraSuspiciousPaths) > 0 {
		s.ExtraSuspiciousPaths = o.ExtraSuspiciousPaths
	}
	if len(o.ExtraCmdlinePatterns) > 0 {
		s.ExtraCmdlinePatterns = o.ExtraCmdlinePatterns
	}
	if len(o.ExtraHighRiskASNs) > 0 {
		s.ExtraHighRiskASNs = o.ExtraHighRiskASNs
	}
	if len(o.ExtraJA3BadHashes) > 0 {
		s.ExtraJA3BadHashes = o.ExtraJA3BadHashes
	}
	if len(o.ExemptedProcesses) > 0 {
		s.ExemptedProcesses = o.ExemptedProcesses
	}
	if len(o.DevToolProcesses) > 0 {
		s.DevToolProcesses = o.DevToolProcesses
	}
	// Kill-switches: false is the default, so only true overrides.
	if o.DisableBinaryPathScoring {
		s.DisableBinaryPathScoring = true
	}
	if o.DisableCmdlineScoring {
		s.DisableCmdlineScoring = true
	}
	if o.DisablePortScoring {
		s.DisablePortScoring = true
	}
	if o.DisableBeaconingScoring {
		s.DisableBeaconingScoring = true
	}
	if o.DisableDNSExfilScoring {
		s.DisableDNSExfilScoring = true
	}
	if o.DisableGeoScoring {
		s.DisableGeoScoring = true
	}
	if o.DisableJA3Scoring {
		s.DisableJA3Scoring = true
	}
	if o.DisableReverseDNSScoring {
		s.DisableReverseDNSScoring = true
	}
	if o.DisableSNIScoring {
		s.DisableSNIScoring = true
	}
	if o.DisableQUICScoring {
		s.DisableQUICScoring = true
	}
	if o.DisableLateralMovementScoring {
		s.DisableLateralMovementScoring = true
	}
	if o.DisableProtocolAnomalyScoring {
		s.DisableProtocolAnomalyScoring = true
	}
	if o.DisableAsymmetricScoring {
		s.DisableAsymmetricScoring = true
	}
	if o.DisableHTTPScoring {
		s.DisableHTTPScoring = true
	}
	if o.DisableCertScoring {
		s.DisableCertScoring = true
	}

	c := &dst.Capture
	oc := &override.Capture
	if oc.DefaultDurationSec != 0 {
		c.DefaultDurationSec = oc.DefaultDurationSec
	}
	if oc.MaxDurationSec != 0 {
		c.MaxDurationSec = oc.MaxDurationSec
	}
	if oc.DNSTimeoutMS != 0 {
		c.DNSTimeoutMS = oc.DNSTimeoutMS
	}
	if oc.DNSWorkers != 0 {
		c.DNSWorkers = oc.DNSWorkers
	}
	if oc.DNSCacheTTLSec != 0 {
		c.DNSCacheTTLSec = oc.DNSCacheTTLSec
	}
	if oc.PacketBufferSize != 0 {
		c.PacketBufferSize = oc.PacketBufferSize
	}

	if override.GeoIP.CityDB != "" {
		dst.GeoIP.CityDB = override.GeoIP.CityDB
	}
	if override.GeoIP.ASNDB != "" {
		dst.GeoIP.ASNDB = override.GeoIP.ASNDB
	}

	h := &dst.History
	oh := &override.History
	if oh.MaxSizeMB != 0 {
		h.MaxSizeMB = oh.MaxSizeMB
	}
	if oh.MaxAgeHours != 0 {
		h.MaxAgeHours = oh.MaxAgeHours
	}
	if oh.PruneToHours != 0 {
		h.PruneToHours = oh.PruneToHours
	}

	a := &dst.Alerting
	oa := &override.Alerting
	if oa.Enabled {
		a.Enabled = true
	}
	if oa.WebhookURL != "" {
		a.WebhookURL = oa.WebhookURL
	}
	if oa.MinScoreThreshold != 0 {
		a.MinScoreThreshold = oa.MinScoreThreshold
	}
	if oa.DeduplicationWindowSec != 0 {
		a.DeduplicationWindowSec = oa.DeduplicationWindowSec
	}

	if oa.MaxAlertsPerMinute != 0 {
		a.MaxAlertsPerMinute = oa.MaxAlertsPerMinute
	}
	if oa.WebhookSecret != "" {
		a.WebhookSecret = oa.WebhookSecret
	}

	d := &dst.Daemon
	od := &override.Daemon
	if od.Interface != "" {
		d.Interface = od.Interface
	}
	if len(od.Interfaces) > 0 {
		d.Interfaces = od.Interfaces
	}
	if od.BPFFilter != "" {
		d.BPFFilter = od.BPFFilter
	}
	if od.CaptureIntervalSec != 0 {
		d.CaptureIntervalSec = od.CaptureIntervalSec
	}

	jf := &dst.JA3Feed
	ojf := &override.JA3Feed
	if ojf.Enabled {
		jf.Enabled = true
	}
	if ojf.UpdateIntervalHours != 0 {
		jf.UpdateIntervalHours = ojf.UpdateIntervalHours
	}
	if len(ojf.URLs) > 0 {
		jf.URLs = ojf.URLs
	}
	if ojf.LocalFile != "" {
		jf.LocalFile = ojf.LocalFile
	}

	hf := &dst.HasshFeed
	ohf := &override.HasshFeed
	if ohf.Enabled {
		hf.Enabled = true
	}
	if ohf.UpdateIntervalHours != 0 {
		hf.UpdateIntervalHours = ohf.UpdateIntervalHours
	}
	if len(ohf.URLs) > 0 {
		hf.URLs = ohf.URLs
	}
	if ohf.LocalFile != "" {
		hf.LocalFile = ohf.LocalFile
	}

	ir := &dst.IPRep
	oir := &override.IPRep
	if oir.Enabled {
		ir.Enabled = true
	}
	if oir.UpdateIntervalHours != 0 {
		ir.UpdateIntervalHours = oir.UpdateIntervalHours
	}
	if len(oir.URLs) > 0 {
		ir.URLs = oir.URLs
	}
	if oir.LocalFile != "" {
		ir.LocalFile = oir.LocalFile
	}

	// DomRep
	if override.DomRep.Enabled {
		dst.DomRep.Enabled = true
	}
	if override.DomRep.UpdateIntervalHours != 0 {
		dst.DomRep.UpdateIntervalHours = override.DomRep.UpdateIntervalHours
	}
	if override.DomRep.LocalFile != "" {
		dst.DomRep.LocalFile = override.DomRep.LocalFile
	}
	if len(override.DomRep.URLs) > 0 {
		dst.DomRep.URLs = override.DomRep.URLs
	}

	m := &dst.Metrics
	om := &override.Metrics
	if om.Enabled {
		m.Enabled = true
	}
	if om.ListenAddr != "" {
		m.ListenAddr = om.ListenAddr
	}

	if override.Intel.VirusTotalAPIKey != "" {
		dst.Intel.VirusTotalAPIKey = override.Intel.VirusTotalAPIKey
	}
}

// ─── Loading ──────────────────────────────────────────────────────────────────

// DefaultPath returns the canonical config file location.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return filepath.Join(home, ".config", "mcp-flowsentinel", "config.yaml")
}

// Load reads the YAML config file at path (empty → DefaultPath), merges it
// over the built-in defaults, then applies environment variable overrides.
// The result is stored as the global config and returned.
func Load(path string) (*Config, error) {
	cfg := Default()

	if path == "" {
		path = DefaultPath()
	}
	// If env var is set it overrides the --config flag.
	if ev := os.Getenv("FLOWSENTINEL_CONFIG"); ev != "" {
		path = ev
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// No file is fine — use defaults.
			applyEnvOverrides(cfg)
			Set(cfg)
			return cfg, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var override Config
	if err := yaml.Unmarshal(data, &override); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	mergeOverDefaults(cfg, &override)

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}

	if err := compileScoringPatterns(cfg); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	applyEnvOverrides(cfg)
	Set(cfg)

	lastPathMu.Lock()
	lastPath = path
	lastPathMu.Unlock()

	return cfg, nil
}

// compileScoringPatterns pre-compiles ExtraCmdlinePatterns into
// CompiledExtraCmdlinePatterns to avoid per-flow regex compilation in hot paths.
// Returns an error if any pattern is invalid so the user knows immediately
// rather than silently having their rule ignored at runtime.
func compileScoringPatterns(cfg *Config) error {
	compiled := make([]*regexp.Regexp, 0, len(cfg.Scoring.ExtraCmdlinePatterns))
	for _, pat := range cfg.Scoring.ExtraCmdlinePatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			cfg.Scoring.CompiledExtraCmdlinePatterns = nil
			return fmt.Errorf("scoring.extra_cmdline_patterns: invalid regex %q: %w", pat, err)
		}
		compiled = append(compiled, re)
	}
	cfg.Scoring.CompiledExtraCmdlinePatterns = compiled
	return nil
}

// applyEnvOverrides enforces that environment variables always win over the
// config file (12-factor style).
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("GEOIP_CITY_DB"); v != "" {
		cfg.GeoIP.CityDB = v
	}
	if v := os.Getenv("GEOIP_ASN_DB"); v != "" {
		cfg.GeoIP.ASNDB = v
	}
}

// validate returns an error if any config value is semantically invalid.
func validate(cfg *Config) error {
	s := cfg.Scoring
	if s.BeaconingStrongCV <= 0 || s.BeaconingStrongCV >= 1 {
		return fmt.Errorf("scoring.beaconing_strong_cv must be in (0, 1), got %v", s.BeaconingStrongCV)
	}
	if s.BeaconingPossibleCV <= s.BeaconingStrongCV {
		return fmt.Errorf("scoring.beaconing_possible_cv (%v) must be greater than beaconing_strong_cv (%v)", s.BeaconingPossibleCV, s.BeaconingStrongCV)
	}
	if s.BeaconingMinPackets < 2 {
		return fmt.Errorf("scoring.beaconing_min_packets must be >= 2, got %d", s.BeaconingMinPackets)
	}
	if s.DNSEntropyThreshold <= 0 {
		return fmt.Errorf("scoring.dns_entropy_threshold must be > 0, got %v", s.DNSEntropyThreshold)
	}
	if s.ScanConfirmedDests <= s.ScanPossibleDests {
		return fmt.Errorf("scoring.scan_confirmed_destinations (%d) must be greater than scan_possible_destinations (%d)", s.ScanConfirmedDests, s.ScanPossibleDests)
	}
	c := cfg.Capture
	if c.DefaultDurationSec <= 0 {
		return fmt.Errorf("capture.default_duration_seconds must be > 0, got %d", c.DefaultDurationSec)
	}
	if c.MaxDurationSec < c.DefaultDurationSec {
		return fmt.Errorf("capture.max_duration_seconds (%d) must be >= default_duration_seconds (%d)", c.MaxDurationSec, c.DefaultDurationSec)
	}
	if c.DNSTimeoutMS <= 0 {
		return fmt.Errorf("capture.dns_timeout_ms must be > 0, got %d", c.DNSTimeoutMS)
	}
	if c.DNSWorkers <= 0 || c.DNSWorkers > 200 {
		return fmt.Errorf("capture.dns_workers must be in [1, 200], got %d", c.DNSWorkers)
	}
	if c.DNSCacheTTLSec < 0 {
		return fmt.Errorf("capture.dns_cache_ttl_seconds must be >= 0, got %d", c.DNSCacheTTLSec)
	}
	h := cfg.History
	if h.MaxSizeMB <= 0 {
		return fmt.Errorf("history.max_size_mb must be > 0, got %d", h.MaxSizeMB)
	}
	if h.MaxAgeHours <= 0 {
		return fmt.Errorf("history.max_age_hours must be > 0, got %d", h.MaxAgeHours)
	}
	if h.PruneToHours <= 0 || h.PruneToHours >= h.MaxAgeHours {
		return fmt.Errorf("history.prune_to_hours (%d) must be in (0, max_age_hours=%d)", h.PruneToHours, h.MaxAgeHours)
	}
	if cfg.Daemon.CaptureIntervalSec <= 0 {
		return fmt.Errorf("daemon.capture_interval_seconds must be > 0, got %d", cfg.Daemon.CaptureIntervalSec)
	}
	a := cfg.Alerting
	if a.MinScoreThreshold < 0 || a.MinScoreThreshold > 10 {
		return fmt.Errorf("alerting.min_score_threshold must be in [0, 10], got %v", a.MinScoreThreshold)
	}
	if a.DeduplicationWindowSec < 0 {
		return fmt.Errorf("alerting.deduplication_window_seconds must be >= 0, got %d", a.DeduplicationWindowSec)
	}
	return nil
}

// ─── Init-config helper ───────────────────────────────────────────────────────

// WriteDefault writes a fully commented default config.yaml to path.
// Creates parent directories as needed.
func WriteDefault(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config file already exists at %s — delete it first or edit it directly", path)
	}
	return os.WriteFile(path, []byte(defaultYAML), 0o600)
}

const defaultYAML = `# MCP-FlowSentinel — Configuration File
# Generated by: mcp-flowsentinel --init-config
# Location:     ~/.config/mcp-flowsentinel/config.yaml
#
# Override specific keys only — unset keys fall back to the built-in defaults.
# Environment variables GEOIP_CITY_DB and GEOIP_ASN_DB always take precedence
# over the geoip section below.

# ─── Detection Engine ─────────────────────────────────────────────────────────
scoring:
  # Beaconing — coefficient of variation (CV) of inter-packet arrival times.
  # IMPORTANT: lower CV threshold = stricter detection (higher CV = more jitter allowed).
  # Raising these values makes detection LESS strict (more false positives suppressed).
  beaconing_strong_cv: 0.15     # CV < this → strong beaconing   (+3.5 pts)
  beaconing_possible_cv: 0.30   # CV < this → possible beaconing  (+2.0 pts)
  beaconing_min_packets: 5      # Minimum packets required for statistical validity

  # DNS exfiltration — high-entropy subdomain detection.
  dns_entropy_threshold: 3.5    # Shannon entropy (bits/char) above this → suspicious (+2.5 pts)
  dns_label_len_threshold: 40   # Label length above this → suspicious (+2.5 pts)

  # Port-scan detection — unique destination IP thresholds per source.
  scan_confirmed_destinations: 20  # >= N unique dsts from same src → scan     (+3.0 pts)
  scan_possible_destinations: 8    # >= N unique dsts from same src → possible  (+1.5 pts)

  # ── Custom port lists (additive — merged with built-in lists) ──────────────
  # Add ports you want flagged as suspicious (append to built-in bad-port list).
  # extra_bad_ports: [8888, 9999]

  # Add ports that are normal in your environment to reduce false positives.
  # Common additions: 3000 (Node), 5000 (Flask), 8000 (Django), 9200 (ES)
  # extra_standard_ports: [3000, 5000, 8000, 9200]

  # ── Custom suspicious path prefixes (additive) ────────────────────────────
  # extra_suspicious_paths:
  #   - "/opt/implants/"
  #   - "C:\\Users\\Public\\"

  # ── Custom cmdline patterns — Go regex syntax (additive) ──────────────────
  # extra_cmdline_patterns:
  #   - "(?i)mshta\\.exe"
  #   - "(?i)regsvr32.*scrobj"

  # ── Custom high-risk ASN patterns — case-insensitive substring (additive) ─
  # extra_high_risk_asns:
  #   - "my-bad-hoster"

  # ── Custom JA3 bad hashes (additive) ────────────────────────────────────
  # Format: "hash" or "hash:description"
  # extra_ja3_bad_hashes:
  #   - "abc123def456abc123def456abc123de:My red-team tool"
  #   - "deadbeef00112233deadbeef00112233"

  # ── Process exemptions (skip beaconing + binary-path scoring) ─────────────
  # Useful for cron jobs, monitoring agents, build systems.
  # exempted_processes:
  #   - "prometheus"
  #   - "node_exporter"
  #   - "datadog-agent"

  # ── DNS response analysis ─────────────────────────────────────────────────
  # Flag flows with >= N NXDOMAIN responses (DGA/C2 storm indicator).
  nxdomain_storm_threshold: 5
  # Flag flows whose minimum observed DNS TTL is below N seconds (fast-flux/DGA).
  fast_flux_ttl_threshold: 30

  # ── Asymmetric upload detection ───────────────────────────────────────────
  # Flag flows where sent bytes > N × received bytes (potential exfiltration).
  asymmetric_upload_ratio: 10.0

  # ── Kill-switches — set true to silence noisy signals ─────────────────────
  # Useful if /tmp is normal in your environment (build systems, containers).
  disable_binary_path_scoring: false
  disable_cmdline_scoring: false
  # Useful if your app uses non-standard ports legitimately.
  disable_port_scoring: false
  # Disable beaconing detection (noisy on environments with regular heartbeats).
  disable_beaconing_scoring: false
  # Disable DNS exfiltration detection (entropy, NXDOMAIN storm, fast-flux TTL).
  disable_dns_exfil_scoring: false
  # Disable GeoIP / ASN high-risk scoring.
  disable_geo_scoring: false
  # Disable JA3 TLS fingerprint matching.
  disable_ja3_scoring: false
  # Disable reverse-DNS absence penalty.
  disable_reverse_dns_scoring: false
  # Disable TLS SNI analysis (missing SNI, DoH providers).
  disable_sni_scoring: false
  # Disable QUIC scoring for non-browser processes.
  disable_quic_scoring: false
  # Disable lateral movement detection (RFC1918→RFC1918 on SMB/RDP/WMI/LDAP/WinRM).
  disable_lateral_movement_scoring: false
  # Disable protocol anomaly detection (non-TLS on 443, excessive DNS over TCP).
  disable_protocol_anomaly_scoring: false
  # Disable asymmetric upload ratio detection.
  disable_asymmetric_scoring: false

# ─── Capture Timing ───────────────────────────────────────────────────────────
capture:
  default_duration_seconds: 5    # Default for analyze_network when no duration given
  max_duration_seconds: 60       # Hard cap enforced by analyze_network
  dns_timeout_ms: 200            # Per-IP reverse-DNS lookup timeout
  dns_workers: 20                # Concurrent goroutines for reverse-DNS resolution
  dns_cache_ttl_seconds: 300     # How long PTR results are cached (takes effect on restart)

# ─── GeoIP Enrichment (optional) ─────────────────────────────────────────────
# Download free databases from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
# Environment variables GEOIP_CITY_DB / GEOIP_ASN_DB override these paths.
geoip:
  city_db: ""   # e.g. /home/user/GeoLite2-City.mmdb
  asn_db: ""    # e.g. /home/user/GeoLite2-ASN.mmdb

# ─── Flow History ─────────────────────────────────────────────────────────────
history:
  max_size_mb: 50       # File size cap; aggressive pruning kicks in above this
  max_age_hours: 24     # Entries older than this are always discarded
  prune_to_hours: 12    # When file is oversized, keep only the last N hours

# ─── Webhook Alerting ─────────────────────────────────────────────────────────
# Sends a JSON POST when a flow's suspicion score crosses the threshold.
# Supports generic HTTP endpoints, Slack incoming webhooks, and Discord webhooks.
alerting:
  enabled: false
  # webhook_url: "https://hooks.slack.com/services/T.../B.../..."
  min_score_threshold: 7.0              # Only alert on CRITICAL flows (score >= 7.0)
  deduplication_window_seconds: 300     # Suppress repeat alerts for the same flow within this window
  max_alerts_per_minute: 60            # Rate limit — caps webhook POST rate (0 = unlimited)
  webhook_secret: ""                   # HMAC-SHA256 signing secret — adds X-FlowSentinel-Signature header

# ─── Daemon Mode ──────────────────────────────────────────────────────────────
# Used when running: mcp-flowsentinel --daemon
daemon:
  interface: ""                    # Single interface (legacy — prefer interfaces list below)
  # interfaces:                    # Monitor multiple interfaces in parallel
  #   - "eth0"
  #   - "eth1"
  #   - "docker0"
  bpf_filter: ""                   # Optional BPF filter, e.g. "not port 22"
  capture_interval_seconds: 300    # Analyse traffic in N-second rolling windows

# ─── JA3 Dynamic Threat Feed ──────────────────────────────────────────────────
# Fetches community JA3 fingerprint blacklists and merges with the built-in list.
ja3_feed:
  enabled: false                   # Set true to enable remote feed fetching
  update_interval_hours: 24        # Refresh interval
  urls:
    - "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
  local_file: ""                   # Optional local CSV override (hash,description)

# ─── HASSH Dynamic Threat Feed ────────────────────────────────────────────────
# Fetches HASSH fingerprint lists for offensive SSH libraries.
# No major public feed exists yet — use local_file to supply your own list.
# CSV format: hash,description  (same as JA3 feed)
hassh_feed:
  enabled: false
  update_interval_hours: 24
  # urls:
  #   - "https://example.com/hassh_blacklist.csv"
  local_file: ""   # Optional path to local CSV (hash,description)

# ─── IP Reputation / C2 Blocklists ────────────────────────────────────────────
# Fetches known C2 server and botnet IP blocklists.
# When a destination IP matches, the flow gets +2.5 in the c2 scoring category.
ip_rep:
  enabled: false
  update_interval_hours: 24
  urls:
    - "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    - "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
  local_file: ""   # Optional local file (one IP or CIDR per line)

# ─── Prometheus Metrics ────────────────────────────────────────────────────────
# Exposes a /metrics endpoint for Prometheus scraping.
metrics:
  enabled: false        # Set true to start the metrics HTTP server
  listen_addr: ":9200"  # Address and port for the Prometheus scrape endpoint
`
