# Configuration

Runtime configuration, background monitoring, alerting, history and GeoIP enrichment. Tool inputs are described in [tools.md](tools.md).

## Config file

All thresholds, limits, and optional features can be tuned via a YAML config file.

### Generate a config file

```bash
mcp-flowsentinel --init-config
```

This writes a fully commented `~/.config/mcp-flowsentinel/config.yaml` with every option documented inline.

### Key config sections

This is an abbreviated operational example. Run `--init-config` for the
authoritative, fully commented list of supported fields.

```yaml
# ─── Detection Engine ────────────────────────────────────────────────────
scoring:
  beaconing_strong_cv: 0.15       # CV < this → strong beaconing (+3.5)
  beaconing_possible_cv: 0.30     # CV < this → possible beaconing (+2.0)
  beaconing_min_packets: 5        # minimum packets required for CV calculation
  beaconing_min_interval_seconds: 0  # skip sub-N-second intervals (0 = off)
  dns_entropy_threshold: 3.5      # Shannon entropy above this → suspicious
  dns_label_len_threshold: 40     # label length above this → suspicious
  nxdomain_storm_threshold: 5     # NXDOMAIN responses per flow → DGA storm
  fast_flux_ttl_threshold: 30     # DNS TTL below this (seconds) → fast-flux
  scan_confirmed_destinations: 20 # >= N unique dsts → confirmed port scan
  scan_possible_destinations: 8   # >= N unique dsts → possible scan
  asymmetric_upload_ratio: 10.0   # upload/download ratio → exfil indicator

  # Extend built-in detection lists:
  extra_bad_ports: [8888, 9999]
  extra_standard_ports: [3000, 5000, 8000]   # suppress false positives
  extra_suspicious_paths: ["/opt/implants/"]
  extra_cmdline_patterns: ["(?i)mshta\\.exe"]
  extra_high_risk_asns: ["my-bad-hoster"]
  # Custom JA3 bad hashes (format: "hash" or "hash:description"):
  extra_ja3_bad_hashes:
    - "abc123def456abc123def456abc123de:My red-team tool"
  # Process exemptions — skip beaconing + binary-path scoring for these:
  exempted_processes: ["prometheus", "datadog-agent"]

  # Dev-tool processes — NXDOMAIN threshold is doubled for these:
  dev_tool_processes: ["node", "python3", "docker", "go", "cargo"]

  # Kill-switches for noisy signals:
  disable_binary_path_scoring: false
  disable_port_scoring: false
  disable_ja3_scoring: false       # disables both JA3 and JA3S scoring
  disable_beaconing_scoring: false

# ─── Capture ─────────────────────────────────────────────────────────────
capture:
  default_duration_seconds: 5
  max_duration_seconds: 60
  dns_timeout_ms: 200
  dns_workers: 20
  dns_cache_ttl_seconds: 300
  packet_buffer_size: 4096         # channel capacity for packet events (256–65536)
                                   # raise if capture: packet channel >70% full warnings appear

# ─── History ─────────────────────────────────────────────────────────────
history:
  max_age_hours: 24
  max_size_mb: 50
  prune_to_hours: 12
  compress_rotated: false          # gzip-compress daily rotated history files
  max_rotated_days: 7              # delete compressed files older than N days

# ─── Intel ───────────────────────────────────────────────────────────────
intel:
  virustotal_api_key: ""           # enables VirusTotal lookups in scan_process

# ─── GeoIP ───────────────────────────────────────────────────────────────
geoip:
  city_db: "/path/to/GeoLite2-City.mmdb"
  asn_db:  "/path/to/GeoLite2-ASN.mmdb"

# ─── Webhook Alerting ────────────────────────────────────────────────────
alerting:
  enabled: true
  webhook_url: "https://hooks.slack.com/services/T.../B.../..."
  min_score_threshold: 7.0
  deduplication_window_seconds: 300
  max_alerts_per_minute: 60
  webhook_secret: ""                 # optional HMAC-SHA256 signing secret

# ─── Daemon Mode ─────────────────────────────────────────────────────────
daemon:
  interfaces: [eth0]               # list of interfaces to monitor
  bpf_filter: "not port 22"
  capture_interval_seconds: 300

# ─── JA3 Feed (optional, extends built-in hash list) ─────────────────────
ja3_feed:
  enabled: false
  update_interval_hours: 24
  urls:
    - https://example.com/ja3_feed.csv   # CSV: hash,description

# ─── HASSH Feed (optional, extends built-in hash list) ────────────────────
hassh_feed:
  enabled: false
  update_interval_hours: 24
  urls: []                              # CSV: hash,description
  local_file: ""                        # path to a local CSV file

# ─── IP Reputation (optional, Feodo Tracker + Emerging Threats by default) ─
ip_rep:
  enabled: false                        # set to true to activate blocklist lookups
  update_interval_hours: 24
  urls:
    - https://feodotracker.abuse.ch/downloads/ipblocklist.txt
    - https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
  local_file: ""                        # path to a local IP/CIDR list

# ─── Domain Reputation (optional, URLhaus + ThreatFox by default) ────────
dom_rep:
  enabled: false                        # set to true to activate domain reputation lookups
  update_interval_hours: 24
  urls:
    - https://urlhaus.abuse.ch/downloads/text/
    - https://threatfox.abuse.ch/export/csv/domains/recent/
  local_file: ""                        # path to a local domain list (one domain per line)

# ─── Prometheus metrics (optional) ───────────────────────────────────────
metrics:
  enabled: false
  listen_addr: "127.0.0.1:9200"
```

### Environment variable priority

| Variable | Overrides |
|----------|-----------|
| `FLOWSENTINEL_CONFIG` | Config file path |
| `GEOIP_CITY_DB` | `geoip.city_db` |
| `GEOIP_ASN_DB` | `geoip.asn_db` |
| `FLOWSENTINEL_WEBHOOK_URL` | `alerting.webhook_url` |

## Daemon mode — continuous monitoring

Run the MCP server and a background capture loop at the same time:

```bash
mcp-flowsentinel --daemon
```

The daemon captures rolling windows (default: 5 minutes) continuously, feeding results into the flow history. Your AI can then query that accumulated history at any time:

```
"Show me everything suspicious from the last 30 minutes."
"Did anything beacon while I was away?"
"Were any Python SSH scripts running in the last hour?"
```

## Webhook alerting

When `alerting.enabled: true` and a `webhook_url` is set, MCP-FlowSentinel fires a JSON POST for every flow whose `suspicion_score` meets or exceeds `min_score_threshold` (default: 7.0 = CRITICAL).

```json
{
  "source": "mcp-flowsentinel",
  "timestamp": "2025-04-12T14:23:01Z",
  "severity": "CRITICAL",
  "flow": { "...": "FlowRecord" }
}
```

Compatible with **Slack incoming webhooks**, **Discord webhooks**, and any generic HTTP endpoint. Webhook bodies are HMAC-SHA256 signed when `webhook_secret` is set.

Outbound webhook and threat-feed URLs must use HTTP or HTTPS, include a hostname, contain no embedded credentials, and stay within 2048 characters. Private and loopback destinations remain supported intentionally for local integrations; treat every configured endpoint as trusted operator input.

**Deduplication:** the same flow will not fire more than once per deduplication window (default: 5 min).

**Alert log:** every fired alert is persisted to `~/.cache/mcp-flowsentinel/alerts.jsonl`. Query it via `get_alerts`.

## Flow history

Every capture session automatically appends results to a rolling JSONL history at `~/.cache/mcp-flowsentinel/history.jsonl`.

```
"Show me all connections from the last 2 hours with a score above 5."
"Was curl.exe making any connections in the last hour?"
"Have I seen this IP before today?"
```

Default retention: 24 hours, 50 MB cap. With `compress_rotated: true`, entries older than today are automatically gzip-compressed into per-day `history_YYYY-MM-DD.jsonl.gz` files, and `Query` transparently includes them when the requested time window spans multiple days.

## GeoIP enrichment (optional)

Flows can be enriched with country code, ASN organisation, and high-risk ASN detection using the free [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) databases.

1. Sign up for a free MaxMind account and download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`.
2. Configure the paths (either method works):

**Option A — config file** (persistent):

```yaml
geoip:
  city_db: "/path/to/GeoLite2-City.mmdb"
  asn_db:  "/path/to/GeoLite2-ASN.mmdb"
```

**Option B — environment variables** (always override config file):

```bash
export GEOIP_CITY_DB=/path/to/GeoLite2-City.mmdb
export GEOIP_ASN_DB=/path/to/GeoLite2-ASN.mmdb
```

When enabled, each flow includes `country`, `asn_org`, and `geo_high_risk` fields.
