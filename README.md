# MCP-FlowSentinel

> **Ask your AI assistant: "What is making outbound connections right now — and is any of it suspicious?"**

MCP-FlowSentinel is a [Model Context Protocol](https://modelcontextprotocol.io/) server that gives **any MCP-compatible AI assistant** real-time visibility into your network traffic. It captures packets, maps every connection to the owning process, and runs 30+ detection signals — so you can ask your AI to investigate, explain, or alert on network activity in plain English.

Works with **Claude Desktop, Cursor, Cline, Continue.dev, Zed, Windsurf**, and any other client that supports the MCP stdio transport.

> **How this was built:** this project was developed primarily through [vibe coding](https://en.wikipedia.org/wiki/Vibe_coding) — iterative AI-assisted development with Claude Code. The design, architecture decisions, and implementation were driven by prompting rather than traditional hand-coding. Security-sensitive components (packet parsers, scoring logic) have unit tests and fuzz tests, but the codebase has not undergone a formal third-party security audit. Use accordingly.

![CI](https://github.com/ClementG91/MCP-FlowSentinel/actions/workflows/ci.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## What you can ask your AI

```
"List my network interfaces."
"Capture traffic on Wi-Fi for 30 seconds and show me anything suspicious."
"Which process is making the most outbound connections right now?"
"Analyze this pcap file and explain what it contains."
"Show me all connections with a suspicion score above 5."
"Is there anything beaconing out of my machine right now?"
"Scan the chrome.exe process — is the binary clean? Any VirusTotal hits?"
"Watch traffic from 1.2.3.4 for the next 20 seconds."
"Show me all SSH connections made by Python scripts in the last hour."
```

---

## Install (no Go required)

### Windows

```powershell
irm https://raw.githubusercontent.com/ClementG91/MCP-FlowSentinel/main/install.ps1 | iex
```

> **Prerequisite — Npcap** (packet capture driver, free for personal use):
> 1. Download from **[npcap.com/#download](https://npcap.com/#download)**
> 2. Run the installer — check **"Install Npcap in WinPcap API-compatible Mode"**
> 3. Then run the one-liner above
>
> The MCP server process must run with **Administrator** privileges for packet capture to work.

### Linux

```bash
curl -fsSL https://raw.githubusercontent.com/ClementG91/MCP-FlowSentinel/main/install.sh | bash
```

The script auto-installs `libpcap` via your package manager and grants `cap_net_raw` so you don't need to run as root.

### macOS

```bash
curl -fsSL https://raw.githubusercontent.com/ClementG91/MCP-FlowSentinel/main/install.sh | bash
```

Requires [Homebrew](https://brew.sh). The script installs `libpcap` automatically.

### Manual download

Grab the latest binary for your platform from the [Releases page](https://github.com/ClementG91/MCP-FlowSentinel/releases).

| Platform | File |
|----------|------|
| Windows x64 | `mcp-flowsentinel-windows-amd64.exe` |
| Linux x64 | `mcp-flowsentinel-linux-amd64` |
| Linux ARM64 | `mcp-flowsentinel-linux-arm64` |
| macOS Intel | `mcp-flowsentinel-darwin-amd64` |
| macOS Apple Silicon | `mcp-flowsentinel-darwin-arm64` |

---

## Update

```
mcp-flowsentinel --update
```

Checks GitHub for a newer release and replaces the binary in-place. Set `GITHUB_TOKEN` to avoid rate limits when running multiple instances.

---

## Client configuration

MCP-FlowSentinel uses the **stdio transport** — the binary is launched as a subprocess by your AI client. The configuration format is the same across clients; only the config file location differs.

> **Windows note:** the binary must run as Administrator for packet capture. See your client's docs for how to launch MCP servers with elevated privileges, or pre-elevate the terminal that starts your client.

### Claude Desktop

**Config file:**
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "flowsentinel": {
      "command": "/absolute/path/to/mcp-flowsentinel",
      "args": []
    }
  }
}
```

Restart Claude Desktop after editing.

---

### Cursor

**Config file:** `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (per-project)

```json
{
  "mcpServers": {
    "flowsentinel": {
      "command": "/absolute/path/to/mcp-flowsentinel",
      "args": []
    }
  }
}
```

Reload the window (`Ctrl+Shift+P` → *Developer: Reload Window*) after editing.

---

### Cline (VS Code)

Open VS Code settings (`Ctrl+,`), search for **Cline MCP**, click *Edit in settings.json*, and add:

```json
{
  "cline.mcpServers": {
    "flowsentinel": {
      "command": "/absolute/path/to/mcp-flowsentinel",
      "args": []
    }
  }
}
```

---

### Continue.dev

**Config file:** `~/.continue/config.json`

```json
{
  "mcpServers": [
    {
      "name": "flowsentinel",
      "transport": {
        "type": "stdio",
        "command": "/absolute/path/to/mcp-flowsentinel",
        "args": []
      }
    }
  ]
}
```

---

### Zed

**Config file:** `~/.config/zed/settings.json`

```json
{
  "context_servers": {
    "flowsentinel": {
      "command": {
        "path": "/absolute/path/to/mcp-flowsentinel",
        "args": []
      }
    }
  }
}
```

---

### Windsurf (Codeium)

**Config file:** `~/.codeium/windsurf/mcp_config.json`

```json
{
  "mcpServers": {
    "flowsentinel": {
      "command": "/absolute/path/to/mcp-flowsentinel",
      "args": []
    }
  }
}
```

---

## Tools

| Tool | Description |
|------|-------------|
| `list_interfaces` | List all pcap-visible network interfaces |
| `analyze_network` | Live capture on a named interface (default 5 s, max 60 s) |
| `analyze_pcap` | Analyze a saved `.pcap` / `.pcapng` file (max 1 GB) |
| `live_watch` | Targeted live capture filtered by process name and/or IP address |
| `scan_process` | Deep security scan of a process: binary hash, VirusTotal lookup, loaded modules |
| `get_process_map` | Snapshot of all processes with open sockets |
| `get_flow_history` | Query the rolling history of past capture sessions |
| `analyze_process` | Deep-dive on a specific process: open connections, parent chain, GeoIP, history |
| `get_config` | Return the current runtime configuration (webhook URL masked) |
| `get_daemon_stats` | Return runtime statistics for the background daemon |
| `get_alerts` | Query the persistent alert log for fired webhook alerts |
| `reload_config` | Hot-reload the YAML config file without restarting the server |

### Tool details

**`analyze_network` / `analyze_pcap`** accept optional filters:
- `min_score` (0–10) — only return flows at or above this suspicion score
- `top_n` — return only the N highest-scoring flows
- `bpf_filter` — Berkeley Packet Filter expression (e.g. `tcp port 443`, `host 1.2.3.4`)

**`live_watch`** inputs: `interface` (required), `process_name`, `target_ip`, `duration_seconds` (1–60), `min_score`. At least one of `process_name` or `target_ip` is required. Automatically sets a BPF pre-filter on `target_ip` when provided.

**`scan_process`** inputs: `pid` or `process_name` (case-insensitive substring). Returns per-binary:
- SHA-256 hash of the binary on disk
- Binary location analysis (suspicious paths: `/tmp`, `AppData\Local\Temp`, etc.)
- Loaded shared-library / DLL modules (Linux only — reads `/proc/<pid>/maps`)
- Optional VirusTotal reputation lookup (requires `intel.virustotal_api_key` in config)
- Consolidated list of suspicious signals

**`get_flow_history`** filters: `max_age_hours`, `min_score`, `src_ip`, `dst_ip`, `process_name`, `top_n`.

**`analyze_process`** accepts `pid` and/or `process_name` (case-insensitive substring match).

---

## Detection engine

Each flow is scored using **categorical bounded scoring** across six signal buckets. Every bucket has an independent cap, preventing correlated signals from stacking unboundedly. The final score is always in **[0, 10]**. Every fired signal is recorded in `suspicion_reasons`; matched [MITRE ATT&CK](https://attack.mitre.org/) techniques are included in `mitre_techniques`.

### Scoring architecture

| Bucket | Cap | Contains |
|--------|-----|----------|
| `c2` | 6.0 | Known-bad JA3/JA3S/HASSH fingerprints, known-bad ports, IP reputation, C2 User-Agent |
| `tls` | 3.5 | TLS certificate anomalies (self-signed, expired, long lifetime, IP CN, missing SAN) |
| `behavioral` | 4.0 | Beaconing, port scan, asymmetric upload, long-lived connections, high transfer rates |
| `dns` | 3.0 | High-entropy labels, NXDOMAIN storm, fast-flux TTL, DoH from non-browser |
| `process` | 3.5 | Suspicious binary path/cmdline, unresolved path |
| `network` | 5.0 | High-risk ASN, geo, lateral movement, non-standard ports, HTTP CONNECT, IPv6 anomalies |

After bucket totals are summed, a **baseline anomaly multiplier** scales the raw score (0.7× for typical traffic, 1.0× for normal, 1.3× at 2σ deviation, 1.8× at ≥3σ). The final score is hard-capped at **10.0**.

### Baseline learning

In daemon mode, MCP-FlowSentinel continuously learns the normal behaviour of each process using several online models. Baseline state persists across restarts at `~/.cache/mcp-flowsentinel/baseline.json` (XDG_CACHE_HOME respected). Entries older than 72 hours are pruned automatically.

**Byte-volume anomaly (Welford online algorithm):** Each `(process, destination port)` pair tracks rolling mean and variance. Flows that deviate significantly from the process's historical byte volume are scored higher via a multiplier:

| Deviation from baseline | Multiplier |
|------------------------|------------|
| < 5 observations (cold start) | 1.0× (neutral) |
| < 1σ above mean | 0.7× (typical — score is dampened) |
| 1–2σ | 1.0× (normal range) |
| 2–3σ | 1.3× (elevated) |
| ≥ 3σ | 1.8× (anomalous) |

**New destination tracking:** Per process, MCP-FlowSentinel records the set of destination IPs it has contacted (bounded at 2000 entries). The first time a process connects to an IP it has never been seen contacting, a +1.5 behavioral signal fires — but only after the process has accumulated 5+ total connections (cold-start protection).

**Expected-beaconer suppression:** Legitimate processes (NTP clients, monitoring agents, chat apps) produce periodic connections that look like C2 beaconing. After a process triggers the beaconing signal 10+ times, MCP-FlowSentinel classifies it as an expected beaconer and suppresses the signal to avoid false-positive fatigue. Suppression is per-process-name and case-insensitive.

### Process context masking

MCP-FlowSentinel classifies the process making a connection and suppresses signals that are expected for that class, reducing false positives:

| Context | Examples | Suppressed signals |
|---------|----------|-------------------|
| Browser | chrome, firefox, msedge, safari | DoH (+0.5), QUIC (+1.5), DoH from non-browser |
| System service | svchost, systemd, chronyd, launchd | Beaconing scoring (heartbeat is expected) |
| Dev tool | node, python3, docker, go | NXDOMAIN threshold doubled (frequent in development) |

### Scoring signals

| Signal | Pts | Bucket | Notes |
|--------|-----|--------|-------|
| Known-bad port (4444, 1337, 31337, 6666–6669 …) | +4.0 | c2 | Metasploit defaults, back-connect shells, botnets |
| **JA3 TLS client fingerprint — known malware** | **+4.0** | c2 | Cobalt Strike, Meterpreter, Empire, Sliver, Dridex, TrickBot, Emotet … |
| **JA3S TLS server fingerprint — known C2** | **+3.5** | c2 | Identifies C2 infrastructure even when implant randomises its ClientHello |
| **IP reputation blocklist hit** | **+2.5** | c2 | Destination IP matched Feodo Tracker, Emerging Threats, or custom feed |
| **HASSH SSH client fingerprint — offensive library** | **+2.5** | c2 | Paramiko, AsyncSSH, libssh2 — common in credential-stuffing and lateral movement |
| Known-bad HTTP User-Agent (Cobalt Strike, Meterpreter …) | +3.0 | c2 | Default C2 profile fingerprints |
| Beaconing — strong (inter-packet CV < 0.15, ≥ 5 pkts) | +3.5 | behavioral | C2 heartbeat pattern |
| Port scan — confirmed (≥ 20 unique destinations) | +3.0 | behavioral | Active network scan |
| Beaconing — possible (CV < 0.30) | +2.0 | behavioral | Possible C2 heartbeat |
| Asymmetric upload (upload > 10× download) | +2.0 | behavioral | Data exfiltration indicator |
| Very high transfer rate (> 20 MB/s, > 2 MB total) | +1.0 | behavioral | Rapid exfiltration indicator |
| Long-lived connection (> 10 min with traffic) | +0.5 | behavioral | Persistent C2 keepalive |
| Large transfer (> 5 MB) | +0.5 | behavioral | Bulk exfiltration indicator |
| Port scan — possible (≥ 8 unique destinations) | +1.5 | behavioral | Possible scan activity |
| **TLS self-signed certificate** | **+2.0** | tls | Common on attacker-controlled C2 infrastructure |
| TLS expired certificate | +1.5 | tls | Misconfigured or attacker-controlled |
| TLS certificate lifetime > 10 years | +1.5 | tls | Self-generated attacker certificate |
| TLS certificate CN is an IP address | +1.0 | tls | Attacker-generated certificate |
| Missing TLS SAN | +0.5 | tls | Pre-2017 or self-generated certificate |
| High-entropy DNS label (entropy > 3.5 or label > 40 chars) | +2.5 | dns | DNS exfiltration / C2 tunneling |
| NXDOMAIN storm (≥ 5 NXDOMAIN per flow) | +2.0 | dns | DGA / C2-over-DNS |
| Low DNS TTL (< 30 s) | +1.5 | dns | Fast-flux / DGA domain |
| DNS-over-HTTPS from non-browser process | +0.5 | dns | Resolver bypass / DNS tunneling |
| Suspicious binary path (`/tmp`, `AppData\Local\Temp` …) | +2.5 | process | Classic implant staging location |
| Suspicious cmdline pattern (`base64 -d`, `curl\|sh`, `python -c` …) | +2.0 | process | One-liner attacker techniques |
| Unresolved binary path | +1.0 | process | Process hiding or rapid exit |
| Lateral movement to RFC1918 (SMB/RDP/WMI/LDAP/SSH) | +1.0–2.5 | network | Score depends on port: SMB/RDP=2.5, WinRM/WMI=2.0, LDAP=1.5, SSH=1.0 |
| HTTP CONNECT tunnel | +2.0 | network | Proxy-based C2 channel |
| Destination in high-risk ASN (bulletproof hosters) | +1.5 | network | Frantech, Serverius, QuadraNet … |
| QUIC from non-browser process | +1.5 | network | Encrypted UDP C2 channel |
| HTTP/2 on non-standard port | +1.5 | network | C2 over non-standard channel |
| HTTP on non-standard port | +1.5 | network | Potential covert channel |
| High-entropy HTTP URI | +1.5 | network | Encoded/obfuscated C2 commands |
| IPv6 Routing Header type 0 (deprecated, RFC 5095) | +1.5 | network | Source-routing evasion technique |
| Destination in high-risk ASN + QUIC | +1.0 | network | Encrypted UDP C2 channel |
| No reverse DNS on public IP | +0.8 | network | Direct IP connections |
| Missing TLS SNI on port 443 (> 3 pkts) | +0.7 | network | Stealthy TLS client |
| Non-standard port (< 49152, not in standard list) | +1.0 | network | Low-noise signal |
| IPv6 fragmentation | +0.5 | network | Potential JA3 evasion via fragmentation |
| **Domain reputation hit (URLhaus / ThreatFox)** | **+2.0** | dns | DNS query or TLS SNI matched a known-bad domain |
| **Slow-and-low C2 (≥ 3 capture windows)** | **+0.5–2.0** | behavioral | Same flow key recurs across multiple 5-min windows: 3–4=+0.5, 5–9=+1.0, 10–19=+1.5, ≥20=+2.0 |
| **First-seen destination for process** | **+1.5** | behavioral | Process connects to an IP it has never contacted before (confident after 5+ total connections) |

All signals can be individually disabled via `disable_*_scoring` config flags. Low-scoring flows include a `clean_signals` array explaining why they look benign (standard port, resolved hostname, country, TLS SNI).

**Risk tiers:**

| Score | Level |
|-------|-------|
| ≥ 7.0 | `CRITICAL` |
| ≥ 5.0 | `HIGH` |
| ≥ 2.0 | `MEDIUM` |
| < 2.0 | `LOW` |

---

## TLS fingerprinting

### JA3 (client fingerprint)

Every TLS `ClientHello` is fingerprinted using the [JA3 algorithm](https://github.com/salesforce/ja3): MD5 of TLS version, cipher suites, extensions, elliptic curves, and EC point formats — with GREASE values (RFC 8701) filtered. The `ja3_hash` field is always included for TLS flows.

If the hash matches the built-in table, the flow gets **+4.0 points** and `ja3_known_bad` names the family. Extend coverage with `extra_ja3_bad_hashes` in config or a live CSV feed.

| Family | Description |
|--------|-------------|
| Cobalt Strike (default profile) | Post-exploitation C2 framework |
| Metasploit Meterpreter | Reverse HTTPS stager |
| Empire / Sliver / Havoc / BruteRatel | Modern offensive frameworks |
| Dridex / TrickBot / Emotet | Banking trojans / loaders |
| AsyncRAT / njRAT / Raccoon / Redline | RATs and stealers |

### JA3S (server fingerprint)

Every TLS `ServerHello` received on ports 443/8443 is fingerprinted using the [JA3S algorithm](https://github.com/salesforce/ja3): MD5 of negotiated TLS version, selected cipher suite, and server extensions. Result is in `ja3s_hash`.

**Why it matters:** a C2 implant can randomise its `ClientHello` (defeating JA3), but the server response is determined by the server's TLS stack. JA3S identifies the C2 *server infrastructure*, independently of how the client connects.

If the hash matches a known C2 server profile, the flow gets **+3.5 points** and `ja3s_known_bad` names the family.

---

## SSH HASSH fingerprinting

Every SSH `SSH_MSG_KEXINIT` observed on port 22 is fingerprinted using the [HASSH algorithm](https://github.com/salesforce/hassh): MD5 of the key-exchange, encryption (client→server), MAC (client→server), and compression (client→server) algorithm lists. Result is in `hassh_hash`.

**Why it matters:** Python-based offensive tools (Paramiko, AsyncSSH, Twisted Conch) produce distinctive HASSH fingerprints that differ from OpenSSH, regardless of the SSH version banner. This detects scripted credential-stuffing, automated lateral movement, and C2-over-SSH tooling.

If the hash matches a known offensive library, the flow gets **+2.5 points** and `hassh_known_bad` names the library.

| Library | Why suspicious |
|---------|----------------|
| Paramiko (Python) | Most common Python SSH library in automated attacks, scanners, and red-team tooling |
| AsyncSSH (Python) | Async Python SSH, used in scripted attack frameworks |
| Twisted Conch (Python) | Python networking, used in exploit frameworks |
| libssh2 (C) | Used by Hydra, Medusa, and custom C implants |
| Dropbear SSH | Common on IoT botnet implants |

---

## TLS certificate analysis

For flows on ports 443/8443, MCP-FlowSentinel parses the `ServerCertificate` TLS handshake message and flags anomalies in the `tls_cert_*` fields:

| Field | Meaning |
|-------|---------|
| `tls_cert_self_signed` | Certificate is self-signed — common on attacker-controlled C2 infrastructure |
| `tls_cert_expired` | Certificate is past its `NotAfter` date |
| `tls_cert_valid_days` | Total validity window — >3650 days is anomalous |
| `tls_cert_cn` | Subject Common Name — useful for threat intel lookups |
| `tls_cert_has_san` | False = missing Subject Alternative Name (pre-2017 CA practice, or self-generated) |
| `tls_cert_ip_cn` | True = CN is an IP address rather than a hostname |

---

## TCP stream reassembly

TLS `ClientHello` messages can legally span multiple TCP segments (common on VPNs with reduced MTU, or C2 profiles that pad payloads). MCP-FlowSentinel uses `gopacket/tcpassembly` to reassemble fragmented streams before attempting SNI and JA3 extraction, ensuring no handshake is missed due to TCP segmentation.

---

## Protocol detection

Beyond standard flow metadata, MCP-FlowSentinel detects protocol usage in packet payloads:

| Protocol | Detection method | Fields set |
|----------|-----------------|------------|
| TLS (ClientHello) | Hand-rolled parser | `tls_sni`, `ja3_hash` |
| TLS (ServerHello) | Hand-rolled parser | `ja3s_hash` |
| TLS (ServerCertificate) | `crypto/x509` | `tls_cert_*` |
| SSH KEXINIT | RFC 4253 binary packet parser | `hassh_hash` |
| HTTP/1.1 | `net/http.ReadRequest` | `http_method`, `http_host`, `http_user_agent`, `http_uri` |
| HTTP/2 | 24-byte client preface (RFC 7540) | `is_http2` |
| gRPC | Length-Prefixed Message frames (≥ 2 consecutive) | `is_grpc` |
| QUIC v1 | Long-header bit + version field | `is_quic` |
| DNS | gopacket layers | `dns_queries`, `nxdomain_count`, `min_dns_ttl` |
| IPv6 Routing Header type 0 | gopacket layer | `is_ipv6_rh0` |
| IPv6 Fragment Header | gopacket layer | `is_ipv6_fragment` |

---

## Process correlation

MCP-FlowSentinel maps every captured flow to the process that owns it by reading the OS socket table (via `gopsutil`) and resolving each socket's PID to full process metadata. This runs at 2-second refresh intervals during live capture.

Each flow record includes:

| Field | Description |
|-------|-------------|
| `pid` | Process ID |
| `process_name` | Executable name |
| `binary_path` | Full path to the binary on disk |
| `cmdline` | Full command line |
| `parent_pid` / `parent_name` | Parent process (detects spawning by cmd.exe, powershell, etc.) |
| `username` | OS user account owning the process |
| `create_time_ms` | Process start time (epoch ms) |

The `scan_process` tool extends this with on-demand binary analysis: SHA-256 hash, suspicious-path detection, loaded modules (Linux), and optional VirusTotal lookup.

---

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

---

## Configuration

All thresholds, limits, and optional features can be tuned via a YAML config file.

### Generate a config file

```bash
mcp-flowsentinel --init-config
```

This writes a fully commented `~/.config/mcp-flowsentinel/config.yaml` with every option documented inline.

### Key config sections

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
  listen_addr: ":9200"
```

### Environment variable priority

| Variable | Overrides |
|----------|-----------|
| `FLOWSENTINEL_CONFIG` | Config file path |
| `GEOIP_CITY_DB` | `geoip.city_db` |
| `GEOIP_ASN_DB` | `geoip.asn_db` |
| `FLOWSENTINEL_WEBHOOK_URL` | `alerting.webhook_url` |

---

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

---

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

**Deduplication:** the same flow will not fire more than once per deduplication window (default: 5 min).

**Alert log:** every fired alert is persisted to `~/.cache/mcp-flowsentinel/alerts.jsonl`. Query it via `get_alerts`.

---

## Flow history

Every capture session automatically appends results to a rolling JSONL history at `~/.cache/mcp-flowsentinel/history.jsonl`.

```
"Show me all connections from the last 2 hours with a score above 5."
"Was curl.exe making any connections in the last hour?"
"Have I seen this IP before today?"
```

Default retention: 24 hours, 50 MB cap. With `compress_rotated: true`, entries older than today are automatically gzip-compressed into per-day `history_YYYY-MM-DD.jsonl.gz` files, and `Query` transparently includes them when the requested time window spans multiple days.

---

## CLI reference

| Command | Description |
|---------|-------------|
| `mcp-flowsentinel` | Start MCP server on stdio |
| `mcp-flowsentinel --daemon` | Continuous background monitoring + MCP server |
| `mcp-flowsentinel --check` | Verify pcap access, list interfaces, run smoke test |
| `mcp-flowsentinel --init-config` | Write default `config.yaml` |
| `mcp-flowsentinel --init-config /path` | Write default config to a custom path |
| `mcp-flowsentinel --config /path` | Load config from a specific path |
| `mcp-flowsentinel --validate-config` | Validate loaded config and print summary |
| `mcp-flowsentinel --test-alert` | Send a test webhook alert |
| `mcp-flowsentinel --update` | Self-update to the latest GitHub release |
| `mcp-flowsentinel --version` | Print version and exit |

---

## Build from source

### Windows
```powershell
.\build-windows.ps1
```

### Linux
```bash
chmod +x build-linux.sh && ./build-linux.sh
```

### macOS
```bash
chmod +x build-macos.sh && ./build-macos.sh
```

### Requirements
- Go 1.22+
- CGO enabled
- libpcap dev headers (`libpcap-dev` on Debian/Ubuntu, `libpcap` via Homebrew on macOS)
- Windows: [Npcap SDK](https://npcap.com/#download) + GCC (MinGW-w64)

---

## Architecture

```
main.go                             CLI entry point + MCP server bootstrap
internal/
  config/     config.go             YAML config + env var overrides (global singleton)
  capture/    capture.go            Live pcap capture loop + protocol parsers
              interfaces.go         NIC enumeration (cross-platform)
              reader.go             Offline pcap reader
              reassembly.go         TCP stream reassembly for fragmented TLS ClientHellos
              http.go               HTTP/1.1 + HTTP/2 preface + gRPC frame detection
              tls.go                TLS SNI extraction (hand-rolled ClientHello parser)
              tls_cert.go           TLS ServerCertificate parsing (crypto/x509)
              ssh.go                SSH HASSH fingerprinting (RFC 4253 KEXINIT parser)
              hassh_feed.go         Dynamic HASSH feed: static built-ins + URL/file feed + disk cache
  correlate/  correlate.go          Maps socket 4-tuples → processes (gopsutil)
  aggregate/  aggregate.go          Flow aggregation, categorical bounded scoring, process context, baseline multiplier
              filter.go             min_score / top_n filtering
  baseline/   baseline.go           Welford online stats per (process, port); anomaly multiplier; destination tracking; beaconing suppression; JSON persistence
  intel/      intel.go              GeoIP + high-risk ASN enrichment (MaxMind GeoLite2)
              iprep.go              IP reputation: exact-IP map + CIDR range scan; Feodo Tracker + ET feeds
              domrep.go             Domain reputation: URLhaus + ThreatFox feeds; exact + parent-domain match; disk-cached
              mitre.go              MITRE ATT&CK technique mapping
  ja3/        ja3.go                JA3 TLS client fingerprinting + known-bad hash lookup
              ja3s.go               JA3S TLS server fingerprinting + known-bad C2 server lookup
  history/    history.go            Rolling JSONL persistence + gzip daily rotation + RecurrenceMap for cross-window correlation
  alerting/   alerting.go           Webhook notifications with deduplication + HMAC signing
              store.go              Persistent alert log (JSONL) + GetAlerts query
  daemon/     daemon.go             Continuous background capture loop; baseline init; feed updater goroutines
  updater/    updater.go            Self-update from GitHub Releases
  cache/      lru.go                Generic bounded LRU cache (DNS PTR, GeoIP)
  tools/      register.go           MCP tool registration
              analyze_network.go    live capture tool
              analyze_pcap.go       offline analysis tool
              analyze_process.go    per-process deep-dive tool
              live_watch.go         targeted live capture tool
              scan_process.go       binary hash + VirusTotal scan tool
              get_flow_history.go   flow history query tool
              list_interfaces.go    interface listing tool
              process_map.go        process map tool
              get_config.go         runtime config inspection tool
              get_daemon_stats.go   daemon statistics tool
              get_alerts.go         alert log query tool
              reload_config.go      hot-reload config tool
```

**Data flow:**

```
Packet stream (libpcap)
  → capture.CapturePackets / OfflineReader
      ↳ DNS query/response extraction      (port 53)
      ↳ TLS ClientHello → SNI + JA3        (hand-rolled parser)
      ↳ TLS ServerHello → JA3S             (hand-rolled parser, ports 443/8443)
      ↳ TLS ServerCertificate → cert info  (crypto/x509, ports 443/8443)
      ↳ SSH KEXINIT → HASSH               (RFC 4253 parser, port 22)
      ↳ HTTP/1.1 headers                  (net/http.ReadRequest)
      ↳ HTTP/2 preface / gRPC frames      (fixed-pattern detection)
      ↳ QUIC v1 long-header              (bit + version field)
      ↳ IPv6 extension headers            (gopacket layers)
      ↳ TCP reassembler                   (fragmented ClientHello → SNI + JA3)
  → aggregate.Aggregator.Add             (accumulate into per-flow state)
  → correlate.SocketTable.Lookup         (map flow → process)
  → aggregate.Finalize
      ↳ Pass 1: build base FlowRecords
      ↳ Pass 2: parallel reverse-DNS           (configurable workers, LRU cache)
      ↳ Pass 2.5: GeoIP + JA3/JA3S/HASSH + IP reputation + domain reputation enrichment
      ↳ Pass 3: categorical bounded scoring (6 buckets, hard cap 10.0)
                + baseline anomaly multiplier (Welford online stats)
                + cross-window recurrence (slow-and-low C2, behavioral +0.5–2.0)
                + new-destination anomaly (behavioral +1.5)
                + domain reputation (+2.0 dns)
                + expected-beaconer suppression (per-process learning)
                + process context masking (browser/system/devtool)
                + MITRE mapping + clean signals
      ↳ Pass 4: cross-flow scan detection
  → history.Append                       (persist to rolling JSONL)
  → alerting.Fire                        (webhook POST for CRITICAL flows)
  → FlowRecord JSON (sorted by SuspicionScore desc)
```

---

## Npcap on Windows — FAQ

**Why can't you auto-install Npcap?**
Npcap's license prohibits silent/bundled redistribution. You must install it yourself — it's free and takes 2 minutes.

**Which option should I check during install?**
Check **"Install Npcap in WinPcap API-compatible Mode"**. Required for `gopacket`.

**Why does capture need Administrator on Windows?**
Windows requires elevated privileges to open raw sockets via Npcap.

**Is there a way without Admin?**
Not on Windows. On Linux use `cap_net_raw` (the installer sets this). On macOS, `chmod o+r /dev/bpf*` works but resets on reboot.

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started.

- [Open an issue](https://github.com/ClementG91/MCP-FlowSentinel/issues)
- [Start a discussion](https://github.com/ClementG91/MCP-FlowSentinel/discussions)
- [Submit a pull request](https://github.com/ClementG91/MCP-FlowSentinel/pulls)

---

## License

MIT — see [LICENSE](LICENSE).
