# Architecture and detection engine

How MCP-FlowSentinel captures traffic, attributes it to processes and scores it. For the output format, see [flow_record_schema.md](flow_record_schema.md).

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

## TCP stream reassembly

TLS `ClientHello` messages can legally span multiple TCP segments (common on VPNs with reduced MTU, or C2 profiles that pad payloads). MCP-FlowSentinel uses `gopacket/tcpassembly` to reassemble fragmented streams before attempting SNI and JA3 extraction, ensuring no handshake is missed due to TCP segmentation.

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

## Package layout

```
main.go                             CLI entry point (run) + MCP server bootstrap
privileges_{unix,windows}.go        Capture privilege checks for --check
internal/
  config/     config.go             YAML config + env var overrides (global singleton)
  capture/    capture.go            Live pcap capture loop + protocol parsers
              interfaces.go         NIC enumeration (cross-platform)
              reader.go             Offline pcap reader
              reassembly.go         TCP stream reassembly for fragmented TLS ClientHellos
              http.go               HTTP/1.1 + HTTP/2 preface + gRPC frame detection
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
              feed.go               Dynamic JA3 feed: static built-ins + URL/file feed
  history/    history.go            Rolling JSONL persistence + gzip daily rotation + RecurrenceMap for cross-window correlation
  alerting/   alerting.go           Webhook notifications with deduplication + HMAC signing
              store.go              Persistent alert log (JSONL) + GetAlerts query
  daemon/     daemon.go             Continuous background capture loop; baseline init; feed updater goroutines
  metrics/    metrics.go            Prometheus metrics and health endpoint
  updater/    updater.go            Self-update from GitHub Releases (SHA256SUMS.txt + atomic replace)
              provenance.go         Sigstore SLSA provenance verification of release assets
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
