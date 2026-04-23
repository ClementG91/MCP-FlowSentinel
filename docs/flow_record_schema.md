# FlowRecord JSON Schema

Every flow emitted by MCP-FlowSentinel — whether from `scan_network`, `get_flow_history`, `live_watch`, or the webhook — uses the same `FlowRecord` JSON object. This document describes every field.

---

## Identification

| Field | Type | Always present | Description |
|---|---|---|---|
| `src_ip` | string | yes | Source IP address (IPv4 or IPv6) |
| `dst_ip` | string | yes | Destination IP address |
| `src_port` | integer | yes | Source port (0–65535) |
| `dst_port` | integer | yes | Destination port |
| `protocol` | string | yes | `"TCP"`, `"UDP"`, or `"ICMPv4"` / `"ICMPv6"` |

---

## Traffic volume

| Field | Type | Always present | Description |
|---|---|---|---|
| `packet_count` | integer | yes | Total packets observed in both directions |
| `byte_count` | integer | yes | Total payload bytes |
| `first_seen` | RFC 3339 timestamp | yes | Time of the first packet |
| `last_seen` | RFC 3339 timestamp | yes | Time of the most recent packet |
| `duration_ms` | integer | yes | `last_seen − first_seen` in milliseconds |

---

## Process attribution

Populated when the packet's four-tuple matches a socket in the local OS socket table. All fields omitted when no match is found.

| Field | Type | Description |
|---|---|---|
| `pid` | integer | Process ID of the socket owner |
| `process_name` | string | Process name (e.g. `"chrome"`, `"python3"`) |
| `binary_path` | string | Absolute path to the executable |
| `cmdline` | string | Full command line as a single string |
| `parent_pid` | integer | PID of the parent process |
| `parent_name` | string | Name of the parent process |
| `username` | string | OS user that owns the process |
| `create_time_ms` | integer | Process creation time (Unix ms) |

---

## Network intelligence

| Field | Type | Description |
|---|---|---|
| `reverse_dns` | string | PTR record for the remote IP (best-effort) |
| `country` | string | Two-letter ISO country code from GeoIP (e.g. `"RU"`, `"CN"`) |
| `asn_org` | string | ASN owner string from GeoIP (e.g. `"AS20473 Vultr Holdings LLC"`) |
| `geo_high_risk` | boolean | `true` when the country is in the configured high-risk country list |
| `tls_sni` | string | Server Name Indication from TLS ClientHello |
| `dns_queries` | string[] | Unique DNS question names observed for this flow |
| `ip_rep_label` | string | Blocklist label when the destination IP matches an IP reputation feed (e.g. `"feodo: C2 server"`, `"et: known attacker"`). Omitted when the IP is clean. |
| `dom_rep_label` | string | Feed label when a DNS query or TLS SNI matches a known-bad domain (e.g. `"urlhaus"`, `"threatfox"`). Omitted when no match. |

---

## TLS fingerprinting (JA3 / JA3S)

JA3 fingerprints the **TLS client** from the ClientHello; JA3S fingerprints the **TLS server** from the ServerHello. Both use MD5 and filter GREASE values (RFC 8701).

| Field | Type | Description |
|---|---|---|
| `ja3_hash` | string | 32-char MD5 hex of `"TLSVersion,Ciphers,Extensions,Curves,PointFormats"` |
| `ja3_known_bad` | string | Malware family if `ja3_hash` matches a known-bad fingerprint (e.g. `"Cobalt Strike (default profile)"`) |
| `ja3s_hash` | string | 32-char MD5 hex of `"TLSVersion,Cipher,Extensions"` from ServerHello |
| `ja3s_known_bad` | string | C2 server family if `ja3s_hash` matches a known-bad fingerprint (e.g. `"Sliver C2 (Go TLS server)"`) |

JA3S is extracted from **inbound** traffic on ports 443 and 8443. It is particularly effective for detecting C2 infrastructure because the server's TLS stack is harder to randomise than the client's.

---

## SSH HASSH fingerprinting

HASSH fingerprints the SSH **client library** from `SSH_MSG_KEXINIT`. It identifies offensive Python libraries (Paramiko, AsyncSSH, Twisted Conch) and C-based attack tools (libssh2, Dropbear) regardless of the banner they present.

Formula: `MD5("kex_algorithms;enc_c2s;mac_c2s;comp_c2s")`

| Field | Type | Description |
|---|---|---|
| `hassh_hash` | string | 32-char MD5 hex of the KEXINIT algorithm lists |
| `hassh_known_bad` | string | Offensive library name if `hassh_hash` matches a known fingerprint (e.g. `"Paramiko (Python SSH)"`) |

---

## TLS certificate anomalies

Extracted from the TLS `Certificate` handshake message (first certificate in the chain). All fields are omitted when no certificate was observed.

| Field | Type | Description |
|---|---|---|
| `tls_cert_self_signed` | boolean | `true` when issuer CN == subject CN |
| `tls_cert_expired` | boolean | `true` when `NotAfter < now` at capture time |
| `tls_cert_valid_days` | integer | Days until expiry (negative = already expired) |
| `tls_cert_cn` | string | Subject Common Name |
| `tls_cert_has_san` | boolean | `true` when at least one Subject Alternative Name extension is present |
| `tls_cert_ip_cn` | boolean | `true` when the CN is a raw IP address (e.g. `"192.168.1.1"`) |

---

## Protocol detection

Boolean flags set when the corresponding protocol signature is observed in the flow's payload. All default to `false` and are omitted from JSON when false.

| Field | Detected by | Notes |
|---|---|---|
| `is_quic` | QUIC Initial packet header (`0xC0`, QUIC long-header magic) | UDP/443 only |
| `is_http2` | HTTP/2 client preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) | Any port |
| `is_grpc` | gRPC Length-Prefixed Message frame (5-byte header, compressed flag = 0) | Any port |

---

## DNS analysis

Populated for flows carrying DNS traffic (UDP/TCP port 53).

| Field | Type | Description |
|---|---|---|
| `nxdomain_count` | integer | Number of NXDOMAIN responses in this flow |
| `min_dns_ttl` | integer | Lowest A/AAAA TTL seen in responses (seconds). `0` means no A/AAAA answers were observed. Very low values (1–10 s) indicate fast-flux or DGA domains. |

---

## HTTP/1.1 enrichment

Populated from the first HTTP/1.1 request observed in the flow. All fields omitted when no HTTP request was parsed.

| Field | Type | Description |
|---|---|---|
| `http_method` | string | HTTP verb: `"GET"`, `"POST"`, `"CONNECT"`, etc. |
| `http_host` | string | Value of the `Host:` header |
| `http_user_agent` | string | Value of the `User-Agent:` header |
| `http_uri` | string | Request-URI (path + query string) |

---

## IPv6 extension header anomalies

| Field | Type | Description |
|---|---|---|
| `is_ipv6_rh0` | boolean | IPv6 Routing Header type 0 (RH0) was present. RH0 was deprecated by RFC 5095 due to DoS amplification. Its presence is anomalous. |
| `is_ipv6_fragment` | boolean | An IPv6 Fragment Header was present in at least one packet |

---

## Risk scoring

| Field | Type | Always present | Description |
|---|---|---|---|
| `suspicion_score` | number | yes | Score in **[0, 10]**. Signals are grouped into six bounded buckets (c2, tls, behavioral, dns, process, network); the sum is scaled by a baseline anomaly multiplier and hard-capped at 10.0. Thresholds: `< 2.0` = low, `≥ 2.0` = medium, `≥ 5.0` = high, `≥ 7.0` = critical |
| `risk_level` | string | yes | `"low"`, `"medium"`, `"high"`, or `"critical"` |
| `suspicion_reasons` | string[] | when score > 0 | Human-readable explanation for each signal that contributed to the score |
| `clean_signals` | string[] | when present | Signals that were evaluated but found benign (reduces false-positive noise) |

### Scoring architecture

Signals are grouped into six independent buckets. Each bucket saturates at its cap; correlated signals within the same bucket cannot stack unboundedly. After summation, a **baseline anomaly multiplier** (0.7×–1.8×, based on Welford running stats per `(process, port)`) scales the total, which is then hard-capped at **10.0**.

| Bucket | Cap | Representative signals |
|--------|-----|------------------------|
| `c2` | 6.0 | JA3/JA3S/HASSH fingerprints, known-bad port, IP reputation, C2 User-Agent |
| `tls` | 3.5 | Self-signed, expired, long-lifetime, IP CN, missing SAN |
| `behavioral` | 4.0 | Beaconing, port scan, asymmetric upload, large transfer, high rate |
| `dns` | 3.0 | High-entropy label, NXDOMAIN storm, fast-flux TTL, DoH bypass |
| `process` | 3.5 | Suspicious path/cmdline, unresolved binary |
| `network` | 5.0 | High-risk ASN, geo, lateral movement, non-standard ports, CONNECT, IPv6 |

### Score signal reference

See `internal/aggregate/aggregate.go` for the authoritative list.

| Signal | Score | Bucket | Notes |
|---|---|---|---|
| Domain reputation hit (URLhaus / ThreatFox) | +2.0 | dns | `dom_rep_label` is set — DNS query or TLS SNI matched a known-bad domain |
| Slow-and-low C2 recurrence (≥ 3 windows) | +0.5–2.0 | behavioral | Same flow key observed in multiple 5-min capture windows: 3–4=+0.5, 5–9=+1.0, 10–19=+1.5, ≥20=+2.0 |
| First-seen destination for process | +1.5 | behavioral | Process contacts an IP it has never been seen connecting to (confident after 5+ total connections) |
| Known-bad JA3 (client) | +4.0 | c2 | `ja3_known_bad` is set |
| Known-bad port (4444, 1337, 31337, 6666–6669…) | +4.0 | c2 | Metasploit defaults, back-connect shells |
| Known-bad JA3S (server) | +3.5 | c2 | `ja3s_known_bad` is set |
| IP reputation blocklist hit | +2.5 | c2 | `ip_rep_label` is set (Feodo Tracker, Emerging Threats, custom feed) |
| Known-bad HASSH (SSH) | +2.5 | c2 | `hassh_known_bad` is set |
| Suspicious HTTP User-Agent | +3.0 | c2 | Default C2 profile User-Agent strings |
| Beaconing — strong (inter-packet CV < 0.15, ≥ 5 pkts) | +3.5 | behavioral | C2 heartbeat pattern |
| Port scan — confirmed (≥ 20 unique destinations) | +3.0 | behavioral | Active network scan |
| Beaconing — possible (CV < 0.30) | +2.0 | behavioral | Possible C2 heartbeat |
| Asymmetric upload (> 10× download) | +2.0 | behavioral | Cross-flow detection; requires bidirectional flows |
| Very high transfer rate (> 20 MB/s, > 2 MB) | +1.0 | behavioral | Rapid exfiltration indicator |
| Large transfer (> 5 MB) | +0.5 | behavioral | `byte_count` > 5 MB |
| Long-lived connection (> 10 min with traffic) | +0.5 | behavioral | Persistent C2 keepalive indicator |
| Port scan — possible (≥ 8 unique destinations) | +1.5 | behavioral | Possible scan activity |
| Self-signed TLS certificate | +2.0 | tls | `tls_cert_self_signed` = true |
| Expired TLS certificate | +1.5 | tls | `tls_cert_expired` = true |
| TLS certificate lifetime > 10 years | +1.5 | tls | `tls_cert_valid_days` > 3650 |
| TLS cert with IP as CN | +1.0 | tls | `tls_cert_ip_cn` = true |
| Missing TLS SAN | +0.5 | tls | `tls_cert_has_san` = false (and cert present) |
| High-entropy DNS label (entropy > 3.5 or label > 40 chars) | +2.5 | dns | `dns_queries` contains suspected DGA/exfil domain |
| NXDOMAIN storm (≥ 5 NXDOMAIN responses) | +2.0 | dns | `nxdomain_count` ≥ 5 |
| Low DNS TTL (< 30 s) | +1.5 | dns | `min_dns_ttl` > 0 and < 30 |
| DNS-over-HTTPS from non-browser | +0.5 | dns | DoH provider SNI from a non-browser process |
| Suspicious binary path (`/tmp`, AppData\Temp…) | +2.5 | process | `binary_path` matches known staging locations |
| Suspicious cmdline pattern | +2.0 | process | `cmdline` matches known attacker one-liners |
| Unresolved binary path | +1.0 | process | Process path could not be read (possible process hiding) |
| Lateral movement (RFC 1918 → RFC 1918) | +1.0–2.5 | network | Depends on port: SMB/RDP=2.5, WinRM/WMI=2.0, LDAP=1.5, SSH=1.0 |
| HTTP CONNECT tunnel | +2.0 | network | `http_method` = CONNECT |
| Destination in high-risk ASN | +1.5 | network | `asn_org` matches bulletproof hoster list |
| QUIC from non-browser process | +1.5 | network | `is_quic` = true and process is not a known browser |
| HTTP on non-standard port | +1.5 | network | HTTP request on port that is not 80/8080 |
| HTTP/2 on non-standard port | +1.5 | network | `is_http2` = true and port is not 443/8443 |
| High-entropy HTTP URI | +1.5 | network | `http_uri` entropy indicates encoded C2 commands |
| IPv6 RH0 present | +1.5 | network | `is_ipv6_rh0` = true |
| Non-standard port (< 49152, not in standard list) | +1.0 | network | Low-noise signal |
| QUIC to high-risk ASN | +1.0 | network | `is_quic` = true and `geo_high_risk` = true |
| No reverse DNS on public IP | +0.8 | network | `reverse_dns` is empty and `dst_ip` is a public IP |
| Missing TLS SNI on port 443 (> 3 pkts) | +0.7 | network | Stealthy or non-standard TLS client |
| IPv6 fragmentation | +0.5 | network | `is_ipv6_fragment` = true |

### Baseline anomaly multiplier

In daemon mode, each `(process_name, dst_port)` pair accumulates byte-count statistics using Welford's online algorithm. The multiplier applied to the raw categorical score is:

| Deviation from historical mean | Multiplier |
|-------------------------------|------------|
| < 5 observations (cold start) | 1.0× |
| < 1σ | 0.7× (typical traffic, score dampened) |
| 1–2σ | 1.0× |
| 2–3σ | 1.3× |
| ≥ 3σ | 1.8× |

The multiplier is applied per-flow; the result is hard-capped at 10.0.

### Destination tracking

Per process, MCP-FlowSentinel maintains the set of destination IPs it has ever contacted (bounded at 2 000 entries per process). The first connection to a new IP fires a **+1.5 behavioral** signal. Cold-start protection: signal is suppressed until the process has accumulated ≥ 5 total outbound connections.

### Expected-beaconer suppression

After a process triggers a beaconing signal ≥ 10 times, MCP-FlowSentinel classifies it as an expected beaconer and suppresses beaconing scoring for that process. This prevents false-positive fatigue for legitimate periodic processes (monitoring agents, NTP clients, chat apps). Suppression is per-process-name, case-insensitive, and persists across restarts via `baseline.json`.

---

## MITRE ATT&CK mapping

| Field | Type | Description |
|---|---|---|
| `mitre_techniques` | object[] | ATT&CK techniques inferred from `suspicion_reasons`. Each entry: `{"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols"}` |

---

## Daemon-mode metadata

| Field | Type | Description |
|---|---|---|
| `interface` | string | Capture interface name (e.g. `"eth0"`, `"en0"`). Omitted for PCAP analysis. |

---

## Minimal example

```json
{
  "src_ip": "10.0.0.42",
  "dst_ip": "185.220.101.47",
  "src_port": 54312,
  "dst_port": 443,
  "protocol": "TCP",
  "packet_count": 128,
  "byte_count": 87654,
  "first_seen": "2026-04-19T14:00:00Z",
  "last_seen": "2026-04-19T14:00:45Z",
  "duration_ms": 45000,
  "process_name": "python3",
  "binary_path": "/usr/bin/python3",
  "cmdline": "python3 implant.py --server 185.220.101.47",
  "pid": 8421,
  "country": "DE",
  "geo_high_risk": false,
  "tls_sni": "updates.example.com",
  "ja3_hash": "51c64c77e60f3980eea90869b68c58a8",
  "ja3_known_bad": "Cobalt Strike (default profile)",
  "ja3s_hash": "ae4edc6faf64d08308082ad26be60767",
  "ja3s_known_bad": "Cobalt Strike (default SSL server)",
  "tls_cert_self_signed": true,
  "tls_cert_valid_days": 7,
  "tls_cert_has_san": false,
  "suspicion_score": 10.0,
  "risk_level": "critical",
  "suspicion_reasons": [
    "JA3 client fingerprint matches known malware: Cobalt Strike (default profile) [51c64c77e60f3980eea90869b68c58a8]",
    "JA3S server fingerprint matches known C2 infrastructure: Cobalt Strike (default SSL server) [ae4edc6faf64d08308082ad26be60767]",
    "TLS certificate is self-signed",
    "TLS certificate expires in 7 days",
    "suspicious binary path: /tmp/implant.py",
    "suspicious cmdline pattern matched: implant.py"
  ],
  "mitre_techniques": [
    {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols"},
    {"id": "T1573.001", "name": "Encrypted Channel: Symmetric Cryptography"}
  ],
  "interface": "eth0"
}
```
