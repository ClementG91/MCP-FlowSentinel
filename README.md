# MCP-FlowSentinel

> **Ask your AI assistant: "What is making outbound connections right now?"**

MCP-FlowSentinel is a [Model Context Protocol](https://modelcontextprotocol.io/) server that gives **any MCP-compatible AI assistant** real-time visibility into your network traffic. It captures packets, maps every connection to the process that owns it, and scores each flow for suspiciousness — so you can ask your AI to investigate, explain, or alert on network activity in plain English.

Works with **Claude Desktop, Cursor, Cline, Continue.dev, Zed, Windsurf**, and any other client that supports the MCP stdio transport.

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

Or edit `cline_mcp_settings.json` directly (path shown in the Cline MCP panel).

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

### Generic MCP client

MCP-FlowSentinel speaks the standard **MCP stdio transport** (newline-delimited JSON-RPC 2.0 on stdin/stdout). If your client supports stdio MCP servers, point it at the binary — no extra arguments needed.

The binary writes logs to **stderr** only; **stdout** is reserved for the MCP JSON-RPC stream.

---

## Tools

| Tool | Description |
|------|-------------|
| `list_interfaces` | List all pcap-visible network interfaces |
| `analyze_network` | Live capture on a named interface (default 5 s, max 60 s) |
| `analyze_pcap` | Analyze a saved `.pcap` / `.pcapng` file (max 1 GB) |
| `get_process_map` | Snapshot of all processes with open sockets |
| `get_flow_history` | Query the rolling 24-hour history of past capture sessions |
| `analyze_process` | Deep-dive on a specific process: open connections, parent chain, GeoIP, history |

`analyze_network` and `analyze_pcap` accept optional filters:
- `min_score` (0–10) — only return flows at or above this suspicion score
- `top_n` — return only the N highest-scoring flows
- `bpf_filter` — Berkeley Packet Filter expression (e.g. `tcp port 443`, `host 1.2.3.4`)

`get_flow_history` filters: `max_age_hours`, `min_score`, `src_ip`, `dst_ip`, `process_name`, `top_n`

`analyze_process` accepts `pid` and/or `process_name` (case-insensitive substring match).

---

## Suspicion scoring

Each flow is scored 0–10 based on multiple signals:

| Signal | Points | Rationale |
|--------|--------|-----------|
| Known-bad port (4444, 1337, 31337, 6666 …) | +4.0 | Metasploit, back-connect shells, botnets |
| Non-standard port (< 49152, not in allowlist) | +1.0 | Uncommon ports deserve attention |
| No reverse DNS on public IP | +0.8 | Direct IP connections bypass hostname filtering |
| High-entropy DNS subdomain (entropy > 3.5 or label > 40 chars) | +2.5 | DNS exfiltration / C2 over DNS |
| Destination in high-risk ASN (bulletproof hosters) | +1.5 | Known abuse-tolerant infrastructure |
| Suspicious binary path (`/tmp`, `AppData\Local\Temp` …) | +2.5 | Classic implant staging location |
| Unresolved binary path (PID known, path lookup failed) | +1.0 | Process hiding or rapid exit |
| Suspicious cmdline pattern (`base64 -d`, `curl\|sh`, `python -c` …) | +2.0 | One-liner attacker techniques |
| Beaconing — strong (interval CV < 0.15, min 5 packets) | +3.5 | C2 heartbeat pattern |
| Beaconing — possible (interval CV < 0.30, min 5 packets) | +2.0 | Possible C2 communication |
| Port scan — confirmed (≥ 20 unique destinations) | +3.0 | Active network scan |
| Port scan — possible (≥ 8 unique destinations) | +1.5 | Possible scan activity |
| Large transfer (> 5 MB) | +0.5 | Bulk exfiltration indicator |

Private/loopback/link-local IPs (RFC 1918, `127.x`, `169.254.x`, IPv6 private ranges) are never penalised for missing PTR records.

Low-scoring flows include a `clean_signals` array explaining why they look benign (standard port, resolved hostname, country, TLS SNI) — useful context for the AI.

**Risk tiers:**

| Score | Level |
|-------|-------|
| 7–10 | `CRITICAL` |
| 5–6.9 | `HIGH` |
| 2–4.9 | `MEDIUM` |
| 0–1.9 | `LOW` |

---

## GeoIP enrichment (optional)

Flows can be enriched with country code, ASN organisation, and high-risk ASN detection using the free [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) databases.

1. Sign up for a free MaxMind account and download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`.
2. Set the environment variables before starting your AI client:

```bash
export GEOIP_CITY_DB=/path/to/GeoLite2-City.mmdb
export GEOIP_ASN_DB=/path/to/GeoLite2-ASN.mmdb
```

On Windows (PowerShell):
```powershell
$env:GEOIP_CITY_DB = "C:\path\to\GeoLite2-City.mmdb"
$env:GEOIP_ASN_DB  = "C:\path\to\GeoLite2-ASN.mmdb"
```

When enabled, each flow response includes `country`, `asn_org`, and `geo_high_risk` fields. The `analyze_process` tool includes per-connection GeoIP data. Without these env vars the feature is silently disabled — the tool works fine without it.

---

## Flow history

Every `analyze_network` and `analyze_pcap` session automatically appends results to a rolling 24-hour JSONL history at `~/.cache/mcp-flowsentinel/history.jsonl`. Ask your AI:

```
"Show me all connections from the last 2 hours with a score above 5."
"Was curl.exe making any connections in the last hour?"
"Have I seen this IP before today?"
```

The history file is capped at 50 MB. Older entries are pruned automatically.

---

## Verify your install

```
mcp-flowsentinel --check
```

Confirms pcap access, lists your interfaces, and runs a 200 ms capture smoke test.

---

## Build from source

Only needed if you want to contribute or customize the binary.

### Windows
```powershell
.\build-windows.ps1
```
Automatically installs Go (via winget), GCC (WinLibs), and the Npcap SDK if missing.

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
- libpcap dev headers (`libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on Fedora, `libpcap` via Homebrew)
- Windows: [Npcap SDK](https://npcap.com/#download) + GCC (MinGW-w64)

---

## Architecture

```
main.go                          CLI: --version, --check, --update + MCP server bootstrap
internal/
  capture/    capture.go         Live pcap capture + DNS/TLS SNI extraction
              interfaces.go      NIC enumeration (cross-platform)
              reader.go          Offline pcap reader (shared drain loop)
  correlate/  correlate.go       Maps socket 4-tuples to processes (gopsutil)
  aggregate/  aggregate.go       Flow aggregation, scoring, beaconing, DNS exfil, clean signals
              filter.go          min_score / top_n filtering
  intel/      intel.go           GeoIP + threat-intel enrichment (MaxMind GeoLite2, cached)
  history/    history.go         Rolling 24 h JSONL persistence (~/.cache/mcp-flowsentinel/)
  updater/    updater.go         Self-update from GitHub Releases
  tools/      register.go        MCP tool registration
              analyze_network.go live capture tool
              analyze_pcap.go    offline analysis tool
              analyze_process.go per-process deep-dive tool
              get_flow_history.go flow history query tool
              list_interfaces.go interface listing tool
              process_map.go     process map tool
```

**Data flow:**

```
Packet stream (libpcap)
  → capture.CapturePackets / OfflineReader
      ↳ DNS query extraction (UDP/TCP port 53)
      ↳ TLS SNI extraction (TCP ClientHello raw parse)
  → aggregate.Aggregator.Add          (accumulate into flows, collect DNS/TLS sets)
  → correlate.SocketTable.Lookup      (map flow → process)
  → aggregate.Finalize
      ↳ Pass 1: build base FlowRecords
      ↳ Pass 2: parallel reverse-DNS (20 goroutines, 5 min TTL cache)
      ↳ Pass 2.5: GeoIP enrichment (intel.Lookup, sync.Map cache)
      ↳ Pass 3: per-flow scoring + clean signals
      ↳ Pass 4: cross-flow scan detection
  → history.Append                    (persist to rolling JSONL)
  → aggregate.FilterOptions.Apply     (min_score / top_n)
  → FlowRecord JSON (sorted by SuspicionScore desc)
```

---

## Npcap on Windows — FAQ

**Why can't you auto-install Npcap?**
Npcap's license prohibits silent/bundled redistribution. You must install it yourself. It's free, takes 2 minutes, and only needs to be done once.

**Which option should I check during install?**
Check **"Install Npcap in WinPcap API-compatible Mode"**. This is required for `gopacket` to find the library.

**Why does capture need Administrator on Windows?**
Windows requires elevated privileges to open raw sockets via Npcap. This is a Windows security restriction, not a limitation of this tool.

**Is there a way without Admin?**
Not on Windows. On Linux you can use `cap_net_raw` (the installer sets this automatically). On macOS, `chmod o+r /dev/bpf*` works but is reset on reboot.

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started.

Quick links:
- [Open an issue](https://github.com/ClementG91/MCP-FlowSentinel/issues)
- [Start a discussion](https://github.com/ClementG91/MCP-FlowSentinel/discussions)
- [Submit a pull request](https://github.com/ClementG91/MCP-FlowSentinel/pulls)

---

## License

MIT — see [LICENSE](LICENSE).
