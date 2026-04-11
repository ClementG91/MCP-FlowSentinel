# MCP-FlowSentinel

> **Ask Claude: "What is making outbound connections right now?"**

MCP-FlowSentinel is a [Model Context Protocol](https://modelcontextprotocol.io/) server that gives Claude real-time visibility into your network traffic. It captures packets, maps every connection to the process that owns it, and scores each flow for suspiciousness — so you can ask Claude to investigate, explain, or alert on network activity in plain English.

![CI](https://github.com/ClementG91/MCP-FlowSentinel/actions/workflows/ci.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## What you can ask Claude

```
"List my network interfaces."
"Capture traffic on Wi-Fi for 30 seconds and show me anything suspicious."
"Which process is making the most outbound connections right now?"
"Analyze this pcap file and explain what it contains."
"Show me all connections with a suspicion score above 5."
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
> After install, **restart Claude Desktop as Administrator** (right-click → Run as administrator).

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

| Platform      | File |
|--------------|------|
| Windows x64  | `mcp-flowsentinel-windows-amd64.exe` |
| Linux x64    | `mcp-flowsentinel-linux-amd64` |
| Linux ARM64  | `mcp-flowsentinel-linux-arm64` |
| macOS Intel  | `mcp-flowsentinel-darwin-amd64` |
| macOS Apple Silicon | `mcp-flowsentinel-darwin-arm64` |

---

## Update

```
mcp-flowsentinel --update
```

Checks GitHub for a newer release and replaces the binary in-place.

---

## Claude Desktop configuration

The installer configures Claude Desktop automatically. If you need to do it manually, add this to your config file:

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Linux:** `~/.config/Claude/claude_desktop_config.json`

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

Restart Claude Desktop after editing the config.

---

## Tools

| Tool | Description |
|------|-------------|
| `list_interfaces` | List all pcap-visible network interfaces |
| `analyze_network` | Live capture on a named interface (default 30 s) |
| `analyze_pcap` | Analyze a saved `.pcap` / `.pcapng` file |
| `get_process_map` | Snapshot of all processes with open sockets |

All tools accept optional filters:
- `min_score` (0–10) — only return flows at or above this suspicion score
- `top_n` — return only the N highest-scoring flows

---

## Suspicion scoring

Each flow is scored 0–10 based on multiple signals:

| Signal | Points | Rationale |
|--------|--------|-----------|
| Known-bad port (4444, 1337, 31337, 6666 …) | +4.0 | Metasploit, back-connect shells, botnets |
| Non-standard port | +0.5 | Uncommon ports deserve attention |
| No reverse DNS | +0.8 | Unresolvable public IPs are suspicious |
| Suspicious binary path | +1.5 | `/tmp`, `AppData\Local\Temp`, etc. |
| Suspicious cmdline pattern | +1.0–2.0 | PowerShell encoded commands, `wget \|sh`, etc. |
| Beaconing (regular intervals) | +2.0–3.5 | C2 heartbeat pattern |
| Port scan pattern | +1.5–3.0 | Many unique destinations |
| Large transfer (> 10 MB) | +0.5 | Bulk exfil indicator |

**Risk tiers:**

| Score | Level |
|-------|-------|
| 7–10 | `CRITICAL` |
| 5–6.9 | `HIGH` |
| 2–4.9 | `MEDIUM` |
| 0–1.9 | `LOW` |

---

## Verify your install

```
mcp-flowsentinel --check
```

This confirms pcap access, lists your interfaces, and runs a 200 ms capture smoke test.

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
  capture/    capture.go         Live pcap capture (gopacket)
              interfaces.go      NIC enumeration (cross-platform)
              reader.go          PacketReader interface (live + offline)
  correlate/  correlate.go       Maps socket 4-tuples to processes (gopsutil)
  aggregate/  aggregate.go       Flow aggregation, beaconing detection, scoring
              filter.go          min_score / top_n filtering
  updater/    updater.go         Self-update from GitHub Releases
  tools/      register.go        MCP tool registration
              analyze_network.go live capture tool
              analyze_pcap.go    offline analysis tool
              list_interfaces.go interface listing tool
              process_map.go     process map tool
```

**Data flow:**

```
Packet stream (libpcap)
  → capture.CapturePackets / OfflineReader
  → aggregate.Aggregator.Add          (accumulate into flows)
  → correlate.SocketTable.Lookup      (map flow → process)
  → aggregate.Finalize                (score + reverse DNS)
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
