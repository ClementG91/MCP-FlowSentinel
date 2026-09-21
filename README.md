# MCP-FlowSentinel

> **Ask your AI assistant: "What is making outbound connections right now — and is any of it suspicious?"**

MCP-FlowSentinel is a [Model Context Protocol](https://modelcontextprotocol.io/) server that gives **any MCP-compatible AI assistant** real-time visibility into your network traffic. It captures packets, maps every connection to the owning process, and runs 30+ detection signals — so you can ask your AI to investigate, explain, or alert on network activity in plain English.

Works with **Codex, ChatGPT desktop, Claude Desktop, Cursor, Cline, Continue.dev, Zed, Windsurf**, and any other client that supports the MCP stdio transport.

> **Security status:** packet parsers and scoring paths are covered by unit, race,
> fuzz-seed, static-analysis, and vulnerability checks. The project has not yet
> undergone a formal third-party security audit and should complement—not
> replace—an EDR, firewall, IDS, or professional incident-response workflow.

[![CI](https://github.com/ClementG91/MCP-FlowSentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/ClementG91/MCP-FlowSentinel/actions/workflows/ci.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/ClementG91/MCP-FlowSentinel?logo=go)](go.mod)
[![MCP 2026-07-28](https://img.shields.io/badge/MCP-2026--07--28-6f42c1)](https://modelcontextprotocol.io/specification/2026-07-28)
[![Release](https://img.shields.io/github/v/release/ClementG91/MCP-FlowSentinel?sort=semver)](https://github.com/ClementG91/MCP-FlowSentinel/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ClementG91/MCP-FlowSentinel/badge)](https://scorecard.dev/viewer/?uri=github.com/ClementG91/MCP-FlowSentinel)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security policy](https://img.shields.io/badge/security-policy-blue.svg)](SECURITY.md)

## Why FlowSentinel

- **Local-first:** packet inspection and behavioral scoring run on your machine; encrypted payloads are never decrypted.
- **Process-aware:** flows are correlated with the executable and process that owns each socket.
- **Explainable detection:** 30+ bounded signals expose their reasons and mapped MITRE ATT&CK techniques instead of returning an opaque verdict.
- **MCP-native:** the official Go SDK supports MCP `2026-07-28`, negotiates older revisions, and returns native structured tool results.
- **Defense in depth:** race tests, static analysis, vulnerability scanning, pinned CI actions, release checksums, SBOMs, and build provenance protect the delivery chain.

## MCP protocol compatibility

FlowSentinel uses the official `modelcontextprotocol/go-sdk` and supports the
MCP `2026-07-28` specification over STDIO. This includes `server/discover`,
per-request protocol metadata, deterministic tool discovery, JSON Schema
2020-12 input validation, server instructions, and tool behavior annotations.
The SDK also negotiates `2025-11-25`, `2025-06-18`, `2025-03-26`, and
`2024-11-05` with older clients.

FlowSentinel does not expose a remote Streamable HTTP endpoint, so the new HTTP
routing headers and OAuth requirements are intentionally outside its attack
surface. It does not use the deprecated roots, sampling, or protocol logging
features.

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

## Install

The installers below download the latest published GitHub release and verify its
SHA-256 checksum before replacing an existing binary. They require at least one
entry on the [Releases page](https://github.com/ClementG91/MCP-FlowSentinel/releases).
If no release is available yet, use [Build from source](#build-from-source).

### Prebuilt release (no Go required)

#### Windows

```powershell
irm https://raw.githubusercontent.com/ClementG91/MCP-FlowSentinel/main/install.ps1 | iex
```

> **Prerequisite — Npcap** (packet capture driver, free for personal use):
> 1. Download from **[npcap.com/#download](https://npcap.com/#download)**
> 2. Run the installer — check **"Install Npcap in WinPcap API-compatible Mode"**
> 3. Then run the one-liner above
>
> The MCP server process must run with **Administrator** privileges for packet capture to work.

#### Linux and macOS

```bash
curl -fsSL https://raw.githubusercontent.com/ClementG91/MCP-FlowSentinel/main/install.sh | bash
```

- **Linux:** the script installs `libpcap` through the detected package manager
  and grants `cap_net_raw`, so routine capture does not require root.
- **macOS:** [Homebrew](https://brew.sh) is required; the script installs
  `libpcap` automatically.

#### Manual download

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

Self-update is available only when a release exists. Before downloading, the
updater verifies the release's Sigstore provenance attestation: it must be
signed by this repository's `release.yml` workflow for the exact release tag and
list the platform binary with the digest published in `SHA256SUMS.txt`. Updates
without a valid attestation are refused. The previous binary is restored if
replacement fails. See [SECURITY.md](SECURITY.md#verifying-releases).

---

## Client configuration

MCP-FlowSentinel uses the **stdio transport** — the binary is launched as a subprocess by your AI client. Each client uses its own configuration syntax.

> **Windows note:** the binary must run as Administrator for packet capture. See your client's docs for how to launch MCP servers with elevated privileges, or pre-elevate the terminal that starts your client.

### Codex and ChatGPT desktop

Codex CLI, the Codex IDE extension, and ChatGPT desktop share the MCP
configuration stored in `~/.codex/config.toml`. After installing FlowSentinel,
the shortest setup is:

```bash
codex mcp add flowsentinel -- mcp-flowsentinel
codex mcp list
```

Alternatively, merge the following into `~/.codex/config.toml` or a trusted
project's `.codex/config.toml`:

```toml
[mcp_servers.flowsentinel]
command = "mcp-flowsentinel"
enabled = true
startup_timeout_sec = 15
tool_timeout_sec = 90
default_tools_approval_mode = "writes"
```

The `writes` approval mode uses FlowSentinel's MCP tool annotations: read-only
inspection tools can run normally, while live captures, PCAP analysis, history
writes, and configuration reloads request approval. Use `/mcp` in Codex or
ChatGPT desktop to verify the connection. If the binary is not on `PATH`, set
`command` to its absolute path.

See the [official OpenAI MCP documentation](https://developers.openai.com/codex/mcp)
for the CLI, desktop, IDE, and advanced tool-policy options.

### Shared JSON clients

Claude Desktop, Cursor, Cline project configurations, and Windsurf use the same
`mcpServers` object. Merge this block without overwriting unrelated servers:

| Client | Where to configure |
|--------|--------------------|
| Claude Desktop | Windows: `%APPDATA%\Claude\claude_desktop_config.json`<br>macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`<br>Linux: `~/.config/Claude/claude_desktop_config.json` |
| Cursor | Global: `~/.cursor/mcp.json`<br>Project: `.cursor/mcp.json` |
| Cline | IDE: **MCP Servers → Configure MCP Servers**<br>Project: `.cline/mcp.json`<br>CLI: `cline mcp` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

```json
{
  "mcpServers": {
    "flowsentinel": {
      "command": "/absolute/path/to/mcp-flowsentinel"
    }
  }
}
```

Save the file, then restart or reload the client.

### Continue.dev

**Config file:** `~/.continue/config.yaml`

```yaml
name: Local configuration
version: 1.0.0
schema: v1

mcpServers:
  - name: flowsentinel
    command: /absolute/path/to/mcp-flowsentinel
```

### Zed

Open **Settings → AI → MCP Servers → Add Local Server**, name it
`flowsentinel`, and select the absolute path to the binary as its command. Zed
writes the corresponding `context_servers` entry to `settings.json`.

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

Inputs, filters and outputs of each tool: [docs/tools.md](docs/tools.md).

---

## Configuration

All thresholds, limits, and optional features are set in a YAML file:

```bash
mcp-flowsentinel --init-config
```

This writes a fully commented `~/.config/mcp-flowsentinel/config.yaml`. Daemon
mode (`--daemon`), webhook alerting, flow history, threat feeds, GeoIP and
environment variable overrides are described in
[docs/configuration.md](docs/configuration.md).

---

## Documentation

| Document | Contents |
|----------|----------|
| [docs/tools.md](docs/tools.md) | Tool inputs, filters and outputs |
| [docs/configuration.md](docs/configuration.md) | Config file, daemon mode, alerting, history, GeoIP |
| [docs/architecture.md](docs/architecture.md) | Detection engine, scoring signals, fingerprinting, package layout |
| [docs/flow_record_schema.md](docs/flow_record_schema.md) | `FlowRecord` output schema |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting and release verification |

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
- Go 1.26.8+
- CGO enabled
- libpcap dev headers (`libpcap-dev` on Debian/Ubuntu, `libpcap` via Homebrew on macOS)
- Windows: [Npcap SDK](https://npcap.com/#download) + GCC (MinGW-w64)

---

## Limitations and data handling

- Encrypted TLS, SSH, QUIC, and HTTPS payloads are not decrypted. Detection uses
  observable metadata, protocol handshakes, fingerprints, timing, and process
  context.
- JA3, JA3S, and HASSH use protocol-defined MD5 fingerprints for compatibility;
  MD5 is not used for passwords, signatures, or integrity protection. Custom or
  randomized fingerprints can evade matching.
- Process attribution is best-effort. Short-lived sockets, privileged processes,
  NAT, containers, and OS timing can leave a flow unattributed.
- Detection scores are heuristics, not verdicts. Tune exemptions and thresholds
  for your environment and investigate high scores before taking action.
- PCAPs, process command lines, history files, and webhook bodies may contain
  sensitive operational data. Protect them accordingly.
- Threat feeds and VirusTotal are opt-in. VirusTotal lookup sends a binary's
  SHA-256 hash, not the binary itself.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and deployment
guidance.

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

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for the community standards.

- [Open an issue](https://github.com/ClementG91/MCP-FlowSentinel/issues)
- [Submit a pull request](https://github.com/ClementG91/MCP-FlowSentinel/pulls)
- [Get support](SUPPORT.md)
- [Review the changelog](CHANGELOG.md)

---

## License

MIT — see [LICENSE](LICENSE).
