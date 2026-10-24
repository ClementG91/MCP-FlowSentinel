---
name: flowsentinel
description: Investigate suspicious network activity with the MCP-FlowSentinel server. Use when the user asks which process is talking to the network, wants to capture or replay traffic, check beaconing or C2, scan a process binary, or explain a suspicion score. Requires the mcp-flowsentinel MCP server (stdio) and packet capture privileges.
---

# FlowSentinel network investigation

MCP-FlowSentinel captures packets locally, attributes each flow to the process that owns the socket, and scores flows with explainable behavioral signals. Scores are heuristics, not verdicts: always present the reasons and let the user decide.

## Prerequisites

- The `mcp-flowsentinel` server is registered in the MCP client (install: https://github.com/ClementG91/MCP-FlowSentinel).
- Live capture needs libpcap (Linux/macOS) or Npcap (Windows) and capture privileges. If a capture fails, ask the user to run `mcp-flowsentinel --check` and report its output.

## Workflow

1. **Pick the interface.** Call `list_interfaces` and choose the one carrying the traffic (ask if ambiguous). Never guess an interface name.
2. **Look at the sockets first (cheap).** `get_process_map` shows every process with open sockets, with no capture needed.
3. **Capture.** Use the narrowest tool that fits:
   - `analyze_network`: general capture (default 5 s, max 60 s). Pass `min_score` (e.g. 2) and `top_n` (e.g. 20) to keep output short.
   - `live_watch`: focus on one `process_name` and/or `target_ip` (at least one required).
   - `analyze_pcap`: replay a saved `.pcap`/`.pcapng` (max 1 GB). Use it for offline or incident data.
   - `get_flow_history`: look back at earlier sessions (`max_age_hours`, `process_name`, `src_ip`, `dst_ip`).
4. **Drill into a process.** `analyze_process` (connections, parent chain, GeoIP, history) and `scan_process` (binary SHA-256, location check, loaded modules on Linux, optional VirusTotal lookup).
5. **Explain.** For each flagged flow report `suspicion_score`, every entry of `suspicion_reasons`, the process (`process_name`, `binary_path`, `parent_name`), the destination (`dst_ip`, `country`, `asn_org`, `tls_sni`) and `mitre_techniques`.

## Reading scores

`suspicion_score` is in [0, 10]: below 2 low, 2 and above medium, 5 and above high, 7 and above critical. Unattributed flows (no `pid`) are common for short-lived sockets, NAT or containers; say so instead of treating them as malicious.

## Rules

- Start with a short capture (5-10 s) and widen only if needed. Filter with `min_score`/`top_n` rather than dumping raw flows.
- Encrypted payloads are never decrypted; conclusions rest on metadata, fingerprints (JA3/JA3S/HASSH), timing and process context. State this limit when relevant.
- Do not claim a host is compromised from one score. Recommend corroborating checks (`scan_process`, history, threat-feed labels such as `ip_rep_label`).
- `scan_process` sends only a SHA-256 hash to VirusTotal, and only if the user configured an API key. Never ask the user to paste a key into the chat.
- Capture files, command lines and webhook bodies can contain sensitive data: do not paste them into other tools or services.

## Example prompts

- "Capture Wi-Fi for 30 seconds and show anything suspicious."
- "Which process makes the most outbound connections right now?"
- "Is anything beaconing out of this machine?"
- "Scan chrome.exe: is the binary clean?"
- "Analyze this pcap and explain what it contains."
