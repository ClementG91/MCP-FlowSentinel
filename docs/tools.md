# MCP tools

Every tool validates its arguments against a JSON Schema 2020-12 input schema with `additionalProperties: false`; unknown arguments are rejected. Results are returned as MCP structured content following [flow_record_schema.md](flow_record_schema.md).

## Tool list

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

## Tool details

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
