# Contributing to MCP-FlowSentinel

Thanks for your interest! This project is community-driven and welcomes all kinds of contributions — bug reports, feature ideas, documentation improvements, and code.

---

## Ways to contribute

- **Report a bug** — [Open an issue](https://github.com/ClementG91/MCP-FlowSentinel/issues/new?template=bug_report.md)
- **Request a feature** — [Open an issue](https://github.com/ClementG91/MCP-FlowSentinel/issues/new?template=feature_request.md)
- **Ask a question** — [Start a discussion](https://github.com/ClementG91/MCP-FlowSentinel/discussions)
- **Fix a bug or add a feature** — Fork → branch → PR

---

## Development setup

### Prerequisites

- Go 1.22+
- libpcap dev headers (see [README.md](README.md) for platform-specific instructions)
- For Windows: Npcap SDK + GCC (run `build-windows.ps1` to auto-install)

### Clone and build

```bash
git clone https://github.com/ClementG91/MCP-FlowSentinel.git
cd MCP-FlowSentinel

# Linux
chmod +x build-linux.sh && ./build-linux.sh

# macOS
chmod +x build-macos.sh && ./build-macos.sh

# Windows (PowerShell, right-click -> Run as administrator)
.\build-windows.ps1
```

### Run tests

```bash
go test -v ./internal/aggregate/... ./internal/correlate/...
```

Tests in `internal/capture/` require root/admin and are skipped in CI.

### Run all checks

```bash
go vet ./...
go test ./internal/aggregate/... ./internal/correlate/...
```

---

## Project structure

```
internal/
  capture/    Packet capture and NIC enumeration (gopacket/libpcap)
  correlate/  Socket → process mapping (gopsutil)
  aggregate/  Flow aggregation, beaconing detection, scoring engine
  updater/    Self-update from GitHub Releases
  tools/      MCP tool handlers (these are what the AI client calls)
```

If you want to add a new MCP tool, look at `internal/tools/list_interfaces.go` as the simplest example, then register it in `internal/tools/register.go`.

---

## MCP client compatibility

This server uses the **stdio transport** and is compatible with any MCP client — not just Claude Desktop. When writing or testing tools, ensure they work generically: avoid Claude-specific assumptions in tool descriptions or output format. See [README.md](README.md) for the full list of supported clients.

---

## Code style

- Standard `gofmt` / `goimports` formatting — no exceptions
- Errors wrapped with `fmt.Errorf("context: %w", err)`
- New packages need at least basic table-driven tests
- Functions under 50 lines where practical
- No external dependencies without discussion first

---

## Pull request checklist

- [ ] Tests pass: `go test ./internal/aggregate/... ./internal/correlate/...`
- [ ] No vet warnings: `go vet ./...`
- [ ] Code formatted: `gofmt -l .` returns nothing
- [ ] PR description explains what and why

---

## Ideas for contributions

Looking for something to work on? Here are some ideas:

| Area | Idea |
|------|------|
| **Scoring** | GeoIP scoring — flag connections to high-risk countries (MaxMind GeoLite2) |
| **Scoring** | DNS tunneling / exfiltration detection (high-entropy subdomains) |
| **Scoring** | TLS fingerprinting — extract SNI and JA3 hash from ClientHello |
| **Scoring** | Process ancestry chain — suspicious parent→child spawning patterns |
| **Tools** | `get_flow_history` — query a rolling 24 h flow database |
| **Tools** | `analyze_process` — deep dive on a single PID's network activity |
| **Tools** | `alert_on_score` — watch and notify when a flow exceeds a threshold |
| **Output** | CSV / NDJSON export format |
| **Output** | `clean_signals` field explaining why a flow scored 0 |
| **Tests** | Unit tests for MCP tool handlers (mock MCP context) |
| **Tests** | Capture tests using pre-recorded pcap fixtures |
| **Docs** | Video walkthrough / demo GIF for README |
| **Clients** | Config snippets for additional MCP clients |
| **Platform** | Windows ARM64 native binary support |

---

## Commit messages

```
feat: add GeoIP scoring heuristic
fix: handle empty process cmdline on macOS
docs: add Cursor MCP configuration snippet
test: add beaconing edge case for single-packet flows
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`

---

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
