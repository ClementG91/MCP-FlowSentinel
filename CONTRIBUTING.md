# Contributing to MCP-FlowSentinel

Thanks for your interest! This project is community-driven and welcomes all kinds of contributions — bug reports, feature ideas, documentation improvements, and code.

---

## Ways to contribute

- **Report a bug** — [Open an issue](https://github.com/ClementG91/MCP-FlowSentinel/issues/new?template=bug_report.md)
- **Request a feature** — [Open an issue](https://github.com/ClementG91/MCP-FlowSentinel/issues/new?template=feature_request.md)
- **Fix a bug or add a feature** — Fork → branch → PR

Report suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

---

## Development setup

### Prerequisites

- Go 1.25.12+
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
go test -shuffle=on ./...
```

The unit suite uses synthetic packets and offline fixtures; it does not open a
live capture handle. Live packet capture still requires the OS privileges listed
in the README.

### Run all checks

```bash
go vet ./...
go test -race -shuffle=on ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.28.0 -quiet -exclude='G103,G104,G302,G304,G703' ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
```

The race detector requires CGO and is run on Linux and macOS in CI. Windows CI
runs the complete test suite without `-race`.

---

## Project structure

```
internal/
  aggregate/  Flow aggregation and bounded scoring engine
  alerting/   Webhook delivery, rate limiting, HMAC, and alert history
  baseline/   Persistent behavioral baselines
  capture/    Live/offline capture and protocol parsers
  config/     Strict YAML configuration and validation
  correlate/  Socket-to-process mapping
  daemon/     Continuous multi-interface monitoring
  history/    JSONL persistence, indexes, rotation, and compression
  intel/      GeoIP, IP/domain reputation, and MITRE mapping
  ja3/        JA3/JA3S fingerprints and dynamic feeds
  metrics/    Prometheus metrics and health endpoint
  tools/      MCP tool handlers
  updater/    Checksummed self-update with rollback
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

- [ ] Tests pass: `go test -race -shuffle=on ./...`
- [ ] No vet warnings: `go vet ./...`
- [ ] Code formatted: `gofmt -l .` returns nothing
- [ ] Static and vulnerability scans pass
- [ ] PR description explains what and why
- [ ] User-facing behavior and schema changes are documented

---

## Ideas for contributions

Looking for something to work on? Useful areas that remain open include:

| Area | Idea |
|------|------|
| **Detection** | Add validated protocol edge cases with synthetic or redistributable PCAP fixtures |
| **Testing** | Raise total coverage above the enforced 70% floor, especially on daemon and tool error paths |
| **Performance** | Add reproducible benchmarks for high packet rates and large history files |
| **Release** | Add artifact signing and provenance verification |
| **Docs** | Add a privacy-conscious walkthrough or demo capture |
| **Clients** | Validate and maintain configuration examples for additional MCP clients |
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
