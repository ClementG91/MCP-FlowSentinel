# CLAUDE.md

Guidance for AI coding agents working in this repository.

MCP-FlowSentinel is a Go 1.27 MCP server (stdio transport, official
`modelcontextprotocol/go-sdk`) that captures packets with libpcap/Npcap,
attributes flows to local processes and scores them with behavioral detection
signals. The public GitHub repository `ClementG91/MCP-FlowSentinel` is the
source of truth.

## Package layout

| Path | Responsibility |
|------|----------------|
| `main.go` | CLI (`run(args, stdout, stderr) int`), MCP server bootstrap, `--check` / `--test-alert` / `--daemon` |
| `privileges_{unix,windows}.go` | Capture privilege checks used by `--check` |
| `internal/config` | YAML config, env overrides, validation, global singleton (`Get`/`Set`/`Load`) |
| `internal/capture` | Live capture (`CapturePackets`), offline `OfflineReader` (pure-Go pcap/pcapng), protocol parsers, TCP reassembly, HASSH |
| `internal/correlate` | Socket 4-tuple → process mapping (gopsutil) with a process cache |
| `internal/aggregate` | Flow aggregation, scoring, filters (`min_score`, `top_n`) |
| `internal/baseline` | Per-process statistical baseline and persistence |
| `internal/intel` | GeoIP, IP and domain reputation feeds, MITRE mapping |
| `internal/ja3` | JA3/JA3S fingerprints and feed |
| `internal/history` | Rolling JSONL flow history with gzip rotation |
| `internal/alerting` | Webhook alerts (dedup, HMAC) and alert log |
| `internal/daemon` | Continuous capture windows and feed updaters |
| `internal/metrics` | Prometheus endpoint |
| `internal/tools` | One file per MCP tool, registered in `register.go` |
| `internal/updater` | `--update`: SHA256SUMS + Sigstore provenance verification, atomic replace |
| `internal/cache` | Generic bounded LRU |

Details: [docs/architecture.md](docs/architecture.md). Output contract:
[docs/flow_record_schema.md](docs/flow_record_schema.md).

## Build

CGO is required (gopacket/pcap).

- **Linux:** `sudo apt-get install libpcap-dev` (Fedora: `libpcap-devel`), then `go build ./...` or `./build-linux.sh`.
- **macOS:** `brew install libpcap`, then `go build ./...` or `./build-macos.sh`.
- **Windows:** install the Npcap runtime (WinPcap API-compatible mode) and the
  [Npcap SDK](https://npcap.com/#download) (e.g. `C:\npcap-sdk`), then
  `.\build-windows.ps1`, or set
  `CGO_CFLAGS=-IC:\npcap-sdk\Include` and `CGO_LDFLAGS=-LC:\npcap-sdk\Lib\x64` before `go build ./...`.
  Offline tests do not need the Npcap runtime.

## Verification (must pass before every PR)

```bash
go mod tidy -diff && gofmt -l . && go vet ./... && go test -race -shuffle=on ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 -quiet -exclude='G103,G104,G302,G304,G703' ./...
```

CI also enforces 70% total coverage and per-package floors (main 40%,
`internal/daemon` 60%).

## Conventions

- Work on a branch and open a PR; never push to `main`. Squash or rebase merges only (linear history).
- Conventional Commits: `feat:`, `fix:`, `test:`, `docs:`, `chore:`.
- Update `CHANGELOG.md` under `[Unreleased]` for user-visible changes.
- Tests must never open a live interface (`pcap.OpenLive`). Replay generated
  PCAPs through `capture.OfflineReader` and use the package-level seams in
  `main.go` and `internal/daemon` (`capturePackets`, `listInterfaces`, `now`, …).
  Isolate globals with `config.Set`, `history.SetPathForTesting` and
  `alerting.SetAlertLogPathForTesting`.
- Do not weaken CI: no new gosec exclusions, govulncheck stays blocking.
- Detection behavior and `docs/flow_record_schema.md` are a public contract;
  flag any change to scoring or the schema explicitly in the PR.
- stdout is reserved for MCP JSON-RPC in server modes; log to stderr.
- Pin GitHub Actions by commit SHA and runners by version (`ubuntu-24.04`).
- Outbound URLs from config must go through `config.ValidateHTTPURL`.
