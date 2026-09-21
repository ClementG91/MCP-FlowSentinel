# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-09-21

### Security

- Built with Go 1.27.1, the current Go release. Compiled dependencies are refreshed: `golang.org/x/crypto` v0.57.0, `golang.org/x/net` v0.59.0, `golang.org/x/sys` v0.48.0, `google.golang.org/grpc` v1.84.0 and `google.golang.org/protobuf` v1.36.12.
- Release notes now include the `gh attestation verify` command and the manual upgrade path for v0.2.0 installations.

### Changed

- CI tools upgraded: staticcheck v0.8.1 (needed for Go 1.27), govulncheck v1.8.0 and gosec v2.29.0. The gosec exclusion list is unchanged.

## [0.3.0] - 2026-09-21

### Security

- Built with Go 1.26.8 instead of 1.25.12: Go 1.25 no longer receives security fixes, and the move picks up standard-library fixes for GO-2026-6218 (`net/url`), GO-2026-6090 (`crypto/tls`), GO-2026-6089 and GO-2026-5026 (`net/http`), and GO-2026-5972 (`encoding/asn1`). `golang.org/x/crypto` v0.56.0 fixes GO-2026-6354 and GO-2026-6355.
- `--update` now verifies release authenticity, not just integrity: it requires the `attestation.sigstore.json` Sigstore bundle, checks it against the Sigstore public-good trust root, and only accepts SLSA provenance signed by this repository's `release.yml` for the exact release tag that lists the binary's SHA-256. Releases without a valid attestation are refused.
- Releases now publish their provenance bundle as the `attestation.sigstore.json` asset.
- Each capture window or PCAP analysis now tracks at most 250,000 distinct flows. Packets that would open a flow beyond that are dropped and logged once, so a port scan or spoofed-source flood cannot exhaust memory. Packets for flows already tracked are still counted.
- Remote JA3, HASSH, IP-reputation and domain-reputation feeds are read up to 128 MiB each.

### Fixed

- An empty or comment-only configuration file now loads the built-in defaults instead of failing with `parse config …: EOF`.

### Changed

- Upgraded `modelcontextprotocol/go-sdk` from v1.7.0 to v1.8.0.
- Pinned GitHub-hosted Ubuntu runners to `ubuntu-24.04` instead of `ubuntu-latest`.
- The daemon and command-line entry point expose test seams for capture, interface enumeration, the clock and external side effects; runtime behavior is unchanged.

### Tests

- Daemon capture windows, auto-selection, feed updaters and runtime statistics are exercised with offline PCAP replay (daemon coverage 14.6% → 86%).
- Every CLI command (`--help`, `--version`, `--update`, `--init-config`, `--validate-config`, `--test-alert`, `--check`, `--daemon`, stdio mode) and configuration error path is covered without live capture (main package coverage 9.9% → 90%+).
- CI enforces per-package coverage floors of 40% for the main package and 60% for `internal/daemon`, in addition to the 70% global minimum.

### Documentation

- Split the README: tool details moved to `docs/tools.md`, configuration, daemon mode, alerting, history and GeoIP to `docs/configuration.md`, and the detection engine and package layout to `docs/architecture.md`. The README keeps the overview, installation, client configuration, tool list and CLI reference.
- Replaced `CLAUDE.md`, which held personal tooling instructions, with project guidance for coding agents: package layout, per-OS build prerequisites, verification commands and conventions.
- Consolidated identical client and Unix installation examples into canonical blocks, removed redundant empty arguments, and corrected the Cline CLI guidance.
- Removed the redundant standalone Codex configuration snippet; the canonical TOML example remains in the README.
- Removed the retired Go Report Card badge after the upstream service shut down.

## [0.2.0] - 2026-08-10

### Added

- Codex, ChatGPT desktop, CLI, and IDE configuration with approval behavior driven by MCP tool annotations.
- MCP structured tool results, server instructions, human-readable tool titles, and explicit read-only, idempotent, open-world, and destructive-behavior hints.
- An end-to-end protocol test covering MCP `2026-07-28` negotiation, tool discovery, JSON Schema dialect, annotations, and invalid-input rejection.

### Changed

- Migrated from the third-party `mark3labs/mcp-go` package to the official `modelcontextprotocol/go-sdk` v1.7.0.
- Upgraded protocol support from MCP `2025-11-25` to `2026-07-28` while retaining automatic negotiation with older clients.
- Tool arguments now use JSON Schema 2020-12 with `additionalProperties: false` and server-side validation before handler execution.

### Security

- Reject non-IP `live_watch.target_ip` values before constructing the BPF filter, preventing filter-expression injection through that parameter.

### Documentation

- Updated the supported-version policy and added a direct private vulnerability-reporting link.
- Documented the July 2026 MCP changes, STDIO security boundary, backward compatibility, and Codex setup.

## [0.1.0] - 2026-08-10

### Added

- Cross-platform MCP server for live network capture, offline PCAP analysis, process correlation, flow history, alerting, and continuous monitoring.
- Explainable behavioral detection with bounded scoring, MITRE ATT&CK mapping, JA3/JA3S/HASSH fingerprints, reputation feeds, and adaptive baselines.
- Security-focused CI across Linux, macOS, and Windows with race tests, static analysis, vulnerability scanning, secret scanning, and OpenSSF Scorecard reporting.
- Cross-platform release assets for five OS/architecture targets with SHA-256 checksums, SPDX SBOM, and build provenance attestations.
- Installer scripts, self-update support, security policy, contribution guide, support policy, issue forms, and pull-request template.

### Security

- Hardened packet parsers, filesystem operations, remote feed handling, webhook delivery, configuration validation, and update rollback behavior.
- Reject malformed, unsupported, credential-bearing, and oversized webhook or threat-feed URLs before any outbound request.

[Unreleased]: https://github.com/ClementG91/MCP-FlowSentinel/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/ClementG91/MCP-FlowSentinel/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/ClementG91/MCP-FlowSentinel/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ClementG91/MCP-FlowSentinel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ClementG91/MCP-FlowSentinel/releases/tag/v0.1.0
