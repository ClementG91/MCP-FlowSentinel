# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documentation

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

[Unreleased]: https://github.com/ClementG91/MCP-FlowSentinel/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ClementG91/MCP-FlowSentinel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ClementG91/MCP-FlowSentinel/releases/tag/v0.1.0
