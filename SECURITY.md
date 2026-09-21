# Security Policy

MCP-FlowSentinel processes privileged network telemetry and should be treated as
security-sensitive software. It is not a replacement for a firewall, EDR, IDS,
or professional incident-response tooling.

## Supported versions

Security fixes are applied to the latest `0.2.x` release and the latest commit
on `main`.

| Version | Supported |
|---------|-----------|
| `0.2.x` | Yes |
| `<= 0.1.x` | No |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use
[GitHub private vulnerability reporting](https://github.com/ClementG91/MCP-FlowSentinel/security/advisories/new)
so the report, proof of concept, logs, and affected versions remain private.

Please include:

- the affected commit or version;
- the operating system and architecture;
- clear reproduction steps;
- the expected impact and any suggested mitigation;
- only the minimum packet or log data needed to reproduce the issue, with
  credentials and personal data removed.

You should receive an acknowledgement within 72 hours and an initial assessment
within seven days. Timelines for a fix and coordinated disclosure depend on the
severity and complexity of the issue.

## Verifying releases

Every release is built by [`release.yml`](.github/workflows/release.yml) on a
`v*` tag. The workflow writes `SHA256SUMS.txt` and uses `actions/attest` to
publish a keyless Sigstore SLSA provenance attestation whose subjects are all
files listed in `SHA256SUMS.txt`. The attestation is recorded in the public Rekor
transparency log and published as the `attestation.sigstore.json` release asset.

A checksum file alone only proves integrity: anyone able to change the release
could change both the binary and its checksum. The attestation proves
authenticity because its Fulcio certificate is bound to the GitHub Actions OIDC
identity of the workflow run.

### Self-update (`--update`)

`mcp-flowsentinel --update` refuses to install a release unless all of the
following hold:

1. the release has `SHA256SUMS.txt` and `attestation.sigstore.json` assets;
2. the bundle verifies against the Sigstore public-good trust root, fetched and
   kept current through TUF, with an embedded SCT, a Rekor transparency-log
   entry and an observer timestamp;
3. the signing certificate was issued by
   `https://token.actions.githubusercontent.com` to exactly
   `https://github.com/ClementG91/MCP-FlowSentinel/.github/workflows/release.yml@refs/tags/<release tag>`,
   so a signature from another repository, workflow, branch or older tag is
   rejected;
4. the statement is SLSA provenance v1 and lists the platform binary under its
   asset name with the same SHA-256 as `SHA256SUMS.txt`;
5. the downloaded binary matches that SHA-256.

Releases up to and including `v0.2.0` do not ship `attestation.sigstore.json`,
and binaries up to `v0.2.0` do not perform this check. Update those
installations manually with the procedure below.

### Manual verification

With the [GitHub CLI](https://cli.github.com/):

```bash
gh attestation verify mcp-flowsentinel-linux-amd64 \
  --repo ClementG91/MCP-FlowSentinel \
  --signer-workflow ClementG91/MCP-FlowSentinel/.github/workflows/release.yml \
  --source-ref refs/tags/v0.3.0
sha256sum --check --ignore-missing SHA256SUMS.txt
```

Replace the asset name and tag with the ones you downloaded. The bundle is also
available offline as the `attestation.sigstore.json` release asset
(`gh attestation verify ... --bundle attestation.sigstore.json`).

## Operational security

- Run the binary with only the packet-capture privileges required by your OS.
- Keep the Prometheus listener on loopback unless remote access is explicitly
  protected by a firewall or authenticated reverse proxy.
- Treat PCAP files, process command lines, webhook payloads, and flow history as
  sensitive data.
- Store webhook secrets, VirusTotal keys, and local configuration outside the
  repository.
- Review custom threat-feed and webhook URLs before enabling them.
