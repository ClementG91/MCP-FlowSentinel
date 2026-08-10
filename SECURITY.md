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

## Operational security

- Run the binary with only the packet-capture privileges required by your OS.
- Keep the Prometheus listener on loopback unless remote access is explicitly
  protected by a firewall or authenticated reverse proxy.
- Treat PCAP files, process command lines, webhook payloads, and flow history as
  sensitive data.
- Store webhook secrets, VirusTotal keys, and local configuration outside the
  repository.
- Review custom threat-feed and webhook URLs before enabling them.
