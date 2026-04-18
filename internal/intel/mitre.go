// Package intel — MITRE ATT&CK tagging.
// Maps detection reason strings to ATT&CK technique IDs so that AI clients
// can correlate alerts with the MITRE framework without doing their own lookup.
package intel

import "strings"

// MITRETechnique is a single ATT&CK entry attached to a flow.
type MITRETechnique struct {
	ID   string `json:"id"`   // e.g. "T1071.001"
	Name string `json:"name"` // e.g. "Application Layer Protocol: Web Protocols"
}

// mitreMapping maps a reason keyword (substring match) to the corresponding
// ATT&CK technique. Order matters: more specific entries should come first.
var mitreMapping = []struct {
	keyword   string
	technique MITRETechnique
}{
	// Beaconing / C2
	{"strong beaconing", MITRETechnique{"T1071.001", "Application Layer Protocol: Web Protocols"}},
	{"possible beaconing", MITRETechnique{"T1071.001", "Application Layer Protocol: Web Protocols"}},
	{"beaconing", MITRETechnique{"T1071.001", "Application Layer Protocol: Web Protocols"}},

	// DNS exfiltration
	{"dns exfil", MITRETechnique{"T1048.003", "Exfiltration Over Alternative Protocol: DNS"}},
	{"high-entropy dns", MITRETechnique{"T1048.003", "Exfiltration Over Alternative Protocol: DNS"}},
	{"dns label", MITRETechnique{"T1048.003", "Exfiltration Over Alternative Protocol: DNS"}},
	{"dns nxdomain storm", MITRETechnique{"T1568.002", "Dynamic Resolution: Domain Generation Algorithms"}},
	{"nxdomain", MITRETechnique{"T1568.002", "Dynamic Resolution: Domain Generation Algorithms"}},
	{"low dns ttl", MITRETechnique{"T1568.001", "Dynamic Resolution: Fast Flux DNS"}},
	{"ttl=0", MITRETechnique{"T1048.003", "Exfiltration Over Alternative Protocol: DNS"}},
	{"dns txt", MITRETechnique{"T1048.003", "Exfiltration Over Alternative Protocol: DNS"}},
	{"dns rebinding", MITRETechnique{"T1557", "Adversary-in-the-Middle"}},
	{"dns over non-standard port", MITRETechnique{"T1572", "Protocol Tunneling"}},

	// JA3 / TLS
	{"ja3 known-bad", MITRETechnique{"T1071.001", "Application Layer Protocol: Web Protocols"}},
	{"ja3", MITRETechnique{"T1071.001", "Application Layer Protocol: Web Protocols"}},
	{"self-signed", MITRETechnique{"T1573.001", "Encrypted Channel: Symmetric Cryptography"}},
	{"tls 1.0", MITRETechnique{"T1040", "Network Sniffing"}},
	{"tls 1.1", MITRETechnique{"T1040", "Network Sniffing"}},
	{"missing sni", MITRETechnique{"T1071.001", "Application Layer Protocol: Web Protocols"}},
	{"no sni", MITRETechnique{"T1071.001", "Application Layer Protocol: Web Protocols"}},
	{"non-tls", MITRETechnique{"T1572", "Protocol Tunneling"}},

	// Port / scan
	{"scan", MITRETechnique{"T1046", "Network Service Discovery"}},
	{"bad port", MITRETechnique{"T1571", "Non-Standard Port"}},
	{"non-standard port", MITRETechnique{"T1571", "Non-Standard Port"}},

	// Lateral movement
	{"smb", MITRETechnique{"T1021.002", "Remote Services: SMB/Windows Admin Shares"}},
	{"rdp", MITRETechnique{"T1021.001", "Remote Services: Remote Desktop Protocol"}},
	{"lateral ssh", MITRETechnique{"T1021.004", "Remote Services: SSH"}},
	{"wmi", MITRETechnique{"T1047", "Windows Management Instrumentation"}},
	{"ldap", MITRETechnique{"T1087.002", "Account Discovery: Domain Account"}},
	{"lateral", MITRETechnique{"T1021", "Remote Services"}},

	// Exfiltration
	{"asymmetric upload", MITRETechnique{"T1041", "Exfiltration Over C2 Channel"}},
	{"high transfer", MITRETechnique{"T1041", "Exfiltration Over C2 Channel"}},
	{"large upload", MITRETechnique{"T1041", "Exfiltration Over C2 Channel"}},

	// HTTP
	{"http connect", MITRETechnique{"T1572", "Protocol Tunneling"}},
	{"suspicious user-agent", MITRETechnique{"T1071.001", "Application Layer Protocol: Web Protocols"}},
	{"user-agent", MITRETechnique{"T1071.001", "Application Layer Protocol: Web Protocols"}},
	{"http on non-standard port", MITRETechnique{"T1571", "Non-Standard Port"}},

	// Process / binary
	{"suspicious path", MITRETechnique{"T1059", "Command and Scripting Interpreter"}},
	{"suspicious cmdline", MITRETechnique{"T1059", "Command and Scripting Interpreter"}},

	// Geo / infra
	{"geo high-risk", MITRETechnique{"T1090.003", "Proxy: Multi-hop Proxy"}},
	{"high-risk asn", MITRETechnique{"T1583", "Acquire Infrastructure"}},
	{"no reverse dns", MITRETechnique{"T1583", "Acquire Infrastructure"}},
	{"reverse dns", MITRETechnique{"T1583", "Acquire Infrastructure"}},

	// QUIC
	{"quic", MITRETechnique{"T1071.001", "Application Layer Protocol: Web Protocols"}},

	// DoH / DoT
	{"dns-over-https", MITRETechnique{"T1071.004", "Application Layer Protocol: DNS"}},
	{"dns-over-tls", MITRETechnique{"T1071.004", "Application Layer Protocol: DNS"}},

	// Reputation
	{"abuseipdb", MITRETechnique{"T1583", "Acquire Infrastructure"}},

	// Protocol anomaly
	{"protocol anomaly", MITRETechnique{"T1572", "Protocol Tunneling"}},
}

// TagFlow returns the deduplicated set of ATT&CK techniques that correspond
// to the supplied detection reasons. Reasons are matched case-insensitively
// using substring search against the keyword table above.
func TagFlow(reasons []string) []MITRETechnique {
	seen := make(map[string]struct{})
	var out []MITRETechnique

	for _, reason := range reasons {
		lower := strings.ToLower(reason)
		for _, m := range mitreMapping {
			if strings.Contains(lower, m.keyword) {
				if _, ok := seen[m.technique.ID]; !ok {
					seen[m.technique.ID] = struct{}{}
					out = append(out, m.technique)
				}
				break // first match per reason is enough
			}
		}
	}
	return out
}
