// SSH HASSH fingerprinting.
//
// HASSH fingerprints SSH clients based on the algorithms they advertise in
// the SSH_MSG_KEXINIT message: key-exchange, encryption (c→s), MAC (c→s),
// and compression (c→s). This identifies the underlying SSH library regardless
// of version banners, and is particularly effective for detecting scripted /
// offensive Python SSH libraries (Paramiko, AsyncSSH, Twisted Conch).
//
// Formula: MD5("kex_algorithms;enc_c2s;mac_c2s;comp_c2s")
// Reference: https://github.com/salesforce/hassh
package capture

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// knownBadHasshHashes maps HASSH fingerprints of known offensive SSH libraries
// to their identifying description.
// Sources: salesforce/hassh repository, abuse.ch, threat intelligence reports.
var knownBadHasshHashes = map[string]string{
	// Paramiko (Python) — the most common SSH library in offensive Python tooling,
	// automated credential-stuffing, and vulnerability scanners.
	"b307ecfe3313e6a04c58bfdd13d91d4f": "Paramiko (Python SSH)",
	"aaabb9370e4a47cc5e1b28f977804e43": "Paramiko (legacy version)",
	// AsyncSSH (Python async SSH library, used in automated attack scripts)
	"3a3e20f79a67c89d97bfe68a4f4fb12c": "AsyncSSH (Python)",
	// Twisted Conch (Python async networking)
	"418aa6a4a45e9bf44cc53fbe75e29649": "Twisted Conch (Python SSH)",
	// libssh2 default configuration — used by numerous scripted scanners
	// and C-based attack tools (Hydra, Medusa, libssh2-based implants)
	"5cc135b601c61e58a16cd7a15eebcb3f": "libssh2 (C scanner/implant)",
	// Dropbear SSH client (common on embedded/IoT botnet implants)
	"92674389fa1e47a27ddd8d9b63ecd42b": "Dropbear SSH (IoT/embedded)",
}

// ExtractHASH computes the HASSH fingerprint from a raw TCP payload.
// Returns "" if the payload does not contain a parseable SSH_MSG_KEXINIT.
//
// Handles both bare KEXINIT packets and packets prefixed by an SSH banner
// ("SSH-2.0-...\r\n" or "SSH-2.0-...\n").
func ExtractHASH(payload []byte) string {
	kex, enc, mac, comp, ok := parseSSHKexInit(payload)
	if !ok {
		return ""
	}
	s := kex + ";" + enc + ";" + mac + ";" + comp
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// LookupHASH checks whether a HASSH fingerprint matches a known offensive
// SSH library. Returns (description, true) on a match; ("", false) otherwise.
func LookupHASH(hash string) (string, bool) {
	if hash == "" {
		return "", false
	}
	desc, ok := knownBadHasshHashes[strings.ToLower(hash)]
	return desc, ok
}

// parseSSHKexInit extracts the four HASSH algorithm fields from an SSH binary
// packet containing SSH_MSG_KEXINIT (message type 20).
//
// SSH Binary Packet format (RFC 4253 §6):
//
//	uint32  packet_length     (does not include the 4-byte field itself)
//	byte    padding_length
//	byte[N] payload           (N = packet_length - padding_length - 1)
//	byte[P] random padding
//
// The payload starts with the message type byte. For KEXINIT (type 20):
//
//	byte      msg_type        = 20
//	byte[16]  cookie
//	name-list kex_algorithms
//	name-list server_host_key_algorithms
//	name-list enc_algorithms_client_to_server   ← HASSH field 2
//	name-list enc_algorithms_server_to_client
//	name-list mac_algorithms_client_to_server   ← HASSH field 3
//	name-list mac_algorithms_server_to_client
//	name-list comp_algorithms_client_to_server  ← HASSH field 4
//	...
//
// Returns (kex, enc, mac, comp, true) on success; ("", "", "", "", false) on failure.
func parseSSHKexInit(payload []byte) (kex, enc, mac, comp string, ok bool) {
	// Skip SSH identification banner if present:
	// "SSH-2.0-OpenSSH_8.9p1\r\n" (or "\n" only on some implementations).
	if len(payload) >= 4 &&
		payload[0] == 'S' && payload[1] == 'S' && payload[2] == 'H' && payload[3] == '-' {
		nlIdx := -1
		// Banner is at most 255 bytes per RFC 4253.
		end := len(payload)
		if end > 256 {
			end = 256
		}
		for i := 4; i < end; i++ {
			if payload[i] == '\n' {
				nlIdx = i + 1
				break
			}
		}
		if nlIdx < 0 {
			return
		}
		payload = payload[nlIdx:]
	}

	// SSH Binary Packet: uint32 packet_length + uint8 padding_length + payload…
	if len(payload) < 6 {
		return
	}
	pktLen := int(binary.BigEndian.Uint32(payload[0:4]))
	// Sanity bounds: SSH_MSG_KEXINIT is at least 17 bytes of payload + 1 padding.
	if pktLen < 18 || pktLen > 65535 || len(payload) < 4+pktLen {
		return
	}
	paddingLen := int(payload[4])
	payloadLen := pktLen - 1 - paddingLen // subtract padding_length byte + padding
	if payloadLen < 17 || 5+payloadLen > len(payload) {
		return
	}
	msg := payload[5 : 5+payloadLen]

	// First byte: message type must be 20 (SSH_MSG_KEXINIT).
	if msg[0] != 20 {
		return
	}
	// Skip type(1) + cookie(16).
	pos := 17

	// Parse 10 name-list fields.
	const nFields = 10
	fields := make([]string, nFields)
	for i := 0; i < nFields; i++ {
		if pos+4 > len(msg) {
			return
		}
		fieldLen := int(binary.BigEndian.Uint32(msg[pos : pos+4]))
		pos += 4
		if fieldLen > len(msg)-pos {
			return
		}
		fields[i] = string(msg[pos : pos+fieldLen])
		pos += fieldLen
	}

	// Field layout:
	// 0  kex_algorithms
	// 1  server_host_key_algorithms
	// 2  encryption_algorithms_client_to_server
	// 3  encryption_algorithms_server_to_client
	// 4  mac_algorithms_client_to_server
	// 5  mac_algorithms_server_to_client
	// 6  compression_algorithms_client_to_server
	// 7  compression_algorithms_server_to_client
	// 8  languages_client_to_server
	// 9  languages_server_to_client
	return fields[0], fields[2], fields[4], fields[6], fields[0] != ""
}
