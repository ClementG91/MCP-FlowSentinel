// Package ja3 — JA3S fingerprinting of TLS ServerHello messages.
//
// JA3S is the server-side complement to JA3: it fingerprints the TLS
// ServerHello based on the negotiated version, selected cipher suite, and
// extensions the server returns. This allows detection of C2 server
// infrastructure even when the implant randomises its ClientHello.
//
// Formula: MD5("TLSVersion,Cipher,Extensions")
// GREASE values (RFC 8701) are filtered before hashing.
//
// Reference: https://github.com/salesforce/ja3
package ja3

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
)

// knownBadServerHashes maps documented JA3S fingerprints of C2 server
// implementations to their identifying description.
// Sources: abuse.ch JA3 feeds, Corelight research, public threat intel reports.
var knownBadServerHashes = map[string]string{
	// Cobalt Strike — default SSL configuration (OpenSSL with default settings)
	"ae4edc6faf64d08308082ad26be60767": "Cobalt Strike (default SSL server)",
	// Cobalt Strike — alternate profile observed in the wild
	"fd4bc6cea4877646ccd62f0792ec8bf6": "Cobalt Strike (profile variant)",
	// Metasploit multi/handler default SSL responder
	"07d7a9b8a8f4fc193ecdbe4e28e7b945": "Metasploit SSL handler",
	// Sliver C2 — Go crypto/tls server defaults (TLS 1.3)
	"769c20bdc8def79a3a28f58c8abe437c": "Sliver C2 (Go TLS server)",
	// Havoc C2 server
	"e35bcc7bd33e3a72f64289df0f48c90d": "Havoc C2 server",
	// Empire C2 server (Python ssl module)
	"3b5074b1b5d032e5620f69f9159c1217": "Empire C2 server",
}

// serverHello holds the fields required for JA3S computation.
type serverHello struct {
	version    uint16
	cipher     uint16
	extensions []uint16
}

// FingerprintServer computes the JA3S fingerprint from a raw TCP payload.
// Returns "" if the payload is not a parseable TLS ServerHello.
// JA3S formula: MD5("TLSVersion,Cipher,Extensions")
func FingerprintServer(payload []byte) string {
	sh, ok := parseServerHello(payload)
	if !ok {
		return ""
	}
	return computeJA3S(sh)
}

// LookupServer checks whether a JA3S hash matches a known C2 server fingerprint.
// Returns (description, true) on a match; ("", false) otherwise.
func LookupServer(hash string) (string, bool) {
	if hash == "" {
		return "", false
	}
	desc, ok := knownBadServerHashes[strings.ToLower(hash)]
	return desc, ok
}

func computeJA3S(sh serverHello) string {
	s := fmt.Sprintf("%d,%d,%s",
		sh.version,
		sh.cipher,
		joinUint16(sh.extensions),
	)
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// parseServerHello extracts JA3S fields from a TLS ServerHello payload.
func parseServerHello(payload []byte) (serverHello, bool) {
	// TLS record header: content_type(1) + version(2) + length(2)
	if len(payload) < 5 {
		return serverHello{}, false
	}
	if payload[0] != 0x16 { // TLS Handshake content type
		return serverHello{}, false
	}
	recordLen := int(payload[3])<<8 | int(payload[4])
	if len(payload) < 5+recordLen {
		return serverHello{}, false
	}
	hs := payload[5 : 5+recordLen]

	// Handshake message: type(1) + length(3)
	if len(hs) < 4 || hs[0] != 0x02 { // 0x02 = ServerHello
		return serverHello{}, false
	}
	hsBodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsBodyLen {
		return serverHello{}, false
	}
	body := hs[4 : 4+hsBodyLen]
	pos := 0

	// server_version: 2 bytes
	if pos+2 > len(body) {
		return serverHello{}, false
	}
	serverVersion := uint16(body[pos])<<8 | uint16(body[pos+1])
	pos += 2

	// random: 32 bytes
	pos += 32
	if pos > len(body) {
		return serverHello{}, false
	}

	// session_id: length(1) + data
	if pos+1 > len(body) {
		return serverHello{}, false
	}
	sessionIDLen := int(body[pos])
	pos += 1 + sessionIDLen
	if pos > len(body) {
		return serverHello{}, false
	}

	// cipher_suite: 2 bytes (single selected suite)
	if pos+2 > len(body) {
		return serverHello{}, false
	}
	cipher := uint16(body[pos])<<8 | uint16(body[pos+1])
	if grease[cipher] {
		cipher = 0
	}
	pos += 2

	// compression_method: 1 byte
	pos++
	if pos > len(body) {
		return serverHello{
			version: serverVersion,
			cipher:  cipher,
		}, true
	}

	// extensions: length(2) — optional in older TLS versions
	if pos+2 > len(body) {
		return serverHello{
			version: serverVersion,
			cipher:  cipher,
		}, true
	}
	extTotal := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	extEnd := pos + extTotal
	if extEnd > len(body) {
		return serverHello{}, false
	}

	var extensions []uint16
	for pos+4 <= extEnd {
		extType := uint16(body[pos])<<8 | uint16(body[pos+1])
		extLen := int(body[pos+2])<<8 | int(body[pos+3])
		pos += 4
		if pos+extLen > extEnd {
			break
		}
		pos += extLen
		if !grease[extType] {
			extensions = append(extensions, extType)
		}
	}

	return serverHello{
		version:    serverVersion,
		cipher:     cipher,
		extensions: extensions,
	}, true
}
