// Package ja3 computes JA3 TLS fingerprints from raw TCP payloads.
//
// JA3 is an industry-standard method (Salesforce Engineering) for fingerprinting
// TLS clients based on the contents of the ClientHello message. It produces a
// 32-character MD5 hex string that identifies the TLS library and settings of
// the client, regardless of the destination server or certificate.
//
// Formula: MD5("TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats")
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

// grease is the set of GREASE values defined in RFC 8701. These are injected
// by modern TLS implementations to prevent ossification and must be excluded
// from JA3 computation.
var grease = map[uint16]bool{
	0x0A0A: true, 0x1A1A: true, 0x2A2A: true, 0x3A3A: true,
	0x4A4A: true, 0x5A5A: true, 0x6A6A: true, 0x7A7A: true,
	0x8A8A: true, 0x9A9A: true, 0xAAAA: true, 0xBABA: true,
	0xCACA: true, 0xDADA: true, 0xEAEA: true, 0xFAFA: true,
}

// knownBadHashes maps well-documented JA3 fingerprints to the malware family
// or tool they identify. Sources: abuse.ch JA3 feeds, Salesforce research,
// public threat intelligence reports.
var knownBadHashes = map[string]string{
	// Cobalt Strike — default Malleable C2 profile
	"51c64c77e60f3980eea90869b68c58a8": "Cobalt Strike (default profile)",
	// Metasploit Meterpreter (Reverse HTTPS stager)
	"6734f37431670b3ab4292b8f60f29984": "Metasploit Meterpreter",
	// Empire C2 framework
	"3b5074b1b5d032e5620f69f9159c1217": "Empire C2",
	// Sliver C2 (default mTLS/WireGuard)
	"d0ec4b50a944b182f68cf08c01bc59ea": "Sliver C2",
	// Dridex banking trojan
	"6d4986b04beb6df16e7c7b6b1b6b8e14": "Dridex",
	// TrickBot
	"c12f54a3f91dc7bafd92cb59fe009a35": "TrickBot",
	// Emotet (loader)
	"04b8a36ff48bbf6cc0a6fd34b05c46e5": "Emotet",
	// Havoc C2 framework
	"8a0c8d28bb85b4c7eedc5dd6a67f0cf5": "Havoc C2",
	// BruteRatel C4
	"65ea0c4b63b34c0b9b02af8e0bc7e7cc": "BruteRatel C4",
	// njRAT / Bladabindi
	"a0e9f5d64349fb13191bc781f81f42e1": "njRAT",
	// AsyncRAT
	"29ccb6a9e0d2506b56640d4f1c1ce87e": "AsyncRAT",
	// Raccoon Stealer
	"eb539ba9041ef7c6bc1d88b89e3de43a": "Raccoon Stealer",
	// Redline Stealer
	"dc23e61665a89e17ec9bd4b7a5a52e22": "Redline Stealer",
	// Python-Requests (common in script-kiddie tooling and automated scanners)
	"5e7b88d7f79b87f63c23d680f2a0dd05": "Python-requests (potential scanner)",
	// curl (informational, low confidence)
	"197781a6c9bf68e89b6ef2e82b001a99": "curl (informational)",
}

// Fingerprint computes the JA3 fingerprint from a raw TCP payload and returns
// the 32-character MD5 hex string, or "" if the payload is not a TLS ClientHello.
func Fingerprint(payload []byte) string {
	ch, ok := parseClientHello(payload)
	if !ok {
		return ""
	}
	return computeJA3(ch)
}

// Lookup checks whether a JA3 hash matches a known-bad fingerprint.
// Returns the malware family description and true if found, ("", false) otherwise.
func Lookup(hash string) (string, bool) {
	if hash == "" {
		return "", false
	}
	desc, ok := knownBadHashes[strings.ToLower(hash)]
	return desc, ok
}

// LookupWithCustom checks the hash against the built-in known-bad list and
// any custom hashes supplied by the caller (from config.ScoringConfig.ExtraJA3BadHashes).
//
// Each entry in extraHashes must be either:
//   - "hash"              → description defaults to "custom threat indicator"
//   - "hash:description"  → uses the provided description
func LookupWithCustom(hash string, extraHashes []string) (string, bool) {
	if desc, ok := Lookup(hash); ok {
		return desc, true
	}
	if len(extraHashes) == 0 || hash == "" {
		return "", false
	}
	normalized := strings.ToLower(hash)
	for _, entry := range extraHashes {
		parts := strings.SplitN(entry, ":", 2)
		if strings.ToLower(strings.TrimSpace(parts[0])) == normalized {
			if len(parts) > 1 && parts[1] != "" {
				return parts[1], true
			}
			return "custom threat indicator", true
		}
	}
	return "", false
}

// clientHello holds the parsed fields required for JA3 computation.
type clientHello struct {
	version            uint16
	cipherSuites       []uint16
	extensions         []uint16
	ellipticCurves     []uint16
	ecPointFormats     []uint8
}

// computeJA3 produces the final MD5 hash from a parsed ClientHello.
func computeJA3(ch clientHello) string {
	s := fmt.Sprintf("%d,%s,%s,%s,%s",
		ch.version,
		joinUint16(ch.cipherSuites),
		joinUint16(ch.extensions),
		joinUint16(ch.ellipticCurves),
		joinUint8(ch.ecPointFormats),
	)
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func joinUint16(vals []uint16) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

func joinUint8(vals []uint8) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

// parseClientHello attempts to decode a TLS ClientHello from a raw TCP payload.
// Returns the parsed struct and true on success; false on any parse failure.
func parseClientHello(payload []byte) (clientHello, bool) {
	// TLS record: content_type(1) + legacy_version(2) + length(2)
	if len(payload) < 5 {
		return clientHello{}, false
	}
	if payload[0] != 0x16 { // Handshake record type
		return clientHello{}, false
	}
	recordLen := int(payload[3])<<8 | int(payload[4])
	if len(payload) < 5+recordLen {
		return clientHello{}, false
	}
	hs := payload[5 : 5+recordLen]

	// Handshake message: msg_type(1) + length(3)
	if len(hs) < 4 || hs[0] != 0x01 { // ClientHello = 1
		return clientHello{}, false
	}
	// Total handshake body length (skip the 4-byte header).
	hsBodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsBodyLen {
		return clientHello{}, false
	}
	body := hs[4 : 4+hsBodyLen]

	pos := 0

	// client_version: 2 bytes
	if pos+2 > len(body) {
		return clientHello{}, false
	}
	clientVersion := uint16(body[pos])<<8 | uint16(body[pos+1])
	pos += 2

	// random: 32 bytes
	pos += 32
	if pos > len(body) {
		return clientHello{}, false
	}

	// session_id: length(1) + data
	if pos+1 > len(body) {
		return clientHello{}, false
	}
	sessionIDLen := int(body[pos])
	pos += 1 + sessionIDLen
	if pos > len(body) {
		return clientHello{}, false
	}

	// cipher_suites: length(2) + list of uint16
	if pos+2 > len(body) {
		return clientHello{}, false
	}
	csLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	if pos+csLen > len(body) || csLen%2 != 0 {
		return clientHello{}, false
	}
	var cipherSuites []uint16
	for i := 0; i < csLen; i += 2 {
		cs := uint16(body[pos+i])<<8 | uint16(body[pos+i+1])
		if !grease[cs] {
			cipherSuites = append(cipherSuites, cs)
		}
	}
	pos += csLen

	// compression_methods: length(1) + data
	if pos+1 > len(body) {
		return clientHello{}, false
	}
	compLen := int(body[pos])
	pos += 1 + compLen
	if pos > len(body) {
		return clientHello{}, false
	}

	// extensions: length(2) — optional (TLSv1.0 may omit)
	if pos+2 > len(body) {
		return clientHello{
			version:      clientVersion,
			cipherSuites: cipherSuites,
		}, true
	}
	extTotal := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	extEnd := pos + extTotal
	if extEnd > len(body) {
		return clientHello{}, false
	}

	var extensions []uint16
	var ellipticCurves []uint16
	var ecPointFormats []uint8

	for pos+4 <= extEnd {
		extType := uint16(body[pos])<<8 | uint16(body[pos+1])
		extLen := int(body[pos+2])<<8 | int(body[pos+3])
		pos += 4
		if pos+extLen > extEnd {
			break
		}
		extData := body[pos : pos+extLen]
		pos += extLen

		if !grease[extType] {
			extensions = append(extensions, extType)
		}

		switch extType {
		case 0x000A: // supported_groups (elliptic curves)
			if len(extData) < 2 {
				break
			}
			listLen := int(extData[0])<<8 | int(extData[1])
			if len(extData) < 2+listLen || listLen%2 != 0 {
				break
			}
			for i := 0; i < listLen; i += 2 {
				curve := uint16(extData[2+i])<<8 | uint16(extData[2+i+1])
				if !grease[curve] {
					ellipticCurves = append(ellipticCurves, curve)
				}
			}
		case 0x000B: // ec_point_formats
			if len(extData) < 1 {
				break
			}
			fmtLen := int(extData[0])
			if len(extData) < 1+fmtLen {
				break
			}
			for i := 0; i < fmtLen; i++ {
				ecPointFormats = append(ecPointFormats, extData[1+i])
			}
		}
	}

	return clientHello{
		version:        clientVersion,
		cipherSuites:   cipherSuites,
		extensions:     extensions,
		ellipticCurves: ellipticCurves,
		ecPointFormats: ecPointFormats,
	}, true
}
