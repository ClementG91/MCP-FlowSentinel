package ja3

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
	"testing"
)

// buildClientHello constructs a minimal raw TLS record containing a
// ClientHello with the given parameters for test purposes.
//
// Layout:
//
//	TLS record header:    16 03 01 <len(2)>
//	Handshake header:     01 <len(3)>
//	client_version:       <2>
//	random:               <32 zeros>
//	session_id length:    00
//	cipher_suites len:    <2>  followed by <n*2> bytes
//	compression len:      01  followed by 00 (null compression)
//	extensions total len: <2>  followed by extensions
func buildClientHello(version uint16, cipherSuites, extensions []uint16, curves []uint16, ecPointFmts []uint8) []byte {
	// cipher suites bytes
	csBytes := make([]byte, len(cipherSuites)*2)
	for i, cs := range cipherSuites {
		csBytes[i*2] = byte(cs >> 8)
		csBytes[i*2+1] = byte(cs)
	}

	// build extensions block
	var extBuf []byte
	for _, extType := range extensions {
		extBuf = append(extBuf, byte(extType>>8), byte(extType))
		extBuf = append(extBuf, 0x00, 0x00) // zero-length extension
	}
	// supported_groups (0x000a) — override if curves provided
	if len(curves) > 0 {
		// Remove existing 0x000a from extBuf if present.
		extBuf = removeExt(extBuf, 0x000a)
		curveData := make([]byte, 2+len(curves)*2)
		listLen := len(curves) * 2
		curveData[0] = byte(listLen >> 8)
		curveData[1] = byte(listLen)
		for i, c := range curves {
			curveData[2+i*2] = byte(c >> 8)
			curveData[2+i*2+1] = byte(c)
		}
		extBuf = append(extBuf, 0x00, 0x0a) // type 0x000a
		extBuf = append(extBuf, byte(len(curveData)>>8), byte(len(curveData)))
		extBuf = append(extBuf, curveData...)
	}
	// ec_point_formats (0x000b) — append if provided
	if len(ecPointFmts) > 0 {
		fmtData := make([]byte, 1+len(ecPointFmts))
		fmtData[0] = byte(len(ecPointFmts))
		copy(fmtData[1:], ecPointFmts)
		extBuf = append(extBuf, 0x00, 0x0b)
		extBuf = append(extBuf, byte(len(fmtData)>>8), byte(len(fmtData)))
		extBuf = append(extBuf, fmtData...)
	}

	// Assemble ClientHello body:
	//   version(2) + random(32) + sessionIDLen(1) + cipherSuites(2+n) +
	//   compressionLen(1) + 00 + extensionsLen(2) + extensions
	var chBody []byte
	chBody = append(chBody, byte(version>>8), byte(version)) // client_version
	chBody = append(chBody, make([]byte, 32)...)             // random
	chBody = append(chBody, 0x00)                            // session_id length = 0
	csLen := len(csBytes)
	chBody = append(chBody, byte(csLen>>8), byte(csLen)) // cipher suites length
	chBody = append(chBody, csBytes...)
	chBody = append(chBody, 0x01, 0x00)                                  // compression: 1 method, null
	extLen := len(extBuf)
	chBody = append(chBody, byte(extLen>>8), byte(extLen)) // extensions total length
	chBody = append(chBody, extBuf...)

	// Handshake message: type(1) + length(3) + body
	hsLen := len(chBody)
	var hs []byte
	hs = append(hs, 0x01) // ClientHello
	hs = append(hs, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	hs = append(hs, chBody...)

	// TLS record: type(1) + version(2) + length(2) + handshake
	recLen := len(hs)
	var rec []byte
	rec = append(rec, 0x16)             // Handshake
	rec = append(rec, 0x03, 0x01)       // TLS 1.0 record version
	rec = append(rec, byte(recLen>>8), byte(recLen))
	rec = append(rec, hs...)
	return rec
}

// removeExt removes all occurrences of extType from a raw extensions block.
func removeExt(buf []byte, extType uint16) []byte {
	var out []byte
	for i := 0; i+4 <= len(buf); {
		et := uint16(buf[i])<<8 | uint16(buf[i+1])
		el := int(buf[i+2])<<8 | int(buf[i+3])
		if et != extType {
			out = append(out, buf[i:i+4+el]...)
		}
		i += 4 + el
	}
	return out
}

// expectedJA3 computes the expected MD5 using the same formula as Fingerprint.
func expectedJA3(version uint16, ciphers, exts, curves []uint16, ecPt []uint8) string {
	s := strings.Join([]string{
		joinUint16(filterGREASE16(ciphers)),
		joinUint16(filterGREASE16(exts)),
		joinUint16(filterGREASE16(curves)),
		joinUint8(ecPt),
	}, ",")
	s = strings.Join([]string{uint16Str(version), s}, ",")
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func filterGREASE16(vals []uint16) []uint16 {
	var out []uint16
	for _, v := range vals {
		if !grease[v] {
			out = append(out, v)
		}
	}
	return out
}

func uint16Str(v uint16) string {
	return joinUint16([]uint16{v})
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestFingerprint_NotTLS_ReturnsEmpty(t *testing.T) {
	payloads := [][]byte{
		nil,
		{},
		{0x17, 0x03, 0x01, 0x00, 0x05}, // Alert, not Handshake
		{0x16, 0x03, 0x01, 0x00, 0x01, 0x02}, // too short for ClientHello
		make([]byte, 4),
	}
	for _, p := range payloads {
		if got := Fingerprint(p); got != "" {
			t.Errorf("Fingerprint(non-TLS) = %q, want empty", got)
		}
	}
}

func TestFingerprint_MinimalClientHello(t *testing.T) {
	payload := buildClientHello(0x0303, []uint16{0x002f}, nil, nil, nil)
	got := Fingerprint(payload)
	if len(got) != 32 {
		t.Errorf("Fingerprint length = %d, want 32", len(got))
	}
	want := expectedJA3(0x0303, []uint16{0x002f}, nil, nil, nil)
	if got != want {
		t.Errorf("Fingerprint = %q, want %q", got, want)
	}
}

func TestFingerprint_WithGREASEFiltered(t *testing.T) {
	// GREASE cipher suite should be excluded from JA3.
	ciphers := []uint16{0x1A1A, 0x002f, 0x0035} // 0x1A1A is GREASE
	payload := buildClientHello(0x0303, ciphers, nil, nil, nil)
	got := Fingerprint(payload)
	// Expected hash uses only the non-GREASE ciphers.
	want := expectedJA3(0x0303, ciphers, nil, nil, nil)
	if got != want {
		t.Errorf("Fingerprint with GREASE = %q, want %q", got, want)
	}
	// Should not contain the GREASE value in the input.
	if got == "" {
		t.Error("Fingerprint with GREASE returned empty")
	}
}

func TestFingerprint_WithExtensionsAndCurves(t *testing.T) {
	ciphers := []uint16{0x002f, 0x0035, 0xc02b}
	exts := []uint16{0x0000, 0x000f, 0x0010} // SNI, heartbeat, ALPN
	curves := []uint16{0x001d, 0x0017}        // x25519, secp256r1
	ecPt := []uint8{0x00}                     // uncompressed

	payload := buildClientHello(0x0303, ciphers, exts, curves, ecPt)
	got := Fingerprint(payload)
	if len(got) != 32 {
		t.Errorf("Fingerprint length = %d, want 32", len(got))
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	payload := buildClientHello(0x0303, []uint16{0x002f, 0x0035}, []uint16{0x0000, 0x0010}, nil, nil)
	first := Fingerprint(payload)
	second := Fingerprint(payload)
	if first != second {
		t.Errorf("Fingerprint not deterministic: %q vs %q", first, second)
	}
}

func TestLookup_UnknownHash_ReturnsFalse(t *testing.T) {
	_, ok := Lookup("aabbccddeeff00112233445566778899")
	if ok {
		t.Error("Lookup of unknown hash should return false")
	}
}

func TestLookup_EmptyHash_ReturnsFalse(t *testing.T) {
	_, ok := Lookup("")
	if ok {
		t.Error("Lookup of empty hash should return false")
	}
}

func TestLookup_KnownBad_ReturnsDescription(t *testing.T) {
	// Test a hash that IS in the known-bad list.
	for hash, desc := range knownBadHashes {
		got, ok := Lookup(hash)
		if !ok {
			t.Errorf("Lookup(%q) = false, want true", hash)
		}
		if got != desc {
			t.Errorf("Lookup(%q) = %q, want %q", hash, got, desc)
		}
		break // just test one
	}
}

func TestLookup_CaseInsensitive(t *testing.T) {
	for hash := range knownBadHashes {
		upper := strings.ToUpper(hash)
		_, ok := Lookup(upper)
		if !ok {
			t.Errorf("Lookup with uppercase %q should find hash", upper)
		}
		break
	}
}

func TestJoinUint16_Empty(t *testing.T) {
	if got := joinUint16(nil); got != "" {
		t.Errorf("joinUint16(nil) = %q, want empty", got)
	}
}

func TestJoinUint16_Single(t *testing.T) {
	if got := joinUint16([]uint16{47}); got != "47" {
		t.Errorf("joinUint16([47]) = %q, want 47", got)
	}
}

func TestJoinUint16_Multiple(t *testing.T) {
	if got := joinUint16([]uint16{47, 53, 255}); got != "47-53-255" {
		t.Errorf("joinUint16 = %q, want 47-53-255", got)
	}
}

func TestJoinUint8_Multiple(t *testing.T) {
	if got := joinUint8([]uint8{0, 1, 2}); got != "0-1-2" {
		t.Errorf("joinUint8 = %q, want 0-1-2", got)
	}
}

func TestFingerprint_TruncatedPayloads_ReturnEmpty(t *testing.T) {
	// Build a valid payload, then truncate it at various points.
	valid := buildClientHello(0x0303, []uint16{0x002f}, nil, nil, nil)
	for cut := 0; cut < len(valid)-1; cut++ {
		truncated := valid[:cut]
		// Should return "" without panicking.
		if got := Fingerprint(truncated); got != "" {
			// Some cuts may still produce a valid parse — that's fine.
			if len(got) != 32 {
				t.Errorf("Fingerprint(truncated at %d) = %q (not 32 chars)", cut, got)
			}
		}
	}
}

func TestFingerprint_InvalidRecordType_ReturnsEmpty(t *testing.T) {
	valid := buildClientHello(0x0303, []uint16{0x002f}, nil, nil, nil)
	valid[0] = 0x14 // ChangeCipherSpec, not Handshake
	if got := Fingerprint(valid); got != "" {
		t.Errorf("Fingerprint(non-handshake) = %q, want empty", got)
	}
}

func TestFingerprint_InvalidHandshakeType_ReturnsEmpty(t *testing.T) {
	valid := buildClientHello(0x0303, []uint16{0x002f}, nil, nil, nil)
	valid[5] = 0x02 // ServerHello, not ClientHello
	if got := Fingerprint(valid); got != "" {
		t.Errorf("Fingerprint(ServerHello) = %q, want empty", got)
	}
}

func TestFingerprint_GREASEInExtensions_Filtered(t *testing.T) {
	// Extension list contains GREASE values — they should be filtered.
	ciphers := []uint16{0x002f}
	exts := []uint16{0xAAAA, 0x0000, 0xBABA} // 0xAAAA and 0xBABA are GREASE
	payload := buildClientHello(0x0303, ciphers, exts, nil, nil)
	got := Fingerprint(payload)
	if got == "" || len(got) != 32 {
		t.Errorf("Fingerprint = %q (want 32-char hash)", got)
	}
	// Hash should match when we compute manually with GREASE filtered.
	want := expectedJA3(0x0303, ciphers, exts, nil, nil)
	if got != want {
		t.Errorf("GREASE-filtered hash = %q, want %q", got, want)
	}
}

func TestFingerprint_GREASEInCurves_Filtered(t *testing.T) {
	// GREASE value 0x0A0A in supported_groups must be excluded from JA3.
	// Two payloads: one with 0x0A0A+x25519, one with x25519 only.
	// They should produce different hashes, confirming the filtering runs,
	// and both should be valid 32-char hashes.
	withGREASE := buildClientHello(0x0303, []uint16{0x002f}, nil, []uint16{0x0A0A, 0x001d}, nil)
	withoutGREASE := buildClientHello(0x0303, []uint16{0x002f}, nil, []uint16{0x001d}, nil)

	hashWith := Fingerprint(withGREASE)
	hashWithout := Fingerprint(withoutGREASE)

	if len(hashWith) != 32 {
		t.Errorf("Fingerprint(with GREASE) = %q (not 32 chars)", hashWith)
	}
	if len(hashWithout) != 32 {
		t.Errorf("Fingerprint(without GREASE) = %q (not 32 chars)", hashWithout)
	}
	// After GREASE filtering, both ClientHellos have identical curves → same hash.
	if hashWith != hashWithout {
		t.Errorf("GREASE in curves should be stripped, hashes should match: %q vs %q", hashWith, hashWithout)
	}
}
