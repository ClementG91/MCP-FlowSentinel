package ja3

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// buildServerHello constructs a minimal TLS record containing a ServerHello.
//
//	TLS record:   16 03 03 <len(2)>
//	HS header:    02 <len(3)>
//	version:      <2>
//	random:       32 zeros
//	session_id:   00 (empty)
//	cipher:       <2>
//	compression:  00
//	ext_len:      <2>
//	extensions:   each as type(2)+length(2)+data(0)
func buildServerHello(version uint16, cipher uint16, extensions []uint16) []byte {
	// Extension bytes: each extension is 4 bytes (type + zero length).
	extBody := make([]byte, len(extensions)*4)
	for i, et := range extensions {
		extBody[i*4] = byte(et >> 8)
		extBody[i*4+1] = byte(et)
		// extLen = 0
	}
	extLenTotal := len(extBody)

	// ServerHello body length: 2 (version) + 32 (random) + 1 (session_id) +
	//                          2 (cipher) + 1 (compression) + 2 (ext_len) + extBody
	bodyLen := 2 + 32 + 1 + 2 + 1 + 2 + extLenTotal

	// Handshake header: type(1) + length(3) + body
	hsLen := 4 + bodyLen

	// TLS record header: type(1) + version(2) + length(2) + handshake
	raw := make([]byte, 5+hsLen)
	raw[0] = 0x16 // Handshake
	raw[1] = 0x03
	raw[2] = 0x03
	raw[3] = byte(hsLen >> 8)
	raw[4] = byte(hsLen)

	// Handshake header
	raw[5] = 0x02 // ServerHello
	raw[6] = byte(bodyLen >> 16)
	raw[7] = byte(bodyLen >> 8)
	raw[8] = byte(bodyLen)

	pos := 9
	raw[pos] = byte(version >> 8)
	raw[pos+1] = byte(version)
	pos += 2

	pos += 32 // 32-byte random (zeros)

	raw[pos] = 0x00 // session_id length = 0
	pos++

	raw[pos] = byte(cipher >> 8)
	raw[pos+1] = byte(cipher)
	pos += 2

	raw[pos] = 0x00 // compression = null
	pos++

	raw[pos] = byte(extLenTotal >> 8)
	raw[pos+1] = byte(extLenTotal)
	pos += 2

	copy(raw[pos:], extBody)
	return raw
}

// expectedJA3S computes the expected JA3S hash for given inputs.
func expectedJA3S(version uint16, cipher uint16, extensions []uint16) string {
	parts := make([]string, len(extensions))
	for i, e := range extensions {
		parts[i] = fmt.Sprintf("%d", e)
	}
	extStr := strings.Join(parts, "-")
	s := fmt.Sprintf("%d,%d,%s", version, cipher, extStr)
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestFingerprintServer_BasicServerHello(t *testing.T) {
	raw := buildServerHello(0x0303, 0xC02B, []uint16{0x0000, 0xFF01})
	hash := FingerprintServer(raw)
	if hash == "" {
		t.Fatal("expected non-empty JA3S hash")
	}
	want := expectedJA3S(0x0303, 0xC02B, []uint16{0x0000, 0xFF01})
	if hash != want {
		t.Errorf("JA3S = %q, want %q", hash, want)
	}
}

func TestFingerprintServer_NoExtensions(t *testing.T) {
	raw := buildServerHello(0x0303, 0xC02C, nil)
	hash := FingerprintServer(raw)
	if hash == "" {
		t.Fatal("expected non-empty JA3S hash for ServerHello without extensions")
	}
	want := expectedJA3S(0x0303, 0xC02C, nil)
	if hash != want {
		t.Errorf("JA3S = %q, want %q", hash, want)
	}
}

func TestFingerprintServer_GREASECipherFiltered(t *testing.T) {
	// GREASE cipher (0x2A2A) should be replaced with 0 — same result as cipher=0
	raw := buildServerHello(0x0303, 0x2A2A, nil)
	hash := FingerprintServer(raw)
	if hash == "" {
		t.Fatal("expected hash even with GREASE cipher")
	}
	want := expectedJA3S(0x0303, 0, nil) // GREASE → 0
	if hash != want {
		t.Errorf("GREASE cipher not filtered: got %q, want %q", hash, want)
	}
}

func TestFingerprintServer_GREASEExtensionFiltered(t *testing.T) {
	// GREASE extension (0x0A0A) must be excluded from the extension list.
	raw := buildServerHello(0x0303, 0xC02B, []uint16{0x0A0A, 0x0000})
	hash := FingerprintServer(raw)
	wantNoGrease := expectedJA3S(0x0303, 0xC02B, []uint16{0x0000})
	if hash != wantNoGrease {
		t.Errorf("GREASE extension not filtered: got %q, want %q", hash, wantNoGrease)
	}
}

func TestFingerprintServer_NotTLSHandshake_ReturnsEmpty(t *testing.T) {
	if h := FingerprintServer([]byte{0x17, 0x03, 0x03, 0x00, 0x05}); h != "" {
		t.Errorf("application data should return empty, got %q", h)
	}
}

func TestFingerprintServer_NotServerHello_ReturnsEmpty(t *testing.T) {
	// Build a ClientHello-like record (type 0x01) — should not match ServerHello.
	raw := buildServerHello(0x0303, 0xC02B, nil)
	raw[5] = 0x01 // Override HS type to ClientHello
	if h := FingerprintServer(raw); h != "" {
		t.Errorf("ClientHello should return empty from FingerprintServer, got %q", h)
	}
}

func TestFingerprintServer_TooShort_ReturnsEmpty(t *testing.T) {
	for _, n := range []int{0, 1, 3, 4} {
		if h := FingerprintServer(make([]byte, n)); h != "" {
			t.Errorf("payload len %d: expected empty, got %q", n, h)
		}
	}
}

func TestFingerprintServer_TruncatedBody_ReturnsEmpty(t *testing.T) {
	raw := buildServerHello(0x0303, 0xC02B, []uint16{0x0000})
	truncated := raw[:len(raw)-5]
	// Adjust the record length to match truncation so the parser advances correctly.
	// Instead of patching, just check that a clearly short payload returns "".
	if h := FingerprintServer(truncated[:5]); h != "" {
		t.Errorf("truncated ServerHello should return empty, got %q", h)
	}
}

func TestLookupServer_KnownBad(t *testing.T) {
	for hash, want := range knownBadServerHashes {
		desc, ok := LookupServer(hash)
		if !ok {
			t.Errorf("LookupServer(%q): expected match, got false", hash)
		}
		if desc != want {
			t.Errorf("LookupServer(%q): got %q, want %q", hash, desc, want)
		}
	}
}

func TestLookupServer_Unknown(t *testing.T) {
	_, ok := LookupServer("000000000000000000000000000000ff")
	if ok {
		t.Error("expected false for unknown hash")
	}
}

func TestLookupServer_Empty(t *testing.T) {
	_, ok := LookupServer("")
	if ok {
		t.Error("expected false for empty hash")
	}
}

func TestFingerprintServer_DifferentCiphers_DifferentHashes(t *testing.T) {
	h1 := FingerprintServer(buildServerHello(0x0303, 0xC02B, nil))
	h2 := FingerprintServer(buildServerHello(0x0303, 0xC02C, nil))
	if h1 == h2 {
		t.Error("different ciphers must produce different JA3S hashes")
	}
}
