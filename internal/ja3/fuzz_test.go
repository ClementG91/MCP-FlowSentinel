package ja3

import (
	"testing"
)

// FuzzFingerprint feeds arbitrary byte slices to the JA3 ClientHello parser.
// The invariant: it must never panic, and must return either "" or a 32-char
// lowercase hex string.
func FuzzFingerprint(f *testing.F) {
	// Seed with payloads that exercise real code paths.
	f.Add([]byte{})                               // empty
	f.Add([]byte{0x16, 0x03, 0x01})              // too short
	f.Add([]byte{0x17, 0x03, 0x03, 0x00, 0x01})  // application data (wrong type)
	// Minimal TLS record with wrong handshake type.
	f.Add([]byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		hash := Fingerprint(data)
		if hash != "" && len(hash) != 32 {
			t.Errorf("Fingerprint returned invalid hash %q (len %d)", hash, len(hash))
		}
	})
}

// FuzzFingerprintServer feeds arbitrary byte slices to the JA3S ServerHello parser.
func FuzzFingerprintServer(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x16, 0x03, 0x03, 0x00, 0x05})               // too short body
	f.Add([]byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}) // ServerHello zero-len
	f.Add([]byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}) // ClientHello type

	f.Fuzz(func(t *testing.T, data []byte) {
		hash := FingerprintServer(data)
		if hash != "" && len(hash) != 32 {
			t.Errorf("FingerprintServer returned invalid hash %q (len %d)", hash, len(hash))
		}
	})
}
