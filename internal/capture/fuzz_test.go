package capture

import (
	"encoding/binary"
	"testing"
)

// FuzzExtractHASH feeds arbitrary byte slices to the SSH KEXINIT parser.
// Invariant: must never panic; result is either "" or a 32-char lowercase hex string.
func FuzzExtractHASH(f *testing.F) {
	// Empty / too-short inputs.
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0x05})

	// Bare packet with wrong message type (not 20).
	pkt1 := makeMinimalKexInit(21, "curve25519-sha256", "aes256-ctr", "hmac-sha2-256", "none")
	f.Add(pkt1)

	// Valid minimal KEXINIT.
	pkt2 := makeMinimalKexInit(20, "curve25519-sha256", "aes256-ctr", "hmac-sha2-256", "none")
	f.Add(pkt2)

	// With a banner prefix.
	banner := append([]byte("SSH-2.0-OpenSSH_8.9\r\n"), pkt2...)
	f.Add(banner)

	// Non-SSH traffic.
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))

	// Packet length field that claims more data than present.
	overflow := []byte{0x00, 0x01, 0x00, 0x00, 0x00}
	f.Add(overflow)

	f.Fuzz(func(t *testing.T, data []byte) {
		hash := ExtractHASH(data)
		if hash != "" && len(hash) != 32 {
			t.Errorf("ExtractHASH returned invalid hash %q (len %d)", hash, len(hash))
		}
	})
}

// makeMinimalKexInit constructs a minimal SSH binary packet containing a
// KEXINIT message. Used only to seed the fuzzer corpus.
func makeMinimalKexInit(msgType byte, kex, enc, mac, comp string) []byte {
	// Build the payload: type(1) + cookie(16) + 10 name-lists + flags(5).
	nameListField := func(s string) []byte {
		b := make([]byte, 4+len(s))
		binary.BigEndian.PutUint32(b, uint32(len(s)))
		copy(b[4:], s)
		return b
	}
	var nameLists []byte
	fields := []string{kex, "ssh-rsa", enc, enc, mac, mac, comp, comp, "", ""}
	for _, f := range fields {
		nameLists = append(nameLists, nameListField(f)...)
	}
	payload := make([]byte, 1+16+len(nameLists)+1+4)
	payload[0] = msgType
	copy(payload[17:], nameLists)

	padding := byte(8)
	pktLen := uint32(1 + len(payload) + int(padding))
	pkt := make([]byte, 4+1+len(payload)+int(padding))
	binary.BigEndian.PutUint32(pkt[0:4], pktLen)
	pkt[4] = padding
	copy(pkt[5:], payload)
	return pkt
}
