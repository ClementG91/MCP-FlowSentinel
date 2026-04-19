package capture

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// buildSSHKexInit constructs a minimal SSH binary packet containing
// SSH_MSG_KEXINIT (type 20) with the given algorithm name-lists.
// fields[0..9] correspond to the 10 name-list fields in RFC 4253.
func buildSSHKexInit(fields [10]string) []byte {
	// Compute payload: type(1) + cookie(16) + 10 name-lists + first_kex_packet_follows(1) + reserved(4)
	var nameListsBytes []byte
	for _, f := range fields {
		b := make([]byte, 4+len(f))
		binary.BigEndian.PutUint32(b, uint32(len(f)))
		copy(b[4:], f)
		nameListsBytes = append(nameListsBytes, b...)
	}
	payload := make([]byte, 1+16+len(nameListsBytes)+1+4)
	payload[0] = 20 // SSH_MSG_KEXINIT
	// cookie: 16 zero bytes (already zero)
	copy(payload[17:], nameListsBytes)
	// first_kex_packet_follows = 0, reserved = 0 (already zero)

	paddingLen := byte(8) // arbitrary padding
	pktLen := uint32(1 + len(payload) + int(paddingLen))
	pkt := make([]byte, 4+1+len(payload)+int(paddingLen))
	binary.BigEndian.PutUint32(pkt[0:4], pktLen)
	pkt[4] = paddingLen
	copy(pkt[5:], payload)
	return pkt
}

// expectedHASH computes the expected HASSH for given algorithm strings.
func expectedHASH(kex, enc, mac, comp string) string {
	s := kex + ";" + enc + ";" + mac + ";" + comp
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestExtractHASH_ValidKexInit(t *testing.T) {
	fields := [10]string{
		"curve25519-sha256,diffie-hellman-group14-sha256", // kex
		"ssh-rsa,ecdsa-sha2-nistp256",                    // server_host_key
		"aes128-ctr,aes256-ctr",                          // enc_c2s
		"aes128-ctr,aes256-ctr",                          // enc_s2c
		"hmac-sha2-256,hmac-sha1",                        // mac_c2s
		"hmac-sha2-256,hmac-sha1",                        // mac_s2c
		"none,zlib@openssh.com",                          // comp_c2s
		"none,zlib@openssh.com",                          // comp_s2c
		"",                                               // lang_c2s
		"",                                               // lang_s2c
	}
	raw := buildSSHKexInit(fields)
	hash := ExtractHASH(raw)
	if hash == "" {
		t.Fatal("expected non-empty HASSH")
	}
	want := expectedHASH(fields[0], fields[2], fields[4], fields[6])
	if hash != want {
		t.Errorf("HASSH = %q, want %q", hash, want)
	}
}

func TestExtractHASH_WithBanner(t *testing.T) {
	// Prepend an SSH banner to the KEXINIT packet.
	fields := [10]string{
		"curve25519-sha256", // kex
		"ssh-rsa",
		"aes256-ctr", // enc_c2s
		"aes256-ctr",
		"hmac-sha2-256", // mac_c2s
		"hmac-sha2-256",
		"none", // comp_c2s
		"none",
		"", "",
	}
	banner := []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
	raw := append(banner, buildSSHKexInit(fields)...)
	hash := ExtractHASH(raw)
	if hash == "" {
		t.Fatal("ExtractHASH with banner: expected non-empty HASSH")
	}
	want := expectedHASH(fields[0], fields[2], fields[4], fields[6])
	if hash != want {
		t.Errorf("HASSH with banner = %q, want %q", hash, want)
	}
}

func TestExtractHASH_NotSSH_ReturnsEmpty(t *testing.T) {
	// HTTP traffic — should not match.
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if h := ExtractHASH(payload); h != "" {
		t.Errorf("HTTP payload should return empty HASSH, got %q", h)
	}
}

func TestExtractHASH_TooShort_ReturnsEmpty(t *testing.T) {
	for _, n := range []int{0, 3, 5} {
		if h := ExtractHASH(make([]byte, n)); h != "" {
			t.Errorf("payload len %d: expected empty, got %q", n, h)
		}
	}
}

func TestExtractHASH_WrongMessageType_ReturnsEmpty(t *testing.T) {
	fields := [10]string{"kex", "", "enc", "", "mac", "", "comp", "", "", ""}
	raw := buildSSHKexInit(fields)
	raw[5] = 21 // Override message type (21 = SSH_MSG_NEWKEYS, not KEXINIT)
	if h := ExtractHASH(raw); h != "" {
		t.Errorf("wrong message type should return empty HASSH, got %q", h)
	}
}

func TestExtractHASH_EmptyKexAlgorithms_ReturnsEmpty(t *testing.T) {
	// kex_algorithms is empty — HASSH requires at least a non-empty kex field.
	fields := [10]string{"", "", "aes256-ctr", "", "hmac-sha2-256", "", "none", "", "", ""}
	raw := buildSSHKexInit(fields)
	if h := ExtractHASH(raw); h != "" {
		t.Errorf("empty kex_algorithms should return empty HASSH, got %q", h)
	}
}

func TestLookupHASH_KnownBad(t *testing.T) {
	for hash, want := range knownBadHasshHashes {
		desc, ok := LookupHASH(hash)
		if !ok {
			t.Errorf("LookupHASH(%q): expected match", hash)
		}
		if desc != want {
			t.Errorf("LookupHASH(%q): got %q, want %q", hash, desc, want)
		}
	}
}

func TestLookupHASH_Unknown(t *testing.T) {
	_, ok := LookupHASH("000000000000000000000000000000ff")
	if ok {
		t.Error("expected false for unknown HASSH")
	}
}

func TestLookupHASH_Empty(t *testing.T) {
	_, ok := LookupHASH("")
	if ok {
		t.Error("expected false for empty HASSH")
	}
}

func TestExtractHASH_DifferentAlgorithms_DifferentHashes(t *testing.T) {
	fields1 := [10]string{"curve25519-sha256", "", "aes256-ctr", "", "hmac-sha2-256", "", "none", "", "", ""}
	fields2 := [10]string{"diffie-hellman-group14-sha256", "", "aes128-ctr", "", "hmac-sha1", "", "zlib", "", "", ""}
	h1 := ExtractHASH(buildSSHKexInit(fields1))
	h2 := ExtractHASH(buildSSHKexInit(fields2))
	if h1 == "" || h2 == "" {
		t.Fatal("expected non-empty hashes")
	}
	if h1 == h2 {
		t.Error("different algorithm sets must produce different HASSH values")
	}
}
