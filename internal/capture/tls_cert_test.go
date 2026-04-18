package capture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"
)

// buildCertPayload wraps a DER-encoded certificate into a TLS Certificate
// handshake message so it can be fed to extractServerCert.
func buildCertPayload(derCert []byte) []byte {
	certLen := len(derCert)

	// Certificate handshake body:
	//   certificates_length(3) + cert_length(3) + cert_data
	certListLen := 3 + certLen
	body := make([]byte, 3+certListLen)
	body[0] = byte(certListLen >> 16)
	body[1] = byte(certListLen >> 8)
	body[2] = byte(certListLen)
	body[3] = byte(certLen >> 16)
	body[4] = byte(certLen >> 8)
	body[5] = byte(certLen)
	copy(body[6:], derCert)

	// Handshake header: type(1) + length(3)
	hsBodyLen := len(body)
	hs := make([]byte, 4+hsBodyLen)
	hs[0] = 0x0B // Certificate
	hs[1] = byte(hsBodyLen >> 16)
	hs[2] = byte(hsBodyLen >> 8)
	hs[3] = byte(hsBodyLen)
	copy(hs[4:], body)

	// TLS record header: content_type(1) + version(2) + length(2)
	recordLen := len(hs)
	record := make([]byte, 5+recordLen)
	record[0] = 0x16 // Handshake
	record[1] = 0x03
	record[2] = 0x03 // TLS 1.2
	binary.BigEndian.PutUint16(record[3:5], uint16(recordLen))
	copy(record[5:], hs)
	return record
}

// generateSelfSignedCert creates a minimal self-signed certificate for testing.
func generateSelfSignedCert(t *testing.T, template *x509.Certificate) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert create: %v", err)
	}
	return der
}

func TestExtractServerCert_SelfSigned(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "evil.c2.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der := generateSelfSignedCert(t, template)
	payload := buildCertPayload(der)

	info := extractServerCert(payload)
	if info == nil {
		t.Fatal("expected non-nil CertInfo")
	}
	if !info.IsSelfSigned {
		t.Error("expected IsSelfSigned=true")
	}
	if info.SubjectCN != "evil.c2.example" {
		t.Errorf("SubjectCN=%q, want evil.c2.example", info.SubjectCN)
	}
	if info.IsExpired {
		t.Error("cert should not be expired")
	}
}

func TestExtractServerCert_LongValidity(t *testing.T) {
	// > 10 years lifetime — typical of auto-generated C2 certs.
	notBefore := time.Now().Add(-time.Hour)
	notAfter := notBefore.Add(365 * 11 * 24 * time.Hour) // ~11 years
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "long-lived.example"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der := generateSelfSignedCert(t, template)
	info := extractServerCert(buildCertPayload(der))
	if info == nil {
		t.Fatal("expected non-nil CertInfo")
	}
	if info.ValidityDays <= 3650 {
		t.Errorf("ValidityDays=%d, expected > 3650 for 11-year cert", info.ValidityDays)
	}
}

func TestExtractServerCert_Expired(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "expired.example"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour), // expired 1 hour ago
	}
	der := generateSelfSignedCert(t, template)
	info := extractServerCert(buildCertPayload(der))
	if info == nil {
		t.Fatal("expected non-nil CertInfo")
	}
	if !info.IsExpired {
		t.Error("expected IsExpired=true")
	}
}

func TestExtractServerCert_IPAddressCN(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "192.168.1.100"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der := generateSelfSignedCert(t, template)
	info := extractServerCert(buildCertPayload(der))
	if info == nil {
		t.Fatal("expected non-nil CertInfo")
	}
	if !info.IsIPAddressCN {
		t.Errorf("expected IsIPAddressCN=true for CN=%q", info.SubjectCN)
	}
}

func TestExtractServerCert_WithSAN(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(5),
		Subject:      pkix.Name{CommonName: "legit.example.com"},
		DNSNames:     []string{"legit.example.com", "www.legit.example.com"},
		IPAddresses:  []net.IP{net.ParseIP("10.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der := generateSelfSignedCert(t, template)
	info := extractServerCert(buildCertPayload(der))
	if info == nil {
		t.Fatal("expected non-nil CertInfo")
	}
	if !info.HasSAN {
		t.Error("expected HasSAN=true for cert with DNS names")
	}
}

func TestExtractServerCert_NonTLSPayload_ReturnsNil(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if extractServerCert(payload) != nil {
		t.Error("expected nil for non-TLS payload")
	}
}

func TestExtractServerCert_TruncatedPayload_ReturnsNil(t *testing.T) {
	payload := []byte{0x16, 0x03, 0x03, 0x00, 0x10, 0x0B}
	if extractServerCert(payload) != nil {
		t.Error("expected nil for truncated TLS payload")
	}
}

func TestExtractServerCert_EmptyPayload_ReturnsNil(t *testing.T) {
	if extractServerCert(nil) != nil {
		t.Error("expected nil for nil payload")
	}
	if extractServerCert([]byte{}) != nil {
		t.Error("expected nil for empty payload")
	}
}

func TestExtractServerCert_ClientHello_ReturnsNil(t *testing.T) {
	// Handshake type 0x01 (ClientHello) — not a Certificate message.
	payload := []byte{0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}
	if extractServerCert(payload) != nil {
		t.Error("expected nil for ClientHello payload (type 0x01, not 0x0B)")
	}
}

func TestExtractServerCert_CorruptDER_ReturnsNil(t *testing.T) {
	// Build a valid wrapper but stuff garbage as DER bytes.
	garbage := make([]byte, 100)
	for i := range garbage {
		garbage[i] = byte(i)
	}
	payload := buildCertPayload(garbage)
	// Should return nil, not panic.
	info := extractServerCert(payload)
	if info != nil {
		t.Error("expected nil for corrupt DER content")
	}
}
