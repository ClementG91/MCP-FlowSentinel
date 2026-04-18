// Package capture — tls_cert.go extracts and analyses TLS server certificates
// from raw TCP payloads.
//
// The TLS ServerCertificate message (handshake type 0x0B) is transmitted in
// cleartext before the session is established, so we can parse it without
// decryption. This reveals certificate characteristics that are strong
// indicators of C2 infrastructure:
//   - Self-signed certificates (issuer == subject)
//   - Certificates with very long validity (> 10 years, common C2 default)
//   - Certificates whose CN is an IP address
//   - Certificates with no Subject Alternative Name
//   - Expired certificates
package capture

import (
	"crypto/x509"
	"encoding/binary"
	"net"
	"time"
)

// CertInfo holds the security-relevant fields extracted from the first
// certificate in a TLS Certificate message chain.
type CertInfo struct {
	IsSelfSigned  bool
	IsExpired     bool
	ValidityDays  int    // total lifetime in days
	SubjectCN     string
	IssuerCN      string
	NotBefore     time.Time
	NotAfter      time.Time
	HasSAN        bool
	IsIPAddressCN bool // CN is a raw IP address (unusual for legitimate certs post-2017)
}

// extractServerCert attempts to parse a TLS Certificate handshake message
// from a raw TCP payload and returns a CertInfo, or nil if the payload is not
// a TLS Certificate message or parsing fails.
//
// Supported formats:
//   - TLS 1.0–1.3 Certificate message (handshake type 0x0B)
//   - Single-record payloads (the common case for first-flight server responses)
//
// The function is safe to call on any TCP payload — it returns nil quickly
// when the payload cannot be a Certificate message.
func extractServerCert(payload []byte) *CertInfo {
	// ── TLS record header ──────────────────────────────────────────────────────
	// content_type(1) version(2) length(2) → minimum 5 bytes
	if len(payload) < 9 {
		return nil
	}
	// Content type must be 0x16 (Handshake).
	if payload[0] != 0x16 {
		return nil
	}
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if len(payload) < 5+recordLen {
		return nil
	}

	hs := payload[5 : 5+recordLen]

	// ── Handshake header ───────────────────────────────────────────────────────
	// msg_type(1) length(3)
	if len(hs) < 4 {
		return nil
	}
	// Handshake type 0x0B = Certificate.
	if hs[0] != 0x0B {
		return nil
	}
	hsBodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsBodyLen {
		return nil
	}
	body := hs[4 : 4+hsBodyLen]

	// ── Certificate list ───────────────────────────────────────────────────────
	// certificates_length(3) then repeated: cert_length(3) + DER bytes
	if len(body) < 3 {
		return nil
	}
	listLen := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
	if len(body) < 3+listLen || listLen < 3 {
		return nil
	}
	certData := body[3 : 3+listLen]

	// Parse only the first (leaf) certificate.
	if len(certData) < 3 {
		return nil
	}
	firstCertLen := int(certData[0])<<16 | int(certData[1])<<8 | int(certData[2])
	if len(certData) < 3+firstCertLen || firstCertLen == 0 {
		return nil
	}
	derBytes := certData[3 : 3+firstCertLen]

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil
	}

	return analyzeCert(cert)
}

// analyzeCert extracts security-relevant fields from a parsed x509 certificate.
func analyzeCert(cert *x509.Certificate) *CertInfo {
	now := time.Now()
	info := &CertInfo{
		SubjectCN:    cert.Subject.CommonName,
		IssuerCN:     cert.Issuer.CommonName,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		ValidityDays: int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24),
		IsExpired:    now.After(cert.NotAfter),
		HasSAN:       len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0,
	}

	// Self-signed: issuer matches subject on all significant fields.
	info.IsSelfSigned = cert.Subject.String() == cert.Issuer.String()

	// IP address CN: common with auto-generated C2 certs (e.g. Cobalt Strike,
	// Metasploit self-signed certs for reverse HTTPS).
	info.IsIPAddressCN = net.ParseIP(cert.Subject.CommonName) != nil

	return info
}
