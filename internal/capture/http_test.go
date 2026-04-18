package capture

import (
	"testing"
)

// ─── extractHTTPInfo ──────────────────────────────────────────────────────────

func TestExtractHTTPInfo_GET(t *testing.T) {
	payload := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestAgent/1.0\r\n\r\n")
	info := extractHTTPInfo(payload)
	if info == nil {
		t.Fatal("expected non-nil HTTPInfo for valid GET request")
	}
	if !info.IsRequest {
		t.Error("expected IsRequest=true")
	}
	if info.Method != "GET" {
		t.Errorf("Method=%q, want GET", info.Method)
	}
	if info.URI != "/index.html" {
		t.Errorf("URI=%q, want /index.html", info.URI)
	}
	if info.Host != "example.com" {
		t.Errorf("Host=%q, want example.com", info.Host)
	}
	if info.UserAgent != "TestAgent/1.0" {
		t.Errorf("UserAgent=%q, want TestAgent/1.0", info.UserAgent)
	}
}

func TestExtractHTTPInfo_POST(t *testing.T) {
	payload := []byte("POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n")
	info := extractHTTPInfo(payload)
	if info == nil {
		t.Fatal("expected non-nil HTTPInfo for POST")
	}
	if info.Method != "POST" {
		t.Errorf("Method=%q, want POST", info.Method)
	}
}

func TestExtractHTTPInfo_CONNECT(t *testing.T) {
	payload := []byte("CONNECT evil.c2.example.com:443 HTTP/1.1\r\nHost: evil.c2.example.com:443\r\n\r\n")
	info := extractHTTPInfo(payload)
	if info == nil {
		t.Fatal("expected non-nil HTTPInfo for CONNECT")
	}
	if info.Method != "CONNECT" {
		t.Errorf("Method=%q, want CONNECT", info.Method)
	}
}

func TestExtractHTTPInfo_Response(t *testing.T) {
	payload := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n")
	info := extractHTTPInfo(payload)
	if info == nil {
		t.Fatal("expected non-nil HTTPInfo for response")
	}
	if info.IsRequest {
		t.Error("expected IsRequest=false for response")
	}
	if info.StatusCode != 200 {
		t.Errorf("StatusCode=%d, want 200", info.StatusCode)
	}
}

func TestExtractHTTPInfo_TLSPayload_ReturnsNil(t *testing.T) {
	// TLS handshake starts with 0x16 — must not be parsed as HTTP.
	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00}
	info := extractHTTPInfo(payload)
	if info != nil {
		t.Error("expected nil for TLS payload")
	}
}

func TestExtractHTTPInfo_BinaryPayload_ReturnsNil(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D}
	info := extractHTTPInfo(payload)
	if info != nil {
		t.Error("expected nil for binary payload")
	}
}

func TestExtractHTTPInfo_TooShort_ReturnsNil(t *testing.T) {
	info := extractHTTPInfo([]byte("GET /"))
	if info != nil {
		t.Error("expected nil for payload shorter than minimum HTTP request")
	}
}

func TestExtractHTTPInfo_NilPayload_ReturnsNil(t *testing.T) {
	info := extractHTTPInfo(nil)
	if info != nil {
		t.Error("expected nil for nil payload")
	}
}

// ─── IsKnownBadUserAgent ──────────────────────────────────────────────────────

func TestIsKnownBadUserAgent_CobaltStrike(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
	if !IsKnownBadUserAgent(ua) {
		t.Errorf("expected Cobalt Strike default UA to be flagged: %q", ua)
	}
}

func TestIsKnownBadUserAgent_Metasploit(t *testing.T) {
	ua := "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
	if !IsKnownBadUserAgent(ua) {
		t.Errorf("expected Metasploit Meterpreter UA to be flagged: %q", ua)
	}
}

func TestIsKnownBadUserAgent_PythonUrllib(t *testing.T) {
	if !IsKnownBadUserAgent("python-urllib/3.10") {
		t.Error("expected python-urllib to be flagged")
	}
}

func TestIsKnownBadUserAgent_Legitimate_NotFlagged(t *testing.T) {
	legitimate := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
		"curl/7.88.1",
		"Go-http-client/1.1",
	}
	for _, ua := range legitimate {
		if IsKnownBadUserAgent(ua) {
			t.Errorf("legitimate UA incorrectly flagged: %q", ua)
		}
	}
}

func TestIsKnownBadUserAgent_Empty(t *testing.T) {
	// Empty UA is handled separately in scoring (len < 5), not via this function.
	if IsKnownBadUserAgent("") {
		t.Error("empty UA should not match known-bad patterns")
	}
}

// ─── IsHTTP2Preface ───────────────────────────────────────────────────────────

func TestIsHTTP2Preface_Valid(t *testing.T) {
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if !IsHTTP2Preface(preface) {
		t.Error("expected HTTP/2 preface to be detected")
	}
}

func TestIsHTTP2Preface_WithExtraData(t *testing.T) {
	payload := append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), []byte{0x00, 0x00, 0x0C}...)
	if !IsHTTP2Preface(payload) {
		t.Error("expected HTTP/2 preface detected with trailing data")
	}
}

func TestIsHTTP2Preface_HTTP1_NotMatched(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if IsHTTP2Preface(payload) {
		t.Error("HTTP/1.1 request should not match HTTP/2 preface")
	}
}

func TestIsHTTP2Preface_TooShort(t *testing.T) {
	if IsHTTP2Preface([]byte("PRI * HTTP/2")) {
		t.Error("truncated preface should not match")
	}
}

// ─── IsHighEntropyURI ─────────────────────────────────────────────────────────

func TestIsHighEntropyURI_RandomPath(t *testing.T) {
	// Typical C2 random check-in path.
	uri := "/xK9mQpRvL3nBwYjT"
	if !IsHighEntropyURI(uri) {
		t.Errorf("expected high-entropy URI to be detected: %q", uri)
	}
}

func TestIsHighEntropyURI_NormalPath(t *testing.T) {
	paths := []string{"/index.html", "/api/users", "/static/logo.png"}
	for _, p := range paths {
		if IsHighEntropyURI(p) {
			t.Errorf("normal URI incorrectly flagged as high-entropy: %q", p)
		}
	}
}

func TestIsHighEntropyURI_TooShort(t *testing.T) {
	if IsHighEntropyURI("/ab") {
		t.Error("short URI should not be flagged")
	}
}

// ─── IsGRPCFrames ─────────────────────────────────────────────────────────────

func buildGRPCFrame(compFlag byte, data []byte) []byte {
	frame := make([]byte, 5+len(data))
	frame[0] = compFlag
	frame[1] = byte(len(data) >> 24)
	frame[2] = byte(len(data) >> 16)
	frame[3] = byte(len(data) >> 8)
	frame[4] = byte(len(data))
	copy(frame[5:], data)
	return frame
}

func TestIsGRPCFrames_TwoFrames(t *testing.T) {
	f1 := buildGRPCFrame(0, []byte{0x0A, 0x05, 'h', 'e', 'l', 'l', 'o'})
	f2 := buildGRPCFrame(0, []byte{0x0A, 0x05, 'w', 'o', 'r', 'l', 'd'})
	payload := append(f1, f2...)
	if !IsGRPCFrames(payload) {
		t.Error("expected 2 valid gRPC frames to be detected")
	}
}

func TestIsGRPCFrames_CompressedFrame(t *testing.T) {
	f1 := buildGRPCFrame(1, []byte{0x01, 0x02, 0x03})
	f2 := buildGRPCFrame(0, []byte{0x04, 0x05, 0x06})
	payload := append(f1, f2...)
	if !IsGRPCFrames(payload) {
		t.Error("expected compressed-flag=1 frames to be accepted")
	}
}

func TestIsGRPCFrames_SingleFrame_NotDetected(t *testing.T) {
	f1 := buildGRPCFrame(0, []byte{0x01, 0x02})
	if IsGRPCFrames(f1) {
		t.Error("single frame should not be flagged (requires 2+)")
	}
}

func TestIsGRPCFrames_InvalidCompressFlag_NotDetected(t *testing.T) {
	// compress flag = 2 is invalid per gRPC spec.
	payload := []byte{0x02, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03}
	if IsGRPCFrames(payload) {
		t.Error("invalid compress flag (>1) should reject the payload")
	}
}

func TestIsGRPCFrames_OversizedMessage_NotDetected(t *testing.T) {
	// Message length = 17 MB > 16 MB limit.
	payload := []byte{0x00, 0x01, 0x10, 0x00, 0x01}
	if IsGRPCFrames(payload) {
		t.Error("message length >16 MB should be rejected")
	}
}

func TestIsGRPCFrames_TooShort_NotDetected(t *testing.T) {
	if IsGRPCFrames([]byte{0x00, 0x00, 0x00}) {
		t.Error("payload shorter than 5 bytes should not match")
	}
}

func TestIsGRPCFrames_EmptyPayload_NotDetected(t *testing.T) {
	if IsGRPCFrames(nil) {
		t.Error("nil payload should not match")
	}
	if IsGRPCFrames([]byte{}) {
		t.Error("empty payload should not match")
	}
}

// ─── IsStandardHTTPPort ───────────────────────────────────────────────────────

func TestIsStandardHTTPPort(t *testing.T) {
	standard := []uint16{80, 8080, 8000, 8888, 3000}
	for _, p := range standard {
		if !IsStandardHTTPPort(p) {
			t.Errorf("port %d should be standard", p)
		}
	}
	nonStandard := []uint16{443, 4444, 1337, 9001}
	for _, p := range nonStandard {
		if IsStandardHTTPPort(p) {
			t.Errorf("port %d should not be standard HTTP", p)
		}
	}
}
