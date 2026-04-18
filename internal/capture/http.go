// Package capture — http.go provides lightweight HTTP/1.1 and HTTP/2 detection
// from raw TCP payload bytes.
//
// The parser is intentionally minimal: it uses net/http's ReadRequest /
// ReadResponse to avoid hand-rolling header parsing (which is error-prone),
// but wraps every call in recover() so that malformed payloads can never
// panic the capture goroutine.
package capture

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"math"
	"net/http"
	"strings"
)

// HTTPInfo carries the fields extracted from an HTTP/1.1 request or response.
type HTTPInfo struct {
	IsRequest   bool
	Method      string // "GET", "POST", "CONNECT", …
	URI         string // request-target (first 256 chars)
	Host        string // Host header value
	UserAgent   string // User-Agent header value
	ContentType string // Content-Type header (responses only)
	StatusCode  int    // HTTP status code (0 = request)
}

// extractHTTPInfo attempts to parse a TCP payload as HTTP/1.1.
// Returns nil when the payload is not HTTP (binary, TLS, empty, …).
// Never panics — malformed payloads are caught with recover().
func extractHTTPInfo(payload []byte) (info *HTTPInfo) {
	if len(payload) < 14 { // "GET / HTTP/1.1" = 14 bytes minimum
		return nil
	}

	// Fast pre-filter: avoid running the full parser on binary payloads.
	if !isHTTPRequestStart(payload) && !bytes.HasPrefix(payload, []byte("HTTP/")) {
		return nil
	}

	defer func() {
		if r := recover(); r != nil {
			info = nil // swallow parse panics from malformed payloads
		}
	}()

	if isHTTPRequestStart(payload) {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
		if err != nil {
			return nil
		}
		uri := req.URL.RequestURI()
		if len(uri) > 256 {
			uri = uri[:256]
		}
		return &HTTPInfo{
			IsRequest: true,
			Method:    req.Method,
			URI:       uri,
			Host:      req.Host,
			UserAgent: req.UserAgent(),
		}
	}

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(payload)), nil)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	return &HTTPInfo{
		IsRequest:   false,
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
	}
}

// httpMethods is the set of valid HTTP method prefixes used for fast pre-checks.
var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
	[]byte("HEAD "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
	[]byte("TRACE "),
}

func isHTTPRequestStart(b []byte) bool {
	for _, m := range httpMethods {
		if bytes.HasPrefix(b, m) {
			return true
		}
	}
	return false
}

// ─── Known-bad User-Agent detection ──────────────────────────────────────────

// knownBadUASubstrings is a list of User-Agent fragments associated with C2
// frameworks and RATs. Matching is case-insensitive substring search so that
// minor profile variants still trigger.
//
// Sources: Cobalt Strike Malleable C2 profiles, Sliver defaults, Empire,
// Metasploit Meterpreter HTTP stager, async-RAT, njRAT.
var knownBadUASubstrings = []string{
	// Cobalt Strike default Malleable profile — exact match common in the wild.
	"windows nt 6.3; trident/7.0; rv:11.0",
	// Cobalt Strike second common default.
	"windows nt 6.1; wow64; trident/7.0; rv:11.0",
	// Metasploit Meterpreter HTTP stager.
	"mozilla/4.0 (compatible; msie 6.0; windows nt 5.1)",
	// Metasploit Meterpreter second variant.
	"mozilla/4.0 (compatible; msie 7.0; windows nt 6.0)",
	// Empire C2 default.
	"windows nt 6.1; wow64; rv:40.0",
	// Sliver HTTP profile default (fixed string, not randomised by default).
	"mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/96.0",
	// Python urllib default (common in script tooling / auto-scanners).
	"python-urllib",
	// Go default HTTP client — legitimate but worth noting when on bad ports.
	// "go-http-client" — omitted (too many false positives from Go services)
	// Curl / wget are informational only — excluded from hard scoring here.
}

// IsKnownBadUserAgent returns true if the User-Agent matches a known C2/RAT pattern.
// Exported for use in tests and aggregate scoring.
func IsKnownBadUserAgent(ua string) bool {
	lower := strings.ToLower(ua)
	for _, bad := range knownBadUASubstrings {
		if strings.Contains(lower, bad) {
			return true
		}
	}
	return false
}

// ─── HTTP/2 detection ─────────────────────────────────────────────────────────

// http2ClientPreface is the fixed 24-byte client connection preface defined
// in RFC 7540 §3.5. It is identical across all implementations including C2
// frameworks (Sliver gRPC, BruteRatel HTTP2), making it a reliable indicator.
const http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// IsHTTP2Preface returns true if the payload starts with the HTTP/2 client preface.
func IsHTTP2Preface(payload []byte) bool {
	return len(payload) >= 24 && string(payload[:24]) == http2ClientPreface
}

// ─── URI entropy ─────────────────────────────────────────────────────────────

// IsHighEntropyURI returns true when the URI path component has Shannon entropy
// above 3.8 bits/char, indicating a randomly generated check-in path (common in
// Cobalt Strike and Metasploit HTTP stagers).
func IsHighEntropyURI(uri string) bool {
	if len(uri) < 8 {
		return false
	}
	// Strip query string for entropy calculation — static queries are benign.
	path := uri
	if i := strings.IndexByte(uri, '?'); i > 0 {
		path = uri[:i]
	}
	// Strip leading slash and extension before entropy check.
	path = strings.TrimPrefix(path, "/")
	if i := strings.LastIndexByte(path, '.'); i > 0 {
		path = path[:i]
	}
	if len(path) < 6 {
		return false
	}
	return shannonEntropy(path) > 3.8
}

// shannonEntropy computes the Shannon entropy of a string in bits/char.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int, 64)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// standardHTTPPorts are ports on which HTTP traffic is expected; HTTP on other
// ports earns an additional scoring penalty.
var standardHTTPPorts = map[uint16]bool{
	80: true, 8080: true, 8000: true, 8888: true, 3000: true,
}

// IsStandardHTTPPort returns true when the port is a well-known HTTP port.
func IsStandardHTTPPort(port uint16) bool { return standardHTTPPorts[port] }

// ─── gRPC detection ───────────────────────────────────────────────────────────

// IsGRPCFrames returns true when the payload looks like a sequence of gRPC
// Length-Prefixed Message frames (RFC: 5-byte header — 1 compressed-flag +
// 4-byte big-endian message length — followed by the message bytes).
//
// Two or more consecutive valid frames constitute a strong indicator of gRPC
// traffic. The check deliberately avoids requiring that all bytes be consumed:
// the tail of the payload may be a partial frame from a multi-packet message.
//
// False-positive rate is negligible: only well-formed binary streams whose
// leading bytes happen to be a valid compressed-flag (0 or 1) followed by a
// plausible length will match, and two consecutive such frames are astronomically
// unlikely in non-gRPC traffic.
func IsGRPCFrames(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}
	pos := 0
	frames := 0
	for pos+5 <= len(payload) && frames < 3 {
		compFlag := payload[pos]
		if compFlag > 1 {
			// Compressed flag must be 0 (uncompressed) or 1 (compressed).
			return false
		}
		msgLen := int(binary.BigEndian.Uint32(payload[pos+1 : pos+5]))
		if msgLen > 16*1024*1024 {
			// Message larger than 16 MB is not valid gRPC.
			return false
		}
		pos += 5 + msgLen
		frames++
	}
	return frames >= 2
}
