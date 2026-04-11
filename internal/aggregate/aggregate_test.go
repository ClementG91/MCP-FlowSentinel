package aggregate

import (
	"strings"
	"testing"
	"time"
)

// ─── beaconingScore tests ──────────────────────────────────────────────────────

func TestBeaconingScore_Regular(t *testing.T) {
	// 10 packets exactly 1 s apart → strong beacon (CV ≈ 0).
	ts := make([]time.Time, 10)
	base := time.Now()
	for i := range ts {
		ts[i] = base.Add(time.Duration(i) * time.Second)
	}
	got, reason := beaconingScore(ts)
	if got < 3.0 {
		t.Errorf("expected score ≥ 3.0 for perfectly regular intervals, got %.2f", got)
	}
	if reason == "" {
		t.Error("expected non-empty reason for beaconing")
	}
}

func TestBeaconingScore_Irregular(t *testing.T) {
	// 10 packets with wildly varying gaps → no beaconing.
	gaps := []time.Duration{
		10 * time.Millisecond,
		5 * time.Second,
		200 * time.Millisecond,
		8 * time.Second,
		50 * time.Millisecond,
		3 * time.Second,
		700 * time.Millisecond,
		4 * time.Second,
		100 * time.Millisecond,
	}
	ts := make([]time.Time, len(gaps)+1)
	ts[0] = time.Now()
	for i, g := range gaps {
		ts[i+1] = ts[i].Add(g)
	}
	got, _ := beaconingScore(ts)
	if got > 0 {
		t.Errorf("expected 0 score for irregular intervals, got %.2f", got)
	}
}

func TestBeaconingScore_TooFew(t *testing.T) {
	// Fewer than 3 packets → cannot compute inter-arrival variance.
	ts := []time.Time{
		time.Now(),
		time.Now().Add(time.Second),
	}
	got, _ := beaconingScore(ts)
	if got != 0 {
		t.Errorf("expected 0 score with only 2 timestamps, got %.2f", got)
	}
}

// ─── score() tests ─────────────────────────────────────────────────────────────

func makeRec(opts ...func(*FlowRecord)) FlowRecord {
	rec := FlowRecord{}
	for _, o := range opts {
		o(&rec)
	}
	return rec
}

func withBinaryPath(p string) func(*FlowRecord) { return func(r *FlowRecord) { r.BinaryPath = p } }
func withCmdline(c string) func(*FlowRecord)     { return func(r *FlowRecord) { r.Cmdline = c } }
func withPID(pid int32) func(*FlowRecord)         { return func(r *FlowRecord) { r.PID = pid } }
func withRDNS(h string) func(*FlowRecord)         { return func(r *FlowRecord) { r.ReverseDNS = h } }

func TestScore_KnownBadPort(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "8.8.8.8", DstPort: 4444, Proto: "TCP"}
	rec := makeRec(withRDNS("some.host")) // suppress DNS penalty
	s, reasons := score(key, rec, nil)
	if s < 4.0 {
		t.Errorf("expected score ≥ 4.0 for port 4444, got %.2f", s)
	}
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "Metasploit") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'Metasploit' in reasons, got %v", reasons)
	}
}

func TestScore_StandardPort(t *testing.T) {
	// Port 443 should not add a port penalty.
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: 443, Proto: "TCP"}
	rec := makeRec(withRDNS("cloudflare.com"))
	s, reasons := score(key, rec, nil)
	for _, r := range reasons {
		if strings.Contains(r, "non-standard port") || strings.Contains(r, "high-risk port") {
			t.Errorf("unexpected port reason %q for port 443 (score=%.2f)", r, s)
		}
	}
}

func TestScore_EphemeralPort(t *testing.T) {
	// Ephemeral port (≥49152) on a return flow must NOT be scored.
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "192.168.1.5", DstPort: 55000, Proto: "TCP"}
	rec := makeRec(withRDNS("internal.host"))
	_, reasons := score(key, rec, nil)
	for _, r := range reasons {
		if strings.Contains(r, "non-standard port") {
			t.Errorf("ephemeral port 55000 should not trigger port reason, got %q", r)
		}
	}
}

func TestScore_SuspiciousPath(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.2", DstIP: "1.2.3.4", DstPort: 80, Proto: "TCP"}
	rec := makeRec(withPID(1234), withBinaryPath("/tmp/backdoor"), withRDNS("host.example"))
	s, reasons := score(key, rec, nil)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "suspicious path") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected suspicious-path reason, got %v (score=%.2f)", reasons, s)
	}
	if s < 2.5 {
		t.Errorf("expected score ≥ 2.5 for /tmp/ binary, got %.2f", s)
	}
}

func TestScore_SuspiciousCmdline(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.3", DstIP: "5.6.7.8", DstPort: 443, Proto: "TCP"}
	rec := makeRec(withRDNS("cdn.host"), withCmdline("python3 -c 'import socket; ...'"))
	s, reasons := score(key, rec, nil)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "cmdline") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected cmdline reason, got %v (score=%.2f)", reasons, s)
	}
	if s < 2.0 {
		t.Errorf("expected score ≥ 2.0 for suspicious cmdline, got %.2f", s)
	}
}

func TestScore_CmdlineRegexWhitespaceVariant(t *testing.T) {
	// Regex must catch "base64  -d" (extra space) — missed by old exact-string matching.
	key := FlowKey{SrcIP: "10.0.0.3", DstIP: "5.6.7.8", DstPort: 443, Proto: "TCP"}
	rec := makeRec(withRDNS("cdn.host"), withCmdline("base64  -d < /tmp/payload | bash"))
	_, reasons := score(key, rec, nil)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "cmdline") {
			found = true
		}
	}
	if !found {
		t.Errorf("regex should catch 'base64  -d' (extra whitespace), got %v", reasons)
	}
}

func withDstIP(ip string) func(*FlowRecord) { return func(r *FlowRecord) { r.DstIP = ip } }

func TestScore_PrivateIPNoDNSPenalty(t *testing.T) {
	// RFC 1918 destinations must NOT receive the DNS penalty — they never have PTR records.
	for _, dstIP := range []string{"10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"} {
		key := FlowKey{SrcIP: "10.0.0.2", DstIP: dstIP, DstPort: 8080, Proto: "TCP"}
		rec := makeRec(withDstIP(dstIP)) // DstIP must match key so isPrivateIP is evaluated correctly
		_, reasons := score(key, rec, nil)
		for _, r := range reasons {
			if strings.Contains(r, "reverse DNS") {
				t.Errorf("private IP %s should not receive DNS penalty, got reason: %q", dstIP, r)
			}
		}
	}
}

func TestScore_PublicIPGetsDNSPenalty(t *testing.T) {
	// A public IP with no PTR record should still score the DNS penalty.
	// Port 80 avoids port-score noise; DstIP must be set on rec for isPrivateIP to evaluate.
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "203.0.113.1", DstPort: 80, Proto: "TCP"}
	rec := makeRec(withDstIP("203.0.113.1"), withRDNS("")) // explicit empty RDNS
	_, reasons := score(key, rec, nil)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "reverse DNS") {
			found = true
		}
	}
	if !found {
		t.Errorf("public IP with no PTR should get DNS penalty, reasons: %v", reasons)
	}
}
