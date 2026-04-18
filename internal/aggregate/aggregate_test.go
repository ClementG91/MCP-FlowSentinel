package aggregate

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
)

// ─── beaconingScore tests ──────────────────────────────────────────────────────

func TestBeaconingScore_Regular(t *testing.T) {
	// 10 packets exactly 1 s apart → strong beacon (CV ≈ 0).
	ts := make([]time.Time, 10)
	base := time.Now()
	for i := range ts {
		ts[i] = base.Add(time.Duration(i) * time.Second)
	}
	got, reason := beaconingScore(ts, config.Default().Scoring)
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
	got, _ := beaconingScore(ts, config.Default().Scoring)
	if got > 0 {
		t.Errorf("expected 0 score for irregular intervals, got %.2f", got)
	}
}

func TestBeaconingScore_TooFew(t *testing.T) {
	// Fewer than 5 packets → CV is statistically meaningless.
	ts := []time.Time{
		time.Now(),
		time.Now().Add(time.Second),
		time.Now().Add(2 * time.Second),
		time.Now().Add(3 * time.Second),
	}
	got, _ := beaconingScore(ts, config.Default().Scoring)
	if got != 0 {
		t.Errorf("expected 0 score with only 4 timestamps, got %.2f", got)
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
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "203.0.113.1", DstPort: 80, Proto: "TCP"}
	rec := makeRec(withDstIP("203.0.113.1"), withRDNS(""))
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

// ─── riskLabel ─────────────────────────────────────────────────────────────────

func TestRiskLabel(t *testing.T) {
	tests := []struct{ score float64; want string }{
		{10.0, "CRITICAL"},
		{7.0, "CRITICAL"},
		{6.9, "HIGH"},
		{5.0, "HIGH"},
		{4.9, "MEDIUM"},
		{2.0, "MEDIUM"},
		{1.9, "LOW"},
		{0.0, "LOW"},
	}
	for _, tc := range tests {
		if got := riskLabel(tc.score); got != tc.want {
			t.Errorf("riskLabel(%.1f) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

// ─── shannonEntropy ───────────────────────────────────────────────────────────

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		s    string
		want float64 // approximate lower bound to assert non-trivially
	}{
		{"", 0},
		{"aaaa", 0},           // uniform → entropy = 0
		{"ab", 1.0},           // 2 equiprobable chars → 1 bit
		{"abcd", 2.0},         // 4 equiprobable chars → 2 bits
		{"aHk3mXpQ2", 3.0},   // high entropy, > 3 bits
	}
	for _, tc := range tests {
		got := shannonEntropy(tc.s)
		if got < tc.want-0.001 {
			t.Errorf("shannonEntropy(%q) = %.3f, want ≥ %.3f", tc.s, got, tc.want)
		}
	}
}

// ─── isHighEntropyDomain ──────────────────────────────────────────────────────

func TestIsHighEntropyDomain(t *testing.T) {
	tests := []struct {
		fqdn string
		want bool
	}{
		// Clearly normal domains
		{"example.com", false},
		{"www.google.com", false},
		{"api.github.com", false},
		// Top-level only — no subdomain to analyze
		{"google.com", false},
		// High-entropy subdomain — 20 fully distinct chars → ~4.3 bits/char > 3.5
		{"zXpQmVwBrNkJsDgTyFhc.example.com", true},
		// Very long label (> 40 chars) — DNS tunnel indicator
		{"averylonglabelthatexceedsfortycharactersinlength.example.com", true},
		// Trailing dot (FQDN notation)
		{"normal.example.com.", false},
	}
	for _, tc := range tests {
		got := isHighEntropyDomain(tc.fqdn)
		if got != tc.want {
			t.Errorf("isHighEntropyDomain(%q) = %v, want %v", tc.fqdn, got, tc.want)
		}
	}
}

// ─── computeCleanSignals ──────────────────────────────────────────────────────

func TestComputeCleanSignals_LowScore_PopulatesSignals(t *testing.T) {
	rec := FlowRecord{
		DstPort:        443,
		ReverseDNS:     "example.com",
		TLSSNIName:     "example.com",
		Country:        "US",
		GeoHighRisk:    false,
		SuspicionScore: 0.0,
	}
	signals := computeCleanSignals(rec)
	if len(signals) == 0 {
		t.Error("expected clean signals for low-score flow, got none")
	}
	found443 := false
	for _, s := range signals {
		if strings.Contains(s, "HTTPS") || strings.Contains(s, "443") {
			found443 = true
		}
	}
	if !found443 {
		t.Errorf("expected HTTPS/443 signal, got: %v", signals)
	}
}

func TestComputeCleanSignals_HighScore_ReturnsNil(t *testing.T) {
	rec := FlowRecord{
		DstPort:        443,
		ReverseDNS:     "example.com",
		SuspicionScore: 5.0,
	}
	if signals := computeCleanSignals(rec); signals != nil {
		t.Errorf("high-score flow should not have clean signals, got: %v", signals)
	}
}

// ─── Aggregator.Add + Finalize (no pcap, no process resolver) ────────────────

func TestAggregatorAddAndFinalize_BasicFlow(t *testing.T) {
	agg := &Aggregator{}

	now := time.Now()
	for i := 0; i < 10; i++ {
		agg.Add(PacketEvent{
			SrcIP:      net.ParseIP("10.0.0.1"),
			DstIP:      net.ParseIP("8.8.8.8"),
			SrcPort:    12345,
			DstPort:    53,
			Proto:      "UDP",
			PayloadLen: 64,
			Timestamp:  now.Add(time.Duration(i) * time.Second),
		})
	}

	records := agg.Finalize(nil)
	if len(records) != 1 {
		t.Fatalf("expected 1 flow record, got %d", len(records))
	}
	r := records[0]
	if r.SrcIP != "10.0.0.1" {
		t.Errorf("SrcIP = %q, want 10.0.0.1", r.SrcIP)
	}
	if r.DstIP != "8.8.8.8" {
		t.Errorf("DstIP = %q, want 8.8.8.8", r.DstIP)
	}
	if r.PacketCount != 10 {
		t.Errorf("PacketCount = %d, want 10", r.PacketCount)
	}
	if r.ByteCount != 640 {
		t.Errorf("ByteCount = %d, want 640", r.ByteCount)
	}
	if r.RiskLevel == "" {
		t.Error("RiskLevel should not be empty after Finalize")
	}
}

func TestAggregatorAdd_AccumulatesDNSQueries(t *testing.T) {
	agg := &Aggregator{}
	now := time.Now()

	for _, q := range []string{"evil.com", "evil.com", "other.com"} {
		agg.Add(PacketEvent{
			SrcIP:     net.ParseIP("10.0.0.1"),
			DstIP:     net.ParseIP("8.8.8.8"),
			SrcPort:   54321,
			DstPort:   53,
			Proto:     "UDP",
			Timestamp: now,
			DNSQuery:  q,
		})
	}

	records := agg.Finalize(nil)
	if len(records) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(records))
	}
	// "evil.com" and "other.com" are distinct — deduplication should yield 2.
	if len(records[0].DNSQueries) != 2 {
		t.Errorf("expected 2 unique DNS queries, got %d: %v", len(records[0].DNSQueries), records[0].DNSQueries)
	}
}

func TestAggregatorAdd_AccumulatesTLSSNI(t *testing.T) {
	agg := &Aggregator{}
	now := time.Now()

	for _, sni := range []string{"example.com", "example.com", "other.net"} {
		agg.Add(PacketEvent{
			SrcIP:      net.ParseIP("10.0.0.1"),
			DstIP:      net.ParseIP("1.2.3.4"),
			SrcPort:    12345,
			DstPort:    443,
			Proto:      "TCP",
			Timestamp:  now,
			TLSSNIName: sni,
		})
	}

	records := agg.Finalize(nil)
	if len(records) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(records))
	}
	// TLSSNIName should be set to the alphabetically first unique name.
	if records[0].TLSSNIName == "" {
		t.Error("TLSSNIName should be set when SNI data is present")
	}
}

func TestAggregatorFinalize_MultipleFlows_SortedByScore(t *testing.T) {
	agg := &Aggregator{}
	now := time.Now()

	// Flow 1: known-bad port → high score
	for i := 0; i < 5; i++ {
		agg.Add(PacketEvent{
			SrcIP:     net.ParseIP("10.0.0.1"),
			DstIP:     net.ParseIP("1.2.3.4"),
			SrcPort:   12345,
			DstPort:   4444, // Metasploit
			Proto:     "TCP",
			Timestamp: now.Add(time.Duration(i) * time.Second),
		})
	}

	// Flow 2: standard port → low score
	for i := 0; i < 5; i++ {
		agg.Add(PacketEvent{
			SrcIP:     net.ParseIP("10.0.0.1"),
			DstIP:     net.ParseIP("5.6.7.8"),
			SrcPort:   23456,
			DstPort:   443,
			Proto:     "TCP",
			Timestamp: now.Add(time.Duration(i) * time.Second),
		})
	}

	records := agg.Finalize(nil)
	if len(records) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(records))
	}
	if records[0].SuspicionScore < records[1].SuspicionScore {
		t.Errorf("Finalize should return flows sorted by score desc: got %.2f, %.2f",
			records[0].SuspicionScore, records[1].SuspicionScore)
	}
	if records[0].DstPort != 4444 {
		t.Errorf("highest-score flow should be port 4444, got %d", records[0].DstPort)
	}
}

// ─── isPrivateIP edge cases ───────────────────────────────────────────────────

func TestIsPrivateIP_InvalidIP_ReturnsTrueNoPanic(t *testing.T) {
	// Unparseable IPs must return true (no penalty) and must not panic.
	for _, bad := range []string{"", "not-an-ip", "999.999.999.999", "::gg"} {
		if !isPrivateIP(bad) {
			t.Errorf("isPrivateIP(%q) = false, want true for unparseable input", bad)
		}
	}
}

// ─── score edge cases ─────────────────────────────────────────────────────────

func TestScore_PIDWithoutBinaryPath_AddsReason(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "8.8.8.8", DstPort: 443, Proto: "TCP"}
	rec := makeRec(withRDNS("google.com"), withPID(1234)) // PID > 0, BinaryPath empty
	s, reasons := score(key, rec, nil)
	_ = s
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "binary path") {
			found = true
		}
	}
	if !found {
		t.Errorf("PID with no binary path should add reason, got: %v", reasons)
	}
}

func TestScore_GeoHighRisk_AddsReason(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "1.2.3.4", DstPort: 443, Proto: "TCP"}
	rec := makeRec(
		withRDNS("evil.host"),
		func(r *FlowRecord) {
			r.GeoHighRisk = true
			r.ASNOrg = "FranTech Solutions"
			r.DstIP = "1.2.3.4"
		},
	)
	s, reasons := score(key, rec, nil)
	if s <= 0 {
		t.Errorf("expected positive score for GeoHighRisk flow, got %.2f", s)
	}
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "high-risk ASN") {
			found = true
		}
	}
	if !found {
		t.Errorf("GeoHighRisk should add 'high-risk ASN' reason, got: %v", reasons)
	}
}

// ─── isHighEntropyDomain short-domain edge case ───────────────────────────────

func TestIsHighEntropyDomain_TwoPartDomain_ReturnsFalse(t *testing.T) {
	// Two-part domain (e.g. "example.com") has no subdomain to analyse.
	if isHighEntropyDomain("example.com") {
		t.Error("two-part domain should return false (no subdomain to score)")
	}
}

func TestIsHighEntropyDomain_EmptyLabel_Skipped(t *testing.T) {
	// Leading dot creates an empty label; should not panic or return true spuriously.
	result := isHighEntropyDomain(".example.com")
	t.Logf("isHighEntropyDomain('.example.com') = %v (empty label skipped)", result)
}

// ─── computeCleanSignals — port-specific branches ─────────────────────────────

func TestComputeCleanSignals_Port80(t *testing.T) {
	rec := FlowRecord{DstPort: 80, SuspicionScore: 0.0}
	signals := computeCleanSignals(rec)
	if len(signals) == 0 {
		t.Fatal("expected signals for port 80, got none")
	}
	if !strings.Contains(signals[0], "HTTP") {
		t.Errorf("expected HTTP signal for port 80, got: %v", signals)
	}
}

func TestComputeCleanSignals_Port53(t *testing.T) {
	rec := FlowRecord{DstPort: 53, SuspicionScore: 0.0}
	signals := computeCleanSignals(rec)
	if len(signals) == 0 {
		t.Fatal("expected signals for port 53, got none")
	}
	if !strings.Contains(signals[0], "DNS") {
		t.Errorf("expected DNS signal for port 53, got: %v", signals)
	}
}

func TestComputeCleanSignals_Port22(t *testing.T) {
	rec := FlowRecord{DstPort: 22, SuspicionScore: 0.0}
	signals := computeCleanSignals(rec)
	if len(signals) == 0 {
		t.Fatal("expected signals for port 22, got none")
	}
	if !strings.Contains(signals[0], "SSH") {
		t.Errorf("expected SSH signal for port 22, got: %v", signals)
	}
}

func TestComputeCleanSignals_OtherStandardPort(t *testing.T) {
	// Port 8080 is in standardPorts but not a named case → default branch.
	rec := FlowRecord{DstPort: 8080, SuspicionScore: 0.0}
	signals := computeCleanSignals(rec)
	if len(signals) == 0 {
		t.Fatal("expected signals for port 8080, got none")
	}
	if !strings.Contains(signals[0], "8080") {
		t.Errorf("expected port-number signal for 8080, got: %v", signals)
	}
}

// ─── Finalize — process resolver branch ──────────────────────────────────────

func TestFinalize_WithResolver_SetsProcessInfo(t *testing.T) {
	agg := &Aggregator{}
	now := time.Now()

	agg.Add(PacketEvent{
		SrcIP:     net.ParseIP("10.0.0.1"),
		DstIP:     net.ParseIP("8.8.8.8"),
		SrcPort:   12345,
		DstPort:   53,
		Proto:     "UDP",
		Timestamp: now,
	})

	resolver := ProcessResolver(func(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) *ProcessSnapshot {
		if srcIP == "10.0.0.1" {
			return &ProcessSnapshot{PID: 4321, Name: "test-proc", BinaryPath: "/usr/bin/test-proc"}
		}
		return nil
	})

	records := agg.Finalize(resolver)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	r := records[0]
	if r.ProcessName != "test-proc" {
		t.Errorf("ProcessName = %q, want test-proc", r.ProcessName)
	}
	if r.PID != 4321 {
		t.Errorf("PID = %d, want 4321", r.PID)
	}
	if r.BinaryPath != "/usr/bin/test-proc" {
		t.Errorf("BinaryPath = %q, want /usr/bin/test-proc", r.BinaryPath)
	}
}

// ─── Finalize — scan detection ────────────────────────────────────────────────

func TestFinalize_ScanDetection_ManyDestinations(t *testing.T) {
	agg := &Aggregator{}
	now := time.Now()

	// 20 unique destinations from the same source → "scan pattern" bonus (≥ 3.0 added).
	for i := 1; i <= 20; i++ {
		agg.Add(PacketEvent{
			SrcIP:     net.ParseIP("10.0.0.1"),
			DstIP:     net.ParseIP(fmt.Sprintf("1.0.0.%d", i)),
			SrcPort:   12345,
			DstPort:   80,
			Proto:     "TCP",
			Timestamp: now,
		})
	}

	records := agg.Finalize(nil)
	if len(records) != 20 {
		t.Fatalf("expected 20 flow records, got %d", len(records))
	}

	found := false
	for _, r := range records {
		for _, reason := range r.SuspicionReasons {
			if strings.Contains(reason, "scan pattern") {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Error("expected 'scan pattern' reason for 20 unique destinations, found none")
	}
}

func TestFinalize_ScanDetection_PossibleScan(t *testing.T) {
	agg := &Aggregator{}
	now := time.Now()

	// 8 unique destinations → "possible scan" bonus (1.5 added, 8 ≤ n < 20).
	for i := 1; i <= 8; i++ {
		agg.Add(PacketEvent{
			SrcIP:     net.ParseIP("10.0.0.2"),
			DstIP:     net.ParseIP(fmt.Sprintf("2.0.0.%d", i)),
			SrcPort:   23456,
			DstPort:   80,
			Proto:     "TCP",
			Timestamp: now,
		})
	}

	records := agg.Finalize(nil)
	found := false
	for _, r := range records {
		for _, reason := range r.SuspicionReasons {
			if strings.Contains(reason, "possible scan") {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Error("expected 'possible scan' reason for 8 unique destinations, found none")
	}
}

// ─── score — missing branches ─────────────────────────────────────────────────

func TestScore_HighByteCount_AddsReason(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "8.8.8.8", DstPort: 443, Proto: "TCP"}
	rec := makeRec(withRDNS("google.com"), func(r *FlowRecord) {
		r.ByteCount = 6 * 1024 * 1024 // 6 MB — above 5 MB threshold
	})
	_, reasons := score(key, rec, nil)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "high data transfer") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'high data transfer' reason for 6 MB flow, got: %v", reasons)
	}
}

func TestScore_CapAt10_IsEnforced(t *testing.T) {
	// Stack: knownBadPort(4.0) + suspiciousPath(2.5) + suspiciousCmdline(2.0)
	// + geoHighRisk(1.5) + noRDNS(0.8) = 10.8 → must be capped at 10.
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "203.0.113.1", DstPort: 4444, Proto: "TCP"}
	rec := makeRec(
		withPID(1234),
		withBinaryPath("/tmp/evil"),
		withCmdline("python3 -c 'import socket'"),
		func(r *FlowRecord) {
			r.GeoHighRisk = true
			r.ASNOrg = "Shady ASN"
			r.DstIP = "203.0.113.1"
		},
	)
	s, _ := score(key, rec, nil)
	if s != 10.0 {
		t.Errorf("score should be capped at 10.0, got %.2f", s)
	}
}

func TestScore_DNSExfiltration_AddsReason(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "8.8.8.8", DstPort: 53, Proto: "UDP"}
	rec := makeRec(withRDNS("dns.google"), func(r *FlowRecord) {
		// Label with high entropy — 20 random chars > 3.5 bits/char entropy
		r.DNSQueries = []string{"xKp2mVwBrNkJsDgTyFhc.evil.com"}
	})
	_, reasons := score(key, rec, nil)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "DNS exfiltration") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'DNS exfiltration' reason for high-entropy query, got: %v", reasons)
	}
}

func TestScore_BenignCmdline_NoReason(t *testing.T) {
	// Non-empty cmdline that matches NONE of the suspicious patterns.
	// Covers the "loop iterates but never matches" path.
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "8.8.8.8", DstPort: 443, Proto: "TCP"}
	rec := makeRec(withRDNS("google.com"), withCmdline("java -jar myapp.jar"))
	_, reasons := score(key, rec, nil)
	for _, r := range reasons {
		if strings.Contains(r, "cmdline") {
			t.Errorf("benign cmdline should not produce cmdline reason, got: %q", r)
		}
	}
}

func TestBeaconingScore_MeanNearZero_ReturnsZero(t *testing.T) {
	// All timestamps identical → all inter-arrival times = 0 ms → mean < 1 → return 0.
	now := time.Now()
	ts := []time.Time{now, now, now, now, now, now}
	got, _ := beaconingScore(ts, config.Default().Scoring)
	if got != 0 {
		t.Errorf("mean near zero should return 0 score, got %.2f", got)
	}
}

func TestBeaconingScore_PossibleBeaconing(t *testing.T) {
	// Alternating 800ms / 1200ms gaps: mean=1000ms, CV ≈ 0.2 → "possible beaconing".
	ts := make([]time.Time, 11)
	ts[0] = time.Now()
	for i := 1; i <= 10; i++ {
		var gap time.Duration
		if i%2 == 1 {
			gap = 800 * time.Millisecond
		} else {
			gap = 1200 * time.Millisecond
		}
		ts[i] = ts[i-1].Add(gap)
	}
	got, reason := beaconingScore(ts, config.Default().Scoring)
	if got < 1.5 {
		t.Errorf("alternating 800/1200ms gaps should score ≥1.5 (possible beaconing), got %.2f", got)
	}
	if !strings.Contains(reason, "beaconing") {
		t.Errorf("expected 'beaconing' in reason, got %q", reason)
	}
}

func TestFinalize_ScanDetection_FewDestinations_NoBonuses(t *testing.T) {
	agg := &Aggregator{}
	now := time.Now()

	// 3 unique destinations — below any scan threshold, no scan reason expected.
	for i := 1; i <= 3; i++ {
		agg.Add(PacketEvent{
			SrcIP:     net.ParseIP("10.0.0.3"),
			DstIP:     net.ParseIP(fmt.Sprintf("3.0.0.%d", i)),
			SrcPort:   34567,
			DstPort:   443,
			Proto:     "TCP",
			Timestamp: now,
		})
	}

	records := agg.Finalize(nil)
	for _, r := range records {
		for _, reason := range r.SuspicionReasons {
			if strings.Contains(reason, "scan") {
				t.Errorf("unexpected scan reason for only 3 destinations: %q", reason)
			}
		}
	}
}

func TestScore_NonStandardPort_LessThan49152_AddsReason(t *testing.T) {
	// Port 1234 is < 49152 and NOT in knownBadPorts or standardPorts.
	// This exercises the "else if key.DstPort < 49152 && !standardPorts[...]" branch.
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "1.2.3.4", DstPort: 1234, Proto: "TCP"}
	rec := makeRec(withRDNS("somehost.example"))
	s, reasons := score(key, rec, nil)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "non-standard port 1234") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'non-standard port 1234' reason, got reasons=%v (score=%.2f)", reasons, s)
	}
}

// ─── isBrowserProcess ─────────────────────────────────────────────────────────

func TestIsBrowserProcess(t *testing.T) {
	browsers := []string{"chrome", "Chrome", "CHROME", "chromium", "firefox", "msedge", "safari", "brave", "opera"}
	for _, name := range browsers {
		if !isBrowserProcess(name) {
			t.Errorf("isBrowserProcess(%q) = false, want true", name)
		}
	}
	nonBrowsers := []string{"curl", "python3", "nc", "wget", "implant", ""}
	for _, name := range nonBrowsers {
		if isBrowserProcess(name) {
			t.Errorf("isBrowserProcess(%q) = true, want false", name)
		}
	}
}

// ─── lateralMovementSignal ────────────────────────────────────────────────────

func TestLateralMovementSignal(t *testing.T) {
	cases := []struct {
		port     uint16
		wantPts  float64
		wantHint string
	}{
		{445, 2.5, "SMB"},
		{3389, 2.5, "RDP"},
		{5985, 2.0, "WinRM"},
		{5986, 2.0, "WinRM"},
		{135, 2.0, "WMI"},
		{389, 1.5, "LDAP"},
		{636, 1.5, "LDAPS"},
		{22, 1.0, "SSH"},
		{80, 0, ""},   // normal port — no signal
		{443, 0, ""},  // normal port — no signal
	}
	for _, tc := range cases {
		pts, reason := lateralMovementSignal(tc.port)
		if pts != tc.wantPts {
			t.Errorf("lateralMovementSignal(%d): pts=%.1f, want %.1f", tc.port, pts, tc.wantPts)
		}
		if tc.wantHint != "" && !strings.Contains(reason, tc.wantHint) {
			t.Errorf("lateralMovementSignal(%d): reason=%q should contain %q", tc.port, reason, tc.wantHint)
		}
	}
}

// ─── QUIC scoring ─────────────────────────────────────────────────────────────

func TestScore_QUIC_NonBrowserProcess_AddsReason(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "1.2.3.4", DstPort: 443, Proto: "UDP"}
	rec := makeRec(withRDNS("cdn.example"), func(r *FlowRecord) {
		r.IsQUIC = true
		r.ProcessName = "implant"
		r.DstIP = "1.2.3.4"
	})
	_, reasons := score(key, rec, nil)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "non-browser process") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected QUIC non-browser reason, got: %v", reasons)
	}
}

func TestScore_QUIC_BrowserProcess_NoReason(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "1.2.3.4", DstPort: 443, Proto: "UDP"}
	rec := makeRec(withRDNS("cdn.example"), func(r *FlowRecord) {
		r.IsQUIC = true
		r.ProcessName = "chrome"
		r.DstIP = "1.2.3.4"
	})
	_, reasons := score(key, rec, nil)
	for _, r := range reasons {
		if strings.Contains(r, "non-browser process") {
			t.Errorf("browser process should not produce QUIC reason, got: %q", r)
		}
	}
}

func TestScore_QUIC_HighRiskASN_AddsReason(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "5.5.5.5", DstPort: 443, Proto: "UDP"}
	rec := makeRec(withRDNS("evil.host"), func(r *FlowRecord) {
		r.IsQUIC = true
		r.GeoHighRisk = true
		r.ASNOrg = "BadASN"
		r.DstIP = "5.5.5.5"
	})
	_, reasons := score(key, rec, nil)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "QUIC connection to high-risk ASN") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected QUIC high-risk ASN reason, got: %v", reasons)
	}
}

// ─── Lateral movement scoring ─────────────────────────────────────────────────

func TestScore_LateralMovement_SMB_AddsReason(t *testing.T) {
	// RFC1918 → RFC1918 on port 445 should produce lateral movement reason.
	key := FlowKey{SrcIP: "192.168.1.10", DstIP: "192.168.1.20", DstPort: 445, Proto: "TCP"}
	rec := makeRec(func(r *FlowRecord) {
		r.SrcIP = "192.168.1.10"
		r.DstIP = "192.168.1.20"
	})
	_, reasons := score(key, rec, nil)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "SMB") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SMB lateral movement reason, got: %v", reasons)
	}
}

func TestScore_LateralMovement_PublicDst_NoLateralReason(t *testing.T) {
	// RFC1918 source → public destination should NOT trigger lateral movement.
	key := FlowKey{SrcIP: "192.168.1.10", DstIP: "203.0.113.5", DstPort: 445, Proto: "TCP"}
	rec := makeRec(withRDNS("ext.host"), func(r *FlowRecord) {
		r.SrcIP = "192.168.1.10"
		r.DstIP = "203.0.113.5"
	})
	_, reasons := score(key, rec, nil)
	for _, r := range reasons {
		if strings.Contains(r, "lateral") {
			t.Errorf("public destination should not trigger lateral movement, got: %q", r)
		}
	}
}

// ─── Protocol anomaly scoring ─────────────────────────────────────────────────

func TestScore_ProtocolAnomaly_NonTLSOn443_AddsReason(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "1.2.3.4", DstPort: 443, Proto: "TCP"}
	rec := makeRec(withRDNS("host.example"), func(r *FlowRecord) {
		r.PacketCount = 15
		// JA3Hash and IsQUIC remain zero-value → triggers non-TLS check
		r.DstIP = "1.2.3.4"
	})
	_, reasons := score(key, rec, nil)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "non-TLS traffic on TCP port 443") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected non-TLS reason for TCP 443 without JA3, got: %v", reasons)
	}
}

func TestScore_ProtocolAnomaly_TLSPresent_NoAnomalyReason(t *testing.T) {
	// If JA3 hash is set, the flow IS TLS — no anomaly reason expected.
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "1.2.3.4", DstPort: 443, Proto: "TCP"}
	rec := makeRec(withRDNS("host.example"), func(r *FlowRecord) {
		r.PacketCount = 15
		r.JA3Hash = "deadbeef00112233deadbeef00112233"
		r.DstIP = "1.2.3.4"
	})
	_, reasons := score(key, rec, nil)
	for _, r := range reasons {
		if strings.Contains(r, "non-TLS traffic on TCP port 443") {
			t.Errorf("TLS flow should not trigger non-TLS anomaly, got: %q", r)
		}
	}
}

func TestScore_ProtocolAnomaly_ExcessiveDNSoverTCP_AddsReason(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "8.8.8.8", DstPort: 53, Proto: "TCP"}
	rec := makeRec(withRDNS("dns.google"), func(r *FlowRecord) {
		r.ByteCount = 600 * 1024 // 600 KB > 512 KB threshold
		r.DstIP = "8.8.8.8"
	})
	_, reasons := score(key, rec, nil)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "excessive DNS over TCP") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected excessive DNS over TCP reason, got: %v", reasons)
	}
}

// ─── DNS response analysis scoring ───────────────────────────────────────────

func TestScore_NXDomainStorm_AddsReason(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "8.8.8.8", DstPort: 53, Proto: "UDP"}
	rec := makeRec(withRDNS("dns.google"), func(r *FlowRecord) {
		r.NXDomainCount = 10 // exceeds default threshold of 5
		r.DstIP = "8.8.8.8"
	})
	_, reasons := score(key, rec, nil)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "nxdomain storm") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected NXDOMAIN storm reason for count=10, got: %v", reasons)
	}
}

func TestScore_NXDomainBelowThreshold_NoReason(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "8.8.8.8", DstPort: 53, Proto: "UDP"}
	rec := makeRec(withRDNS("dns.google"), func(r *FlowRecord) {
		r.NXDomainCount = 3 // below default threshold of 5
		r.DstIP = "8.8.8.8"
	})
	_, reasons := score(key, rec, nil)
	for _, r := range reasons {
		if strings.Contains(r, "nxdomain storm") {
			t.Errorf("count=3 should not trigger storm reason, got: %q", r)
		}
	}
}

func TestScore_FastFluxTTL_AddsReason(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "8.8.8.8", DstPort: 53, Proto: "UDP"}
	rec := makeRec(withRDNS("dns.google"), func(r *FlowRecord) {
		r.MinDNSTTL = 10 // < 30s threshold
		r.DstIP = "8.8.8.8"
	})
	_, reasons := score(key, rec, nil)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "low dns ttl") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected low-TTL reason for MinDNSTTL=10, got: %v", reasons)
	}
}

func TestScore_NormalTTL_NoFastFluxReason(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "8.8.8.8", DstPort: 53, Proto: "UDP"}
	rec := makeRec(withRDNS("dns.google"), func(r *FlowRecord) {
		r.MinDNSTTL = 300 // normal 5-minute TTL
		r.DstIP = "8.8.8.8"
	})
	_, reasons := score(key, rec, nil)
	for _, r := range reasons {
		if strings.Contains(r, "low dns ttl") {
			t.Errorf("normal TTL=300 should not trigger fast-flux reason, got: %q", r)
		}
	}
}

// ─── DNS response accumulation in flowState ───────────────────────────────────

func TestAggregatorAdd_NXDomainCountAccumulates(t *testing.T) {
	agg := &Aggregator{}
	now := time.Now()

	for i := 0; i < 7; i++ {
		agg.Add(PacketEvent{
			SrcIP:       net.ParseIP("10.0.0.1"),
			DstIP:       net.ParseIP("8.8.8.8"),
			SrcPort:     12345,
			DstPort:     53,
			Proto:       "UDP",
			Timestamp:   now,
			DNSNXDomain: true,
		})
	}

	records := agg.Finalize(nil)
	if len(records) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(records))
	}
	if records[0].NXDomainCount != 7 {
		t.Errorf("NXDomainCount = %d, want 7", records[0].NXDomainCount)
	}
}

func TestAggregatorAdd_MinDNSTTL_TracksMinimum(t *testing.T) {
	agg := &Aggregator{}
	now := time.Now()

	for _, ttl := range []uint32{300, 60, 10, 120} {
		agg.Add(PacketEvent{
			SrcIP:         net.ParseIP("10.0.0.1"),
			DstIP:         net.ParseIP("8.8.8.8"),
			SrcPort:       12345,
			DstPort:       53,
			Proto:         "UDP",
			Timestamp:     now,
			DNSMinRespTTL: ttl,
		})
	}

	records := agg.Finalize(nil)
	if len(records) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(records))
	}
	if records[0].MinDNSTTL != 10 {
		t.Errorf("MinDNSTTL = %d, want 10 (minimum of 300/60/10/120)", records[0].MinDNSTTL)
	}
}

func TestAggregatorAdd_QUIC_Propagates(t *testing.T) {
	agg := &Aggregator{}
	now := time.Now()

	// First packet: not QUIC; second packet: QUIC — IsQUIC should be true.
	agg.Add(PacketEvent{
		SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("1.2.3.4"),
		SrcPort: 12345, DstPort: 443, Proto: "UDP", Timestamp: now,
	})
	agg.Add(PacketEvent{
		SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("1.2.3.4"),
		SrcPort: 12345, DstPort: 443, Proto: "UDP", Timestamp: now.Add(time.Second),
		IsQUIC: true,
	})

	records := agg.Finalize(nil)
	if len(records) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(records))
	}
	if !records[0].IsQUIC {
		t.Error("IsQUIC should be true when any packet in the flow is QUIC")
	}
}

// ─── Asymmetric upload detection ─────────────────────────────────────────────

func TestFinalize_AsymmetricUpload_AddsReason(t *testing.T) {
	agg := &Aggregator{}
	now := time.Now()

	// Forward flow: client sends 10 MB
	for i := 0; i < 5; i++ {
		agg.Add(PacketEvent{
			SrcIP:      net.ParseIP("10.0.0.1"),
			DstIP:      net.ParseIP("1.2.3.4"),
			SrcPort:    54321,
			DstPort:    443,
			Proto:      "TCP",
			PayloadLen: 2 * 1024 * 1024, // 2 MB each → 10 MB total
			Timestamp:  now.Add(time.Duration(i) * time.Second),
		})
	}
	// Reverse flow: server sends 100 KB
	for i := 0; i < 5; i++ {
		agg.Add(PacketEvent{
			SrcIP:      net.ParseIP("1.2.3.4"),
			DstIP:      net.ParseIP("10.0.0.1"),
			SrcPort:    443,
			DstPort:    54321,
			Proto:      "TCP",
			PayloadLen: 20 * 1024, // 20 KB each → 100 KB total
			Timestamp:  now.Add(time.Duration(i)*time.Second + 100*time.Millisecond),
		})
	}

	records := agg.Finalize(nil)
	found := false
	for _, r := range records {
		for _, reason := range r.SuspicionReasons {
			if strings.Contains(reason, "asymmetric upload") {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected 'asymmetric upload' reason when upload >> download")
	}
}

// ─── IPv6 extension header scoring ───────────────────────────────────────────

func baseIPv6Flow() PacketEvent {
	return PacketEvent{
		SrcIP:     net.ParseIP("2001:db8::1"),
		DstIP:     net.ParseIP("2001:db8::2"),
		SrcPort:   50000,
		DstPort:   443,
		Proto:     "TCP",
		PayloadLen: 100,
		Timestamp: time.Now(),
	}
}

func TestScore_IPv6RH0_RaisesScore(t *testing.T) {
	agg := &Aggregator{}
	pkt := baseIPv6Flow()
	pkt.IsIPv6RH0 = true
	agg.Add(pkt)

	records := agg.Finalize(nil)
	if len(records) == 0 {
		t.Fatal("expected at least one flow record")
	}
	rec := records[0]
	if !rec.IsIPv6RH0 {
		t.Error("expected IsIPv6RH0=true in FlowRecord")
	}
	found := false
	for _, r := range rec.SuspicionReasons {
		if strings.Contains(r, "Routing Header type 0") {
			found = true
		}
	}
	if !found {
		t.Error("expected RH0 reason in SuspicionReasons")
	}
	if rec.SuspicionScore < 1.5 {
		t.Errorf("expected score >= 1.5 for RH0, got %.2f", rec.SuspicionScore)
	}
}

func TestScore_IPv6Fragment_RaisesScore(t *testing.T) {
	agg := &Aggregator{}
	pkt := baseIPv6Flow()
	pkt.IsIPv6Fragment = true
	agg.Add(pkt)

	records := agg.Finalize(nil)
	if len(records) == 0 {
		t.Fatal("expected at least one flow record")
	}
	rec := records[0]
	if !rec.IsIPv6Fragment {
		t.Error("expected IsIPv6Fragment=true in FlowRecord")
	}
	found := false
	for _, r := range rec.SuspicionReasons {
		if strings.Contains(r, "fragmentation") {
			found = true
		}
	}
	if !found {
		t.Error("expected fragmentation reason in SuspicionReasons")
	}
}

func TestScore_IPv6RH0AndFragment_Combined(t *testing.T) {
	agg := &Aggregator{}
	pkt := baseIPv6Flow()
	pkt.IsIPv6RH0 = true
	pkt.IsIPv6Fragment = true
	agg.Add(pkt)

	records := agg.Finalize(nil)
	if len(records) == 0 {
		t.Fatal("expected at least one flow record")
	}
	rec := records[0]
	if rec.SuspicionScore < 2.0 {
		t.Errorf("expected score >= 2.0 for RH0+fragment combination, got %.2f", rec.SuspicionScore)
	}
}
