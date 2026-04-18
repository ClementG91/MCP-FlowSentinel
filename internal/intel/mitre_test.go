package intel

import (
	"testing"
)

func TestTagFlow_BeaconingReason(t *testing.T) {
	reasons := []string{"strong beaconing pattern (interval CV=0.02, mean=1000 ms)"}
	tags := TagFlow(reasons)
	if len(tags) == 0 {
		t.Fatal("expected at least one MITRE technique for beaconing reason")
	}
	found := false
	for _, tag := range tags {
		if tag.ID == "T1071.001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected T1071.001 in tags, got %v", tags)
	}
}

func TestTagFlow_DNSExfil(t *testing.T) {
	reasons := []string{
		"high-entropy dns label: abc.malware.com (entropy=4.5)",
		"dns nxdomain storm: 12 NXDOMAIN responses",
	}
	tags := TagFlow(reasons)
	ids := make(map[string]bool)
	for _, t := range tags {
		ids[t.ID] = true
	}
	if !ids["T1048.003"] {
		t.Error("expected T1048.003 (DNS exfil) in tags")
	}
	if !ids["T1568.002"] {
		t.Error("expected T1568.002 (DGA) in tags")
	}
}

func TestTagFlow_Deduplication(t *testing.T) {
	// Two reasons that both map to T1071.001 — should only appear once.
	reasons := []string{
		"strong beaconing pattern",
		"possible beaconing",
	}
	tags := TagFlow(reasons)
	count := 0
	for _, tag := range tags {
		if tag.ID == "T1071.001" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("T1071.001 should appear once after dedup, got %d", count)
	}
}

func TestTagFlow_EmptyReasons(t *testing.T) {
	tags := TagFlow(nil)
	if len(tags) != 0 {
		t.Errorf("expected empty tags for nil reasons, got %v", tags)
	}
}

func TestTagFlow_UnknownReason(t *testing.T) {
	tags := TagFlow([]string{"some completely unknown signal xyz"})
	if len(tags) != 0 {
		t.Errorf("expected no tags for unrecognized reason, got %v", tags)
	}
}

func TestTagFlow_MultipleDistinctTechniques(t *testing.T) {
	reasons := []string{
		"ja3 known-bad: Cobalt Strike",
		"scan pattern: 25 unique destinations",
		"asymmetric upload ratio=15.2",
	}
	tags := TagFlow(reasons)
	if len(tags) < 2 {
		t.Errorf("expected at least 2 distinct techniques, got %d: %v", len(tags), tags)
	}
}
