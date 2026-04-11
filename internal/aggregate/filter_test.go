package aggregate

import (
	"testing"
)

// helpers to build FlowRecord slices for filter tests.

func flowWithScore(score float64, risk string) FlowRecord {
	return FlowRecord{SuspicionScore: score, RiskLevel: risk}
}

func scoredFlows() []FlowRecord {
	// Pre-sorted descending (as Finalize produces).
	return []FlowRecord{
		flowWithScore(9.5, "CRITICAL"),
		flowWithScore(7.0, "HIGH"),
		flowWithScore(6.0, "HIGH"),
		flowWithScore(3.5, "MEDIUM"),
		flowWithScore(2.1, "MEDIUM"),
		flowWithScore(1.0, "LOW"),
		flowWithScore(0.5, "LOW"),
	}
}

// ─── FilterOptions.Apply ───────────────────────────────────────────────────────

func TestFilterOptions_NoFilter(t *testing.T) {
	flows := scoredFlows()
	out := FilterOptions{}.Apply(flows)
	if len(out) != len(flows) {
		t.Errorf("expected all %d flows with no filter, got %d", len(flows), len(out))
	}
}

func TestFilterOptions_MinScore(t *testing.T) {
	out := FilterOptions{MinScore: 5.0}.Apply(scoredFlows())
	// Scores ≥ 5.0: 9.5, 7.0, 6.0 → 3 flows
	if len(out) != 3 {
		t.Errorf("expected 3 flows with min_score=5.0, got %d", len(out))
	}
	for _, f := range out {
		if f.SuspicionScore < 5.0 {
			t.Errorf("flow with score %.2f should have been filtered out", f.SuspicionScore)
		}
	}
}

func TestFilterOptions_TopN(t *testing.T) {
	out := FilterOptions{TopN: 2}.Apply(scoredFlows())
	if len(out) != 2 {
		t.Errorf("expected 2 flows with top_n=2, got %d", len(out))
	}
	if out[0].SuspicionScore < out[1].SuspicionScore {
		t.Error("results should be descending by score")
	}
}

func TestFilterOptions_MinScoreAndTopN(t *testing.T) {
	// min_score=2.0 → 5 flows; top_n=2 → cap at 2
	out := FilterOptions{MinScore: 2.0, TopN: 2}.Apply(scoredFlows())
	if len(out) != 2 {
		t.Errorf("expected 2 flows with min_score=2.0 and top_n=2, got %d", len(out))
	}
	for _, f := range out {
		if f.SuspicionScore < 2.0 {
			t.Errorf("flow with score %.2f should have been excluded by min_score", f.SuspicionScore)
		}
	}
}

func TestFilterOptions_TopNLargerThanSlice(t *testing.T) {
	// top_n larger than available flows should return all of them.
	out := FilterOptions{TopN: 100}.Apply(scoredFlows())
	if len(out) != 7 {
		t.Errorf("expected 7 flows when top_n exceeds slice length, got %d", len(out))
	}
}

func TestFilterOptions_MinScoreAboveAll(t *testing.T) {
	// min_score higher than every flow → empty result.
	out := FilterOptions{MinScore: 10.0}.Apply(scoredFlows())
	if len(out) != 0 {
		t.Errorf("expected 0 flows with min_score=10.0, got %d", len(out))
	}
}

func TestFilterOptions_EmptyInput(t *testing.T) {
	out := FilterOptions{MinScore: 3.0, TopN: 5}.Apply(nil)
	if len(out) != 0 {
		t.Errorf("expected empty output for nil input, got %d", len(out))
	}
}

// ─── Summarise ─────────────────────────────────────────────────────────────────

func TestSummarise_Counts(t *testing.T) {
	flows := scoredFlows()
	s := Summarise(flows)

	if s.Critical != 1 {
		t.Errorf("expected 1 CRITICAL, got %d", s.Critical)
	}
	if s.High != 2 {
		t.Errorf("expected 2 HIGH, got %d", s.High)
	}
	if s.Medium != 2 {
		t.Errorf("expected 2 MEDIUM, got %d", s.Medium)
	}
	if s.Low != 2 {
		t.Errorf("expected 2 LOW, got %d", s.Low)
	}
}

func TestSummarise_Empty(t *testing.T) {
	s := Summarise(nil)
	if s.Critical+s.High+s.Medium+s.Low != 0 {
		t.Errorf("expected all-zero summary for empty input, got %+v", s)
	}
}

func TestSummarise_AllLow(t *testing.T) {
	flows := []FlowRecord{
		flowWithScore(0.0, "LOW"),
		flowWithScore(1.5, "LOW"),
	}
	s := Summarise(flows)
	if s.Low != 2 || s.Critical != 0 || s.High != 0 || s.Medium != 0 {
		t.Errorf("expected 2 LOW only, got %+v", s)
	}
}
