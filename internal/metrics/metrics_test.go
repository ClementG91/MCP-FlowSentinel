package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleMetrics_ContainsExpectedKeys(t *testing.T) {
	// Reset counters to known state before the test.
	flowsScoredCritical.Store(3)
	flowsScoredHigh.Store(5)
	flowsScoredMedium.Store(7)
	flowsScoredLow.Store(2)
	flowsScoredClean.Store(0)
	alertsFiredTotal.Store(1)
	webhookFailures.Store(0)
	droppedPackets.Store(42)
	windowDurationsSum.Store(15000)
	windowDurationsN.Store(3)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	expected := []string{
		"flowsentinel_flows_scored_total{risk_level=\"critical\"} 3",
		"flowsentinel_flows_scored_total{risk_level=\"high\"} 5",
		"flowsentinel_flows_scored_total{risk_level=\"medium\"} 7",
		"flowsentinel_flows_scored_total{risk_level=\"low\"} 2",
		"flowsentinel_alerts_fired_total 1",
		"flowsentinel_dropped_packets_total 42",
		"flowsentinel_capture_windows_total 3",
	}
	for _, want := range expected {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in metrics output\ngot:\n%s", want, text)
		}
	}
}

func TestRecordFlows_Increments(t *testing.T) {
	flowsScoredCritical.Store(0)
	flowsScoredHigh.Store(0)

	RecordFlows(2, 3, 1, 0, 0)

	if flowsScoredCritical.Load() != 2 {
		t.Errorf("critical = %d, want 2", flowsScoredCritical.Load())
	}
	if flowsScoredHigh.Load() != 3 {
		t.Errorf("high = %d, want 3", flowsScoredHigh.Load())
	}
}

func TestRecordDroppedPackets_Sets(t *testing.T) {
	RecordDroppedPackets(99)
	if droppedPackets.Load() != 99 {
		t.Errorf("dropped = %d, want 99", droppedPackets.Load())
	}
}

func TestRecordWindowDuration_Averages(t *testing.T) {
	windowDurationsSum.Store(0)
	windowDurationsN.Store(0)

	RecordWindowDuration(1000)
	RecordWindowDuration(3000)

	if windowDurationsN.Load() != 2 {
		t.Errorf("N = %d, want 2", windowDurationsN.Load())
	}
	if windowDurationsSum.Load() != 4000 {
		t.Errorf("sum = %d, want 4000", windowDurationsSum.Load())
	}
}

func TestHandleMetrics_ContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)

	ct := w.Result().Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("expected text/plain content-type, got %q", ct)
	}
}
