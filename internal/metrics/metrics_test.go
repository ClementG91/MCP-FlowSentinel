package metrics

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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

func TestRecordAlert_Increments(t *testing.T) {
	alertsFiredTotal.Store(0)
	RecordAlert()
	RecordAlert()
	if alertsFiredTotal.Load() != 2 {
		t.Errorf("alertsFiredTotal = %d, want 2", alertsFiredTotal.Load())
	}
}

func TestRecordWebhookFailure_Increments(t *testing.T) {
	webhookFailures.Store(0)
	RecordWebhookFailure()
	if webhookFailures.Load() != 1 {
		t.Errorf("webhookFailures = %d, want 1", webhookFailures.Load())
	}
}

func TestServe_StartsAndResponds(t *testing.T) {
	// Reserve a free port, then release it so Serve() can bind to it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	// Reset the sync.Once so Serve() will actually start (package-level white-box).
	serverOnce = sync.Once{}
	Serve(addr)

	// Poll /healthz until the server is ready (max 2 s).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/healthz") //nolint:gosec
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "ok" {
			t.Fatalf("healthz: status=%d body=%q", resp.StatusCode, body)
		}
		return // success
	}
	t.Fatal("metrics server did not become ready within 2s")
}
