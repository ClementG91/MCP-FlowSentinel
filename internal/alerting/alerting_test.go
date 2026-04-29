package alerting

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
)

func highFlow(score float64) aggregate.FlowRecord {
	return aggregate.FlowRecord{
		SrcIP:          "10.0.0.1",
		DstIP:          "1.2.3.4",
		SrcPort:        12345,
		DstPort:        443,
		Protocol:       "TCP",
		SuspicionScore: score,
	}
}

func TestFire_Disabled_NoRequest(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	defer srv.Close()

	original := config.Get()
	defer config.Set(original)

	cfg := config.Default()
	cfg.Alerting.Enabled = false
	cfg.Alerting.WebhookURL = srv.URL
	cfg.Alerting.MinScoreThreshold = 5.0
	config.Set(cfg)

	Fire([]aggregate.FlowRecord{highFlow(8.0)})
	time.Sleep(100 * time.Millisecond)

	if called {
		t.Error("webhook should not be called when alerting is disabled")
	}
}

func TestFire_NoWebhookURL_NoRequest(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	defer srv.Close()

	original := config.Get()
	defer config.Set(original)

	cfg := config.Default()
	cfg.Alerting.Enabled = true
	cfg.Alerting.WebhookURL = "" // no URL
	config.Set(cfg)

	Fire([]aggregate.FlowRecord{highFlow(8.0)})
	time.Sleep(100 * time.Millisecond)

	if called {
		t.Error("webhook should not be called when URL is empty")
	}
}

func TestFire_ScoreBelowThreshold_NoRequest(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	defer srv.Close()

	original := config.Get()
	defer config.Set(original)

	cfg := config.Default()
	cfg.Alerting.Enabled = true
	cfg.Alerting.WebhookURL = srv.URL
	cfg.Alerting.MinScoreThreshold = 7.0
	config.Set(cfg)

	Fire([]aggregate.FlowRecord{highFlow(5.0)}) // below threshold
	time.Sleep(100 * time.Millisecond)

	if called {
		t.Error("webhook should not fire for low-score flow")
	}
}

func TestFire_AboveThreshold_PostsJSON(t *testing.T) {
	received := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- body
		w.WriteHeader(200)
	}))
	defer srv.Close()

	original := config.Get()
	defer config.Set(original)

	cfg := config.Default()
	cfg.Alerting.Enabled = true
	cfg.Alerting.WebhookURL = srv.URL
	cfg.Alerting.MinScoreThreshold = 7.0
	config.Set(cfg)

	Fire([]aggregate.FlowRecord{highFlow(8.5)})

	select {
	case body := <-received:
		var a alert
		if err := json.Unmarshal(body, &a); err != nil {
			t.Fatalf("unmarshal alert body: %v", err)
		}
		if a.Source != "mcp-flowsentinel" {
			t.Errorf("Source = %q, want mcp-flowsentinel", a.Source)
		}
		if a.Flow.SuspicionScore != 8.5 {
			t.Errorf("SuspicionScore = %v, want 8.5", a.Flow.SuspicionScore)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook not called within 3s")
	}
}

func TestFire_WebhookError_NosPanic(t *testing.T) {
	original := config.Get()
	defer config.Set(original)

	cfg := config.Default()
	cfg.Alerting.Enabled = true
	cfg.Alerting.WebhookURL = "http://127.0.0.1:1" // no server listening
	cfg.Alerting.MinScoreThreshold = 5.0
	config.Set(cfg)

	// Should not panic or hang.
	Fire([]aggregate.FlowRecord{highFlow(8.0)})
	time.Sleep(200 * time.Millisecond)
}

func TestFire_BadHTTPStatus_LogsNotPanics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	original := config.Get()
	defer config.Set(original)

	cfg := config.Default()
	cfg.Alerting.Enabled = true
	cfg.Alerting.WebhookURL = srv.URL
	cfg.Alerting.MinScoreThreshold = 5.0
	config.Set(cfg)

	Fire([]aggregate.FlowRecord{highFlow(8.0)})
	time.Sleep(200 * time.Millisecond)
	// Just verifying no panic.
}

func TestFire_Deduplication_SuppressesRepeat(t *testing.T) {
	received := make(chan struct{}, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- struct{}{}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	original := config.Get()
	defer config.Set(original)
	ResetDedupForTesting()

	cfg := config.Default()
	cfg.Alerting.Enabled = true
	cfg.Alerting.WebhookURL = srv.URL
	cfg.Alerting.MinScoreThreshold = 5.0
	cfg.Alerting.DeduplicationWindowSec = 60
	config.Set(cfg)

	flow := highFlow(8.0)
	Fire([]aggregate.FlowRecord{flow})
	// Wait for the first alert to land.
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("first alert not received within 3s")
	}
	// Second Fire for the same flow key — dedup should suppress it.
	Fire([]aggregate.FlowRecord{flow})
	time.Sleep(200 * time.Millisecond) // give it time to (not) fire
	if len(received) != 0 {
		t.Errorf("expected dedup to suppress second alert, but %d additional calls occurred", len(received))
	}
}

func TestFire_Deduplication_AllowsDifferentFlows(t *testing.T) {
	received := make(chan struct{}, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- struct{}{}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	original := config.Get()
	defer config.Set(original)
	ResetDedupForTesting()

	cfg := config.Default()
	cfg.Alerting.Enabled = true
	cfg.Alerting.WebhookURL = srv.URL
	cfg.Alerting.MinScoreThreshold = 5.0
	cfg.Alerting.DeduplicationWindowSec = 60
	config.Set(cfg)

	flow1 := aggregate.FlowRecord{SrcIP: "10.0.0.1", DstIP: "1.2.3.4", SrcPort: 111, DstPort: 443, Protocol: "TCP", SuspicionScore: 8.0}
	flow2 := aggregate.FlowRecord{SrcIP: "10.0.0.2", DstIP: "1.2.3.5", SrcPort: 222, DstPort: 80, Protocol: "TCP", SuspicionScore: 8.0}

	Fire([]aggregate.FlowRecord{flow1, flow2})

	got := 0
	deadline := time.After(3 * time.Second)
	for got < 2 {
		select {
		case <-received:
			got++
		case <-deadline:
			t.Errorf("expected 2 webhook calls for distinct flows, got %d", got)
			return
		}
	}
}

// ─── FiredCount ───────────────────────────────────────────────────────────────

func TestFiredCount_IncrementsOnFire(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	original := config.Get()
	defer config.Set(original)
	ResetDedupForTesting()

	cfg := config.Default()
	cfg.Alerting.Enabled = true
	cfg.Alerting.WebhookURL = srv.URL
	cfg.Alerting.MinScoreThreshold = 5.0
	cfg.Alerting.DeduplicationWindowSec = 60
	config.Set(cfg)

	before := FiredCount()
	Fire([]aggregate.FlowRecord{
		{SrcIP: "99.0.0.1", DstIP: "99.0.0.2", SrcPort: 1, DstPort: 443, Protocol: "TCP", SuspicionScore: 9.0},
	})
	time.Sleep(150 * time.Millisecond)
	after := FiredCount()

	if after <= before {
		t.Errorf("FiredCount did not increment: before=%d after=%d", before, after)
	}
}

// ─── alert store ─────────────────────────────────────────────────────────────

func TestWriteAlertRecord_GetAlerts_RoundTrip(t *testing.T) {
	tmp := t.TempDir() + "/alerts.jsonl"
	SetAlertLogPathForTesting(tmp)
	t.Cleanup(func() { SetAlertLogPathForTesting(tmp) })

	rec := AlertRecord{
		Timestamp: time.Now().UTC(),
		Severity:  "HIGH",
		DedupeKey: "1.2.3.4:100->5.6.7.8:443/TCP",
		Flow:      aggregate.FlowRecord{SrcIP: "1.2.3.4", DstIP: "5.6.7.8", SuspicionScore: 7.5},
	}
	writeAlertRecord(rec)

	alerts, err := GetAlerts(AlertQueryOpts{MaxAgeHours: 24})
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", alerts[0].Severity)
	}
	if alerts[0].Flow.SuspicionScore != 7.5 {
		t.Errorf("SuspicionScore = %v, want 7.5", alerts[0].Flow.SuspicionScore)
	}
}

func TestGetAlerts_MinScoreFilter(t *testing.T) {
	tmp := t.TempDir() + "/alerts.jsonl"
	SetAlertLogPathForTesting(tmp)
	t.Cleanup(func() { SetAlertLogPathForTesting(tmp) })

	writeAlertRecord(AlertRecord{
		Timestamp: time.Now().UTC(),
		Severity:  "LOW",
		DedupeKey: "low",
		Flow:      aggregate.FlowRecord{SuspicionScore: 3.0},
	})
	writeAlertRecord(AlertRecord{
		Timestamp: time.Now().UTC(),
		Severity:  "HIGH",
		DedupeKey: "high",
		Flow:      aggregate.FlowRecord{SuspicionScore: 8.0},
	})

	alerts, err := GetAlerts(AlertQueryOpts{MaxAgeHours: 24, MinScore: 5.0})
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert with score >= 5, got %d", len(alerts))
	}
	if alerts[0].Flow.SuspicionScore < 5.0 {
		t.Errorf("returned alert with score below filter: %v", alerts[0].Flow.SuspicionScore)
	}
}

func TestGetAlerts_TopN(t *testing.T) {
	tmp := t.TempDir() + "/alerts.jsonl"
	SetAlertLogPathForTesting(tmp)
	t.Cleanup(func() { SetAlertLogPathForTesting(tmp) })

	for i := 0; i < 5; i++ {
		writeAlertRecord(AlertRecord{
			Timestamp: time.Now().UTC(),
			Severity:  "HIGH",
			DedupeKey: fmt.Sprintf("flow-%d", i),
			Flow:      aggregate.FlowRecord{SuspicionScore: 7.0},
		})
	}

	alerts, err := GetAlerts(AlertQueryOpts{MaxAgeHours: 24, TopN: 3})
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	if len(alerts) != 3 {
		t.Errorf("expected 3 alerts (TopN=3), got %d", len(alerts))
	}
}

func TestGetAlerts_NoFile_ReturnsEmpty(t *testing.T) {
	tmp := t.TempDir() + "/nonexistent_alerts.jsonl"
	SetAlertLogPathForTesting(tmp)
	t.Cleanup(func() { SetAlertLogPathForTesting(tmp) })

	alerts, err := GetAlerts(AlertQueryOpts{MaxAgeHours: 24})
	if err != nil {
		t.Fatalf("GetAlerts on missing file: %v", err)
	}
	if alerts != nil {
		t.Errorf("expected nil slice for missing file, got %v", alerts)
	}
}

// TestWebhookRetry_EventualSuccess verifies that a transient failure followed
// by a success is handled correctly (no webhookFailures increment).
func TestWebhookRetry_EventualSuccess(t *testing.T) {
	attempt := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt < 2 {
			w.WriteHeader(500) // fail first attempt
			return
		}
		w.WriteHeader(200) // succeed on second attempt
	}))
	defer srv.Close()

	original := config.Get()
	defer config.Set(original)
	ResetDedupForTesting()

	cfg := config.Default()
	cfg.Alerting.Enabled = true
	cfg.Alerting.WebhookURL = srv.URL
	cfg.Alerting.MinScoreThreshold = 5.0
	cfg.Alerting.DeduplicationWindowSec = 1
	config.Set(cfg)

	failsBefore := WebhookFailures()
	firedBefore := FiredCount()
	flow := aggregate.FlowRecord{SrcIP: "10.1.1.1", DstIP: "2.3.4.5", SrcPort: 9001, DstPort: 443, Protocol: "TCP", SuspicionScore: 9.0}
	Fire([]aggregate.FlowRecord{flow})

	// Wait long enough for one retry (1s back-off) + margin.
	deadline := time.After(4 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("webhook not fired within 4s; attempt=%d firedCount=%d", attempt, FiredCount())
		case <-time.After(100 * time.Millisecond):
			if FiredCount() > firedBefore {
				// Success path taken.
				if WebhookFailures() != failsBefore {
					t.Errorf("webhookFailures incremented on eventual success")
				}
				return
			}
		}
	}
}

// ─── Rate limiter ─────────────────────────────────────────────────────────────

func TestRateLimiter_AllowsUpToMax(t *testing.T) {
	rl := newRateLimiter(3)
	for i := 0; i < 3; i++ {
		if !rl.allow() {
			t.Fatalf("allow() returned false on attempt %d, expected true", i+1)
		}
	}
	// 4th attempt must be blocked
	if rl.allow() {
		t.Error("allow() returned true beyond max tokens")
	}
}

func TestRateLimiter_Unlimited(t *testing.T) {
	rl := newRateLimiter(0) // 0 = unlimited
	for i := 0; i < 1000; i++ {
		if !rl.allow() {
			t.Fatalf("unlimited rate limiter blocked on attempt %d", i+1)
		}
	}
}

func TestRateLimiter_Refills(t *testing.T) {
	rl := newRateLimiter(2)
	rl.allow()
	rl.allow()
	if rl.allow() {
		t.Fatal("should be empty after 2 allows")
	}
	// Force a refill by backdating lastRefill by 1 minute
	rl.mu.Lock()
	rl.lastRefill = time.Now().Add(-time.Minute)
	rl.mu.Unlock()
	if !rl.allow() {
		t.Error("should allow after refill")
	}
}

func TestFire_RateLimit_CapsWebhooks(t *testing.T) {
	received := make(chan struct{}, 100)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received <- struct{}{}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	original := config.Get()
	defer config.Set(original)
	ResetDedupForTesting()

	cfg := config.Default()
	cfg.Alerting.Enabled = true
	cfg.Alerting.WebhookURL = srv.URL
	cfg.Alerting.MinScoreThreshold = 5.0
	cfg.Alerting.DeduplicationWindowSec = 1 // short window so flows aren't deduped
	cfg.Alerting.MaxAlertsPerMinute = 2
	config.Set(cfg)

	// Force rate limiter to be rebuilt with the new max
	rateLimiterMu.Lock()
	rateLimiterLastMax = -1 // force rebuild
	rateLimiterMu.Unlock()

	// Build 10 distinct flows
	flows := make([]aggregate.FlowRecord, 10)
	for i := range flows {
		flows[i] = aggregate.FlowRecord{
			SrcIP: fmt.Sprintf("10.0.%d.1", i), DstIP: "1.2.3.4",
			SrcPort: uint16(10000 + i), DstPort: 443, Protocol: "TCP",
			SuspicionScore: 9.0,
		}
	}
	Fire(flows)
	time.Sleep(500 * time.Millisecond)

	n := len(received)
	if n > 2 {
		t.Errorf("rate limit of 2/min exceeded: got %d webhook calls", n)
	}
}

// ─── HMAC signing ─────────────────────────────────────────────────────────────

func TestSignPayload_Deterministic(t *testing.T) {
	sig1 := signPayload("secret", []byte(`{"test":1}`))
	sig2 := signPayload("secret", []byte(`{"test":1}`))
	if sig1 != sig2 {
		t.Error("signPayload is not deterministic")
	}
	if sig1[:7] != "sha256=" {
		t.Errorf("expected sha256= prefix, got %q", sig1[:7])
	}
}

func TestSignPayload_DifferentSecrets(t *testing.T) {
	body := []byte(`{"alert":"test"}`)
	sig1 := signPayload("secret1", body)
	sig2 := signPayload("secret2", body)
	if sig1 == sig2 {
		t.Error("different secrets produced identical signatures")
	}
}

func TestFire_HMACSignature_SentWhenSecretConfigured(t *testing.T) {
	received := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("X-FlowSentinel-Signature")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	original := config.Get()
	defer config.Set(original)
	ResetDedupForTesting()

	cfg := config.Default()
	cfg.Alerting.Enabled = true
	cfg.Alerting.WebhookURL = srv.URL
	cfg.Alerting.MinScoreThreshold = 5.0
	cfg.Alerting.WebhookSecret = "mysecret"
	config.Set(cfg)

	Fire([]aggregate.FlowRecord{{
		SrcIP: "10.5.5.5", DstIP: "1.2.3.4", SrcPort: 55555, DstPort: 443,
		Protocol: "TCP", SuspicionScore: 9.0,
	}})

	select {
	case sig := <-received:
		if sig == "" {
			t.Error("X-FlowSentinel-Signature header was empty")
		}
		if len(sig) < 7 || sig[:7] != "sha256=" {
			t.Errorf("unexpected signature format: %q", sig)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook not called within 3s")
	}
}

func TestFire_NoHMACSignature_WhenSecretEmpty(t *testing.T) {
	received := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("X-FlowSentinel-Signature")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	original := config.Get()
	defer config.Set(original)
	ResetDedupForTesting()

	cfg := config.Default()
	cfg.Alerting.Enabled = true
	cfg.Alerting.WebhookURL = srv.URL
	cfg.Alerting.MinScoreThreshold = 5.0
	cfg.Alerting.WebhookSecret = "" // no secret
	config.Set(cfg)

	Fire([]aggregate.FlowRecord{{
		SrcIP: "10.6.6.6", DstIP: "1.2.3.4", SrcPort: 60000, DstPort: 443,
		Protocol: "TCP", SuspicionScore: 9.0,
	}})

	select {
	case sig := <-received:
		if sig != "" {
			t.Errorf("expected no signature header, got %q", sig)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook not called within 3s")
	}
}

func TestFire_EnvVarWebhook_Overrides(t *testing.T) {
	received := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- struct{}{}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	original := config.Get()
	defer config.Set(original)

	// Config has alerting enabled but no URL.
	cfg := config.Default()
	cfg.Alerting.Enabled = true
	cfg.Alerting.WebhookURL = ""
	cfg.Alerting.MinScoreThreshold = 5.0
	config.Set(cfg)

	t.Setenv("FLOWSENTINEL_WEBHOOK_URL", srv.URL)

	Fire([]aggregate.FlowRecord{highFlow(8.0)})

	select {
	case <-received:
		// env var override worked
	case <-time.After(3 * time.Second):
		t.Fatal("webhook not called via env var override within 3s")
	}
}

func TestAlertLogPath_NonEmpty(t *testing.T) {
	p := AlertLogPath()
	if p == "" {
		t.Error("AlertLogPath() returned empty string")
	}
}

func TestFireTest_Success(t *testing.T) {
	received := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	original := config.Get()
	defer config.Set(original)

	cfg := config.Default()
	cfg.Alerting.WebhookURL = srv.URL
	config.Set(cfg)

	err := FireTest(highFlow(9.0))
	if err != nil {
		t.Fatalf("FireTest returned error: %v", err)
	}

	select {
	case body := <-received:
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("response body is not valid JSON: %v", err)
		}
		if payload["severity"] != "TEST" {
			t.Errorf("severity = %v, want \"TEST\"", payload["severity"])
		}
		if payload["source"] != "mcp-flowsentinel/test" {
			t.Errorf("source = %v, want \"mcp-flowsentinel/test\"", payload["source"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook not called within 3s")
	}
}

func TestFireTest_NoURL_ReturnsError(t *testing.T) {
	original := config.Get()
	defer config.Set(original)

	cfg := config.Default()
	cfg.Alerting.WebhookURL = ""
	config.Set(cfg)

	err := FireTest(highFlow(9.0))
	if err == nil {
		t.Error("expected error when no webhook URL configured")
	}
}

func TestFireTest_BadStatus_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	original := config.Get()
	defer config.Set(original)

	cfg := config.Default()
	cfg.Alerting.WebhookURL = srv.URL
	config.Set(cfg)

	err := FireTest(highFlow(9.0))
	if err == nil {
		t.Error("expected error on non-2xx response")
	}
}
