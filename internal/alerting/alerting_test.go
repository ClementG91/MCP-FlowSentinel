package alerting

import (
	"encoding/json"
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
