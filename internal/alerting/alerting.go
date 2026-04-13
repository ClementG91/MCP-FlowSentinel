// Package alerting sends webhook notifications for high-suspicion flows.
// Supports generic HTTP POST endpoints, Slack incoming webhooks, and Discord
// webhooks — all accept the same JSON POST body format.
//
// Alerting is fire-and-forget with deduplication: the same flow key will not
// trigger more than one alert within the configured deduplication window.
// Disabled by default; enable via config or FLOWSENTINEL_WEBHOOK_URL.
package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
)

// alert is the JSON body sent to the webhook endpoint.
type alert struct {
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Severity  string                 `json:"severity"`
	Flow      aggregate.FlowRecord   `json:"flow"`
}

// deduplication state: flow key → last alerted time.
var (
	dedupMu  sync.Mutex
	dedupMap = make(map[string]time.Time)
)

// firedCount tracks total alerts fired since startup.
var firedCount atomic.Int64

// FiredCount returns the total number of webhook alerts fired since startup.
func FiredCount() int64 { return firedCount.Load() }

// flowDedupeKey returns a stable string identifying a flow for deduplication.
func flowDedupeKey(flow aggregate.FlowRecord) string {
	return fmt.Sprintf("%s:%d->%s:%d/%s", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Protocol)
}

// shouldFire checks the dedup map and returns true if this flow key has not
// been alerted within the configured deduplication window.
func shouldFire(flowKey string, windowSec int) bool {
	window := time.Duration(windowSec) * time.Second
	if window <= 0 {
		window = 300 * time.Second
	}
	dedupMu.Lock()
	defer dedupMu.Unlock()
	if last, ok := dedupMap[flowKey]; ok && time.Since(last) < window {
		return false
	}
	dedupMap[flowKey] = time.Now()
	return true
}

// Fire posts an alert for every flow whose suspicion score meets or exceeds
// the configured threshold. Deduplicates within the configured window.
// No-op when alerting is disabled or unconfigured.
func Fire(flows []aggregate.FlowRecord) {
	cfg := config.Get().Alerting

	webhookURL := cfg.WebhookURL
	if v := os.Getenv("FLOWSENTINEL_WEBHOOK_URL"); v != "" {
		webhookURL = v
	}

	if webhookURL == "" || !cfg.Enabled {
		return
	}

	for _, f := range flows {
		if f.SuspicionScore < cfg.MinScoreThreshold {
			continue
		}
		key := flowDedupeKey(f)
		if !shouldFire(key, cfg.DeduplicationWindowSec) {
			continue
		}
		severity := f.RiskLevel
		firedCount.Add(1)
		writeAlertRecord(AlertRecord{
			Timestamp: time.Now().UTC(),
			Severity:  severity,
			DedupeKey: key,
			Flow:      f,
		})
		go post(webhookURL, f, severity)
	}
}

func post(url string, flow aggregate.FlowRecord, severity string) {
	body, err := json.Marshal(alert{
		Source:    "mcp-flowsentinel",
		Timestamp: time.Now().UTC(),
		Severity:  severity,
		Flow:      flow,
	})
	if err != nil {
		log.Printf("alerting: marshal error: %v", err)
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("alerting: webhook POST failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("alerting: webhook returned HTTP %d", resp.StatusCode)
		return
	}

	log.Printf("alerting: [%s] fired for flow %s→%s score=%.1f",
		severity,
		fmt.Sprintf("%s:%d", flow.SrcIP, flow.SrcPort),
		fmt.Sprintf("%s:%d", flow.DstIP, flow.DstPort),
		flow.SuspicionScore)
}

// FireTest sends a single test alert bypassing deduplication and score threshold.
// Returns an error if the webhook POST fails or returns a non-2xx status.
func FireTest(flow aggregate.FlowRecord) error {
	cfg := config.Get().Alerting

	webhookURL := cfg.WebhookURL
	if v := os.Getenv("FLOWSENTINEL_WEBHOOK_URL"); v != "" {
		webhookURL = v
	}
	if webhookURL == "" {
		return fmt.Errorf("webhook URL is not configured")
	}

	severity := "TEST"
	body, err := json.Marshal(alert{
		Source:    "mcp-flowsentinel/test",
		Timestamp: time.Now().UTC(),
		Severity:  severity,
		Flow:      flow,
	})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("POST failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// ResetDedupForTesting clears the deduplication map. Only for tests.
func ResetDedupForTesting() {
	dedupMu.Lock()
	dedupMap = make(map[string]time.Time)
	dedupMu.Unlock()
}
