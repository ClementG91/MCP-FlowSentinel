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
	"sync/atomic"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/cache"
	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
)

const (
	maxRetries    = 3
	retryBaseWait = time.Second
)

// alert is the JSON body sent to the webhook endpoint.
type alert struct {
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Severity  string                 `json:"severity"`
	Flow      aggregate.FlowRecord   `json:"flow"`
}

// dedupCache is a bounded LRU cache (max 10 000 entries) used for alert
// deduplication. Each entry stores the time the alert was last fired and
// expires after the configured deduplication window, so memory is naturally
// reclaimed without a separate cleanup goroutine.
// Capacity 10 000 covers tens of thousands of unique flows while staying under
// ~2 MB of RAM.
var dedupCache = cache.New[string, time.Time](10_000)

// firedCount tracks total alerts fired since startup.
var firedCount atomic.Int64

// webhookFailures tracks total webhook POST failures (all retries exhausted).
var webhookFailures atomic.Int64

// FiredCount returns the total number of webhook alerts fired since startup.
func FiredCount() int64 { return firedCount.Load() }

// WebhookFailures returns the number of webhook deliveries that failed after
// all retries were exhausted since startup.
func WebhookFailures() int64 { return webhookFailures.Load() }

// flowDedupeKey returns a stable string identifying a flow for deduplication.
func flowDedupeKey(flow aggregate.FlowRecord) string {
	return fmt.Sprintf("%s:%d->%s:%d/%s", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Protocol)
}

// shouldFire returns true if this flow key has not been alerted within the
// configured deduplication window. Uses a bounded LRU cache with TTL so
// entries are automatically evicted — no unbounded memory growth.
func shouldFire(flowKey string, windowSec int) bool {
	window := time.Duration(windowSec) * time.Second
	if window <= 0 {
		window = 300 * time.Second
	}
	if _, hit := dedupCache.Get(flowKey); hit {
		return false
	}
	dedupCache.Set(flowKey, time.Now(), window)
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
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential back-off: 1s, 2s, 4s, …
			time.Sleep(retryBaseWait << (attempt - 1))
		}
		resp, err := client.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			lastErr = err
			log.Printf("alerting: webhook POST attempt %d/%d failed: %v", attempt+1, maxRetries, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			log.Printf("alerting: webhook attempt %d/%d returned %s", attempt+1, maxRetries, lastErr)
			continue
		}
		log.Printf("alerting: [%s] fired for flow %s→%s score=%.1f",
			severity,
			fmt.Sprintf("%s:%d", flow.SrcIP, flow.SrcPort),
			fmt.Sprintf("%s:%d", flow.DstIP, flow.DstPort),
			flow.SuspicionScore)
		return
	}
	webhookFailures.Add(1)
	log.Printf("alerting: all %d attempts failed for %s:%d→%s:%d: %v",
		maxRetries, flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, lastErr)
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

// ResetDedupForTesting replaces the dedup cache with a fresh one. Only for tests.
func ResetDedupForTesting() {
	dedupCache = cache.New[string, time.Time](10_000)
}
