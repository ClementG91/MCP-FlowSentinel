// Package alerting sends webhook notifications for high-suspicion flows.
// Supports generic HTTP POST endpoints, Slack incoming webhooks, and Discord
// webhooks — all accept the same JSON POST body format.
//
// Alerting is fire-and-forget: failures are logged but never propagate to the
// caller. Disabled by default; enable via config or FLOWSENTINEL_WEBHOOK_URL.
package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
)

// alert is the JSON body sent to the webhook endpoint.
type alert struct {
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Flow      aggregate.FlowRecord   `json:"flow"`
}

// Fire posts an alert for every flow whose suspicion score meets or exceeds
// the configured threshold. No-op when alerting is disabled or unconfigured.
func Fire(flows []aggregate.FlowRecord) {
	cfg := config.Get().Alerting

	webhookURL := cfg.WebhookURL
	if v := os.Getenv("FLOWSENTINEL_WEBHOOK_URL"); v != "" {
		webhookURL = v
	}

	if webhookURL == "" {
		return
	}
	if !cfg.Enabled {
		return
	}

	for _, f := range flows {
		if f.SuspicionScore >= cfg.MinScoreThreshold {
			go post(webhookURL, f)
		}
	}
}

func post(url string, flow aggregate.FlowRecord) {
	body, err := json.Marshal(alert{
		Source:    "mcp-flowsentinel",
		Timestamp: time.Now().UTC(),
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

	log.Printf("alerting: fired for flow %s→%s score=%.1f",
		fmt.Sprintf("%s:%d", flow.SrcIP, flow.SrcPort),
		fmt.Sprintf("%s:%d", flow.DstIP, flow.DstPort),
		flow.SuspicionScore)
}
