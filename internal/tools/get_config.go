package tools

import (
	"context"
	"encoding/json"

	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerGetConfig(s *server.MCPServer) {
	s.AddTool(mcp.NewTool("get_config",
		mcp.WithDescription(`Return the current runtime configuration.

Useful for verifying which settings are active without reading the config file
directly. Secret values are never returned; only their configured state is shown.

Returns a JSON object with all configuration sections: scoring thresholds,
capture timing, GeoIP paths, history retention, alerting settings, and
daemon parameters. Also includes the path of the loaded config file (empty
if using built-in defaults).`),
	), getConfigHandler)
}

func getConfigHandler(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cfg := config.Get()

	// Build a complete sanitized view without exposing webhook or API secrets.
	type sanitizedAlerting struct {
		Enabled                 bool    `json:"enabled"`
		WebhookURL              string  `json:"webhook_url"`
		MinScoreThreshold       float64 `json:"min_score_threshold"`
		DeduplicationWindowSec  int     `json:"deduplication_window_seconds"`
		MaxAlertsPerMinute      int     `json:"max_alerts_per_minute"`
		WebhookSecretConfigured bool    `json:"webhook_secret_configured"`
	}

	type sanitizedIntel struct {
		VirusTotalAPIKeyConfigured bool `json:"virustotal_api_key_configured"`
	}

	type sanitizedConfig struct {
		LoadedFrom string                 `json:"loaded_from"`
		Scoring    config.ScoringConfig   `json:"scoring"`
		Capture    config.CaptureConfig   `json:"capture"`
		GeoIP      config.GeoIPConfig     `json:"geoip"`
		History    config.HistoryConfig   `json:"history"`
		Alerting   sanitizedAlerting      `json:"alerting"`
		Daemon     config.DaemonConfig    `json:"daemon"`
		JA3Feed    config.JA3FeedConfig   `json:"ja3_feed"`
		HasshFeed  config.HasshFeedConfig `json:"hassh_feed"`
		IPRep      config.IPRepConfig     `json:"ip_rep"`
		DomRep     config.DomRepConfig    `json:"dom_rep"`
		Metrics    config.MetricsConfig   `json:"metrics"`
		Intel      sanitizedIntel         `json:"intel"`
	}

	url := cfg.Alerting.WebhookURL
	if url != "" {
		url = "***"
	}

	view := sanitizedConfig{
		LoadedFrom: config.LoadedPath(),
		Scoring:    cfg.Scoring,
		Capture:    cfg.Capture,
		GeoIP:      cfg.GeoIP,
		History:    cfg.History,
		Alerting: sanitizedAlerting{
			Enabled:                 cfg.Alerting.Enabled,
			WebhookURL:              url,
			MinScoreThreshold:       cfg.Alerting.MinScoreThreshold,
			DeduplicationWindowSec:  cfg.Alerting.DeduplicationWindowSec,
			MaxAlertsPerMinute:      cfg.Alerting.MaxAlertsPerMinute,
			WebhookSecretConfigured: cfg.Alerting.WebhookSecret != "",
		},
		Daemon:    cfg.Daemon,
		JA3Feed:   cfg.JA3Feed,
		HasshFeed: cfg.HasshFeed,
		IPRep:     cfg.IPRep,
		DomRep:    cfg.DomRep,
		Metrics:   cfg.Metrics,
		Intel: sanitizedIntel{
			VirusTotalAPIKeyConfigured: cfg.Intel.VirusTotalAPIKey != "",
		},
	}

	// Clear compiled patterns from the scoring view (not serializable usefully).
	view.Scoring.CompiledExtraCmdlinePatterns = nil

	data, err := json.MarshalIndent(view, "", "  ")
	if err != nil {
		return errorResult(err.Error()), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}
