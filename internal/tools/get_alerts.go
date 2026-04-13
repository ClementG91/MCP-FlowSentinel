package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ClementG91/MCP-FlowSentinel/internal/alerting"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerGetAlerts(s *server.MCPServer) {
	s.AddTool(mcp.NewTool("get_alerts",
		mcp.WithDescription(`Query the persistent alert log for fired webhook alerts.

Returns alerts that have been triggered (score ≥ min_score_threshold) since
the server started, persisted across restarts in:
  ~/.cache/mcp-flowsentinel/alerts.jsonl

Each alert record includes:
  - timestamp    — when the alert was fired
  - severity     — CRITICAL / HIGH / MEDIUM / LOW
  - dedupe_key   — unique flow identifier (src:port→dst:port/proto)
  - flow         — the full FlowRecord that triggered the alert

Parameters:
  max_age_hours  — how far back to look (default 24)
  min_score      — minimum suspicion score filter (default 0 = all)
  top_n          — maximum results to return (default 50)`),
		mcp.WithNumber("max_age_hours",
			mcp.Description("Maximum age of alerts to return in hours (default 24)"),
		),
		mcp.WithNumber("min_score",
			mcp.Description("Minimum suspicion score filter (0 = return all)"),
		),
		mcp.WithNumber("top_n",
			mcp.Description("Maximum number of alerts to return (default 50)"),
		),
	), getAlertsHandler)
}

func getAlertsHandler(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	opts := alerting.AlertQueryOpts{
		MaxAgeHours: 24,
		TopN:        50,
	}

	if v, ok := req.Params.Arguments["max_age_hours"].(float64); ok && v > 0 {
		opts.MaxAgeHours = int(v)
	}
	if v, ok := req.Params.Arguments["min_score"].(float64); ok && v > 0 {
		opts.MinScore = v
	}
	if v, ok := req.Params.Arguments["top_n"].(float64); ok && v > 0 {
		opts.TopN = int(v)
	}

	alerts, err := alerting.GetAlerts(opts)
	if err != nil {
		return errorResult(fmt.Sprintf("alert log read error: %v", err)), nil
	}

	type response struct {
		AlertLogPath string               `json:"alert_log_path"`
		TotalAlerts  int                  `json:"total_alerts"`
		Alerts       []alerting.AlertRecord `json:"alerts"`
	}

	resp := response{
		AlertLogPath: alerting.AlertLogPath(),
		TotalAlerts:  len(alerts),
		Alerts:       alerts,
	}
	if resp.Alerts == nil {
		resp.Alerts = []alerting.AlertRecord{}
	}

	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return errorResult(err.Error()), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}
