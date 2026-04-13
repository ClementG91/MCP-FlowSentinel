package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerReloadConfig(s *server.MCPServer) {
	s.AddTool(mcp.NewTool("reload_config",
		mcp.WithDescription(`Reload the configuration file without restarting the server.

Re-reads the YAML config from the last loaded path (or the default path if
no file was loaded at startup). Useful after editing config values while the
server is running — scoring thresholds, webhook URL, alerting settings, and
daemon parameters all take effect immediately on the next operation.

Note: GeoIP database paths only take effect on restart. The DNS cache TTL
and size also require a restart.

Returns a summary of the reloaded configuration on success.`),
	), reloadConfigHandler)
}

func reloadConfigHandler(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cfg, err := config.Reload()
	if err != nil {
		return errorResult(fmt.Sprintf("config reload failed: %v", err)), nil
	}

	type summary struct {
		LoadedFrom            string  `json:"loaded_from"`
		AlertingEnabled       bool    `json:"alerting_enabled"`
		MinScoreThreshold     float64 `json:"min_score_threshold"`
		BeaconingStrongCV     float64 `json:"beaconing_strong_cv"`
		CaptureIntervalSec    int     `json:"daemon_capture_interval_seconds"`
		ExtraCmdlinePatterns  int     `json:"extra_cmdline_patterns_compiled"`
		ExtraJA3BadHashes     int     `json:"extra_ja3_bad_hashes"`
	}

	s := summary{
		LoadedFrom:           config.LoadedPath(),
		AlertingEnabled:      cfg.Alerting.Enabled,
		MinScoreThreshold:    cfg.Alerting.MinScoreThreshold,
		BeaconingStrongCV:    cfg.Scoring.BeaconingStrongCV,
		CaptureIntervalSec:   cfg.Daemon.CaptureIntervalSec,
		ExtraCmdlinePatterns: len(cfg.Scoring.CompiledExtraCmdlinePatterns),
		ExtraJA3BadHashes:    len(cfg.Scoring.ExtraJA3BadHashes),
	}

	if s.LoadedFrom == "" {
		s.LoadedFrom = "(built-in defaults — no config file)"
	}

	data, err := json.MarshalIndent(map[string]any{
		"status":  "ok",
		"message": "Configuration reloaded successfully",
		"config":  s,
	}, "", "  ")
	if err != nil {
		return errorResult(err.Error()), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}
