package tools

import (
	"context"
	"encoding/json"

	"github.com/ClementG91/MCP-FlowSentinel/internal/daemon"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerGetDaemonStats(s *server.MCPServer) {
	s.AddTool(mcp.NewTool("get_daemon_stats",
		mcp.WithDescription(`Return runtime statistics for the background daemon.

Reports whether the daemon is currently running, and if so:
  - start_time / uptime_seconds — how long it has been running
  - interface — the network interface being monitored
  - interval_seconds — the capture window length
  - windows_run — total number of completed capture windows
  - flows_scored — total flows analyzed since start
  - alerts_fired — total webhook alerts sent since start
  - window_errors — number of capture windows that failed

If the daemon is not running (MCP server started without --daemon), all
counters are zero and running is false.`),
	), getDaemonStatsHandler)
}

func getDaemonStatsHandler(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	stats := daemon.GetStats()
	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return errorResult(err.Error()), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}
