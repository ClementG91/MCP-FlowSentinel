package tools

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/correlate"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerGetProcessMap(s *server.MCPServer) {
	tool := mcp.NewTool("get_process_map",
		mcp.WithDescription(
			"Return a point-in-time snapshot of every process that has open network "+
				"sockets, together with each socket's local/remote address and state. "+
				"Useful for discovering which binaries are listening or connected right now "+
				"without capturing traffic. Requires root/admin for full PID resolution.",
		),
	)
	s.AddTool(tool, getProcessMapHandler)
}

func getProcessMapHandler(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	byPID, err := correlate.GetAllConnections()
	if err != nil {
		return errorResult("get_process_map failed: " + err.Error()), nil
	}

	// Convert map to a deterministically-ordered slice sorted by PID.
	processes := make([]*correlate.ProcessWithConns, 0, len(byPID))
	for _, pwc := range byPID {
		processes = append(processes, pwc)
	}
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].PID < processes[j].PID
	})

	type response struct {
		Timestamp                  time.Time                    `json:"timestamp"`
		ProcessesWithConnectionsN  int                          `json:"processes_with_connections"`
		Processes                  []*correlate.ProcessWithConns `json:"processes"`
	}
	out, err := json.Marshal(response{
		Timestamp:                 time.Now().UTC(),
		ProcessesWithConnectionsN: len(processes),
		Processes:                 processes,
	})
	if err != nil {
		return errorResult("failed to encode response: " + err.Error()), nil
	}
	return mcp.NewToolResultText(string(out)), nil
}
