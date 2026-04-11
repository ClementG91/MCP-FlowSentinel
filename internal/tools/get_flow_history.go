package tools

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/history"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerGetFlowHistory(s *server.MCPServer) {
	tool := mcp.NewTool("get_flow_history",
		mcp.WithDescription(
			"Query the rolling 24-hour history of previously analyzed network flows. "+
				"Returns flows from past analyze_network and analyze_pcap sessions, "+
				"allowing you to correlate activity over time, track recurring connections, "+
				"or investigate processes that were active earlier. "+
				"History is stored locally at ~/.cache/mcp-flowsentinel/history.jsonl.",
		),
		mcp.WithNumber("max_age_hours",
			mcp.Description(
				"How far back to look, in hours. Default: 24 (full rolling window). "+
					"Use 1 to see only the last hour.",
			),
		),
		mcp.WithNumber("min_score",
			mcp.Description(
				"Only return flows with suspicion_score >= this value (0–10). "+
					"Default: 0 (all flows). Use 5 to show HIGH+ only.",
			),
		),
		mcp.WithString("src_ip",
			mcp.Description("Filter by exact source IP address. Empty means any."),
		),
		mcp.WithString("dst_ip",
			mcp.Description("Filter by exact destination IP address. Empty means any."),
		),
		mcp.WithString("process_name",
			mcp.Description(
				"Case-insensitive substring filter on process name. "+
					"E.g. 'curl' matches 'curl', 'curl.exe', 'libcurl'.",
			),
		),
		mcp.WithNumber("top_n",
			mcp.Description(
				"Return at most this many flows per history entry (highest score first). "+
					"Default: 0 (unlimited).",
			),
		),
	)
	s.AddTool(tool, getFlowHistoryHandler)
}

func getFlowHistoryHandler(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.Params.Arguments

	opts := history.QueryOpts{}

	if v, ok := args["max_age_hours"].(float64); ok && v > 0 {
		opts.MaxAge = time.Duration(v * float64(time.Hour))
	}
	if v, ok := args["min_score"].(float64); ok && v > 0 {
		opts.MinScore = v
	}
	if v, ok := args["src_ip"].(string); ok {
		opts.SrcIP = v
	}
	if v, ok := args["dst_ip"].(string); ok {
		opts.DstIP = v
	}
	if v, ok := args["process_name"].(string); ok {
		opts.ProcessName = v
	}
	if v, ok := args["top_n"].(float64); ok && v > 0 {
		opts.TopN = int(v)
	}

	entries, err := history.Query(opts)
	if err != nil {
		return errorResult("failed to read history: " + err.Error()), nil
	}

	totalFlows := 0
	for _, e := range entries {
		totalFlows += e.FlowCount
	}

	type queryInfo struct {
		MaxAgeHours   float64 `json:"max_age_hours"`
		MinScore      float64 `json:"min_score_filter,omitempty"`
		SrcIPFilter   string  `json:"src_ip_filter,omitempty"`
		DstIPFilter   string  `json:"dst_ip_filter,omitempty"`
		ProcessFilter string  `json:"process_filter,omitempty"`
		EntriesFound  int     `json:"entries_found"`
		TotalFlows    int     `json:"total_flows"`
		HistoryFile   string  `json:"history_file"`
	}
	type response struct {
		QueryInfo queryInfo       `json:"query_info"`
		Entries   []history.Entry `json:"entries"`
	}

	maxAgeHours := 24.0
	if opts.MaxAge > 0 {
		maxAgeHours = opts.MaxAge.Hours()
	}

	out, err := json.Marshal(response{
		QueryInfo: queryInfo{
			MaxAgeHours:   maxAgeHours,
			MinScore:      opts.MinScore,
			SrcIPFilter:   opts.SrcIP,
			DstIPFilter:   opts.DstIP,
			ProcessFilter: opts.ProcessName,
			EntriesFound:  len(entries),
			TotalFlows:    totalFlows,
			HistoryFile:   history.Path(),
		},
		Entries: entries,
	})
	if err != nil {
		return errorResult("failed to encode response: " + err.Error()), nil
	}
	return mcp.NewToolResultText(string(out)), nil
}
