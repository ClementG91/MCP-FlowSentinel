// Package tools wires together the MCP tool definitions and their handlers.
package tools

import "github.com/modelcontextprotocol/go-sdk/mcp"

// Register adds all FlowSentinel tools to the MCP server.
func Register(s *mcp.Server) {
	registerListInterfaces(s)
	registerAnalyzeNetwork(s)
	registerAnalyzePcap(s)
	registerGetProcessMap(s)
	registerGetFlowHistory(s)
	registerAnalyzeProcess(s)
	registerGetConfig(s)
	registerGetDaemonStats(s)
	registerGetAlerts(s)
	registerReloadConfig(s)
	registerScanProcess(s)
	registerLiveWatch(s)
}
