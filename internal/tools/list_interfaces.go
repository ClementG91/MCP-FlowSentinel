package tools

import (
	"context"
	"encoding/json"

	"github.com/ClementG91/MCP-FlowSentinel/internal/capture"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerListInterfaces(s *server.MCPServer) {
	tool := mcp.NewTool("list_interfaces",
		mcp.WithDescription(
			"List all network interfaces available for packet capture, "+
				"including their IP addresses and operational flags. "+
				"Use this before calling analyze_network to pick the right interface name.",
		),
	)
	s.AddTool(tool, listInterfacesHandler)
}

func listInterfacesHandler(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ifaces, err := capture.ListInterfaces()
	if err != nil {
		return errorResult("list_interfaces failed: " + err.Error()), nil
	}

	type response struct {
		InterfaceCount int                 `json:"interface_count"`
		Interfaces     []capture.Interface `json:"interfaces"`
	}
	out, err := json.Marshal(response{
		InterfaceCount: len(ifaces),
		Interfaces:     ifaces,
	})
	if err != nil {
		return errorResult("failed to encode response: " + err.Error()), nil
	}
	return mcp.NewToolResultText(string(out)), nil
}
