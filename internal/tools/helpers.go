package tools

import (
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
)

// errorResult wraps a plain-text error message into an MCP tool result so the
// LLM receives structured feedback instead of a JSON-RPC protocol error.
func errorResult(msg string) *mcp.CallToolResult {
	return mcp.NewToolResultText(fmt.Sprintf(`{"error":%q}`, msg))
}
