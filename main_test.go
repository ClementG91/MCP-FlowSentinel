package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestPrintUsageDocumentsSupportedCommands(t *testing.T) {
	var out bytes.Buffer
	printUsage(&out)
	for _, flag := range []string{
		"--daemon", "--check", "--init-config", "--validate-config",
		"--test-alert", "--update", "--version", "--help", "--config",
	} {
		if !strings.Contains(out.String(), flag) {
			t.Errorf("usage does not document %s", flag)
		}
	}
}

func TestMCPServerSupportsProtocol20260728(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := newMCPServer().Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	defer serverSession.Close()

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "flowsentinel-protocol-test",
		Version: "1.0.0",
	}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	defer clientSession.Close()

	initialization := clientSession.InitializeResult()
	if initialization == nil {
		t.Fatal("missing MCP initialization result")
	}
	if got, want := initialization.ProtocolVersion, "2026-07-28"; got != want {
		t.Fatalf("protocol version = %q, want %q", got, want)
	}
	if !strings.Contains(initialization.Instructions, "list_interfaces") {
		t.Errorf("server instructions do not describe the safe discovery workflow: %q", initialization.Instructions)
	}

	listed, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if got, want := len(listed.Tools), 12; got != want {
		t.Fatalf("tool count = %d, want %d", got, want)
	}

	toolsByName := make(map[string]*mcp.Tool, len(listed.Tools))
	for _, tool := range listed.Tools {
		toolsByName[tool.Name] = tool
	}

	listInterfaces := toolsByName["list_interfaces"]
	if listInterfaces == nil || listInterfaces.Annotations == nil {
		t.Fatal("list_interfaces is missing MCP tool annotations")
	}
	if !listInterfaces.Annotations.ReadOnlyHint || !listInterfaces.Annotations.IdempotentHint {
		t.Errorf("list_interfaces annotations = %+v, want read-only and idempotent", listInterfaces.Annotations)
	}

	analyzeNetwork := toolsByName["analyze_network"]
	if analyzeNetwork == nil || analyzeNetwork.Annotations == nil {
		t.Fatal("analyze_network is missing MCP tool annotations")
	}
	if analyzeNetwork.Annotations.ReadOnlyHint {
		t.Error("analyze_network must not be advertised as read-only because it persists local history")
	}
	schema, ok := analyzeNetwork.InputSchema.(map[string]any)
	if !ok {
		t.Fatalf("analyze_network input schema type = %T, want map[string]any", analyzeNetwork.InputSchema)
	}
	if got := schema["$schema"]; got != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("JSON Schema dialect = %v, want draft 2020-12", got)
	}
	if got := schema["additionalProperties"]; got != false {
		t.Errorf("additionalProperties = %v, want false", got)
	}

	result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_interfaces",
		Arguments: map[string]any{"unexpected": true},
	})
	if err != nil {
		t.Fatalf("call invalid list_interfaces request: %v", err)
	}
	if !result.IsError {
		t.Error("unknown tool arguments must be rejected by JSON Schema validation")
	}

	scanResult, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name:      "scan_process",
		Arguments: map[string]any{"pid": os.Getpid()},
	})
	if err != nil {
		t.Fatalf("call scan_process through MCP: %v", err)
	}
	if scanResult.IsError {
		t.Fatalf("valid integer arguments were rejected: %+v", scanResult.Content)
	}
	if scanResult.StructuredContent == nil {
		t.Fatal("scan_process did not return native MCP structuredContent")
	}
}
