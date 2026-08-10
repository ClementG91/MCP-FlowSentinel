package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const jsonSchemaDraft202012 = "https://json-schema.org/draft/2020-12/schema"

type toolHandler func(context.Context, map[string]any) (*mcp.CallToolResult, error)

type toolSpec struct {
	description string
	title       string
	properties  map[string]any
	required    []string
	annotations *mcp.ToolAnnotations
}

type toolOption func(*toolSpec)

type parameterSpec struct {
	description string
	required    bool
	minimum     *float64
	maximum     *float64
	minLength   *int
	maxLength   *int
	defaultVal  any
}

type parameterOption func(*parameterSpec)

// newTool builds a JSON Schema 2020-12 tool definition for the official MCP
// Go SDK. Unknown arguments are rejected so callers cannot silently misspell
// security-sensitive capture or filtering options.
func newTool(name string, options ...toolOption) *mcp.Tool {
	spec := &toolSpec{
		title:      strings.ReplaceAll(name, "_", " "),
		properties: make(map[string]any),
		annotations: &mcp.ToolAnnotations{
			// Conservative defaults. Every registered tool overrides these with
			// its actual behavior through withBehavior.
			ReadOnlyHint: false,
		},
	}
	for _, option := range options {
		option(spec)
	}

	schema := map[string]any{
		"$schema":              jsonSchemaDraft202012,
		"type":                 "object",
		"properties":           spec.properties,
		"additionalProperties": false,
	}
	if len(spec.required) > 0 {
		schema["required"] = spec.required
	}

	return &mcp.Tool{
		Name:        name,
		Title:       spec.title,
		Description: spec.description,
		InputSchema: schema,
		Annotations: spec.annotations,
	}
}

func withDescription(value string) toolOption {
	return func(spec *toolSpec) { spec.description = value }
}

func withBehavior(title string, readOnly, idempotent, openWorld bool) toolOption {
	return func(spec *toolSpec) {
		spec.title = title
		spec.annotations = &mcp.ToolAnnotations{
			DestructiveHint: boolPtr(false),
			IdempotentHint:  idempotent,
			OpenWorldHint:   boolPtr(openWorld),
			ReadOnlyHint:    readOnly,
			Title:           title,
		}
	}
}

func withString(name string, options ...parameterOption) toolOption {
	return withParameter(name, "string", options...)
}

func withNumber(name string, options ...parameterOption) toolOption {
	return withParameter(name, "number", options...)
}

func withInteger(name string, options ...parameterOption) toolOption {
	return withParameter(name, "integer", options...)
}

func withParameter(name, parameterType string, options ...parameterOption) toolOption {
	return func(tool *toolSpec) {
		parameter := &parameterSpec{}
		for _, option := range options {
			option(parameter)
		}
		property := map[string]any{"type": parameterType}
		if parameter.description != "" {
			property["description"] = parameter.description
		}
		if parameter.minimum != nil {
			property["minimum"] = *parameter.minimum
		}
		if parameter.maximum != nil {
			property["maximum"] = *parameter.maximum
		}
		if parameter.minLength != nil {
			property["minLength"] = *parameter.minLength
		}
		if parameter.maxLength != nil {
			property["maxLength"] = *parameter.maxLength
		}
		if parameter.defaultVal != nil {
			property["default"] = parameter.defaultVal
		}
		tool.properties[name] = property
		if parameter.required {
			tool.required = append(tool.required, name)
		}
	}
}

func description(value string) parameterOption {
	return func(parameter *parameterSpec) { parameter.description = value }
}

func required() parameterOption {
	return func(parameter *parameterSpec) { parameter.required = true }
}

func minimum(value float64) parameterOption {
	return func(parameter *parameterSpec) { parameter.minimum = &value }
}

func maximum(value float64) parameterOption {
	return func(parameter *parameterSpec) { parameter.maximum = &value }
}

func minLength(value int) parameterOption {
	return func(parameter *parameterSpec) { parameter.minLength = &value }
}

func maxLength(value int) parameterOption {
	return func(parameter *parameterSpec) { parameter.maxLength = &value }
}

func defaultValue(value any) parameterOption {
	return func(parameter *parameterSpec) { parameter.defaultVal = value }
}

func boolPtr(value bool) *bool { return &value }

// addTool uses the SDK's typed registration path so input is validated against
// the declared JSON Schema before a FlowSentinel handler receives it.
func addTool(server *mcp.Server, tool *mcp.Tool, handler toolHandler) {
	mcp.AddTool[map[string]any, any](server, tool,
		func(ctx context.Context, _ *mcp.CallToolRequest, arguments map[string]any) (*mcp.CallToolResult, any, error) {
			result, err := handler(ctx, arguments)
			return result, nil, err
		})
}

func textResult(text string) *mcp.CallToolResult {
	result := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}

	// Every FlowSentinel tool currently returns JSON. Publish it as native MCP
	// structuredContent while retaining the text block for older clients.
	var structured any
	if err := json.Unmarshal([]byte(text), &structured); err == nil {
		result.StructuredContent = structured
	}

	return result
}

// errorResult wraps a plain-text error message into an MCP tool result so the
// LLM receives structured feedback instead of a JSON-RPC protocol error.
func errorResult(msg string) *mcp.CallToolResult {
	result := textResult(fmt.Sprintf(`{"error":%q}`, msg))
	result.IsError = true
	return result
}
