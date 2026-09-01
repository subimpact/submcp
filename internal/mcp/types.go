package mcp

import "encoding/json"

// JSON-RPC 2.0 message shapes per the MCP spec (2025-03-26).

// Request is a JSON-RPC request.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Notification is a JSON-RPC notification (no id).
type Notification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// InitializeParams is the MCP initialize request params.
type InitializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"clientInfo"`
}

// InitializeResult is the MCP initialize response.
type InitializeResult struct {
	ProtocolVersion string `json:"protocolVersion"`
	Capabilities    struct {
		Tools     map[string]any `json:"tools,omitempty"`
		Prompts   map[string]any `json:"prompts,omitempty"`
		Resources map[string]any `json:"resources,omitempty"`
	} `json:"capabilities"`
	ServerInfo struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
	Instructions *string `json:"instructions,omitempty"`
}

// Tool is an MCP tool definition.
type Tool struct {
	Name        string           `json:"name"`
	Title       *string          `json:"title,omitempty"`
	Description *string          `json:"description,omitempty"`
	InputSchema json.RawMessage  `json:"inputSchema"`
	Annotations *ToolAnnotations `json:"annotations,omitempty"`
	// Extra passthrough fields (outputSchema, execution, etc.) — the
	// original gateway spreads the full upstream tool object, so unknown
	// fields must survive the round trip.
	Extra map[string]json.RawMessage `json:"-"`
}

// MarshalJSON emits the tool with passthrough fields preserved.
func (t Tool) MarshalJSON() ([]byte, error) {
	out := make(map[string]any, len(t.Extra)+5)
	for k, v := range t.Extra {
		out[k] = json.RawMessage(v)
	}
	out["name"] = t.Name
	if t.Title != nil {
		out["title"] = *t.Title
	}
	if t.Description != nil {
		out["description"] = *t.Description
	}
	out["inputSchema"] = json.RawMessage(t.InputSchema)
	if t.Annotations != nil {
		out["annotations"] = t.Annotations
	}
	return json.Marshal(out)
}

// UnmarshalJSON captures known fields and preserves extras.
func (t *Tool) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	t.Extra = make(map[string]json.RawMessage)
	for k, v := range raw {
		switch k {
		case "name":
			_ = json.Unmarshal(v, &t.Name)
		case "title":
			var s string
			if err := json.Unmarshal(v, &s); err == nil {
				t.Title = &s
			}
		case "description":
			var s string
			if err := json.Unmarshal(v, &s); err == nil {
				t.Description = &s
			}
		case "inputSchema":
			t.InputSchema = v
		case "annotations":
			var a ToolAnnotations
			if err := json.Unmarshal(v, &a); err == nil {
				t.Annotations = &a
			}
		default:
			t.Extra[k] = v
		}
	}
	return nil
}

// ToolAnnotations mirrors the MCP tool annotations object.
type ToolAnnotations struct {
	Title           *string  `json:"title,omitempty"`
	ReadOnlyHint    *bool    `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool    `json:"destructiveHint,omitempty"`
	IDempotentHint  *bool    `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool    `json:"openWorldHint,omitempty"`
}

// ListToolsResult is the tools/list response.
type ListToolsResult struct {
	Tools        []Tool `json:"tools"`
	NextCursor   *string `json:"nextCursor,omitempty"`
}

// CallToolParams is the tools/call request params.
type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// CallToolResult is the tools/call response. The original accepts BOTH the
// legacy toolResult shape and the modern content shape (CompatibilityCallToolResultSchema).
type CallToolResult struct {
	Content []ContentBlock `json:"content"`
	IsError *bool          `json:"isError,omitempty"`
	// Legacy shape passthrough (toolResult) — kept as raw for parity.
	ToolResult json.RawMessage `json:"-"`
}

// ContentBlock is a content block in a call result.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
	// For non-text blocks, keep raw.
	Raw json.RawMessage `json:"-"`
}

// ListToolsRequest is the full tools/list request.
type ListToolsRequest struct {
	Method string `json:"method"`
	Params *struct {
		Cursor *string `json:"cursor,omitempty"`
	} `json:"params,omitempty"`
}

// Standard error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)
