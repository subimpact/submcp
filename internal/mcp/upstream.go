package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// UpstreamClient is a client connection to one upstream MCP server
// (STREAMABLE_HTTP transport). Behavior:
//   - initialize on connect
//   - auth precedence: oauth access_token ?? bearerToken -> Authorization header
//   - session-id header for subsequent requests
type UpstreamClient struct {
	mu sync.Mutex

	serverName string
	url        string
	authHeader string // "Bearer <token>" or ""
	extraHdrs  map[string]string

	httpClient *http.Client

	sessionID string
	initRes   *InitializeResult
	connected bool
}

// UpstreamConfig describes how to reach one upstream.
type UpstreamConfig struct {
	Name       string
	URL        string
	BearerToken string
	Headers    map[string]string
	Timeout    time.Duration
}

// NewUpstreamClient creates a client for a STREAMABLE_HTTP upstream.
func NewUpstreamClient(cfg UpstreamConfig) *UpstreamClient {
	auth := ""
	if cfg.BearerToken != "" {
		auth = "Bearer " + cfg.BearerToken
	}
	return &UpstreamClient{
		serverName: cfg.Name,
		url:        cfg.URL,
		authHeader: auth,
		extraHdrs:  cfg.Headers,
		httpClient: &http.Client{Timeout: cfg.Timeout},
	}
}

// Connect performs initialize and stores the session id.
func (c *UpstreamClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	initParams := map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]any{},
		"clientInfo": map[string]string{
			"name":    "submcp",
			"version": "0.1.0",
		},
	}
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params":  initParams,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build init request: %w", err)
	}
	c.applyHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("initialize %s: %w", c.serverName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("initialize %s: HTTP %d: %s", c.serverName, resp.StatusCode, truncate(string(raw), 300))
	}

	// Capture session id if present.
	if sid := resp.Header.Get("mcp-session-id"); sid != "" {
		c.sessionID = sid
	}

	// Read SSE stream: first event should be the initialize result.
	initRes, err := readFirstSSEMessage(resp.Body)
	if err != nil {
		return fmt.Errorf("read initialize result from %s: %w", c.serverName, err)
	}
	var rpc Response
	if err := json.Unmarshal(initRes, &rpc); err != nil {
		return fmt.Errorf("parse initialize result from %s: %w", c.serverName, err)
	}
	if rpc.Error != nil {
		return fmt.Errorf("initialize %s: rpc error %d: %s", c.serverName, rpc.Error.Code, rpc.Error.Message)
	}
	var init InitializeResult
	if err := json.Unmarshal(rpc.Result, &init); err != nil {
		return fmt.Errorf("parse initialize result payload from %s: %w", c.serverName, err)
	}
	c.initRes = &init
	c.connected = true
	return nil
}

// ListTools calls tools/list on the upstream.
func (c *UpstreamClient) ListTools(ctx context.Context) ([]Tool, error) {
	c.mu.Lock()
	if !c.connected {
		c.mu.Unlock()
		return nil, fmt.Errorf("upstream %s not connected", c.serverName)
	}
	sid := c.sessionID
	c.mu.Unlock()

	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]any{},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.applyHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sid != "" {
		req.Header.Set("mcp-session-id", sid)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tools/list %s: %w", c.serverName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("tools/list %s: HTTP %d: %s", c.serverName, resp.StatusCode, truncate(string(raw), 300))
	}

	msg, err := readFirstSSEMessage(resp.Body)
	if err != nil {
		return nil, err
	}
	var rpc Response
	if err := json.Unmarshal(msg, &rpc); err != nil {
		return nil, err
	}
	if rpc.Error != nil {
		return nil, fmt.Errorf("tools/list %s: rpc error %d: %s", c.serverName, rpc.Error.Code, rpc.Error.Message)
	}
	var result ListToolsResult
	if err := json.Unmarshal(rpc.Result, &result); err != nil {
		return nil, err
	}
	return result.Tools, nil
}

// CallTool calls tools/call on the upstream.
func (c *UpstreamClient) CallTool(ctx context.Context, name string, args json.RawMessage) (json.RawMessage, error) {
	c.mu.Lock()
	if !c.connected {
		c.mu.Unlock()
		return nil, fmt.Errorf("upstream %s not connected", c.serverName)
	}
	sid := c.sessionID
	c.mu.Unlock()

	params := map[string]any{"name": name}
	if len(args) > 0 && string(args) != "null" {
		params["arguments"] = json.RawMessage(args)
	}
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params":  params,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.applyHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sid != "" {
		req.Header.Set("mcp-session-id", sid)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tools/call %s: %w", c.serverName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("tools/call %s: HTTP %d: %s", c.serverName, resp.StatusCode, truncate(string(raw), 300))
	}

	msg, err := readFirstSSEMessage(resp.Body)
	if err != nil {
		return nil, err
	}
	var rpc Response
	if err := json.Unmarshal(msg, &rpc); err != nil {
		return nil, err
	}
	if rpc.Error != nil {
		return nil, fmt.Errorf("tools/call %s: rpc error %d: %s", c.serverName, rpc.Error.Code, rpc.Error.Message)
	}
	return rpc.Result, nil
}

// Close terminates the upstream session (DELETE per streamable HTTP spec).
func (c *UpstreamClient) Close(ctx context.Context) {
	c.mu.Lock()
	sid := c.sessionID
	c.connected = false
	c.mu.Unlock()
	if sid == "" {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.url, nil)
	if err != nil {
		return
	}
	c.applyHeaders(req)
	req.Header.Set("mcp-session-id", sid)
	resp, err := c.httpClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

func (c *UpstreamClient) applyHeaders(req *http.Request) {
	if c.authHeader != "" {
		req.Header.Set("Authorization", c.authHeader)
	}
	for k, v := range c.extraHdrs {
		req.Header.Set(k, v)
	}
}

// readFirstSSEMessage reads the first SSE event from a stream and returns
// its data payload. Handles both SSE framing and plain JSON responses.
func readFirstSSEMessage(r io.Reader) ([]byte, error) {
	// Peek: if the body starts with '{', it's plain JSON (no SSE framing).
	br := bufio.NewReader(r)
	first, err := br.Peek(1)
	if err != nil {
		return nil, err
	}
	if first[0] == '{' {
		return io.ReadAll(io.LimitReader(br, 16<<20))
	}

	var data []byte
	scanner := bufio.NewScanner(br)
	scanner.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if payload != "" {
				data = []byte(payload)
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("no SSE data event received")
	}
	return data, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
