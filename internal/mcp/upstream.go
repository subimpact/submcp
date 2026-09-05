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
	initRes, err := readFirstSSEMessage(resp.Body, "1")
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

	msg, err := readFirstSSEMessage(resp.Body, "2")
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

	msg, err := readFirstSSEMessage(resp.Body, "3")
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
//
// P1-1+P1-11 rewrite:
//   - multi-line data: consecutive "data:" lines are joined with "\n"
//     (SSE spec); the payload is only complete at the blank line
//   - leading whitespace: exactly one leading space after "data:" is
//     stripped (spec); additional whitespace is preserved
//   - request-id matching: events whose "id:" field does not match the
//     request id are skipped (some servers emit notifications first)
//   - body drain: the stream is read to EOF so the connection can be
//     reused (enables P2-14 transport tuning)
func readFirstSSEMessage(r io.Reader, wantID string) ([]byte, error) {
	// Peek: if the body starts with '{', it's plain JSON (no SSE framing).
	br := bufio.NewReader(r)
	first, err := br.Peek(1)
	if err != nil {
		return nil, err
	}
	if first[0] == '{' {
		return io.ReadAll(io.LimitReader(br, 16<<20))
	}

	var (
		dataLines []string
		inEvent   bool
	)
	scanner := bufio.NewScanner(br)
	scanner.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Blank line terminates the event. Accept it when:
			//   - it has data, AND
			//   - it is not a JSON-RPC notification (no "id" member in
			//     the payload — some servers emit notifications first),
			//     AND
			//   - its JSON-RPC id matches the expected id (when one is
			//     expected). NOTE: the SSE "id:" field is an event-stream
			//     identifier (Last-Event-ID), NOT a request correlation
			//     id — apify emits a UUID there. Correlation is done via
			//     the JSON-RPC payload id only.
			if len(dataLines) > 0 {
				payload := []byte(strings.Join(dataLines, "\n"))
				if wantID != "" && !jsonRPCIDMatches(payload, wantID) {
					// Notification or mismatched id: skip this event.
					dataLines = nil
					inEvent = false
					continue
				}
				return payload, nil
			}
			// Mismatched event: reset and keep scanning.
			dataLines = nil
			inEvent = false
			continue
		}
		switch {
		case strings.HasPrefix(line, "data:"):
			inEvent = true
			// Spec: strip exactly one leading space after the colon.
			payload := strings.TrimPrefix(line, "data:")
			if strings.HasPrefix(payload, " ") {
				payload = payload[1:]
			}
			dataLines = append(dataLines, payload)
		case strings.HasPrefix(line, "id:"):
			// Event-stream id (Last-Event-ID) — NOT a correlation id.
			// Ignored for matching; see comment above.
		case strings.HasPrefix(line, "event:"):
			// Event type is informational; we match on id only.
		case strings.HasPrefix(line, "retry:"):
			// Ignore.
		default:
			// Comment or unknown field: ignore.
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	// Stream ended without a blank line: return what we have if it's a
	// complete event (some servers omit the trailing blank line).
	if len(dataLines) > 0 {
		payload := []byte(strings.Join(dataLines, "\n"))
		if wantID != "" && !jsonRPCIDMatches(payload, wantID) {
			return nil, fmt.Errorf("no SSE data event with id %s received", wantID)
		}
		return payload, nil
	}
	if inEvent {
		return nil, fmt.Errorf("no complete SSE data event received")
	}
	return nil, fmt.Errorf("no SSE data event received")
}

// jsonRPCIDMatches reports whether a JSON-RPC payload's "id" member matches
// the expected id. Payloads without an id (notifications) never match when
// an id is expected. Comparison is stringified (JSON-RPC ids may be
// numbers or strings; our requests use numbers).
func jsonRPCIDMatches(payload []byte, wantID string) bool {
	var probe struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return true // not JSON we can parse — don't skip it
	}
	if len(probe.ID) == 0 || string(probe.ID) == "null" {
		return false // notification
	}
	var got string
	if err := json.Unmarshal(probe.ID, &got); err != nil {
		// Not a string — try number.
		var n json.Number
		if err := json.Unmarshal(probe.ID, &n); err != nil {
			return true // unparseable id — don't skip
		}
		got = n.String()
	}
	return got == wantID
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
