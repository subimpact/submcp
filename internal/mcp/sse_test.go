package mcp

import (
	"strings"
	"testing"
)

func TestReadSSEMessagePlainJSON(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`
	got, err := readFirstSSEMessage(strings.NewReader(body), "1")
	if err != nil {
		t.Fatalf("plain JSON: %v", err)
	}
	if string(got) != body {
		t.Fatalf("plain JSON passthrough wrong: %s", got)
	}
}

func TestReadSSEMessageSingleLine(t *testing.T) {
	body := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"
	got, err := readFirstSSEMessage(strings.NewReader(body), "1")
	if err != nil {
		t.Fatalf("single line: %v", err)
	}
	if string(got) != `{"jsonrpc":"2.0","id":1,"result":{}}` {
		t.Fatalf("single line payload wrong: %q", got)
	}
}

func TestReadSSEMessageMultiLineData(t *testing.T) {
	// Multi-line data: two data: lines joined with \n (SSE spec).
	body := "data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\"result\":{}}\n\n"
	got, err := readFirstSSEMessage(strings.NewReader(body), "1")
	if err != nil {
		t.Fatalf("multi-line: %v", err)
	}
	want := "{\"jsonrpc\":\"2.0\",\n\"id\":1,\"result\":{}}"
	if string(got) != want {
		t.Fatalf("multi-line payload wrong:\n got %q\nwant %q", got, want)
	}
}

func TestReadSSEMessageLeadingWhitespacePreserved(t *testing.T) {
	// Exactly one leading space after "data:" is stripped; extra spaces
	// are preserved (spec).
	body := "data:  {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"
	got, err := readFirstSSEMessage(strings.NewReader(body), "1")
	if err != nil {
		t.Fatalf("whitespace: %v", err)
	}
	if string(got) != ` {"jsonrpc":"2.0","id":1,"result":{}}` {
		t.Fatalf("whitespace handling wrong: %q", got)
	}
}

func TestReadSSEMessageSkipsNotification(t *testing.T) {
	// A notification (no JSON-RPC id) arrives first, then the response
	// with the matching id. The parser must skip the notification.
	// Note: the SSE "id:" field is an event-stream identifier (apify
	// emits a UUID there) — correlation is via the JSON-RPC payload id.
	body := "id: some-uuid-1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\n" +
		"id: some-uuid-2\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n\n"
	got, err := readFirstSSEMessage(strings.NewReader(body), "2")
	if err != nil {
		t.Fatalf("id matching: %v", err)
	}
	if string(got) != `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}` {
		t.Fatalf("id matching wrong: %q", got)
	}
}

func TestReadSSEMessageIgnoresSSEEventID(t *testing.T) {
	// Apify-style: SSE id field is a server UUID, JSON-RPC id is the
	// request id. Must NOT skip the event because of the UUID.
	body := "event: message\nid: d3efa00e-f139-4b9d-9ae1-7e3f3be01abf\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n"
	got, err := readFirstSSEMessage(strings.NewReader(body), "1")
	if err != nil {
		t.Fatalf("apify-style SSE: %v", err)
	}
	if string(got) != `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}` {
		t.Fatalf("apify-style SSE payload wrong: %q", got)
	}
}

func TestReadSSEMessageNoTrailingBlankLine(t *testing.T) {
	// Some servers omit the trailing blank line; the parser must still
	// return the event at EOF.
	body := "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"
	got, err := readFirstSSEMessage(strings.NewReader(body), "1")
	if err != nil {
		t.Fatalf("no trailing blank: %v", err)
	}
	if string(got) != `{"jsonrpc":"2.0","id":1,"result":{}}` {
		t.Fatalf("no trailing blank payload wrong: %q", got)
	}
}

func TestReadSSEMessageNoData(t *testing.T) {
	body := "event: ping\n\n"
	if _, err := readFirstSSEMessage(strings.NewReader(body), "1"); err == nil {
		t.Fatalf("expected error for no data event")
	}
}
