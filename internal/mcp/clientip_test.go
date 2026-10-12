package mcp

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPHonoursForwardedHeadersOnlyFromTrustedProxies(t *testing.T) {
	if err := SetTrustedProxies("10.0.5.0/24"); err != nil {
		t.Fatal(err)
	}
	defer SetTrustedProxies("")

	cases := []struct {
		name, remote string
		headers      map[string]string
		want         string
	}{
		{"untrusted peer, spoofed XFF", "203.0.113.9:4000",
			map[string]string{"X-Forwarded-For": "1.2.3.4"}, "203.0.113.9"},
		{"untrusted peer, spoofed CF header", "203.0.113.9:4000",
			map[string]string{"CF-Connecting-IP": "1.2.3.4"}, "203.0.113.9"},
		{"trusted peer, CF-Connecting-IP wins", "10.0.5.7:4000",
			map[string]string{"CF-Connecting-IP": "198.51.100.8", "X-Forwarded-For": "1.2.3.4, 10.0.5.7"}, "198.51.100.8"},
		{"trusted peer, rightmost XFF when no CF header", "10.0.5.7:4000",
			map[string]string{"X-Forwarded-For": "1.2.3.4, 198.51.100.77"}, "198.51.100.77"},
		{"trusted peer, garbage headers fall back to the peer", "10.0.5.7:4000",
			map[string]string{"CF-Connecting-IP": "not-an-ip"}, "10.0.5.7"},
		{"no proxy trusted when the list is empty", "10.0.5.7:4000",
			map[string]string{"CF-Connecting-IP": "198.51.100.8"}, "10.0.5.7"},
	}
	for _, c := range cases {
		if c.name == "no proxy trusted when the list is empty" {
			SetTrustedProxies("")
		} else {
			SetTrustedProxies("10.0.5.0/24")
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		for k, v := range c.headers {
			r.Header.Set(k, v)
		}
		if got := ClientIP(r); got != c.want {
			t.Errorf("%s: ClientIP = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestSetTrustedProxiesRejectsGarbage(t *testing.T) {
	if err := SetTrustedProxies("not-a-cidr"); err == nil {
		t.Fatal("garbage must be refused at startup")
	}
	if err := SetTrustedProxies("10.0.5.0/24, 172.18.0.1"); err != nil {
		t.Fatalf("valid list refused: %v", err)
	}
	SetTrustedProxies("")
}
