package mcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestTenantIPAllowedRefusesInternalRanges(t *testing.T) {
	blocked := []string{
		"0.0.0.0", "0.1.2.3", "127.0.0.1", "127.255.255.254",
		"10.0.5.2",        // docker bridge in use (uy2gf2yhgu9cqi16y69is4ni)
		"10.99.0.4",       // docker bridge in use (shared)
		"172.17.0.2",      // default docker bridge
		"172.16.0.1",      // RFC 1918
		"192.168.1.1",     // RFC 1918
		"169.254.169.254", // cloud metadata
		"100.100.100.100", // CGNAT / Tailscale range
		"100.64.0.1",
		"224.0.0.1", "240.0.0.1", "255.255.255.255",
		"::", "::1", "fe80::1", "fc00::1", "fd00:1234::5",
		"::ffff:127.0.0.1", "::ffff:10.0.5.2", "::ffff:169.254.169.254",
		"64:ff9b::a00:1", "2002:c000:0201::1", "2001:db8::1", "ff02::1",
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test ip %q", s)
		}
		if TenantIPAllowed(ip) {
			t.Errorf("%s must be refused", s)
		}
	}
	allowed := []string{
		"1.1.1.1", "8.8.8.8", "93.184.216.34", "172.32.0.1", "11.0.0.1",
		"2606:4700:4700::1111", "2a00:1450:4001::200e", "::ffff:8.8.8.8",
	}
	for _, s := range allowed {
		if !TenantIPAllowed(net.ParseIP(s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
	if TenantIPAllowed(nil) {
		t.Error("nil address must be refused")
	}
}

func TestValidateTenantURL(t *testing.T) {
	p := DefaultTenantNetPolicy()
	accepted := []string{
		"https://mcp.deepwiki.com/mcp",
		"https://api.peec.ai/mcp",
		"https://mcp.tavily.com/mcp/",
		"https://Example-Server.co.uk:443/mcp",
		"HTTPS://example.com/mcp",
		"https://example.com./mcp",
	}
	for _, raw := range accepted {
		if _, err := ValidateTenantURL(raw, p); err != nil {
			t.Errorf("ValidateTenantURL(%q) refused: %v", raw, err)
		}
	}
	refused := []string{
		"", "http://mcp.example.com/mcp", "ftp://example.com/x", "javascript:alert(1)",
		"https://127.0.0.1", "https://127.0.0.1/mcp", "https://10.0.5.2:5432",
		"https://169.254.169.254/", "https://100.100.100.100", "https://[::1]",
		"https://[fd00::1]/mcp", "https://[::ffff:10.0.5.2]/mcp",
		"https://submcp-saas:12011", // single label: a docker-internal name
		"https://localhost/mcp", "https://foo.localhost", "https://box.internal",
		"https://printer.local", "https://intranet.corp", "https://a.example",
		"https://user:pass@example.com/mcp",
		"https://example.com/mcp?token=abc",
		"https://example.com/mcp?",
		"https://example.com:8443/mcp",
		"https://example.com/mcp#frag",
		"https://127.1",
		"https://0x7f.1",
		"https://exa mple.com/",
		"https://exa_mple.com/",
		"https://-bad.example.com/",
		"https://" + strings.Repeat("a", 64) + ".example.com/",
		"https://example.com/" + strings.Repeat("x", 2100),
	}
	for _, raw := range refused {
		if _, err := ValidateTenantURL(raw, p); err == nil {
			t.Errorf("ValidateTenantURL(%q) accepted, must refuse", raw)
		}
	}
}

// fakeResolver returns fixed answers per host (NXDOMAIN for unknown names).
type fakeResolver map[string][]string

func (f fakeResolver) lookup(_ context.Context, host string) ([]net.IP, error) {
	answers, ok := f[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]net.IP, 0, len(answers))
	for _, a := range answers {
		out = append(out, net.ParseIP(a))
	}
	return out, nil
}

// recordingDialer counts dial attempts and remembers the addresses dialed.
type recordingDialer struct {
	mu    sync.Mutex
	addrs []string
}

func (r *recordingDialer) dial(_ context.Context, _, addr string) (net.Conn, error) {
	r.mu.Lock()
	r.addrs = append(r.addrs, addr)
	r.mu.Unlock()
	return nil, errors.New("test dialer: no connection")
}

func (r *recordingDialer) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.addrs)
}

func TestCheckTenantTargetRefusesDNSToBlockedAddresses(t *testing.T) {
	rec := &recordingDialer{}
	p := &TenantNetPolicy{
		Lookup: fakeResolver{
			"localtest.example-zone.net": {"127.0.0.1"}, // localtest.me style
			"nip.example-zone.net":       {"127.0.0.1"}, // 127.0.0.1.nip.io style
			"rebind.example-zone.net":    {"10.0.5.2"},  // private answer
			"meta.example-zone.net":      {"169.254.169.254"},
			"mixed.example-zone.net":     {"93.184.216.34", "192.168.1.10"},
			"cgnat.example-zone.net":     {"100.100.100.100"},
			"public.example-zone.net":    {"93.184.216.34"},
		}.lookup,
		Dial:    rec.dial,
		AllowIP: TenantIPAllowed,
		Ports:   []string{"443"},
	}
	for _, host := range []string{"localtest.example-zone.net", "nip.example-zone.net", "rebind.example-zone.net", "meta.example-zone.net", "mixed.example-zone.net", "cgnat.example-zone.net"} {
		if err := CheckTenantTarget(context.Background(), "https://"+host+"/mcp", p); !errors.Is(err, ErrTenantAddressBlocked) {
			t.Errorf("%s: err = %v, want ErrTenantAddressBlocked", host, err)
		}
	}
	if err := CheckTenantTarget(context.Background(), "https://public.example-zone.net/mcp", p); err != nil {
		t.Fatalf("public host refused: %v", err)
	}
	if err := CheckTenantTarget(context.Background(), "https://unknown.example-zone.net/mcp", p); err == nil {
		t.Fatal("NXDOMAIN host must be refused")
	}
	if rec.count() != 0 {
		t.Fatalf("DNS checks must never dial: %d dials", rec.count())
	}
}

func TestDialerRefusesBlockedAnswersWithoutDialing(t *testing.T) {
	rec := &recordingDialer{}
	p := &TenantNetPolicy{
		Lookup: fakeResolver{
			"loop.example-zone.net":  {"127.0.0.1"},
			"mixed.example-zone.net": {"93.184.216.34", "10.0.5.2"},
		}.lookup,
		Dial:    rec.dial,
		AllowIP: TenantIPAllowed,
		Ports:   []string{"443"},
	}
	for _, host := range []string{"loop.example-zone.net", "mixed.example-zone.net"} {
		if _, err := p.dialContext(context.Background(), "tcp", net.JoinHostPort(host, "443")); err == nil {
			t.Errorf("%s: dial must be refused", host)
		}
	}
	if rec.count() != 0 {
		t.Fatalf("a refused host must not be dialed: %v", rec.addrs)
	}
}

func TestDialerDialsOnlyTheCheckedAddress(t *testing.T) {
	rec := &recordingDialer{}
	p := &TenantNetPolicy{
		Lookup:  fakeResolver{"flip.example-zone.net": {"93.184.216.34"}}.lookup,
		Dial:    rec.dial,
		AllowIP: TenantIPAllowed,
		Ports:   []string{"443"},
	}
	_, _ = p.dialContext(context.Background(), "tcp", "flip.example-zone.net:443")
	if len(rec.addrs) != 1 || rec.addrs[0] != "93.184.216.34:443" {
		t.Fatalf("dialed %v, want only the checked IP 93.184.216.34:443", rec.addrs)
	}
}

func TestDialerRefusesOtherPorts(t *testing.T) {
	rec := &recordingDialer{}
	p := &TenantNetPolicy{
		Lookup:  fakeResolver{"ok.example-zone.net": {"93.184.216.34"}}.lookup,
		Dial:    rec.dial,
		AllowIP: TenantIPAllowed,
		Ports:   []string{"443"},
	}
	if _, err := p.dialContext(context.Background(), "tcp", "ok.example-zone.net:5432"); err == nil {
		t.Fatal("port 5432 must be refused")
	}
	if rec.count() != 0 {
		t.Fatal("refused port must not be dialed")
	}
}

// strictFixture is a TLS MCP-ish server reached through the production strict
// transport. Only DNS, the address predicate, the port and the trust roots are
// replaced; the rules themselves run unchanged.
type strictFixture struct {
	srv  *httptest.Server
	pol  *TenantNetPolicy
	hits int
	mu   sync.Mutex
}

func newStrictFixture(t *testing.T, handler http.HandlerFunc) *strictFixture {
	t.Helper()
	f := &strictFixture{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits++
		f.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(f.srv.Close)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(f.srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	f.pol = &TenantNetPolicy{
		Lookup: fakeResolver{"fixture.example-zone.net": {"127.0.0.1"}}.lookup,
		AllowIP: func(ip net.IP) bool {
			return ip.Equal(net.ParseIP("127.0.0.1")) || TenantIPAllowed(ip)
		},
		Ports: []string{port},
		// httptest certificates are issued for example.com; the hostname check
		// is not what these tests exercise.
		TLS: &tls.Config{RootCAs: pool, ServerName: "example.com"},
	}
	return f
}

func (f *strictFixture) requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits
}

func TestStrictClientRefusesRedirects(t *testing.T) {
	f := newStrictFixture(t, func(w http.ResponseWriter, r *http.Request) {
		// A redirect toward an internal address must never be followed.
		http.Redirect(w, r, "https://10.0.5.2:5432/", http.StatusFound)
	})
	c := NewUpstreamClient(UpstreamConfig{
		Name:    "redirector",
		URL:     "https://fixture.example-zone.net:" + portOf(t, f.srv.URL) + "/mcp",
		Timeout: 0,
		Policy:  f.pol,
	})
	err := c.Connect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "redirects are not followed") {
		t.Fatalf("Connect err = %v, want the redirect refusal", err)
	}
	if f.requests() != 1 {
		t.Fatalf("expected exactly one request (no follow-up), got %d", f.requests())
	}
}

func TestStrictClientRefusesBlockedHostWithoutRequest(t *testing.T) {
	f := newStrictFixture(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("the blocked host must not receive a request")
	})
	f.pol.Lookup = fakeResolver{"fixture.example-zone.net": {"10.0.5.2"}}.lookup
	c := NewUpstreamClient(UpstreamConfig{
		Name:   "private",
		URL:    "https://fixture.example-zone.net:" + portOf(t, f.srv.URL) + "/mcp",
		Policy: f.pol,
	})
	if err := c.Connect(context.Background()); err == nil {
		t.Fatal("Connect to a private answer must fail")
	}
	if f.requests() != 0 {
		t.Fatalf("private target received %d requests", f.requests())
	}
}

func TestRedactSecretsRemovesCredentialEcho(t *testing.T) {
	headers := map[string]string{"Authorization": "Bearer abcd-secret-9f3e"}
	msg := "upstream said: bad token abcd-secret-9f3e in Authorization: Bearer abcd-secret-9f3e"
	got := redactSecrets(msg, headers)
	if strings.Contains(got, "secret") {
		t.Fatalf("credential survived redaction: %q", got)
	}
	if !strings.Contains(got, "9f3e") {
		t.Fatalf("last four characters should remain visible: %q", got)
	}
}

func TestRedactErrorPassesOperatorErrorsThrough(t *testing.T) {
	src := errors.New("plain error")
	if err := redactError(src, nil); err != src {
		t.Fatal("operator errors must be returned unchanged")
	}
}

// Ensure the strict body cap really truncates (guards against an unbounded
// upstream response).
func TestCapBodyTransportLimitsRead(t *testing.T) {
	big := strings.Repeat("x", tenantResponseCap+1024)
	f := newStrictFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, big)
	})
	rt := f.pol.transport()
	req, _ := http.NewRequest(http.MethodGet, "https://fixture.example-zone.net:"+portOf(t, f.srv.URL)+"/", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, resp.Body)
	if n > tenantResponseCap {
		t.Fatalf("read %d bytes, cap is %d", n, tenantResponseCap)
	}
}

func portOf(t *testing.T, rawURL string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(rawURL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	return port
}
