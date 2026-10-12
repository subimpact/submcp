package mcp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Tenant upstream network policy (SaaS phase 4).
//
// Tenant-managed servers are reached only over public HTTPS. The policy is
// enforced twice:
//   - when a URL is stored or tested: syntax, scheme, port and host rules, and
//     DNS resolution with every answer checked;
//   - when a connection is dialed: the host is resolved again and only the
//     checked addresses are dialed, so DNS rebinding (a name that flips to a
//     private address after the check) cannot reach an internal target.
//
// Redirects are never followed, so a 3xx cannot move the request to another
// host. ALLOW_PRIVATE_UPSTREAMS does not apply to tenant servers; operator
// servers keep the legacy guard (see SSRFGuard).

const (
	maxTenantURLLen   = 2048
	tenantResponseCap = 4 << 20 // bytes read from any one tenant upstream response
)

// ErrTenantAddressBlocked means an address is outside the public unicast range
// tenant upstreams may use.
var ErrTenantAddressBlocked = errors.New("address is not allowed for tenant servers (loopback, private, link-local, CGNAT, metadata or reserved range)")

// tenantBlockedCIDRs lists the ranges a tenant upstream may never reach.
// IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are matched against the IPv4
// entries; they are not listed here. Go's ParseCIDR("::ffff:0:0/96") is the
// IPv4-mapped prefix, and its To4 form is 0.0.0.0/0, so it would match every
// IPv4 address. The translated (SIIT) prefix is ::ffff:0:0:0/96.
var tenantBlockedCIDRs = mustParseCIDRs(
	// IPv4
	"0.0.0.0/8",       // "this network"; 0.0.0.0 reaches localhost on Linux
	"10.0.0.0/8",      // RFC 1918; covers the docker bridges in use (10.0.5.0/24, 10.99.0.0/24)
	"100.64.0.0/10",   // CGNAT; Tailscale addresses
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local; cloud metadata (169.254.169.254)
	"172.16.0.0/12",   // RFC 1918; covers the default docker bridges (172.17.0.0/16)
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.168.0.0/16",  // RFC 1918
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved; includes 255.255.255.255
	"192.88.99.0/24",  // deprecated 6to4 relay anycast (RFC 7526)
	// IPv6
	"::/96",           // unspecified, loopback, and deprecated IPv4-compatible ::a.b.c.d
	"::ffff:0:0:0/96", // SIIT-translated IPv4, ::ffff:0:a.b.c.d (RFC 2765); NOT ::ffff:0:0/96
	"64:ff9b::/96",    // NAT64 (embeds an IPv4 address)
	"64:ff9b:1::/48",  // local-use NAT64 (RFC 8215)
	"100::/64",        // discard-only
	"2001::/32",       // Teredo (embeds an IPv4 address)
	"2001:db8::/32",   // documentation
	"2002::/16",       // 6to4 (embeds an IPv4 address)
	"fc00::/7",        // unique local (ULA)
	"fe80::/10",       // link-local
	"fec0::/10",       // site-local (deprecated)
	"ff00::/8",        // multicast
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("tenant_policy: bad CIDR " + c)
		}
		out = append(out, n)
	}
	return out
}

// TenantIPAllowed reports whether a tenant upstream may connect to ip.
func TenantIPAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		for _, n := range tenantBlockedCIDRs {
			if n.IP.To4() != nil && n.Contains(v4) {
				return false
			}
		}
		return true
	}
	for _, n := range tenantBlockedCIDRs {
		if n.IP.To4() == nil && n.Contains(ip) {
			return false
		}
	}
	return true
}

// tenantBannedTLDs are names that never resolve on the public internet or are
// reserved for local use.
var tenantBannedTLDs = map[string]bool{
	"localhost": true, "local": true, "localdomain": true, "internal": true,
	"lan": true, "home": true, "corp": true, "arpa": true, "test": true,
	"invalid": true, "example": true, "onion": true,
}

// TenantNetPolicy holds the outbound rules for tenant upstreams. Production
// uses DefaultTenantNetPolicy. The function fields exist so tests can replace
// DNS, dialing, the address predicate and TLS roots. The rules themselves are
// the same code path in production and in tests.
type TenantNetPolicy struct {
	Lookup  func(ctx context.Context, host string) ([]net.IP, error)
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	AllowIP func(ip net.IP) bool
	Ports   []string    // allowed ports; empty means only 443
	TLS     *tls.Config // nil means the system roots
	// DenyHosts are gateway-owned names (the tenant base host and the legacy
	// app host). A tenant upstream may not be one of them or a subdomain of
	// one: that would loop the request back through the front door.
	DenyHosts []string
}

// legacyAppHost is the retired app host, still served as a redirect. It is
// refused as an upstream like the live tenant base host.
const legacyAppHost = "app.subimpact.net"

// NewTenantNetPolicy is the production policy for a gateway whose tenant base
// host is baseHost (TENANT_BASE_HOST). The base host and its subdomains, and the
// legacy app host, are refused as upstreams.
func NewTenantNetPolicy(baseHost string) *TenantNetPolicy {
	p := DefaultTenantNetPolicy()
	p.DenyHosts = []string{legacyAppHost}
	if h := strings.ToLower(strings.Trim(strings.TrimSpace(baseHost), ".")); h != "" {
		p.DenyHosts = append(p.DenyHosts, h)
	}
	return p
}

// deniedHost reports whether name is one of the gateway's own hosts or below one.
func (p *TenantNetPolicy) deniedHost(name string) bool {
	for _, d := range p.DenyHosts {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// DefaultTenantNetPolicy is the production policy.
func DefaultTenantNetPolicy() *TenantNetPolicy {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &TenantNetPolicy{
		Lookup: func(ctx context.Context, host string) ([]net.IP, error) {
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			ips := make([]net.IP, 0, len(addrs))
			for _, a := range addrs {
				ips = append(ips, a.IP)
			}
			return ips, nil
		},
		Dial:    d.DialContext,
		AllowIP: TenantIPAllowed,
		Ports:   []string{"443"},
	}
}

func (p *TenantNetPolicy) lookup(ctx context.Context, host string) ([]net.IP, error) {
	if p.Lookup != nil {
		return p.Lookup(ctx, host)
	}
	return DefaultTenantNetPolicy().Lookup(ctx, host)
}

func (p *TenantNetPolicy) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if p.Dial != nil {
		return p.Dial(ctx, network, addr)
	}
	return DefaultTenantNetPolicy().Dial(ctx, network, addr)
}

func (p *TenantNetPolicy) allow(ip net.IP) bool {
	if p.AllowIP != nil {
		return p.AllowIP(ip)
	}
	return TenantIPAllowed(ip)
}

func (p *TenantNetPolicy) portAllowed(port string) bool {
	if port == "" {
		return true // https default
	}
	if len(p.Ports) == 0 {
		return port == "443"
	}
	for _, allowed := range p.Ports {
		if port == allowed {
			return true
		}
	}
	return false
}

// ValidateTenantURL checks a tenant upstream URL without touching the network.
// It refuses anything that is not a plain public https URL on port 443:
// other schemes, credentials, query strings, fragments, IP literals, names
// without a public suffix, and IP literals in blocked ranges.
func ValidateTenantURL(raw string, p *TenantNetPolicy) (*url.URL, error) {
	if p == nil {
		p = DefaultTenantNetPolicy()
	}
	if raw == "" {
		return nil, errors.New("url is required")
	}
	if len(raw) > maxTenantURLLen {
		return nil, fmt.Errorf("url is longer than %d characters", maxTenantURLLen)
	}
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c <= ' ' || c == 0x7f {
			return nil, errors.New("url contains whitespace or control characters")
		}
	}
	if strings.Contains(raw, "#") {
		return nil, errors.New("url fragments are not allowed")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("url is not valid")
	}
	if u.Scheme != "https" {
		return nil, errors.New("only https:// upstreams are allowed")
	}
	if u.User != nil {
		return nil, errors.New("credentials in the url are not allowed: send them as headers")
	}
	if u.RawQuery != "" || strings.Contains(raw, "?") {
		return nil, errors.New("query strings are not allowed: send credentials as headers")
	}
	if !validTenantPath(urlPathPart(raw)) {
		return nil, errors.New("the url path may contain only RFC 3986 characters (letters, digits, - . _ ~ / : @ ! $ & ' ( ) * + , ; = and %XX escapes)")
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("url has no host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !p.allow(ip) {
			return nil, ErrTenantAddressBlocked
		}
		return nil, errors.New("use a hostname, not an IP address")
	}

	name := strings.TrimSuffix(strings.ToLower(host), ".")
	if len(name) > 253 {
		return nil, errors.New("host is not a valid DNS name")
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return nil, errors.New("host must be a public DNS name with a dot")
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return nil, errors.New("host is not a valid DNS name")
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return nil, errors.New("host is not a valid DNS name")
			}
		}
	}
	tld := labels[len(labels)-1]
	if !hasLetter(tld) || tenantBannedTLDs[tld] {
		return nil, errors.New("host must be a public DNS name")
	}
	if p.deniedHost(name) {
		return nil, errors.New("this is a gateway host and cannot be a tenant upstream")
	}
	if port := u.Port(); port != "" && !p.portAllowed(port) {
		return nil, errors.New("only port 443 is allowed for tenant servers")
	}
	return u, nil
}

// urlPathPart returns the path of an absolute https URL that has already passed
// the scheme, query and fragment checks.
func urlPathPart(raw string) string {
	rest := strings.TrimPrefix(raw, "https://")
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return ""
	}
	return rest[i:]
}

// validTenantPath accepts only the RFC 3986 path characters: unreserved,
// sub-delims, ":", "@", "/" and well-formed percent escapes. Markup characters
// such as < > " ' ` { } | \ ^ and spaces are refused, so a URL can never carry
// HTML into an admin or tenant page that renders it.
func validTenantPath(path string) bool {
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c == '%':
			if i+2 >= len(path) || !isHex(path[i+1]) || !isHex(path[i+2]) {
				return false
			}
			i += 2
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-._~!$&'()*+,;=:@/", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hasLetter(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'a' && c <= 'z' {
			return true
		}
	}
	return false
}

// resolveAllowed resolves host and returns its addresses. If any address is
// outside the policy the whole lookup fails, so a name with one private record
// is refused rather than dialed selectively.
func (p *TenantNetPolicy) resolveAllowed(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !p.allow(ip) {
			return nil, ErrTenantAddressBlocked
		}
		return []net.IP{ip}, nil
	}
	ips, err := p.lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("host %s does not resolve", host)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("host %s has no address records", host)
	}
	for _, ip := range ips {
		if !p.allow(ip) {
			return nil, fmt.Errorf("host %s resolves to a blocked address: %w", host, ErrTenantAddressBlocked)
		}
	}
	return ips, nil
}

// CheckTenantTarget validates a tenant URL and resolves its host through the
// policy. It performs DNS only; it never opens a connection to the target.
func CheckTenantTarget(ctx context.Context, raw string, p *TenantNetPolicy) error {
	if p == nil {
		p = DefaultTenantNetPolicy()
	}
	u, err := ValidateTenantURL(raw, p)
	if err != nil {
		return err
	}
	_, err = p.resolveAllowed(ctx, u.Hostname())
	return err
}

// dialContext dials only addresses that pass the policy, and dials them by IP
// so the connection cannot be redirected by a second DNS answer.
func (p *TenantNetPolicy) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if !p.portAllowed(port) {
		return nil, fmt.Errorf("port %s is not allowed for tenant servers", port)
	}
	ips, err := p.resolveAllowed(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := p.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// transport builds the HTTP transport for tenant upstreams: policy dialer,
// no environment proxies, bounded timeouts, capped response bodies.
func (p *TenantNetPolicy) transport() http.RoundTripper {
	t := &http.Transport{
		Proxy:                 nil, // never route tenant traffic through an environment proxy
		DialContext:           p.dialContext,
		TLSClientConfig:       p.TLS,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return capBodyTransport{RoundTripper: t, max: tenantResponseCap}
}

// refuseRedirects stops the client from following any redirect. The 3xx
// response is returned to the caller, which reports it as an error.
func refuseRedirects(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// capBodyTransport limits how much of a response body is read.
type capBodyTransport struct {
	http.RoundTripper
	max int64
}

func (c capBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.RoundTripper.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = cappedBody{Reader: io.LimitReader(resp.Body, c.max), Closer: resp.Body}
	return resp, nil
}

type cappedBody struct {
	io.Reader
	io.Closer
}

// redactSecrets replaces every header value (and the token part of a
// "Bearer x" or "Basic x" value) found in msg with its mask. Upstream error
// bodies and DNS errors are echoed to tenants and stored, so they must never
// carry a credential back out. Each credential is matched in its raw form and
// in its JSON-escaped form (a server that echoes a JSON body escapes quotes,
// backslashes and <>&). Longer forms are replaced first, so no credential is
// left partly visible.
func redactSecrets(msg string, headers map[string]string) string {
	var forms []secretForm
	for _, v := range headers {
		forms = append(forms, secretFormsOf(v)...)
	}
	sort.SliceStable(forms, func(i, j int) bool { return len(forms[i].text) > len(forms[j].text) })
	for _, f := range forms {
		msg = strings.ReplaceAll(msg, f.text, f.mask)
	}
	return msg
}

// secretForm is one spelling of a credential to look for, and its mask.
type secretForm struct{ text, mask string }

// secretFormsOf lists the spellings of one header value that must be redacted.
// Forms shorter than four characters are skipped: they match too much text.
func secretFormsOf(v string) []secretForm {
	mask := MaskSecret(v)
	bases := []string{v}
	for _, scheme := range []string{"Bearer ", "Basic ", "Token "} {
		if strings.HasPrefix(v, scheme) {
			bases = append(bases, strings.TrimPrefix(v, scheme))
		}
	}
	var out []secretForm
	seen := map[string]bool{}
	add := func(text string) {
		if len(text) >= 4 && !seen[text] {
			seen[text] = true
			out = append(out, secretForm{text: text, mask: mask})
		}
	}
	for _, b := range bases {
		add(b)
		add(jsonStringBody(b))
	}
	return out
}

// jsonStringBody returns s as it appears inside a JSON string literal (without
// the surrounding quotes).
func jsonStringBody(s string) string {
	enc, err := json.Marshal(s)
	if err != nil || len(enc) < 2 {
		return s
	}
	return string(enc[1 : len(enc)-1])
}
