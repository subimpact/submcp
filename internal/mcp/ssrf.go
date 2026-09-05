package mcp

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// SSRFGuard blocks outbound requests to dangerous destinations (P1-3).
//
// Always blocked (cloud metadata + loopback):
//   - 169.254.0.0/16 (AWS/GCP/Azure metadata)
//   - 127.0.0.0/8 (loopback)
//   - ::1 (IPv6 loopback)
//
// RFC1918 (10/8, 172.16/12, 192.168/16) and link-local (fe80::/10) are
// blocked UNLESS allowPrivate is set (self-hosted deployments that
// legitimately reach internal upstreams like n8n on a private network).
type SSRFGuard struct {
	allowPrivate bool
}

// NewSSRFGuard creates a guard. allowPrivate permits RFC1918/link-local
// destinations (default ON for self-hosted, OFF for SaaS — see roadmap
// decision gate 5).
func NewSSRFGuard(allowPrivate bool) *SSRFGuard {
	return &SSRFGuard{allowPrivate: allowPrivate}
}

// Check validates a destination URL. Returns an error when the target is
// blocked. DNS is NOT resolved here (the guard is best-effort against
// literal IPs; a full SSRF defense would need a resolving proxy).
func (g *SSRFGuard) Check(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid upstream URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("upstream URL has no host")
	}
	// Literal IPs are the enforceable case.
	ip := net.ParseIP(host)
	if ip == nil {
		// Hostname: only reject obvious metadata/loopback names.
		lower := strings.ToLower(host)
		if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
			return fmt.Errorf("upstream host %q is blocked (loopback)", host)
		}
		if strings.HasSuffix(lower, ".internal") || strings.HasSuffix(lower, ".metadata.google.internal") {
			return fmt.Errorf("upstream host %q is blocked (internal/metadata)", host)
		}
		return nil
	}
	if ip.IsLoopback() {
		return fmt.Errorf("upstream host %q is blocked (loopback)", host)
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("upstream host %q is blocked (link-local)", host)
	}
	if ip.IsPrivate() && !g.allowPrivate {
		return fmt.Errorf("upstream host %q is blocked (private network)", host)
	}
	return nil
}
