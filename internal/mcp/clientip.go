package mcp

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
)

// Client address resolution (P2, #15).
//
// Forwarded headers are client-controlled unless a trusted proxy wrote them.
// They are read only when the TCP peer is inside TRUSTED_PROXY_CIDRS (the
// Traefik network). Otherwise the peer address is the client. Behind Cloudflare
// the real client is CF-Connecting-IP, which Cloudflare sets on every request;
// the rightmost X-Forwarded-For entry is the fallback, because Traefik appends
// to that header and the client cannot write the last entry.

var trustedProxies struct {
	mu   sync.RWMutex
	nets []*net.IPNet
}

// SetTrustedProxies sets the proxy CIDRs whose forwarded headers are honoured.
// An empty string trusts nothing (the default).
func SetTrustedProxies(cidrs string) error {
	var nets []*net.IPNet
	for _, part := range strings.Split(cidrs, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			ip := net.ParseIP(part)
			if ip == nil {
				return fmt.Errorf("TRUSTED_PROXY_CIDRS: %q is not an IP or CIDR", part)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return fmt.Errorf("TRUSTED_PROXY_CIDRS: %q is not a valid CIDR", part)
		}
		nets = append(nets, n)
	}
	trustedProxies.mu.Lock()
	trustedProxies.nets = nets
	trustedProxies.mu.Unlock()
	return nil
}

func isTrustedProxy(ip net.IP) bool {
	trustedProxies.mu.RLock()
	defer trustedProxies.mu.RUnlock()
	for _, n := range trustedProxies.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP returns the address to attribute a request to (rate limits and the
// admin allowlist).
func ClientIP(r *http.Request) string {
	peerStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peerStr = r.RemoteAddr
	}
	peer := net.ParseIP(peerStr)
	if peer == nil || !isTrustedProxy(peer) {
		return peerStr
	}
	if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); net.ParseIP(cf) != nil {
		return cf
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			if cand := strings.TrimSpace(parts[i]); net.ParseIP(cand) != nil {
				return cand
			}
		}
	}
	return peerStr
}
