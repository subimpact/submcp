// Tenant-host admin block (SaaS admin console, defence in depth): on a tenant
// host (<slug>.<TENANT_BASE_HOST>) the operator admin surface must not answer.
// The operator console lives on the apex host only; the matching Traefik rule
// in deploy-blue-green.sh is the outer layer, this check the inner one.
package httpapi

import (
	"net/http"
	"path"
	"strings"
)

// isTenantHost mirrors mcp's subdomainSlug host detection: lowercase, port
// stripped, and a suffix of "."+baseHost that is neither the apex nor its www.
func isTenantHost(host, baseHost string) bool {
	if baseHost == "" || host == "" {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	baseHost = strings.ToLower(strings.TrimSpace(baseHost))
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	// A fully-qualified name with a trailing dot is the same host.
	host = strings.TrimRight(host, ".")
	baseHost = strings.TrimRight(baseHost, ".")
	if host == baseHost || host == "www."+baseHost {
		return false
	}
	return strings.HasSuffix(host, "."+baseHost)
}

// blocksTenantAdmin reports whether a (cleaned, decoded, lowercased) path is
// part of the operator admin surface.
func blocksTenantAdmin(p string) bool {
	return p == "/admin" || strings.HasPrefix(p, "/admin/") ||
		p == "/api/admin" || strings.HasPrefix(p, "/api/admin/")
}

// blockAdminOnTenantHosts answers 404 not_found for /admin[-ish] paths on any
// tenant host, leaving the apex, 127.0.0.1 and other hosts untouched. The path
// is normalised first so /ADMIN/, //admin//, /x/../admin/ and /%61dmin/ are
// all caught.
func blockAdminOnTenantHosts(baseHost string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isTenantHost(r.Host, baseHost) {
			clean := path.Clean("/" + r.URL.Path) // force-rooted: Clean never returns ".."
			low := strings.ToLower(clean)
			if blocksTenantAdmin(low) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"not_found","error_description":"There is nothing at this address."}`))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
