package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/subimpact/submcp/internal/db"
)

// KeyValidator is the DB surface Auth needs (extracted for tests — the
// old TestAuthScoping re-implemented the predicate inline and could not
// catch regressions in the real check).
type KeyValidator interface {
	ValidateAPIKey(ctx context.Context, key string) (*db.APIKey, error)
}

// Auth implements API-key authentication, mirroring the original
// api-key-oauth.middleware.ts behavior:
//   - X-API-Key header
//   - Authorization: Bearer ***
//   - query param (api_key or apikey) when the endpoint allows it
//   - 401 with the exact error shapes captured in fixtures
type Auth struct {
	db KeyValidator
}

// NewAuth creates the authenticator.
func NewAuth(dbPool KeyValidator) *Auth {
	return &Auth{db: dbPool}
}

// Authenticate checks the request against the endpoint's auth config.
// Returns true if authorized; on failure writes the 401 and returns false.
func (a *Auth) Authenticate(w http.ResponseWriter, r *http.Request, ep *db.Endpoint) bool {
	// P0-1.4: OAuth-only endpoints. submcp does not implement OAuth, so
	// we cannot validate OAuth tokens — the secure parity behavior is to
	// always issue the OAuth challenge (deny). The original would accept
	// a valid OAuth token here; we must NOT silently allow.
	if !ep.EnableAPIKeyAuth && ep.EnableOAuth {
		writeOAuthChallenge(w, r, ep)
		return false
	}

	key := extractKey(r, ep.UseQueryParamAuth)
	if key == "" {
		// P0-1.4: when both API key and OAuth are enabled, the original
		// issues the OAuth challenge (which lists API key methods too),
		// not a plain api-key 401.
		if ep.EnableOAuth {
			writeOAuthChallenge(w, r, ep)
			return false
		}
		writeAuthError(w, http.StatusUnauthorized, "authentication_required",
			"Authentication required via API key",
			[]string{"X-API-Key header", "query parameter (api_key or apikey)"})
		return false
	}

	apiKey, err := a.db.ValidateAPIKey(r.Context(), key)
	if err != nil || apiKey == nil {
		writeAuthError(w, http.StatusUnauthorized, "invalid_api_key",
			"The provided API key is invalid or expired", nil)
		return false
	}

	// P0-1.5: tenant scoping — mirror the original's checkApiKeyAccess
	// exactly. A PUBLIC key (user_id NULL) may NOT reach a PRIVATE
	// endpoint (user_id non-NULL); a private key may only reach its own
	// endpoint or public endpoints.
	isPublicKey := apiKey.UserID == nil
	isPrivateEndpoint := ep.UserID != nil
	if isPublicKey && isPrivateEndpoint {
		writeAccessDenied(w, "Public API keys cannot access private endpoints. Use a private API key owned by the endpoint owner.")
		return false
	}
	if !isPublicKey && isPrivateEndpoint && *apiKey.UserID != *ep.UserID {
		writeAccessDenied(w, "You can only access endpoints you own or public endpoints.")
		return false
	}

	return true
}

// writeAccessDenied writes the original's 403 shape
// ({error: "Access denied", message, timestamp}).
func writeAccessDenied(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]any{
		"error":     "Access denied",
		"message":   message,
		"timestamp": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	})
}

// writeOAuthChallenge writes the original's OAuth 401 challenge
// (WWW-Authenticate + resource_metadata body). submcp cannot validate
// OAuth tokens, so this is always a deny — but the shape matches so
// clients that do OAuth discovery get the right signal.
func writeOAuthChallenge(w http.ResponseWriter, r *http.Request, ep *db.Endpoint) {
	base := "https://" + r.Host
	challenge := []string{
		`Bearer realm="MetaMCP"`,
		`scope="admin"`,
		fmt.Sprintf(`resource_metadata="%s/.well-known/oauth-protected-resource"`, base),
	}
	w.Header().Set("WWW-Authenticate", strings.Join(challenge, ", "))
	authMethods := []string{"Authorization header (Bearer token)"}
	if ep.EnableAPIKeyAuth {
		authMethods = append(authMethods, "X-API-Key header")
		if ep.UseQueryParamAuth {
			authMethods = append(authMethods, "query parameter (api_key or apikey)")
		}
	}
	desc := "Authentication required via OAuth bearer token"
	if ep.EnableAPIKeyAuth {
		desc = "Authentication required via OAuth bearer token or API key"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]any{
		"error":             "authentication_required",
		"error_description": desc,
		"resource_metadata": fmt.Sprintf("%s/.well-known/oauth-protected-resource", base),
		"supported_methods": authMethods,
		"timestamp":         time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	})
}

// extractKey pulls the API key from header, bearer, or query param.
func extractKey(r *http.Request, allowQuery bool) string {
	if v := r.Header.Get("X-API-Key"); v != "" {
		return v
	}
	if v := r.Header.Get("Authorization"); v != "" {
		if strings.HasPrefix(v, "Bearer ") {
			return strings.TrimPrefix(v, "Bearer ")
		}
		if strings.HasPrefix(v, "ApiKey ") {
			return strings.TrimPrefix(v, "ApiKey ")
		}
	}
	if allowQuery {
		if v := r.URL.Query().Get("api_key"); v != "" {
			return v
		}
		if v := r.URL.Query().Get("apikey"); v != "" {
			return v
		}
	}
	return ""
}

// writeAuthError writes a 401 with the exact shape from the fixtures.
func writeAuthError(w http.ResponseWriter, status int, code, desc string, supported []string) {
	payload := map[string]any{
		"error":             code,
		"error_description": desc,
		"timestamp":         time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if supported != nil {
		payload["supported_methods"] = supported
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

// newUUID generates a random UUID v4 string.
func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return hex.EncodeToString(b[0:4]) + "-" +
		hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" +
		hex.EncodeToString(b[8:10]) + "-" +
		hex.EncodeToString(b[10:16])
}
