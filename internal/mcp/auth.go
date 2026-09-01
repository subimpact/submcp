package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/subimpact/submcp/internal/db"
)

// Auth implements API-key authentication, mirroring the original
// api-key-oauth.middleware.ts behavior:
//   - X-API-Key header
//   - Authorization: Bearer <key>
//   - query param (api_key or apikey) when the endpoint allows it
//   - 401 with the exact error shapes captured in fixtures
type Auth struct {
	db *db.Pool
}

// NewAuth creates the authenticator.
func NewAuth(dbPool *db.Pool) *Auth {
	return &Auth{db: dbPool}
}

// Authenticate checks the request against the endpoint's auth config.
// Returns true if authorized; on failure writes the 401 and returns false.
func (a *Auth) Authenticate(w http.ResponseWriter, r *http.Request, ep *db.Endpoint) bool {
	key := extractKey(r, ep.UseQueryParamAuth)
	if key == "" {
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
	return true
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
