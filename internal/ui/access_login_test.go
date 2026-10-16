package ui

// R3: admin login via a verified Cloudflare Access JWT, CSRF protection on
// the admin API's state-changing methods, and /api/admin/whoami. All
// hermetic: a fake JWKS endpoint, a local RSA key, fake team/aud/email
// values (real deployment values come from env, never from tests).

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/subimpact/submcp/internal/access"
	"github.com/subimpact/submcp/internal/db"
	"github.com/subimpact/submcp/internal/mcp"
)

// jwtRig serves a one-key JWKS document and mints RS256 tokens signed with a
// local test key (fake team domain, aud tag and email throughout).
type jwtRig struct {
	srv    *httptest.Server
	ver    *access.Verifier
	key    *rsa.PrivateKey
	kid    string
	Team   string
	AudTag string
	Email  string
}

func newJWTRig(t *testing.T) *jwtRig {
	t.Helper()
	// httptest.NewRequest uses RemoteAddr 192.0.2.1: treat it as the reverse
	// proxy, as Traefik is in production. The JWT path requires a trusted peer.
	if err := mcp.SetTrustedProxies("192.0.2.1/32"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mcp.SetTrustedProxies("") })
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	r := &jwtRig{key: k, kid: "ui-test-key-1",
		Team: "team.example.com", AudTag: "aud-app-3", Email: "admin@example.com"}
	pub := map[string]any{
		"kty": "RSA", "kid": r.kid,
		"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(bigExpE(k.E)),
	}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{pub}})
	}))
	t.Cleanup(r.srv.Close)
	r.ver = access.New(access.Config{
		TeamDomain:  r.Team,
		AUD:         r.AudTag,
		AdminEmails: []string{r.Email},
		CertsURL:    r.srv.URL,
	})
	return r
}

func bigExpE(e int) []byte {
	var out []byte
	for x := e; x > 0; x >>= 8 {
		out = append([]byte{byte(x)}, out...)
	}
	if out == nil {
		out = []byte{0}
	}
	return out
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// mint builds a token; rewrite lets a case alter header and claims before
// signing.
func (r *jwtRig) mint(t *testing.T, now time.Time, rewrite func(hdr map[string]any, cl map[string]any)) string {
	t.Helper()
	hdr := map[string]any{"alg": "RS256", "kid": r.kid, "typ": "JWT"}
	cl := map[string]any{
		"iss":   "https://" + r.Team,
		"aud":   []string{r.AudTag},
		"exp":   now.Add(30 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"email": r.Email,
		"type":  "app",
	}
	if rewrite != nil {
		rewrite(hdr, cl)
	}
	hj, _ := json.Marshal(hdr)
	cj, _ := json.Marshal(cl)
	signing := b64u(hj) + "." + b64u(cj)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, r.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signing + "." + b64u(sig)
}

func jwtAuth(r *jwtRig, req *http.Request, token string) *http.Request {
	req.Header.Set(access.Header, token)
	return req
}

// keyStore adds one valid is_admin key to the spy store for the key-login
// tests.
type keyStore struct {
	spyStore
}

func (s *keyStore) ValidateAPIKey(_ context.Context, key string) (*db.APIKey, error) {
	if key == "sk_test_admin_key_1" {
		return &db.APIKey{UUID: "k-root", Name: "root-key", IsActive: true, IsAdmin: true}, nil
	}
	return nil, nil
}

func getBody(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", rr.Body.String(), err)
	}
	return m
}

// A valid Cloudflare Access JWT opens the admin API: overview 200 and whoami
// reports via=access with the verified email.
func TestAccessJWTLoginGrantsAdmin(t *testing.T) {
	r := newJWTRig(t)
	u := NewWithAccess(&spyStore{}, "", r.ver)
	now := time.Now()
	h := u.Handler()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, jwtAuth(r, httptest.NewRequest(http.MethodGet, "/api/admin/overview", nil), r.mint(t, now, nil)))
	if rr.Code != http.StatusOK {
		t.Fatalf("overview with valid JWT = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, jwtAuth(r, httptest.NewRequest(http.MethodGet, "/api/admin/whoami", nil), r.mint(t, now, nil)))
	if rr.Code != http.StatusOK {
		t.Fatalf("whoami = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	w := getBody(t, rr)
	if w["via"] != "access" {
		t.Fatalf("whoami via = %v, want access", w["via"])
	}
	if w["email"] != r.Email {
		t.Fatalf("whoami email = %v, want %s", w["email"], r.Email)
	}
	if w["key_name"] != nil {
		t.Fatalf("whoami key_name = %v, want null", w["key_name"])
	}
}

// No cookie and no JWT: 401, as always.
func TestNoCredentials401(t *testing.T) {
	r := newJWTRig(t)
	u := NewWithAccess(&spyStore{}, "", r.ver)
	rr := httptest.NewRecorder()
	u.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/admin/overview", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no credentials = %d, want 401", rr.Code)
	}
}

// Wrong aud / expired / alg none / unknown email are all refused with 401.
func TestAccessJWTRejects(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		rewrite func(hdr map[string]any, cl map[string]any)
	}{
		{"wrong aud", func(_ map[string]any, c map[string]any) { c["aud"] = []string{"other-app"} }},
		{"expired", func(_ map[string]any, c map[string]any) { c["exp"] = now.Add(-120 * time.Second).Unix() }},
		{"alg none", func(h map[string]any, _ map[string]any) { h["alg"] = "none"; delete(h, "kid") }},
		{"unknown email", func(_ map[string]any, c map[string]any) { c["email"] = "intruder@else.example" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newJWTRig(t)
			u := NewWithAccess(&spyStore{}, "", r.ver)
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/admin/overview", nil)
			jwtAuth(r, req, r.mint(t, now, tc.rewrite))
			u.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("%s: status = %d, want 401", tc.name, rr.Code)
			}
			if !strings.Contains(rr.Body.String(), "unauthorized") {
				t.Fatalf("%s: body = %s, want unauthorized", tc.name, rr.Body.String())
			}
		})
	}
}

// JWT login disabled (env missing -> nil verifier): a token that would be
// valid is ignored, header present or not, and the caller is 401.
func TestAccessDisabledIgnoresJWT(t *testing.T) {
	r := newJWTRig(t)
	u := NewWithAccess(&spyStore{}, "", nil)
	now := time.Now()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/overview", nil)
	jwtAuth(r, req, r.mint(t, now, nil))
	u.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("disabled JWT login = %d, want 401 (header must be ignored)", rr.Code)
	}
	// An unready verifier (partially configured env) fails closed the same way.
	u2 := NewWithAccess(&spyStore{}, "", access.New(access.Config{TeamDomain: r.Team}))
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/admin/overview", nil)
	jwtAuth(r, req, r.mint(t, now, nil))
	u2.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("partial config = %d, want 401", rr.Code)
	}
}

// The admin IP allowlist still applies to JWT requests: outside the list is
// 403 even with a valid token, inside works.
func TestAccessAllowlistAppliesToJWT(t *testing.T) {
	r := newJWTRig(t)
	now := time.Now()
	// httptest clients appear at 192.0.2.1.
	inside := NewWithAccess(&spyStore{}, "192.0.2.0/24", r.ver)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/overview", nil)
	jwtAuth(r, req, r.mint(t, now, nil))
	inside.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("allowed client with JWT = %d, want 200", rr.Code)
	}

	outside := NewWithAccess(&spyStore{}, "10.9.0.0/16", r.ver)
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/admin/overview", nil)
	jwtAuth(r, req, r.mint(t, now, nil))
	outside.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("allowlisted-out client with JWT = %d, want 403", rr.Code)
	}
}

// The API-key login keeps working and whoami reports via=session with the
// key name.
func TestKeyLoginStillWorks(t *testing.T) {
	r := newJWTRig(t)
	u := NewWithAccess(&keyStore{}, "", r.ver)
	h := u.Handler()

	rr := httptest.NewRecorder()
	login := httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(`{"key":"sk_test_admin_key_1"}`))
	h.ServeHTTP(rr, login)
	if rr.Code != http.StatusOK {
		t.Fatalf("key login = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var setCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookie {
			setCookie = c
		}
	}
	if setCookie == nil || setCookie.Value == "" {
		t.Fatal("login did not set the session cookie")
	}

	rr = httptest.NewRecorder()
	who := httptest.NewRequest(http.MethodGet, "/api/admin/whoami", nil)
	who.AddCookie(&http.Cookie{Name: sessionCookie, Value: setCookie.Value})
	h.ServeHTTP(rr, who)
	if rr.Code != http.StatusOK {
		t.Fatalf("whoami = %d, want 200", rr.Code)
	}
	w := getBody(t, rr)
	if w["via"] != "session" {
		t.Fatalf("whoami via = %v, want session", w["via"])
	}
	if w["key_name"] != "root-key" {
		t.Fatalf("whoami key_name = %v, want root-key", w["key_name"])
	}
	if w["email"] != nil {
		t.Fatalf("whoami email = %v, want null", w["email"])
	}
}

// CSRF: a cross-site browser POST carrying the operator's session cookie is
// refused with 403.
func TestCSRFCrossSitePostRefused(t *testing.T) {
	r := newJWTRig(t)
	u := NewWithAccess(&spyStore{}, "", r.ver)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/servers", strings.NewReader(`{"name":"x"}`))
	sessAuth(u, req, nil) // valid session cookie
	req.Header.Set("Origin", "https://evil.example")
	rr := httptest.NewRecorder()
	u.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-site POST = %d, want 403", rr.Code)
	}
}

// CSRF: the same POST without Origin/Sec-Fetch-Site (curl, scripts, Hermes)
// is not blocked.
func TestCSRFNoOriginPostAllowed(t *testing.T) {
	r := newJWTRig(t)
	u := NewWithAccess(&spyStore{}, "", r.ver)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/servers", strings.NewReader(`{"name":"x"}`))
	sessAuth(u, req, nil)
	rr := httptest.NewRecorder()
	u.Handler().ServeHTTP(rr, req)
	if rr.Code == http.StatusForbidden {
		t.Fatalf("non-browser POST was blocked by CSRF: %d", rr.Code)
	}
	if rr.Code != http.StatusCreated {
		t.Fatalf("non-browser POST = %d, want 201: %s", rr.Code, rr.Body.String())
	}
}

// CSRF: /api/admin/login still works from the admin page itself (same-origin
// POST, browsers send Origin on cross-origin-capable submissions; it matches
// the Host).
func TestCSRFSameOriginLoginWorks(t *testing.T) {
	r := newJWTRig(t)
	u := NewWithAccess(&keyStore{}, "", r.ver)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(`{"key":"sk_test_admin_key_1"}`))
	req.Header.Set("Origin", "http://"+req.Host)
	rr := httptest.NewRecorder()
	u.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("same-origin login = %d, want 200: %s", rr.Code, rr.Body.String())
	}
}

// Review P2-1: a valid JWT presented straight to a direct listener (peer not
// the trusted proxy: loopback, Tailscale) is ignored, so the key stays the
// only way in there.
func TestAccessJWTIgnoredFromUntrustedPeer(t *testing.T) {
	r := newJWTRig(t)
	u := NewWithAccess(&spyStore{}, "", r.ver)
	for _, peer := range []string{"127.0.0.1:5555", "100.64.1.2:443"} {
		rr := httptest.NewRecorder()
		req := jwtAuth(r, httptest.NewRequest(http.MethodGet, "/api/admin/overview", nil), r.mint(t, time.Now(), nil))
		req.RemoteAddr = peer
		u.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("peer %s: status = %d, want 401", peer, rr.Code)
		}
	}
}

// Review P2-3: the server test endpoint is POST only (CSRF-covered).
func TestServerTestRequiresPost(t *testing.T) {
	r := newJWTRig(t)
	u := NewWithAccess(&spyStore{}, "", r.ver)
	rr := httptest.NewRecorder()
	u.Handler().ServeHTTP(rr, jwtAuth(r, httptest.NewRequest(http.MethodGet, "/api/admin/servers/00000000-0000-0000-0000-000000000001/test", nil), r.mint(t, time.Now(), nil)))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET test: status = %d, want 405", rr.Code)
	}
}
