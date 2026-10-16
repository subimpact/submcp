package access

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
	"sync"
	"testing"
	"time"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jwk(key *rsa.PublicKey, kid string) map[string]any {
	n := key.N.Bytes()
	var e []byte
	for x := key.E; x > 0; x >>= 8 {
		e = append([]byte{byte(x)}, e...)
	}
	return map[string]any{"kty": "RSA", "kid": kid, "n": b64(n), "e": b64(e)}
}

func genKey(bits int) *rsa.PrivateKey {
	k, _ := rsa.GenerateKey(rand.Reader, bits)
	return k
}

// rig serves a JWKS document from an httptest server; keys is mutable so tests
// can swap what the endpoint publishes. All team/aud/email values here are
// fake; real deployment values come from env, never from tests.
type rig struct {
	srv   *httptest.Server
	ver   *Verifier
	lk    sync.Mutex
	keys  []map[string]any
	key   *rsa.PrivateKey
	kid   string
	other *rsa.PrivateKey
}

func newRig(t *testing.T) *rig {
	t.Helper()
	k := genKey(2048)
	o := genKey(2048)
	r := &rig{key: k, kid: "test-key-1", other: o,
		keys: []map[string]any{jwk(&k.PublicKey, "test-key-1"), jwk(&o.PublicKey, "other-key")}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.lk.Lock()
		defer r.lk.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": r.keys})
	}))
	r.ver = New(Config{
		TeamDomain:  "team.example.com",
		AUD:         "aud-tag-1",
		AdminEmails: []string{"admin@example.com"},
		CertsURL:    r.srv.URL,
	})
	return r
}

func (r *rig) setKeys(keys []map[string]any) {
	r.lk.Lock()
	defer r.lk.Unlock()
	r.keys = keys
}

func (r *rig) mint(header map[string]any, claims map[string]any, key *rsa.PrivateKey) string {
	hj, _ := json.Marshal(header)
	cj, _ := json.Marshal(claims)
	signing := b64(hj) + "." + b64(cj)
	sum := sha256.Sum256([]byte(signing))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	return signing + "." + b64(sig)
}

func (r *rig) claims(now time.Time) map[string]any {
	return map[string]any{
		"iss":   "https://team.example.com",
		"aud":   []string{"aud-tag-1"},
		"exp":   now.Add(30 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"email": "admin@example.com",
		"type":  "app",
	}
}

func (r *rig) good(now time.Time) string {
	return r.mint(map[string]any{"alg": "RS256", "kid": r.kid}, r.claims(now), r.key)
}

func TestVerifyValid(t *testing.T) {
	r := newRig(t)
	defer r.srv.Close()
	now := time.Now()
	email, err := r.ver.Verify(t.Context(), r.good(now), now)
	if err != nil || email != "admin@example.com" {
		t.Fatalf("Verify = %q, %v", email, err)
	}
}

// failName drives every negative case through one body: it mints from defaults
// and lets the case rewrite header and claims.
func TestVerifyRejects(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		rewrite func(hdr map[string]any, cl map[string]any)
		key     *rsa.PrivateKey
		want    string
	}{
		{"alg none", func(h map[string]any, _ map[string]any) { h["alg"] = "none"; delete(h, "kid") }, nil, reasonBadAlg},
		{"HS256", func(h map[string]any, _ map[string]any) { h["alg"] = "HS256" }, nil, reasonBadAlg},
		{"ES256", func(h map[string]any, _ map[string]any) { h["alg"] = "ES256" }, nil, reasonBadAlg},
		{"missing kid", func(h map[string]any, _ map[string]any) { delete(h, "kid") }, nil, reasonMalformed},
		{"unknown kid", func(h map[string]any, _ map[string]any) { h["kid"] = "nope" }, nil, reasonBadKid},
		{"wrong aud", func(h map[string]any, c map[string]any) { c["aud"] = []string{"other"} }, nil, reasonBadAud},
		{"aud as string wrong", func(h map[string]any, c map[string]any) { c["aud"] = "other" }, nil, reasonBadAud},
		{"wrong iss", func(h map[string]any, c map[string]any) { c["iss"] = "https://evil.example.com" }, nil, reasonBadIss},
		{"expired", func(h map[string]any, c map[string]any) { c["exp"] = now.Add(-70 * time.Second).Unix() }, nil, reasonExpired},
		{"nbf future", func(h map[string]any, c map[string]any) { c["nbf"] = now.Add(120 * time.Second).Unix() }, nil, reasonFuture},
		{"iat future", func(h map[string]any, c map[string]any) { c["iat"] = now.Add(120 * time.Second).Unix() }, nil, reasonFuture},
		{"email not allowed", func(h map[string]any, c map[string]any) { c["email"] = "someone@else.com" }, nil, reasonNotAllowed},
		{"empty email", func(h map[string]any, c map[string]any) { c["email"] = "" }, nil, reasonNotAllowed},
		{"tampered payload", nil, nil, reasonBadSig},
		{"signed by other key", func(h map[string]any, c map[string]any) { c["email"] = "admin@example.com" }, nil, reasonBadSig},
	}
	for i := range cases {
		c := &cases[i]
		t.Run(c.name, func(t *testing.T) {
			rr := newRig(t)
			defer rr.srv.Close()
			hdr := map[string]any{"alg": "RS256", "kid": rr.kid}
			cl := rr.claims(now)
			key := rr.key
			if c.name == "signed by other key" {
				key = rr.other
			}
			if c.rewrite != nil {
				c.rewrite(hdr, cl)
			}
			tok := rr.mint(hdr, cl, key)
			if c.name == "tampered payload" {
				tok = rr.good(now) + "x"
			}
			if _, err := rr.ver.Verify(t.Context(), tok, now); err == nil || err.Error() != c.want {
				t.Fatalf("verify err = %v, want %s", err, c.want)
			}
		})
	}
}

func TestEmailCaseInsensitive(t *testing.T) {
	r := newRig(t)
	defer r.srv.Close()
	now := time.Now()
	cl := r.claims(now)
	cl["email"] = "  ADMIN@Example.COM "
	tok := r.mint(map[string]any{"alg": "RS256", "kid": r.kid}, cl, r.key)
	if _, err := r.ver.Verify(t.Context(), tok, now); err != nil {
		t.Fatalf("mixed case email must pass: %v", err)
	}
}

func TestWeakKeyRejected(t *testing.T) {
	weak := genKey(1024)
	r := newRig(t)
	defer r.srv.Close()
	r.setKeys([]map[string]any{jwk(&weak.PublicKey, "weak")})
	// New kid forces a refetch (cooldown elapsed by construction: fresh verifier).
	rr := newRig(t)
	defer rr.srv.Close()
	rr.setKeys([]map[string]any{jwk(&weak.PublicKey, "weak")})
	now := time.Now()
	cl := rr.claims(now)
	tok := rr.mint(map[string]any{"alg": "RS256", "kid": "weak"}, cl, weak)
	if _, err := rr.ver.Verify(t.Context(), tok, now); err == nil || err.Error() != reasonSmallKey {
		t.Fatalf("1024-bit key err = %v, want %s", err, reasonSmallKey)
	}
}

func TestMissingHeader(t *testing.T) {
	r := newRig(t)
	defer r.srv.Close()
	if _, err := r.ver.Verify(t.Context(), "", time.Now()); err == nil || err.Error() != reasonMissing {
		t.Fatalf("err = %v, want missing", err)
	}
}

func TestMalformed(t *testing.T) {
	r := newRig(t)
	defer r.srv.Close()
	for _, tok := range []string{"abc", "a.b.c.d", "!!.$$.##"} {
		if _, err := r.ver.Verify(t.Context(), tok, time.Now()); err == nil || err.Error() != reasonMalformed {
			t.Fatalf("%q: err = %v, want malformed", tok, err)
		}
	}
}

func TestNotConfiguredFailsClosed(t *testing.T) {
	v := New(Config{})
	if v.Ready() {
		t.Fatal("empty config must not be ready")
	}
	if _, err := v.Verify(t.Context(), "x.y.z", time.Now()); err == nil || err.Error() != reasonConfig {
		t.Fatalf("err = %v, want admin_not_configured", err)
	}
}

func TestCertsURLRules(t *testing.T) {
	if err := ValidateCertsURL("https://team.example.com/cdn-cgi/access/certs"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCertsURL("http://127.0.0.1:12092/certs"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCertsURL("http://localhost/certs"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"http://team.example.com/certs", "ftp://x"} {
		if err := ValidateCertsURL(bad); err == nil {
			t.Fatalf("%s must be refused", bad)
		}
	}
}

func TestLoadFromEnv(t *testing.T) {
	cfg := Load(func(k string) string {
		switch k {
		case "ACCESS_TEAM_DOMAIN":
			return " team.example.com "
		case "ACCESS_AUD":
			return "audtag"
		case "ADMIN_EMAILS":
			return " A@X.com, b@y.com, "
		}
		return ""
	})
	if !cfg.Ready() {
		t.Fatal("ready expected")
	}
	if cfg.TeamDomain != "team.example.com" || cfg.AdminEmails[0] != "a@x.com" {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.CertsURL != "https://team.example.com/cdn-cgi/access/certs" {
		t.Fatalf("default certs url = %s", cfg.CertsURL)
	}
	// Missing pieces: not ready, and custom http (non-loopback) URL rejected.
	cfg2 := Load(func(string) string { return "" })
	if cfg2.Ready() {
		t.Fatal("empty env must not be ready")
	}
}

// F4 (security review round 2): the KidRefreshCooldown floor applies to EVERY
// refetch trigger (nil key set, TTL expiry, unknown kid). With a JWKS endpoint
// that keeps failing, 50 rapid Verify calls cause one fetch, not fifty.
func TestKeyForCooldownAppliesToAllTriggers(t *testing.T) {
	var hits int64
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	ver := New(Config{
		TeamDomain:  "team.example.com",
		AUD:         "aud-tag-1",
		AdminEmails: []string{"admin@example.com"},
		CertsURL:    srv.URL,
	})
	key := genKey(2048)
	token := ver_mint(key, "unknown-kid")
	for i := 0; i < 50; i++ {
		if _, err := ver.Verify(context.Background(), token, time.Now()); err == nil {
			t.Fatalf("call %d: expected refusal, got success", i)
		}
	}
	mu.Lock()
	got := hits
	mu.Unlock()
	if got != 1 {
		t.Fatalf("fetches = %d, want 1 within the 30 s floor", got)
	}

	// The fetch is detached from the caller's context: a client that already
	// canceled must not break (or starve) the refetch; the 5 s client timeout
	// bounds it instead.
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{jwk(&key.PublicKey, "test-key-1")}})
	}))
	t.Cleanup(good.Close)
	ver2 := New(Config{
		TeamDomain:  "team.example.com",
		AUD:         "aud-tag-1",
		AdminEmails: []string{"admin@example.com"},
		CertsURL:    good.URL,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	email, err := ver2.Verify(ctx, ver_mint(key, "test-key-1"), time.Now())
	if err != nil || email != "admin@example.com" {
		t.Fatalf("verify with canceled caller context: %q %v", email, err)
	}
}

// ver_mint builds a syntactically valid RS256 token for the cooldown tests:
// the signature is checked only after the key lookup, which these tests fail.
func ver_mint(key *rsa.PrivateKey, kid string) string {
	hj, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	cj, _ := json.Marshal(map[string]any{
		"iss": "https://team.example.com", "aud": "aud-tag-1",
		"exp": time.Now().Add(time.Hour).Unix(), "email": "admin@example.com",
	})
	signing := b64(hj) + "." + b64(cj)
	sum := sha256.Sum256([]byte(signing))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	return signing + "." + b64(sig)
}
