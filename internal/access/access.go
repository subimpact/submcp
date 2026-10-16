// Package access verifies Cloudflare Access JWTs at origin so the admin UI
// can sit behind Cloudflare Access without trusting the edge alone.
//
// Cloudflare adds a Cf-Access-Jwt-Assertion header (RS256 JWT) to every
// request it lets through. This package checks its signature against the team
// key set, its iss/aud/exp/nbf/iat claims and the admin email allowlist.
// Fail closed: any doubt is a refusal, and an unconfigured deployment simply
// disables JWT login (the API-key login remains the only admin login).
package access

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Header carries the Cloudflare Access JWT.
const Header = "Cf-Access-Jwt-Assertion"

// Reasons are coarse categories, safe to log: never the token itself and never
// the email of a rejected caller.
const (
	reasonMissing    = "missing"
	reasonMalformed  = "malformed"
	reasonBadAlg     = "bad_alg"
	reasonBadKid     = "bad_kid"
	reasonBadSig     = "bad_sig"
	reasonBadIss     = "bad_iss"
	reasonBadAud     = "bad_aud"
	reasonExpired    = "expired"
	reasonFuture     = "claim_in_future"
	reasonNotAllowed = "not_allowed"
	reasonSmallKey   = "weak_key"
	reasonConfig     = "admin_not_configured"
	reasonKeys       = "key_fetch_failed"
)

// KeyFetchTTL caches the key set for an hour; KidRefreshCooldown spaces
// refetches after an unknown kid (at most once per 30 s).
const (
	KeyFetchTTL        = time.Hour
	KidRefreshCooldown = 30 * time.Second
	// leeway is applied to exp/nbf/iat comparisons.
	leeway = 60 * time.Second
	// maxCertsBody caps the JWKS response.
	maxCertsBody = 256 << 10
)

// Config is the Cloudflare Access setup for one deployment.
type Config struct {
	TeamDomain  string   // e.g. example-team.cloudflareaccess.com
	AUD         string   // application audience tag
	AdminEmails []string // lowercased, trimmed
	CertsURL    string   // default https://<team>/cdn-cgi/access/certs
}

// ErrNotConfigured is reported when any of the env settings is missing. The
// gateway starts anyway; JWT admin login is simply disabled.
var ErrNotConfigured = errors.New("cloudflare access is not configured")

// Load reads the env-sourced values. get is the accessor (os.Getenv in prod,
// a stub in tests). Missing members are reported by Ready.
func Load(get func(string) string) Config {
	team := strings.TrimSpace(get("ACCESS_TEAM_DOMAIN"))
	aud := strings.TrimSpace(get("ACCESS_AUD"))
	var emails []string
	for _, e := range strings.Split(get("ADMIN_EMAILS"), ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" {
			emails = append(emails, e)
		}
	}
	certs := strings.TrimSpace(get("ACCESS_CERTS_URL"))
	if certs == "" {
		if team != "" {
			certs = "https://" + team + "/cdn-cgi/access/certs"
		}
	} else if err := ValidateCertsURL(certs); err != nil {
		certs = ""
	}
	return Config{TeamDomain: team, AUD: aud, AdminEmails: emails, CertsURL: certs}
}

// ValidateCertsURL refuses anything but https, except http on 127.0.0.1 or
// localhost, which exists for tests.
func ValidateCertsURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("ACCESS_CERTS_URL: %w", err)
	}
	host := u.Hostname()
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if host == "127.0.0.1" || host == "localhost" || host == "::1" {
			return nil
		}
		return fmt.Errorf("ACCESS_CERTS_URL must be https (http allowed only on loopback): %s", raw)
	default:
		return fmt.Errorf("ACCESS_CERTS_URL must be https: %s", raw)
	}
}

// Ready reports whether verification can run at all.
func (c Config) Ready() bool {
	return c.TeamDomain != "" && c.AUD != "" && len(c.AdminEmails) > 0 && c.CertsURL != ""
}

// Verifier checks Access tokens. Safe for concurrent use.
type Verifier struct {
	cfg    Config
	client *http.Client // no env proxy, no redirects, hard timeout

	mu         sync.Mutex
	keys       map[string]*rsa.PublicKey
	fetchedAt  time.Time
	refetched  time.Time
	warnedOnce bool
}

// New builds a verifier. cfg.Ready() may be false: the verifier then denies
// everything with admin_not_configured.
func New(cfg Config) *Verifier {
	return &Verifier{
		cfg: cfg,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				Proxy:               nil,
				DisableKeepAlives:   false,
				TLSHandshakeTimeout: 3 * time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Ready reports whether JWT login can be served.
func (v *Verifier) Ready() bool { return v.cfg.Ready() }

// jwks is the subset of the Access certs document this package uses.
type jwks struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func (v *Verifier) fetchKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.CertsURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certs endpoint status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCertsBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxCertsBody {
		return nil, errors.New("certs response too large")
	}
	var set jwks
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("parse certs: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" || k.N == "" || k.E == "" {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil || len(e) > 4 {
			continue
		}
		exp := 0
		for _, b := range e {
			exp = exp<<8 + int(b)
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
	}
	if len(keys) == 0 {
		return nil, errors.New("certs document holds no RSA keys")
	}
	return keys, nil
}

// keyFor returns the public key for kid, refreshing the cache when it is
// stale, unknown or unset (at most one fetch per KidRefreshCooldown, across
// every trigger: nil keys, TTL expiry and unknown kid). The fetch runs with
// context.WithoutCancel so a client that disconnects mid-request cannot burn
// the cooldown or cancel the refetch; the client's own 5 s timeout bounds it.
// A failed refresh with cached keys keeps serving from the cache.
func (v *Verifier) keyFor(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := time.Now()
	refetch := false
	if v.keys == nil || now.Sub(v.fetchedAt) > KeyFetchTTL || v.keys[kid] == nil {
		refetch = v.refetched.IsZero() || now.Sub(v.refetched) >= KidRefreshCooldown
	}
	if refetch {
		keys, err := v.fetchKeys(context.WithoutCancel(ctx))
		v.refetched = now
		if err == nil {
			v.keys = keys
			v.fetchedAt = now
		} else if len(v.keys) == 0 {
			if !v.warnedOnce {
				slog.Warn("cloudflare access key set unavailable", "err", err.Error())
				v.warnedOnce = true
			}
			return nil, errors.New(reasonKeys)
		}
	}
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New(reasonBadKid)
}

// claimSet is the Access JWT payload subset.
type claimSet struct {
	Iss   string          `json:"iss"`
	Aud   json.RawMessage `json:"aud"`
	Exp   int64           `json:"exp"`
	Nbf   *int64          `json:"nbf"`
	Iat   *int64          `json:"iat"`
	Email string          `json:"email"`
	Type  string          `json:"type"`
}

// Verify checks the token and returns the verified admin email.
func (v *Verifier) Verify(ctx context.Context, token string, now time.Time) (string, error) {
	if !v.cfg.Ready() {
		return "", errors.New(reasonConfig)
	}
	if token == "" {
		return "", errors.New(reasonMissing)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New(reasonMalformed)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New(reasonMalformed)
	}
	if json.Unmarshal(hb, &hdr) != nil || hdr.Alg != "RS256" || hdr.Kid == "" {
		if hdr.Alg != "RS256" {
			return "", errors.New(reasonBadAlg)
		}
		return "", errors.New(reasonMalformed)
	}
	key, err := v.keyFor(ctx, hdr.Kid)
	if err != nil {
		return "", err
	}
	if key.N.BitLen() < 2048 {
		return "", errors.New(reasonSmallKey)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", errors.New(reasonMalformed)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New(reasonMalformed)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig) != nil {
		return "", errors.New(reasonBadSig)
	}
	var cl claimSet
	if err := json.Unmarshal(payload, &cl); err != nil {
		return "", errors.New(reasonMalformed)
	}
	if cl.Iss != "https://"+v.cfg.TeamDomain {
		return "", errors.New(reasonBadIss)
	}
	if !audContains(string(cl.Aud), v.cfg.AUD) {
		return "", errors.New(reasonBadAud)
	}
	if cl.Exp <= now.Add(-leeway).Unix() {
		return "", errors.New(reasonExpired)
	}
	if cl.Nbf != nil && *cl.Nbf > now.Add(leeway).Unix() {
		return "", errors.New(reasonFuture)
	}
	if cl.Iat != nil && *cl.Iat > now.Add(leeway).Unix() {
		return "", errors.New(reasonFuture)
	}
	email := strings.ToLower(strings.TrimSpace(cl.Email))
	if email == "" {
		return "", errors.New(reasonNotAllowed)
	}
	for _, allowed := range v.cfg.AdminEmails {
		if email == allowed {
			return email, nil
		}
	}
	return "", errors.New(reasonNotAllowed)
}

// audContains accepts "aud" as a bare string or an array of strings.
func audContains(raw, want string) bool {
	var one string
	if json.Unmarshal([]byte(raw), &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal([]byte(raw), &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}