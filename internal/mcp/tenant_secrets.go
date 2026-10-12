package mcp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// Tenant credential storage (SaaS phase 4, format v2).
//
// Header values on tenant-managed servers are sealed with AES-256-GCM under
// TENANT_SECRET_KEY (32 bytes: `openssl rand -base64 32`). A sealed value is
// "enc:v2:" + base64url(nonce || ciphertext). The associated data binds the
// ciphertext to its exact row and header:
//
//	owner user id | server uuid | header name
//
// so a value copied to another header, another server or another owner fails
// to authenticate. The v1 format ("enc:v1:", header name only) is not accepted
// at run time; ResealLegacyTenantHeaders rewrites every v1 value to v2 at boot.
// Losing TENANT_SECRET_KEY makes every stored tenant credential unrecoverable,
// so the key must be backed up next to the database.

const (
	sealPrefix       = "enc:v2:"
	legacySealPrefix = "enc:v1:"
)

// maskPrefix is the fixed-length mask shown in place of a credential. It never
// reveals more than the last four characters, and it does not reveal the
// credential's length either.
const maskPrefix = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"

// maskMinLen is the length below which a credential shows only the mask. Four
// visible characters of a short value are a large fraction of its entropy.
const maskMinLen = 16

// ErrNoSecretKey means a tenant credential must be used but TENANT_SECRET_KEY
// is not configured. The gateway fails closed rather than using a plaintext copy.
var ErrNoSecretKey = errors.New("tenant credential key is not configured (TENANT_SECRET_KEY)")

// SecretBox seals and opens tenant header values.
type SecretBox struct {
	aead cipher.AEAD
}

// NewSecretBox builds a box from a 32-byte key given as standard base64 (44
// characters) or as 64 hex characters.
func NewSecretBox(key string) (*SecretBox, error) {
	key = strings.TrimSpace(key)
	var raw []byte
	if b, err := base64.StdEncoding.DecodeString(key); err == nil && len(b) == 32 {
		raw = b
	} else if h, err := hex.DecodeString(key); err == nil && len(h) == 32 {
		raw = h
	} else {
		return nil, errors.New("TENANT_SECRET_KEY must decode to exactly 32 bytes (openssl rand -base64 32)")
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretBox{aead: gcm}, nil
}

// tenantHeaderAAD is the associated data for one stored header value. The
// separator cannot occur in a user id, a UUID or a validated header name.
func tenantHeaderAAD(owner, serverUUID, header string) string {
	return owner + "\x1f" + serverUUID + "\x1f" + header
}

// Seal encrypts plain, binding aad.
func (b *SecretBox) Seal(plain, aad string) (string, error) {
	return sealWith(b, sealPrefix, plain, aad)
}

func sealWith(b *SecretBox, prefix, plain, aad string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := b.aead.Seal(nil, nonce, []byte(plain), []byte(aad))
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return prefix + base64.RawURLEncoding.EncodeToString(out), nil
}

// Open decrypts a v2 value produced by Seal with the same aad.
func (b *SecretBox) Open(sealed, aad string) (string, error) {
	if !strings.HasPrefix(sealed, sealPrefix) {
		return "", errors.New("value is not sealed in the current format")
	}
	return openWith(b, sealed[len(sealPrefix):], aad)
}

func openWith(b *SecretBox, body, aad string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return "", errors.New("sealed value is malformed")
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("sealed value is malformed")
	}
	pt, err := b.aead.Open(nil, raw[:ns], raw[ns:], []byte(aad))
	if err != nil {
		return "", errors.New("sealed value failed authentication")
	}
	return string(pt), nil
}

// IsSealed reports whether a stored header value is in an encrypted form
// (current or legacy).
func IsSealed(v string) bool {
	return strings.HasPrefix(v, sealPrefix) || strings.HasPrefix(v, legacySealPrefix)
}

// MaskSecret returns the display form of a credential: the fixed mask, plus
// the last four characters when the value is at least maskMinLen long. Shorter
// values show only the mask.
func MaskSecret(v string) string {
	r := []rune(v)
	if len(r) < maskMinLen {
		return maskPrefix
	}
	return maskPrefix + string(r[len(r)-4:])
}

// IsMaskedValue reports whether a submitted value is a mask placeholder rather
// than a credential.
func IsMaskedValue(v string) bool {
	return strings.HasPrefix(v, maskPrefix)
}

// OpenSealedHeaders decrypts a tenant header map for one server. Every value
// must be sealed in the current format and bound to (owner, serverUUID); a
// plaintext or legacy value is refused (fail closed).
func OpenSealedHeaders(raw json.RawMessage, box *SecretBox, owner, serverUUID string) (map[string]string, error) {
	out := map[string]string{}
	if len(raw) == 0 {
		return out, nil
	}
	var stored map[string]string
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, errors.New("stored headers are not a JSON object of strings")
	}
	for k, v := range stored {
		if !IsSealed(v) {
			return nil, errors.New("a stored tenant credential is not encrypted; refusing to use it")
		}
		if strings.HasPrefix(v, legacySealPrefix) {
			return nil, errors.New("a stored tenant credential uses the legacy format and has not been re-sealed")
		}
		if box == nil {
			return nil, ErrNoSecretKey
		}
		plain, err := box.Open(v, tenantHeaderAAD(owner, serverUUID, k))
		if err != nil {
			return nil, errors.New("a stored tenant credential could not be decrypted")
		}
		out[k] = plain
	}
	return out, nil
}

// SealHeaders encrypts every value of a tenant header map for one server and
// returns the JSON stored in mcp_servers.headers. Header names stay in the
// clear so the list view can show them.
func SealHeaders(plain map[string]string, box *SecretBox, owner, serverUUID string) (json.RawMessage, error) {
	sealed := make(map[string]string, len(plain))
	for k, v := range plain {
		if box == nil {
			return nil, ErrNoSecretKey
		}
		s, err := box.Seal(v, tenantHeaderAAD(owner, serverUUID, k))
		if err != nil {
			return nil, err
		}
		sealed[k] = s
	}
	return json.Marshal(sealed)
}

// MaskHeaders returns the display form of a stored header map. Sealed values
// are opened with box (when given) and masked; plaintext values (operator rows)
// are masked directly; a sealed value with no key is shown as the bare mask.
func MaskHeaders(raw json.RawMessage, box *SecretBox, owner, serverUUID string) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	var stored map[string]string
	if err := json.Unmarshal(raw, &stored); err != nil {
		return out
	}
	for k, v := range stored {
		switch {
		case !IsSealed(v):
			out[k] = MaskSecret(v)
		case box == nil || strings.HasPrefix(v, legacySealPrefix):
			out[k] = maskPrefix
		default:
			if plain, err := box.Open(v, tenantHeaderAAD(owner, serverUUID, k)); err == nil {
				out[k] = MaskSecret(plain)
			} else {
				out[k] = maskPrefix
			}
		}
	}
	return out
}

// MaskHeadersJSON masks a stored header object for the admin API, which holds
// no key. Operator values are masked to their last four characters; sealed
// tenant values show only the bare mask.
func MaskHeadersJSON(raw json.RawMessage) json.RawMessage {
	b, err := json.Marshal(MaskHeaders(raw, nil, "", ""))
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

// MergeMaskedHeaders applies a header map submitted by the admin UI, which
// shows masked values. A masked value that matches the stored credential keeps
// the stored value; a masked value that matches nothing is refused; any other
// value replaces the stored one. Used only for operator (plaintext) rows.
func MergeMaskedHeaders(submitted map[string]string, existing json.RawMessage) (json.RawMessage, error) {
	stored := map[string]string{}
	if len(existing) > 0 {
		if err := json.Unmarshal(existing, &stored); err != nil {
			return nil, errors.New("stored headers are not a JSON object of strings")
		}
	}
	out := make(map[string]string, len(submitted))
	for k, v := range submitted {
		if !IsMaskedValue(v) {
			out[k] = v
			continue
		}
		old, ok := stored[k]
		if !ok || IsSealed(old) || MaskSecret(old) != v {
			return nil, errors.New("a masked header value does not match the stored credential; enter the full value")
		}
		out[k] = old
	}
	return json.Marshal(out)
}
