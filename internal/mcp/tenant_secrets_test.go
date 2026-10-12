package mcp

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func testBox(t *testing.T) *SecretBox {
	t.Helper()
	// 32 bytes of fixed test key material (never a real key).
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	box, err := NewSecretBox(key)
	if err != nil {
		t.Fatal(err)
	}
	return box
}

func TestNewSecretBoxAcceptsOnly32ByteKeys(t *testing.T) {
	ok := []string{
		base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		strings.Repeat("ab", 32), // 64 hex characters
	}
	for _, k := range ok {
		if _, err := NewSecretBox(k); err != nil {
			t.Errorf("key %q refused: %v", k, err)
		}
	}
	bad := []string{
		"",
		"short",
		base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")),      // 16 bytes
		base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 36))), // 36 bytes
		strings.Repeat("zz", 32),
	}
	for _, k := range bad {
		if _, err := NewSecretBox(k); err == nil {
			t.Errorf("key %q accepted, must be refused", k)
		}
	}
}

func TestSealOpenRoundTripAndNoPlaintextInCiphertext(t *testing.T) {
	box := testBox(t)
	secret := "Bearer tok-live-1234567890"
	sealed, err := box.Seal(secret, "Authorization")
	if err != nil {
		t.Fatal(err)
	}
	if !IsSealed(sealed) {
		t.Fatalf("sealed value lacks the envelope prefix: %q", sealed)
	}
	if strings.Contains(sealed, "tok-live") {
		t.Fatal("ciphertext contains plaintext")
	}
	back, err := box.Open(sealed, "Authorization")
	if err != nil || back != secret {
		t.Fatalf("Open = %q, %v; want the original", back, err)
	}
	// Fresh nonce per seal: the same input never produces the same ciphertext.
	again, _ := box.Seal(secret, "Authorization")
	if again == sealed {
		t.Fatal("two seals of the same value must differ (random nonce)")
	}
}

func TestOpenRejectsWrongHeaderNameAndTampering(t *testing.T) {
	box := testBox(t)
	sealed, _ := box.Seal("value-123456", "Authorization")
	if _, err := box.Open(sealed, "X-Api-Key"); err == nil {
		t.Fatal("ciphertext moved to another header name must not open")
	}
	raw := []byte(sealed)
	raw[len(raw)-3] ^= 0x01
	if _, err := box.Open(string(raw), "Authorization"); err == nil {
		t.Fatal("tampered ciphertext must not open")
	}
	if _, err := box.Open("not-sealed", "Authorization"); err == nil {
		t.Fatal("plaintext must not open")
	}
}

func TestOpenFailsUnderADifferentKey(t *testing.T) {
	sealed, _ := testBox(t).Seal("value-123456", "h")
	other, err := NewSecretBox(strings.Repeat("cd", 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Open(sealed, "h"); err == nil {
		t.Fatal("a different key must not open the value")
	}
}

func TestMaskSecretShowsOnlyLastFour(t *testing.T) {
	cases := map[string]string{
		"":                 maskPrefix,
		"abc":              maskPrefix,
		"12345678":         maskPrefix, // short values reveal nothing
		"123456789":        maskPrefix, // under 16 characters: bullets only (P3)
		"123456789abcdefg": maskPrefix + "defg",
		"Bearer abcd-1f2e": maskPrefix + "1f2e",
		"ünïcödé-tok-wxyz": maskPrefix + "wxyz",
	}
	for in, want := range cases {
		if got := MaskSecret(in); got != want {
			t.Errorf("MaskSecret(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskHeadersNeverReturnsTheFullValue(t *testing.T) {
	box := testBox(t)
	secret := "Bearer super-secret-token-9999"
	sealed, _ := SealHeaders(map[string]string{"Authorization": secret}, box, testOwner, testServerUUID)

	for _, b := range []*SecretBox{box, nil} {
		masked := MaskHeaders(sealed, b, testOwner, testServerUUID)
		raw, _ := json.Marshal(masked)
		if strings.Contains(string(raw), "super-secret") {
			t.Fatalf("masked output leaks the credential: %s", raw)
		}
	}
	if got := MaskHeaders(sealed, box, testOwner, testServerUUID)["Authorization"]; got != maskPrefix+"9999" {
		t.Fatalf("masked = %q, want last four visible", got)
	}
	if got := MaskHeaders(sealed, nil, testOwner, testServerUUID)["Authorization"]; got != maskPrefix {
		t.Fatalf("admin view without a key = %q, want the bare mask", got)
	}
}

func TestMaskHeadersJSONForAdminAPI(t *testing.T) {
	legacy := json.RawMessage(`{"Authorization":"Bearer matrix-token-AAAA","X-Short":"ab"}`)
	var got map[string]string
	if err := json.Unmarshal(MaskHeadersJSON(legacy), &got); err != nil {
		t.Fatal(err)
	}
	if got["Authorization"] != maskPrefix+"AAAA" || got["X-Short"] != maskPrefix {
		t.Fatalf("admin masking = %v", got)
	}
	if out := string(MaskHeadersJSON(nil)); out != "{}" {
		t.Fatalf("empty headers = %s, want {}", out)
	}
}

func TestOpenSealedHeadersFailsClosedOnPlaintext(t *testing.T) {
	box := testBox(t)
	if _, err := OpenSealedHeaders(json.RawMessage(`{"Authorization":"plain-token"}`), box, testOwner, testServerUUID); err == nil {
		t.Fatal("a plaintext tenant credential must be refused")
	}
	if _, err := OpenSealedHeaders(json.RawMessage(`{"Authorization":"enc:v2:AAAA"}`), nil, testOwner, testServerUUID); err == nil {
		t.Fatal("no key configured must refuse to use a sealed credential")
	}
	sealed, _ := SealHeaders(map[string]string{"Authorization": "tok-123456"}, box, testOwner, testServerUUID)
	got, err := OpenSealedHeaders(sealed, box, testOwner, testServerUUID)
	if err != nil || got["Authorization"] != "tok-123456" {
		t.Fatalf("round trip = %v, %v", got, err)
	}
}

func TestMergeMaskedHeadersKeepsStoredCredentialOnlyForAMatchingMask(t *testing.T) {
	existing := json.RawMessage(`{"Authorization":"Bearer matrix-token-AAAA"}`)

	// The admin form sends back the mask it was given: keep the stored value.
	merged, err := MergeMaskedHeaders(map[string]string{"Authorization": maskPrefix + "AAAA"}, existing)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	_ = json.Unmarshal(merged, &got)
	if got["Authorization"] != "Bearer matrix-token-AAAA" {
		t.Fatalf("masked value replaced the credential: %v", got)
	}

	// A new full value replaces it.
	merged, _ = MergeMaskedHeaders(map[string]string{"Authorization": "Bearer new-token-ZZZZ"}, existing)
	_ = json.Unmarshal(merged, &got)
	if got["Authorization"] != "Bearer new-token-ZZZZ" {
		t.Fatalf("new value not applied: %v", got)
	}

	// A mask that matches nothing is refused, never stored as the credential.
	if _, err := MergeMaskedHeaders(map[string]string{"Authorization": maskPrefix + "XXXX"}, existing); err == nil {
		t.Fatal("a mismatched mask must be refused")
	}
	if _, err := MergeMaskedHeaders(map[string]string{"X-New": maskPrefix + "AAAA"}, existing); err == nil {
		t.Fatal("a mask for a header that does not exist must be refused")
	}
}

// Fixed owner and server for the header tests (the AAD binds both).
const (
	testOwner      = "usera00000000000000000000000001"
	testServerUUID = "00000000-0000-4000-8000-000000000042"
)
