package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/subimpact/submcp/internal/db"
)

// A sealed value must open only for its own owner, server and header (#14).
func TestAADBindsOwnerServerAndHeader(t *testing.T) {
	box := testBox(t)
	sealed, err := SealHeaders(map[string]string{"Authorization": "Bearer aad-secret-1234"}, box, testOwner, testServerUUID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSealedHeaders(sealed, box, testOwner, testServerUUID); err != nil {
		t.Fatalf("the bound owner, server and header must open: %v", err)
	}
	// Another owner.
	if _, err := OpenSealedHeaders(sealed, box, "userb00000000000000000000000002", testServerUUID); err == nil {
		t.Fatal("a value opened under another owner")
	}
	// Another server.
	if _, err := OpenSealedHeaders(sealed, box, testOwner, "00000000-0000-4000-8000-000000000043"); err == nil {
		t.Fatal("a value opened under another server")
	}
	// The same ciphertext moved to another header name in the same row.
	moved := json.RawMessage(strings.Replace(string(sealed), `"Authorization"`, `"X-Api-Key"`, 1))
	if _, err := OpenSealedHeaders(moved, box, testOwner, testServerUUID); err == nil {
		t.Fatal("a ciphertext moved to another header opened")
	}
}

// Moving a ciphertext to another row is refused even when the header name is the
// same (the server uuid differs).
func TestAADRefusesCiphertextMovedToAnotherServer(t *testing.T) {
	box := testBox(t)
	sealed, _ := SealHeaders(map[string]string{"Authorization": "Bearer moved-secret-5678"}, box, testOwner, testServerUUID)
	if _, err := OpenSealedHeaders(sealed, box, testOwner, "00000000-0000-4000-8000-000000000099"); err == nil {
		t.Fatal("a ciphertext copied to another server opened")
	}
}

// Legacy (v1, header-name-only) values open at run time (SaaS 4c, N5: dual-read,
// so a row written by an older image still works in a blue/green overlap or
// after a rollback). The v1 binding covers the header name only, so a v1 value
// moved to another header is still refused. Every write is v2, and the boot
// re-seal rewrites the v1 rows.
func TestLegacyCiphertextOpensAtRunTime(t *testing.T) {
	box := testBox(t)
	v1, err := sealWith(box, legacySealPrefix, "Bearer legacy-9999", "Authorization")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"Authorization": v1})
	got, err := OpenSealedHeaders(raw, box, testOwner, testServerUUID)
	if err != nil {
		t.Fatalf("a v1 value must open at run time: %v", err)
	}
	if got["Authorization"] != "Bearer legacy-9999" {
		t.Fatalf("v1 opened to %q", got["Authorization"])
	}
	if masked := MaskHeaders(raw, box, testOwner, testServerUUID)["Authorization"]; masked != maskPrefix+"9999" {
		t.Fatalf("a v1 value must show the mask and its last four characters, got %q", masked)
	}
	moved, _ := json.Marshal(map[string]string{"X-Api-Key": v1})
	if _, err := OpenSealedHeaders(moved, box, testOwner, testServerUUID); err == nil {
		t.Fatal("a v1 value moved to another header name must not open")
	}
}

// fakeLegacyStore holds tenant rows with v1 ciphertext.
type fakeLegacyStore struct {
	rows []db.TenantHeaderRow
	set  map[string]json.RawMessage
}

func (f *fakeLegacyStore) ListLegacyTenantHeaders(context.Context) ([]db.TenantHeaderRow, error) {
	var out []db.TenantHeaderRow
	for _, r := range f.rows {
		if cur, ok := f.set[r.ServerUUID]; ok {
			r.Headers = cur
		}
		if strings.Contains(string(r.Headers), legacySealPrefix) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeLegacyStore) SetTenantHeaders(_ context.Context, uuid string, expected, headers json.RawMessage) error {
	cur, ok := f.set[uuid]
	if !ok {
		for _, r := range f.rows {
			if r.ServerUUID == uuid {
				cur, ok = r.Headers, true
			}
		}
	}
	if !ok {
		return db.ErrTenantServerNotFound
	}
	if !jsonEqual(cur, expected) {
		return db.ErrTenantHeadersChanged
	}
	f.set[uuid] = headers
	return nil
}

// The boot re-seal rewrites v1 values to v2 bound to owner, server and header,
// is idempotent, and refuses a key that cannot open the old values.
func TestResealLegacyTenantHeaders(t *testing.T) {
	box := testBox(t)
	v1, _ := sealWith(box, legacySealPrefix, "Bearer reseal-secret-4321", "Authorization")
	raw, _ := json.Marshal(map[string]string{"Authorization": v1})
	store := &fakeLegacyStore{
		rows: []db.TenantHeaderRow{{ServerUUID: testServerUUID, OwnerUserID: testOwner, Headers: raw}},
		set:  map[string]json.RawMessage{},
	}
	n, err := ResealLegacyTenantHeaders(context.Background(), store, box)
	if err != nil || n != 1 {
		t.Fatalf("reseal = %d, %v; want 1 row", n, err)
	}
	got, err := OpenSealedHeaders(store.set[testServerUUID], box, testOwner, testServerUUID)
	if err != nil || got["Authorization"] != "Bearer reseal-secret-4321" {
		t.Fatalf("re-sealed value does not open under v2: %v, %v", got, err)
	}
	if strings.Contains(string(store.set[testServerUUID]), "enc:v1:") {
		t.Fatal("a v1 value survived the re-seal")
	}
	n, err = ResealLegacyTenantHeaders(context.Background(), store, box)
	if err != nil || n != 0 {
		t.Fatalf("second run must be a no-op: %d, %v", n, err)
	}
	// A wrong key stops the migration instead of silently rewriting garbage.
	other, _ := NewSecretBox(strings.Repeat("cd", 32))
	store2 := &fakeLegacyStore{rows: store.rows, set: map[string]json.RawMessage{}}
	if _, err := ResealLegacyTenantHeaders(context.Background(), store2, other); err == nil {
		t.Fatal("a key that cannot open the legacy value must stop the re-seal")
	}
}

// The stored form never names a plaintext value and never shows one in a mask.
func TestSealedRowsHoldNoPlaintext(t *testing.T) {
	box := testBox(t)
	sealed, _ := SealHeaders(map[string]string{"X-Api-Key": "plain-value-0000"}, box, testOwner, testServerUUID)
	if strings.Contains(string(sealed), "plain-value") {
		t.Fatal("plaintext in the stored row")
	}
	sum := sha256.Sum256([]byte(testOwner))
	if strings.Contains(string(sealed), hex.EncodeToString(sum[:4])) {
		t.Fatal("owner id leaked into the stored row")
	}
}
