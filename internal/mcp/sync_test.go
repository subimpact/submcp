package mcp

import (
	"testing"
)

func TestToolNamesHashDeterministic(t *testing.T) {
	a := []string{"b", "a", "c"}
	b := []string{"a", "b", "c"}
	if toolNamesHash(a) != toolNamesHash(b) {
		t.Fatalf("hash must be order-independent: %s != %s", toolNamesHash(a), toolNamesHash(b))
	}
	if toolNamesHash(a) == toolNamesHash([]string{"a", "b", "d"}) {
		t.Fatalf("hash must differ when names differ")
	}
	if toolNamesHash(nil) != toolNamesHash([]string{}) {
		t.Fatalf("empty and nil must hash the same")
	}
}

func TestToolNamesHashStableAcrossCalls(t *testing.T) {
	names := []string{"get_execution", "create_workflow", "search"}
	h1 := toolNamesHash(names)
	h2 := toolNamesHash(names)
	if h1 != h2 {
		t.Fatalf("hash must be stable: %s != %s", h1, h2)
	}
}
