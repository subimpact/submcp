package config

import "testing"

func TestValidateInternalAddrRefusesWildcardBinds(t *testing.T) {
	bad := []string{":12013", "0.0.0.0:12013", "[::]:12013", "submcp-gateway:12013", "10.77.0.10", "10.77.0.10:"}
	for _, a := range bad {
		if err := ValidateInternalAddr(a); err == nil {
			t.Errorf("ValidateInternalAddr(%q) accepted; the internal listener must bind one address", a)
		}
	}
	if err := ValidateInternalAddr("10.77.0.10:12013"); err != nil {
		t.Errorf("a specific internal address refused: %v", err)
	}
}
