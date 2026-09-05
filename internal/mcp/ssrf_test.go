package mcp

import "testing"

func TestSSRFGuardAlwaysBlocksMetadataAndLoopback(t *testing.T) {
	g := NewSSRFGuard(true) // even with private allowed
	blocked := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.170.2/credentials",
		"http://127.0.0.1:8080/",
		"http://localhost:12008/health",
		"http://[::1]:8080/",
		"http://metadata.google.internal/computeMetadata/v1/",
	}
	for _, u := range blocked {
		if err := g.Check(u); err == nil {
			t.Errorf("expected %q to be blocked", u)
		}
	}
}

func TestSSRFGuardPrivateRequiresFlag(t *testing.T) {
	strict := NewSSRFGuard(false)
	if err := strict.Check("http://10.0.5.2:5432/"); err == nil {
		t.Errorf("private IP must be blocked when allowPrivate=false")
	}
	if err := strict.Check("http://192.168.1.10/"); err == nil {
		t.Errorf("private IP must be blocked when allowPrivate=false")
	}
	permissive := NewSSRFGuard(true)
	if err := permissive.Check("http://10.0.5.2:5432/"); err != nil {
		t.Errorf("private IP must be allowed when allowPrivate=true: %v", err)
	}
}

func TestSSRFGuardAllowsPublic(t *testing.T) {
	g := NewSSRFGuard(false)
	allowed := []string{
		"https://mcp.apify.com/?tools=fetch-actor-details",
		"https://api.semrush.com/",
		"https://mcp.n8n.io/",
	}
	for _, u := range allowed {
		if err := g.Check(u); err != nil {
			t.Errorf("expected %q to be allowed: %v", u, err)
		}
	}
}
