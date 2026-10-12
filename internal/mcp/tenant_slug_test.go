package mcp

import "testing"

func TestSubdomainSlugIsCaseInsensitive(t *testing.T) {
	cases := map[string]string{
		"ACME.mcp.tenant-fixture.net":     "acme",
		"acme.MCP.tenant-fixture.net:443": "acme",
		"MCP.tenant-fixture.net":          "", // the bare host is not a tenant
		"acme.example.net":                "",
	}
	for host, want := range cases {
		if got := subdomainSlug(host, "MCP.Tenant-Fixture.net"); got != want {
			t.Errorf("subdomainSlug(%q) = %q, want %q", host, got, want)
		}
	}
}
