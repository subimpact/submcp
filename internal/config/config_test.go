package config

import (
	"strings"
	"testing"
)

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

// N6 (SaaS 4c): a missing internal network fails validation before anything
// binds. The default internal address is a wildcard, so a service token without
// a real address must stop the start.
func TestValidateFailsFastOnMissingInternalNetwork(t *testing.T) {
	c := &Config{
		ListenAddr: ":12008", TenantBaseHost: "mcp.subimpact.net",
		TenantSecretKey:       "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		TenantAPIServiceToken: strings.Repeat("t", 40), // test placeholder, not a credential
		TenantAPIInternalAddr: ":12013",
		MaxTotalConns:         100, MaxConnsPerServer: 20, TenantMaxServers: 10,
		TenantTestPerMinute: 10, TenantPoolBudget: 30, TenantNamespaceInFlight: 3,
	}
	if err := c.Validate(); err == nil {
		t.Fatal("a service token with a wildcard internal address must fail validation")
	}
	c.TenantAPIInternalAddr = "10.77.0.10:12013"
	if err := c.Validate(); err != nil {
		t.Fatalf("a bound internal address must validate: %v", err)
	}
}

// Every problem is reported at once, not just the first.
func TestValidateReportsEveryProblem(t *testing.T) {
	c := &Config{
		ListenAddr: "no-port", TrustedProxyCIDRs: "not-a-cidr",
		TenantBaseHost: "mcp.subimpact.net", TenantSecretKey: "short",
		MaxTotalConns: 100, MaxConnsPerServer: 20, TenantMaxServers: 10,
		TenantTestPerMinute: 10, TenantPoolBudget: 30, TenantNamespaceInFlight: 3,
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("bad config validated")
	}
	for _, want := range []string{"LISTEN_ADDR", "TRUSTED_PROXY_CIDRS", "TENANT_SECRET_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}

func TestValidateCIDRList(t *testing.T) {
	for _, ok := range []string{"", "10.0.5.4/32", "10.0.5.4, 172.18.0.1", "fd00::/8"} {
		if err := ValidateCIDRList(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"10.0.5.0/33", "garbage", "10.0.5.4,,x"} {
		if err := ValidateCIDRList(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// R3: the Cloudflare Access settings are optional everywhere. Missing env
// must NOT fail Validate (self-hosted users run without Access) and must
// leave the feature disabled via Access.Ready() == false. Present env loads
// through access.Load semantics (trim, lowercase email list). Values used
// here are fake test values.
func TestCloudflareAccessConfigOptional(t *testing.T) {
	// Nothing set: valid config, feature off.
	t.Setenv("ACCESS_TEAM_DOMAIN", "")
	t.Setenv("ACCESS_AUD", "")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("ACCESS_CERTS_URL", "")
	c := Get()
	if err := c.Validate(); err != nil {
		t.Fatalf("empty Access env must validate: %v", err)
	}
	if c.Access.Ready() {
		t.Fatal("empty Access env must not enable JWT login")
	}

	// All required names set: feature on, certs URL derived from the team.
	t.Setenv("ACCESS_TEAM_DOMAIN", "  team.example.com ")
	t.Setenv("ACCESS_AUD", " aud-app-3 ")
	t.Setenv("ADMIN_EMAILS", " Admin@Example.com, other@example.com ")
	c = Get()
	if err := c.Validate(); err != nil {
		t.Fatalf("configured Access must still validate: %v", err)
	}
	if !c.Access.Ready() {
		t.Fatal("full Access env must enable JWT login")
	}
	if c.Access.AdminEmails[0] != "admin@example.com" {
		t.Fatalf("emails = %v", c.Access.AdminEmails)
	}
	if c.Access.CertsURL != "https://team.example.com/cdn-cgi/access/certs" {
		t.Fatalf("certs url = %q", c.Access.CertsURL)
	}

	// Partially configured: still valid, still off (fail closed).
	t.Setenv("ACCESS_AUD", "")
	c = Get()
	if c.Access.Ready() {
		t.Fatal("missing ACCESS_AUD must disable JWT login")
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("partial Access env must validate: %v", err)
	}
}
