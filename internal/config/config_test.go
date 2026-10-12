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
