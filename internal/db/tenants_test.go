package db

import (
	"testing"
	"time"
)

func TestEvaluateEntitlement(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }

	cases := []struct {
		name       string
		tenant     Tenant
		wantDenied bool
		wantReason string
	}{
		{"active is allowed", Tenant{Status: TenantActive}, false, ""},
		{"active ignores dates", Tenant{Status: TenantActive, TrialEndsAt: at(-time.Hour)}, false, ""},

		{"trialing before trial_ends_at", Tenant{Status: TenantTrialing, TrialEndsAt: at(time.Hour)}, false, ""},
		{"trialing at trial_ends_at is over", Tenant{Status: TenantTrialing, TrialEndsAt: at(0)}, true, "trial_ended"},
		{"trialing after trial_ends_at", Tenant{Status: TenantTrialing, TrialEndsAt: at(-time.Minute)}, true, "trial_ended"},
		{"trialing with no trial end is denied", Tenant{Status: TenantTrialing}, true, "trial_ended"},

		// Grace runs from past_due_since, not from the period end.
		{"past_due inside grace", Tenant{Status: TenantPastDue, PastDueSince: at(-24 * time.Hour)}, false, ""},
		{"past_due one minute before grace ends", Tenant{Status: TenantPastDue, PastDueSince: at(-3*24*time.Hour + time.Minute)}, false, ""},
		{"past_due one minute after grace ends", Tenant{Status: TenantPastDue, PastDueSince: at(-3*24*time.Hour - time.Minute)}, true, "payment_overdue"},
		{"past_due 4 days after it began is denied", Tenant{Status: TenantPastDue, PastDueSince: at(-4 * 24 * time.Hour)}, true, "payment_overdue"},
		{"a late period end does not extend past_due", Tenant{Status: TenantPastDue, PastDueSince: at(-4 * 24 * time.Hour), SubscriptionEndsAt: at(30 * 24 * time.Hour)}, true, "payment_overdue"},
		{"past_due without past_due_since is denied", Tenant{Status: TenantPastDue, SubscriptionEndsAt: at(time.Hour)}, true, "payment_overdue"},

		{"unpaid is denied", Tenant{Status: TenantUnpaid, SubscriptionEndsAt: at(time.Hour)}, true, "payment_overdue"},
		{"incomplete is denied", Tenant{Status: TenantIncomplete}, true, "payment_required"},
		{"paused is denied", Tenant{Status: TenantPaused}, true, "subscription_paused"},
		{"canceled is denied even inside a trial window", Tenant{Status: TenantCanceled, TrialEndsAt: at(time.Hour)}, true, "subscription_canceled"},
		{"unknown status is denied", Tenant{Status: TenantStatus("mystery")}, true, "unknown_tenant_status"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tenant := c.tenant
			got := EvaluateEntitlement(&tenant, now)
			if got.Denied != c.wantDenied {
				t.Fatalf("Denied = %v, want %v (reason %q)", got.Denied, c.wantDenied, got.Reason)
			}
			if got.Reason != c.wantReason {
				t.Fatalf("Reason = %q, want %q", got.Reason, c.wantReason)
			}
		})
	}
}

func TestTrialEndedFlagOnlyForExpiredTrial(t *testing.T) {
	now := time.Now()
	expired := now.Add(-time.Hour)
	if e := EvaluateEntitlement(&Tenant{Status: TenantTrialing, TrialEndsAt: &expired}, now); !e.TrialEnded {
		t.Fatal("expired trial must set TrialEnded")
	}
	if e := EvaluateEntitlement(&Tenant{Status: TenantPastDue}, now); e.TrialEnded {
		t.Fatal("past_due must not set TrialEnded")
	}
}
