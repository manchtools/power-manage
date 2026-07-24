package auth

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/manchtools/power-manage/sdk/guardtest"
)

func TestSCIMFailureLimiter_ChecksProviderAndProviderIPBeforeRecording(t *testing.T) {
	start := time.Date(2026, time.July, 24, 1, 0, 0, 0, time.UTC)
	ipOne := netip.MustParseAddr("192.0.2.10")
	ipTwo := netip.MustParseAddr("198.51.100.10")

	t.Run("provider", func(t *testing.T) {
		limiter, err := NewSCIMFailureLimiter(SCIMFailureLimits{
			PerProvider:   FailureLimit{Attempts: 1, Window: time.Minute},
			PerProviderIP: FailureLimit{Attempts: 10, Window: time.Minute},
		})
		if err != nil {
			t.Fatalf("create SCIM limiter: %v", err)
		}
		if !limiter.Check("corporate", ipOne, start) {
			t.Fatal("first provider failure was rejected before verification")
		}
		limiter.RecordFailure("corporate", ipOne, start)
		if limiter.Check("corporate", ipTwo, start.Add(time.Second)) {
			t.Fatal("another IP bypassed the exhausted provider bucket")
		}
	})

	t.Run("provider plus IP", func(t *testing.T) {
		limiter, err := NewSCIMFailureLimiter(SCIMFailureLimits{
			PerProvider:   FailureLimit{Attempts: 10, Window: time.Minute},
			PerProviderIP: FailureLimit{Attempts: 1, Window: time.Minute},
		})
		if err != nil {
			t.Fatalf("create SCIM limiter: %v", err)
		}
		if !limiter.Check("corporate", ipOne, start) {
			t.Fatal("first provider-IP failure was rejected before verification")
		}
		limiter.RecordFailure("corporate", ipOne, start)
		if limiter.Check("corporate", ipOne, start.Add(time.Second)) {
			t.Fatal("exhausted provider-IP bucket was allowed")
		}
		if !limiter.Check("corporate", ipTwo, start.Add(time.Second)) {
			t.Fatal("independent provider-IP bucket was rejected")
		}
	})
}

func TestSCIMFailureLimiter_ExpiresAndRejectsInvalidKeys(t *testing.T) {
	const window = time.Minute
	start := time.Date(2026, time.July, 24, 1, 0, 0, 0, time.UTC)
	limiter, err := NewSCIMFailureLimiter(SCIMFailureLimits{
		PerProvider:   FailureLimit{Attempts: 1, Window: window},
		PerProviderIP: FailureLimit{Attempts: 1, Window: window},
	})
	if err != nil {
		t.Fatalf("create SCIM limiter: %v", err)
	}
	ip := netip.MustParseAddr("192.0.2.10")
	limiter.RecordFailure("corporate", ip, start)
	if limiter.Check("corporate", ip, start.Add(window-time.Nanosecond)) {
		t.Fatal("SCIM failure bucket expired early")
	}
	if !limiter.Check("corporate", ip, start.Add(window)) {
		t.Fatal("SCIM failure bucket did not expire at its boundary")
	}
	for _, invalid := range []struct {
		slug string
		ip   netip.Addr
	}{
		{slug: "", ip: ip},
		{slug: "Corporate", ip: ip},
		{slug: "corporate"},
	} {
		if limiter.Check(invalid.slug, invalid.ip, start) {
			t.Fatalf("invalid SCIM limiter key (%q, %v) was allowed", invalid.slug, invalid.ip)
		}
	}
}

func TestSCIMFailureLimiter_FailsClosedAtBucketCapacity(t *testing.T) {
	limiter, err := NewSCIMFailureLimiter(SCIMFailureLimits{
		PerProvider:   FailureLimit{Attempts: 10, Window: time.Hour},
		PerProviderIP: FailureLimit{Attempts: 10, Window: time.Hour},
	})
	if err != nil {
		t.Fatalf("create SCIM limiter: %v", err)
	}
	now := time.Date(2026, time.July, 24, 1, 0, 0, 0, time.UTC)
	address := netip.MustParseAddr("192.0.2.10")
	for index := range scimFailureBucketCapacity / 2 {
		limiter.RecordFailure(fmt.Sprintf("p%d", index), address, now)
	}
	if limiter.Check("overflow", address, now) {
		t.Fatal("SCIM limiter allowed bcrypt after exhausting its bucket capacity")
	}
}

func TestGuard_SCIMEnumerationParityCoverage(t *testing.T) {
	profile := EnumerationParityProfiles()[SecretVerifierSCIM]
	discovered := guardtest.Discover(t, "SCIM enumeration failure causes", 4, func() ([]string, error) {
		causes := make([]string, 0, len(profile.FailureCauses))
		for _, cause := range profile.FailureCauses {
			causes = append(causes, string(cause))
		}
		slices.Sort(causes)
		return causes, nil
	})
	want := []string{
		string(EnumerationDisabled),
		string(EnumerationMalformed),
		string(EnumerationNonexistent),
		string(EnumerationWrongSecret),
	}
	if !slices.Equal(discovered, want) {
		t.Fatalf("SCIM parity causes = %v; want %v", discovered, want)
	}
	if profile.MinimumRejectionLatency <= 0 {
		t.Fatal("SCIM parity profile has no rejection-latency floor")
	}
}
