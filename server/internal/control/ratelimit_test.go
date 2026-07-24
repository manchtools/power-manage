package control

import (
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/sdk/guardtest"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/pki"
)

// Guards: INV-15.
func TestGuard_PublicProceduresHaveCompleteRateLimitPolicies(t *testing.T) {
	publicProcedures := guardtest.Discover(t, "public RPC procedures", 12, func() ([]string, error) {
		var procedures []string
		for procedure, class := range auth.ProcedureClassifications() {
			if class == auth.ProcedurePublic {
				procedures = append(procedures, procedure)
			}
		}
		if len(procedures) == 0 {
			return nil, errors.New("authentication registry contains no public procedures")
		}
		slices.Sort(procedures)
		return procedures, nil
	})

	policies := PublicRateLimitPolicies()
	registered := slices.Sorted(maps.Keys(policies))
	if !slices.Equal(registered, publicProcedures) {
		t.Fatalf("public rate-limit policies = %v; classified public procedures = %v", registered, publicProcedures)
	}
	pkiLimits := pki.PublicProcedureLimits()
	for _, procedure := range publicProcedures {
		policy := policies[procedure]
		switch procedure {
		case powermanagev1connect.ControlServiceRefreshSessionProcedure:
			want := refreshRateLimitPolicy()
			if policy != want {
				t.Fatalf("%s policy = %+v; want refresh policy %+v", procedure, policy, want)
			}
			continue
		case powermanagev1connect.ControlServiceStartOidcSessionProcedure,
			powermanagev1connect.ControlServiceCompleteOidcSessionProcedure:
			want := oidcRateLimitPolicy()
			if policy != want {
				t.Fatalf("%s policy = %+v; want OIDC policy %+v", procedure, policy, want)
			}
			continue
		}
		want, exists := pkiLimits[procedure]
		if !exists {
			t.Fatalf("%s has no source PkiService public limit", procedure)
		}
		if policy.PerIP.Attempts != want.Attempts || policy.PerIP.Window != want.Window {
			t.Fatalf("%s per-IP limit = %+v; want PkiService limit %+v", procedure, policy.PerIP, want)
		}
		if policy.PerAccount.Attempts != want.Attempts || policy.PerAccount.Window != want.Window {
			t.Fatalf("%s per-account limit = %+v; want PkiService limit %+v", procedure, policy.PerAccount, want)
		}
	}
}

func TestPublicRateLimitPolicies_DefensivelyCopied(t *testing.T) {
	first := PublicRateLimitPolicies()
	if len(first) == 0 {
		t.Fatal("public rate-limit registry is empty")
	}
	procedure := slices.Sorted(maps.Keys(first))[0]
	want := first[procedure]
	first[procedure] = auth.RateLimitPolicy{}
	delete(first, procedure)
	first["/injected.Service/Method"] = want

	second := PublicRateLimitPolicies()
	if got := second[procedure]; got != want {
		t.Fatalf("mutating returned registry changed %s policy from %+v to %+v", procedure, want, got)
	}
	if _, exists := second["/injected.Service/Method"]; exists {
		t.Fatal("mutating returned registry injected a production policy")
	}
}
