package pki

import (
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/sdk/guardtest"
)

// TestGuard_PkiPublicRateLimitRegistration is GUARD-006-1: every descriptor-
// discovered PkiService procedure must have exactly one public limit policy.
func TestGuard_PkiPublicRateLimitRegistration(t *testing.T) {
	service := powermanagev1.File_powermanage_v1_pki_proto.Services().ByName("PkiService")
	discovered := guardtest.Discover(t, "PkiService procedures", 4, func() ([]string, error) {
		if service == nil {
			return nil, errors.New("PkiService descriptor is absent")
		}
		procedures := make([]string, 0, service.Methods().Len())
		for i := 0; i < service.Methods().Len(); i++ {
			method := service.Methods().Get(i)
			if method == nil {
				return nil, errors.New("PkiService contains a nil method descriptor")
			}
			procedures = append(procedures, "/"+string(service.FullName())+"/"+string(method.Name()))
		}
		return procedures, nil
	})
	slices.Sort(discovered)
	registered := PublicProcedureLimits()
	registeredNames := slices.Sorted(maps.Keys(registered))
	if !slices.Equal(registeredNames, discovered) {
		t.Fatalf("public Pki procedure limits = %v; descriptor procedures = %v", registeredNames, discovered)
	}
	for _, procedure := range []string{
		powermanagev1connect.PkiServiceEnrollAgentProcedure,
		powermanagev1connect.PkiServiceRenewAgentProcedure,
		powermanagev1connect.PkiServiceRevokeAgentProcedure,
		powermanagev1connect.PkiServiceForceRenewAgentProcedure,
	} {
		limit := registered[procedure]
		if limit.Attempts != 5 || limit.Window != time.Minute {
			t.Fatalf("%s public limit = %+v; want five attempts per minute", procedure, limit)
		}
	}
}
