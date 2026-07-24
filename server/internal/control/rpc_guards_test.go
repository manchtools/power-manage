package control

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/sdk/guardtest"
	"github.com/manchtools/power-manage/server/internal/auth"
)

var customControlFlows = map[string]auth.ProcedureClass{
	powermanagev1connect.ControlServiceCompleteOidcSessionProcedure: auth.ProcedurePublic,
	powermanagev1connect.ControlServiceRefreshSessionProcedure:      auth.ProcedurePublic,
	powermanagev1connect.ControlServiceStartOidcSessionProcedure:    auth.ProcedurePublic,
}

func TestGuard_ManagementDomainInventoryAndOperations(t *testing.T) {
	expected := map[string][]crudOperation{
		"actions":             {crudCreate, crudGet, crudList, crudUpdate, crudDelete},
		"action-sets":         {crudCreate, crudGet, crudList, crudUpdate, crudDelete},
		"api-tokens":          {crudCreate, crudGet, crudList, crudUpdate, crudDelete},
		"assignments":         {crudCreate, crudGet, crudList, crudDelete},
		"audit":               {crudList},
		"compliance-policies": {crudCreate, crudGet, crudList, crudUpdate, crudDelete},
		"device-groups":       {crudCreate, crudGet, crudList, crudUpdate, crudDelete},
		"devices":             {crudGet, crudList, crudUpdate, crudDelete},
		"executions":          {crudGet, crudList},
		"gateways":            {crudGet, crudList},
		"grants":              {crudCreate, crudGet, crudList, crudUpdate, crudDelete},
		"identity-providers":  {crudCreate, crudGet, crudList, crudUpdate, crudDelete},
		"inventory":           {crudGet, crudList},
		"registration-tokens": {crudCreate, crudGet, crudList, crudUpdate, crudDelete},
		"roles":               {crudCreate, crudGet, crudList, crudUpdate, crudDelete},
		"scim-configurations": {crudCreate, crudGet, crudList, crudUpdate, crudDelete},
		"server-settings":     {crudCreate, crudGet, crudList, crudUpdate, crudDelete},
		"user-groups":         {crudCreate, crudGet, crudList, crudUpdate, crudDelete},
		"users":               {crudCreate, crudGet, crudList, crudUpdate, crudDelete},
	}
	domains := guardtest.Discover(t, "normative management domains", len(expected), func() ([]crudDomain, error) {
		return managementDomains(nil), nil
	})
	actual := make(map[string][]crudOperation, len(domains))
	for _, domain := range domains {
		operations := slices.Sorted(maps.Keys(domain.requestMessages))
		actual[domain.name] = operations
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("management domain inventory = %v; want %v", actual, expected)
	}
}

func TestGuard_ControlRPCsHaveExactlyOneImplementationClass(t *testing.T) {
	procedures := guardtest.Discover(
		t,
		"ControlService RPCs",
		8,
		discoverControlProcedures,
	)
	domains := guardtest.Discover(t, "registered CRUD domains", 1, func() ([]crudDomain, error) {
		return managementDomains(nil), nil
	})
	kernel := kernelProcedurePermissions(domains)
	violations := controlRPCClassificationViolations(procedures, kernel, customControlFlows)
	if len(violations) > 0 {
		t.Fatalf("ControlService implementation classification: %s", strings.Join(violations, "; "))
	}
}

func discoverControlProcedures() ([]string, error) {
	service := powermanagev1.File_powermanage_v1_control_proto.
		Services().
		ByName("ControlService")
	if service == nil {
		return nil, errors.New("control service descriptor is missing")
	}
	procedures := make([]string, 0, service.Methods().Len())
	for index := 0; index < service.Methods().Len(); index++ {
		method := service.Methods().Get(index)
		procedures = append(
			procedures,
			fmt.Sprintf("/%s/%s", service.FullName(), method.Name()),
		)
	}
	slices.Sort(procedures)
	return procedures, nil
}

func kernelProcedurePermissions(domains []crudDomain) map[string]string {
	procedures := make(map[string]string)
	for _, domain := range domains {
		for _, procedure := range domain.procedures {
			if _, duplicate := procedures[procedure]; duplicate {
				procedures[procedure] = ""
				continue
			}
			procedures[procedure] = string(domain.permission)
		}
	}
	return procedures
}

func controlRPCClassificationViolations(
	procedures []string,
	kernel map[string]string,
	custom map[string]auth.ProcedureClass,
) []string {
	var violations []string
	if len(procedures) == 0 {
		violations = append(violations, "zero ControlService RPCs discovered")
	}
	descriptors := make(map[string]struct{}, len(procedures))
	for _, procedure := range procedures {
		if _, duplicate := descriptors[procedure]; duplicate {
			violations = append(violations, procedure+": duplicate descriptor procedure")
		}
		descriptors[procedure] = struct{}{}
		_, inKernel := kernel[procedure]
		_, inCustom := custom[procedure]
		if inKernel == inCustom {
			violations = append(
				violations,
				procedure+": must be classified exactly once as kernel or custom",
			)
		}
	}
	for procedure, permission := range kernel {
		if permission == "" {
			violations = append(violations, procedure+": duplicate kernel registration")
		}
		if _, exists := descriptors[procedure]; !exists {
			violations = append(violations, procedure+": kernel registration has no descriptor RPC")
		}
	}
	for procedure := range custom {
		if _, exists := descriptors[procedure]; !exists {
			violations = append(violations, procedure+": custom flow has no descriptor RPC")
		}
	}
	slices.Sort(violations)
	return violations
}

func controlAuthorizationViolations(
	procedures []string,
	kernel map[string]string,
	custom map[string]auth.ProcedureClass,
	policies map[string]auth.ProcedureAuthorization,
) []string {
	violations := controlRPCClassificationViolations(procedures, kernel, custom)
	for _, procedure := range procedures {
		policy, exists := policies[procedure]
		if !exists {
			violations = append(violations, procedure+": missing authorization policy")
			continue
		}
		if permission, kernelProcedure := kernel[procedure]; kernelProcedure {
			if policy.Class != auth.ProcedurePermissionGated ||
				string(policy.Permission) != permission {
				violations = append(
					violations,
					procedure+": kernel permission differs from authorization policy",
				)
			}
			continue
		}
		if class, customProcedure := custom[procedure]; customProcedure &&
			(policy.Class != class || policy.Permission != "") {
			violations = append(
				violations,
				procedure+": custom-flow authentication class differs from policy",
			)
		}
	}
	slices.Sort(violations)
	return violations
}

func TestGuard_ControlAuthorizationMatchesImplementationClass(t *testing.T) {
	procedures := guardtest.Discover(
		t,
		"ControlService authorization policies",
		8,
		discoverControlProcedures,
	)
	violations := controlAuthorizationViolations(
		procedures,
		kernelProcedurePermissions(managementDomains(nil)),
		customControlFlows,
		auth.ProcedureAuthorizations(),
	)
	if len(violations) > 0 {
		t.Fatalf("ControlService authorization classification: %s", strings.Join(violations, "; "))
	}
}

func TestControlRPCClassificationGuard_RejectsMissingAndOverlap(t *testing.T) {
	procedures := []string{"/powermanage.v1.ControlService/One"}
	kernel := map[string]string{procedures[0]: "devices.manage"}
	if got := controlRPCClassificationViolations(procedures, kernel, nil); len(got) != 0 {
		t.Fatalf("valid synthetic classification = %v", got)
	}
	wantClassification := []string{
		procedures[0] + ": must be classified exactly once as kernel or custom",
	}
	if got := controlRPCClassificationViolations(procedures, nil, nil); !slices.Equal(got, wantClassification) {
		t.Fatalf("unclassified RPC violations = %v; want %v", got, wantClassification)
	}
	if got := controlRPCClassificationViolations(
		procedures,
		kernel,
		map[string]auth.ProcedureClass{procedures[0]: auth.ProcedurePublic},
	); !slices.Equal(got, wantClassification) {
		t.Fatalf("doubly classified RPC violations = %v; want %v", got, wantClassification)
	}
	wantZero := []string{"zero ControlService RPCs discovered"}
	if got := controlRPCClassificationViolations(nil, nil, nil); !slices.Equal(got, wantZero) {
		t.Fatalf("zero descriptor violations = %v; want %v", got, wantZero)
	}
}

func TestControlAuthorizationGuard_RejectsPermissionMismatch(t *testing.T) {
	procedure := "/powermanage.v1.ControlService/One"
	policies := map[string]auth.ProcedureAuthorization{
		procedure: {
			Class:      auth.ProcedurePermissionGated,
			Permission: "audit.read",
		},
	}
	violations := controlAuthorizationViolations(
		[]string{procedure},
		map[string]string{procedure: "devices.manage"},
		nil,
		policies,
	)
	want := []string{
		procedure + ": kernel permission differs from authorization policy",
	}
	if !slices.Equal(violations, want) {
		t.Fatalf("permission mismatch violations = %v; want %v", violations, want)
	}
}
