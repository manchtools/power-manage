package control

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/manchtools/power-manage/sdk/guardtest"
	"github.com/manchtools/power-manage/server/internal/authz"
)

func TestGuard_ScopablePermissionsHaveBehavioralCoverage(t *testing.T) {
	domains := guardtest.Discover(
		t,
		"registered management scope domains",
		1,
		func() ([]crudDomain, error) {
			return managementDomains(nil), nil
		},
	)
	cases := guardtest.Discover(
		t,
		"real-handler authorization scope cases",
		1,
		func() ([]authorizationScopeCase, error) {
			return authorizationScopeCases(), nil
		},
	)
	if violations := scopableCoverageViolations(domains, cases); len(violations) > 0 {
		t.Fatalf("scopable permission coverage: %v", violations)
	}
}

func TestScopedReadDenialMetadata_RejectsMissingAndUnexpectedExceptions(t *testing.T) {
	execution := executionDomain(nil)
	if err := validateCRUDDomain(execution); err != nil {
		t.Fatalf("validate execution exception metadata: %v", err)
	}
	execution.scopedReadDenial = crudScopedReadNotFound
	if err := validateCRUDDomain(execution); !errors.Is(err, errCRUDDomainMetadata) {
		t.Fatalf("missing execution exception error = %v; want domain metadata", err)
	}

	ordinary := actionDomain(nil)
	ordinary.scopedReadDenial = crudScopedReadPermissionDenied
	if err := validateCRUDDomain(ordinary); !errors.Is(err, errCRUDDomainMetadata) {
		t.Fatalf("unexpected action exception error = %v; want domain metadata", err)
	}

	ordinary.scopedReadDenial = crudScopedReadDenial(255)
	if err := validateCRUDDomain(ordinary); !errors.Is(err, errCRUDDomainMetadata) {
		t.Fatalf("unknown denial mode error = %v; want domain metadata", err)
	}
}

func TestScopableCoverageGuard_RejectsMissingUnexpectedAndZero(t *testing.T) {
	domains := managementDomains(nil)
	cases := authorizationScopeCases()
	if violations := scopableCoverageViolations(domains, cases); len(violations) > 0 {
		t.Fatalf("valid scope coverage = %v; want none", violations)
	}

	tests := map[string]struct {
		domains []crudDomain
		cases   []authorizationScopeCase
		want    []string
	}{
		"zero": {
			want: []string{
				"zero real-handler behavioral scope cases",
				"zero registered management domains",
			},
		},
		"missing": {
			domains: domains,
			cases:   slices.Clone(cases[1:]),
			want: []string{
				"action_sets.manage: missing real-handler behavioral scope case",
			},
		},
		"duplicate": {
			domains: domains,
			cases:   append(slices.Clone(cases), cases[0]),
			want: []string{
				"action_sets.manage: duplicate behavioral scope case",
			},
		},
		"unexpected": {
			domains: domains,
			cases: append(slices.Clone(cases), authorizationScopeCase{
				permission: "logs.read",
				exercise:   func(*testing.T, *authorizationScopeFixture) {},
			}),
			want: []string{
				"logs.read: no registered confinable management domain",
			},
		},
		"global only": {
			domains: domains,
			cases: append(slices.Clone(cases), authorizationScopeCase{
				permission: "pki.manage",
				exercise:   func(*testing.T, *authorizationScopeFixture) {},
			}),
			want: []string{
				"pki.manage: behavioral scope case is not confinable",
			},
		},
		"missing exercise": {
			domains: domains,
			cases: append(
				slices.Clone(cases[:1]),
				append(
					[]authorizationScopeCase{{
						permission: cases[1].permission,
					}},
					cases[2:]...,
				)...,
			),
			want: []string{
				"actions.manage: behavioral scope case has no exercise",
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := scopableCoverageViolations(test.domains, test.cases)
			if !slices.Equal(got, test.want) {
				t.Fatalf("scope coverage violations = %v; want %v", got, test.want)
			}
		})
	}
}

func scopableCoverageViolations(
	domains []crudDomain,
	cases []authorizationScopeCase,
) []string {
	var violations []string
	if len(domains) == 0 {
		violations = append(violations, "zero registered management domains")
	}
	if len(cases) == 0 {
		violations = append(
			violations,
			"zero real-handler behavioral scope cases",
		)
	}

	expected := make(map[authz.Permission]struct{})
	for _, domain := range domains {
		entry, ok := authz.Lookup(domain.permission)
		if !ok {
			violations = append(
				violations,
				fmt.Sprintf("%s: registered domain permission is unknown", domain.permission),
			)
			continue
		}
		if entry.Class == authz.Confinable {
			expected[entry.Name] = struct{}{}
		}
	}

	covered := make(map[authz.Permission]struct{})
	for _, test := range cases {
		entry, ok := authz.Lookup(test.permission)
		switch {
		case !ok:
			violations = append(
				violations,
				fmt.Sprintf("%s: behavioral scope case permission is unknown", test.permission),
			)
			continue
		case entry.Class != authz.Confinable:
			violations = append(
				violations,
				fmt.Sprintf("%s: behavioral scope case is not confinable", test.permission),
			)
			continue
		}
		if _, ok := expected[test.permission]; !ok {
			violations = append(
				violations,
				fmt.Sprintf("%s: no registered confinable management domain", test.permission),
			)
			continue
		}
		if _, duplicate := covered[test.permission]; duplicate {
			violations = append(
				violations,
				fmt.Sprintf("%s: duplicate behavioral scope case", test.permission),
			)
			continue
		}
		covered[test.permission] = struct{}{}
		if test.exercise == nil {
			violations = append(
				violations,
				fmt.Sprintf("%s: behavioral scope case has no exercise", test.permission),
			)
		}
	}
	for permission := range expected {
		if _, ok := covered[permission]; !ok {
			violations = append(
				violations,
				fmt.Sprintf("%s: missing real-handler behavioral scope case", permission),
			)
		}
	}
	slices.Sort(violations)
	return violations
}
