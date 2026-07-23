package auth

import (
	"errors"
	"slices"
	"testing"

	"github.com/manchtools/power-manage/sdk/guardtest"
)

func TestGuard_RefreshEnumerationParityCoverage(t *testing.T) {
	profiles := EnumerationParityProfiles()
	discovered := guardtest.Discover(t, "secret-verification parity profiles", 2, func() ([]string, error) {
		names := make([]string, 0, len(profiles))
		for verifier := range profiles {
			if verifier == "" {
				return nil, errors.New("secret-verifier registry contains an empty name")
			}
			names = append(names, string(verifier))
		}
		slices.Sort(names)
		return names, nil
	})
	if !slices.Equal(discovered, []string{
		string(SecretVerifierPAT),
		string(SecretVerifierRefresh),
	}) {
		t.Fatalf("secret verifiers = %v; want PAT and refresh", discovered)
	}

	profile := profiles[SecretVerifierRefresh]
	gotCauses := slices.Clone(profile.FailureCauses)
	slices.Sort(gotCauses)
	wantCauses := []EnumerationFailureCause{
		EnumerationExpired,
		EnumerationMalformed,
		EnumerationNonexistent,
		EnumerationRevoked,
		EnumerationSuperseded,
	}
	if !slices.Equal(gotCauses, wantCauses) {
		t.Fatalf("refresh parity causes = %v; want %v", gotCauses, wantCauses)
	}
	if profile.MinimumRejectionLatency <= 0 {
		t.Fatal("refresh parity profile has no rejection-latency floor")
	}
	if len(slices.Compact(gotCauses)) != len(gotCauses) {
		t.Fatalf("refresh parity profile repeats causes: %v", gotCauses)
	}
}

func TestGuard_PATEnumerationParityCoverage(t *testing.T) {
	profile := EnumerationParityProfiles()[SecretVerifierPAT]
	discovered := guardtest.Discover(t, "PAT enumeration failure causes", 4, func() ([]string, error) {
		causes := make([]string, 0, len(profile.FailureCauses))
		for _, cause := range profile.FailureCauses {
			if cause == "" {
				return nil, errors.New("PAT parity profile contains an empty failure cause")
			}
			causes = append(causes, string(cause))
		}
		slices.Sort(causes)
		return causes, nil
	})
	wantCauses := []string{
		string(EnumerationExpired),
		string(EnumerationMalformed),
		string(EnumerationNonexistent),
		string(EnumerationRevoked),
	}
	if !slices.Equal(discovered, wantCauses) {
		t.Fatalf("PAT parity causes = %v; want %v", discovered, wantCauses)
	}
	if profile.MinimumRejectionLatency <= 0 {
		t.Fatal("PAT parity profile has no rejection-latency floor")
	}
}

func TestEnumerationParityProfiles_DefensivelyCopied(t *testing.T) {
	first := EnumerationParityProfiles()
	profile := first[SecretVerifierRefresh]
	profile.FailureCauses[0] = "injected"
	first[SecretVerifierRefresh] = profile
	delete(first, SecretVerifierRefresh)

	second := EnumerationParityProfiles()
	if _, exists := second[SecretVerifierRefresh]; !exists {
		t.Fatal("mutating returned parity registry removed the refresh verifier")
	}
	if slices.Contains(second[SecretVerifierRefresh].FailureCauses, EnumerationFailureCause("injected")) {
		t.Fatal("mutating returned parity profile changed its failure causes")
	}
	if len(second) == 0 {
		t.Fatal("secret-verifier registry is empty")
	}
}
