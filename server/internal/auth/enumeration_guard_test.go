package auth

import (
	"errors"
	"slices"
	"testing"

	"github.com/manchtools/power-manage/sdk/guardtest"
)

func TestGuard_RefreshEnumerationParityCoverage(t *testing.T) {
	profiles := EnumerationParityProfiles()
	discovered := guardtest.Discover(t, "secret-verification parity profiles", 1, func() ([]string, error) {
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
	if !slices.Equal(discovered, []string{string(SecretVerifierRefresh)}) {
		t.Fatalf("secret verifiers = %v; want refresh", discovered)
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
