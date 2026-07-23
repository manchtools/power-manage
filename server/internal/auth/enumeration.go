package auth

import (
	"maps"
	"slices"
	"time"
)

// SecretVerifier identifies one credential boundary covered by parity tests.
type SecretVerifier string

const (
	// SecretVerifierPAT is the personal-access-token boundary.
	SecretVerifierPAT SecretVerifier = "pat"
	// SecretVerifierRefresh is the rotating refresh-token boundary.
	SecretVerifierRefresh SecretVerifier = "refresh"
)

// EnumerationFailureCause identifies one externally indistinguishable secret
// rejection state.
type EnumerationFailureCause string

const (
	EnumerationMalformed   EnumerationFailureCause = "malformed"
	EnumerationNonexistent EnumerationFailureCause = "nonexistent"
	EnumerationExpired     EnumerationFailureCause = "expired"
	EnumerationSuperseded  EnumerationFailureCause = "superseded"
	EnumerationRevoked     EnumerationFailureCause = "revoked"
)

// EnumerationParityProfile defines the causes and timing floor exercised for
// one secret verifier.
type EnumerationParityProfile struct {
	FailureCauses           []EnumerationFailureCause
	MinimumRejectionLatency time.Duration
}

var enumerationParityProfiles = map[SecretVerifier]EnumerationParityProfile{
	SecretVerifierPAT: {
		FailureCauses: []EnumerationFailureCause{
			EnumerationMalformed,
			EnumerationNonexistent,
			EnumerationExpired,
			EnumerationRevoked,
		},
		MinimumRejectionLatency: minimumPATRejectionDuration,
	},
	SecretVerifierRefresh: {
		FailureCauses: []EnumerationFailureCause{
			EnumerationMalformed,
			EnumerationNonexistent,
			EnumerationExpired,
			EnumerationSuperseded,
			EnumerationRevoked,
		},
		MinimumRejectionLatency: minimumRefreshRejectionDuration,
	},
}

// EnumerationParityProfiles returns a deep copy of the secret-verifier
// registry consumed by the parity harness.
func EnumerationParityProfiles() map[SecretVerifier]EnumerationParityProfile {
	profiles := maps.Clone(enumerationParityProfiles)
	for verifier, profile := range profiles {
		profile.FailureCauses = slices.Clone(profile.FailureCauses)
		profiles[verifier] = profile
	}
	return profiles
}
