// Package seal carries the sealed-transport domain-info constants of
// SPEC-003 §3.7 ([WIRE-23], SEC-11 SPEC-015).
//
// These strings bind the HKDF info tag at the sdk seal/open seam — a drift
// here silently breaks every already-sealed blob. The seal/open crypto
// itself (X25519 + HKDF-SHA256 + AES-256-GCM) lives EXCLUSIVELY in sdk
// (SDK-13, SPEC-004); sdk imports no in-repo module (SDK-0), so agent and
// server pass these constants into it. The SealedBlob message shape lives
// in sealed.proto with its info tag bound to exactly this closed set.
package seal

const (
	// LpsPasswordSealInfo seals device-originated LPS passwords to
	// control's X25519 key ([WIRE-23]).
	LpsPasswordSealInfo = "power-manage-lps-password:v1"
	// LuksPassphraseSealInfo seals device-originated LUKS passphrases to
	// control's X25519 key ([WIRE-23]).
	LuksPassphraseSealInfo = "power-manage-luks-passphrase:v1"
	// ActionFieldSecretSealInfo seals control-originated inline
	// action-field secrets (WIFI PSK, EAP-TLS key material) to the
	// device's enrollment-registered X25519 key (SEC-11, recorded operator
	// decision 2026-07-19).
	ActionFieldSecretSealInfo = "power-manage-action-field-secret:v1"
)

// InfoStrings returns the closed set of mandated sealing domains — exactly
// the three constants. An entry here without an operator-approved surface
// registration (SEC-11) is an unapproved sealing domain.
func InfoStrings() []string {
	return []string{
		LpsPasswordSealInfo,
		LuksPassphraseSealInfo,
		ActionFieldSecretSealInfo,
	}
}
