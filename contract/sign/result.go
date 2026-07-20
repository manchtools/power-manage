package sign

// The DeviceSigned result-envelope helpers (SPEC-003 §3.6, [WIRE-20..22],
// AC-7) — the device→control mirror of the SignedCommand helpers in sign.go.
// The result framing IS the command framing with a result domain; a second
// divergent framing would be its own bug. No expiry lives here: results are
// records, not commands, and staleness policy is control-side (SPEC-005/007).

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
)

// ResultVerifyOptions carries the verifier's context. Control resolves the
// claimed reporter to its DER-derived registered key (PKI-4, SPEC-006) and
// states here which device it expects; the envelope's device_id must equal
// it ([WIRE-21] resolution stays control-side on top of this).
type ResultVerifyOptions struct {
	DeviceID string
}

// ResultDomain maps a result type to its [WIRE-20] signature domain
// "power-manage:result:" + type + ":v1". The type set is OPEN at M4 — the
// closed per-type set arms with M5's stream frames — so the whole gate is
// the grammar: a non-empty [a-z0-9-]+ token, fail-closed otherwise.
func ResultDomain(resultType string) (string, error) {
	if !isResultType(resultType) {
		return "", fmt.Errorf("result_type %q violates the [a-z0-9-]+ grammar: an unframable type never gets a domain", resultType)
	}
	return "power-manage:result:" + resultType + ":v1", nil
}

// isResultType reports whether s is a non-empty lowercase [a-z0-9-]+ token.
func isResultType(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return true
}

// ResultPreimage builds the [WIRE-20] signing input: length-prefixed,
// domain-separated covered fields in fixed order — lp(domain) ||
// lp(result_type) || lp(device_id) || lp(ts(issued_at)) || lp(payload),
// with lp and ts exactly as in the command framing. It fails closed on a
// grammar-violating result type, an empty payload ([WIRE-25]), a missing
// issued_at, or a non-ULID device_id.
func ResultPreimage(env *powermanagev1.DeviceSigned) ([]byte, error) {
	domain, err := ResultDomain(env.GetResultType())
	if err != nil {
		return nil, err
	}
	if len(env.GetPayload()) == 0 {
		return nil, fmt.Errorf("empty payload: signing inputs are never empty ([WIRE-25])")
	}
	if env.GetIssuedAt() == nil {
		return nil, fmt.Errorf("issued_at is a required covered field")
	}
	if !isULID(env.GetDeviceId()) {
		return nil, fmt.Errorf("device_id is not a ULID: a malformed reporter identity is never framed, signed, or verified ([WIRE-18])")
	}
	var buf bytes.Buffer
	lp(&buf, []byte(domain))
	lp(&buf, []byte(env.GetResultType()))
	lp(&buf, []byte(env.GetDeviceId()))
	lp(&buf, tsBytes(env.GetIssuedAt().GetSeconds(), env.GetIssuedAt().GetNanos()))
	lp(&buf, env.GetPayload())
	return buf.Bytes(), nil
}

// SignResult signs the envelope's covered fields with the device's enrolled
// key ([WIRE-20]) and fills its signature — ECDSA (ASN.1) or RSA PKCS#1
// v1.5, both over the SHA-256 preimage digest, through the shared key gate.
func SignResult(key crypto.Signer, env *powermanagev1.DeviceSigned) error {
	if err := ValidateSigningKey(key); err != nil {
		return err
	}
	preimage, err := ResultPreimage(env)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(preimage)
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return fmt.Errorf("signing result preimage: %w", err)
	}
	env.Signature = sig
	return nil
}

// VerifyResult runs every check fail-closed — key validity, framing (grammar,
// ULID, non-empty payload), reporter addressing, and the signature under the
// type's domain — and returns a copy of the exact verified payload bytes.
// Any failure returns a nil payload; control records only what this returns.
func VerifyResult(pub crypto.PublicKey, env *powermanagev1.DeviceSigned, opts ResultVerifyOptions) ([]byte, error) {
	if err := ValidateSigningKey(pub); err != nil {
		return nil, err
	}
	preimage, err := ResultPreimage(env)
	if err != nil {
		return nil, err
	}
	if env.GetDeviceId() != opts.DeviceID {
		return nil, fmt.Errorf("device_id is not the expected reporter: refusing a report claiming another device's identity ([WIRE-20])")
	}
	digest := sha256.Sum256(preimage)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest[:], env.GetSignature()) {
			return nil, fmt.Errorf("signature does not verify under domain for result_type %q", env.GetResultType())
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], env.GetSignature()); err != nil {
			return nil, fmt.Errorf("signature does not verify under domain for result_type %q: %w", env.GetResultType(), err)
		}
	default:
		// Unreachable after ValidateSigningKey; kept so a future key-type
		// addition cannot fall through to acceptance.
		return nil, fmt.Errorf("unsupported verifying key type %T", pub)
	}
	return append([]byte(nil), env.GetPayload()...), nil
}
