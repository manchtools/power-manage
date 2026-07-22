// Package sign implements the SignedCommand framing, signing, and
// verification helpers of SPEC-003 §3.4 ([WIRE-14..16], AC-4/5/6/14).
//
// It lives in contract (stdlib crypto only, §2 allocation) so the server's
// signer and the agent's verifier share one implementation — the predecessor
// ran five hand-rolled signing schemes whose framings drifted. The signing
// input is length-prefixed and domain-separated; the verifier returns the
// exact verified payload bytes and the caller deserializes only those,
// never a second representation.
package sign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"
	"time"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/identity"
)

// The [WIRE-14] signature domains, one per closed §3.4 command type:
// "power-manage:cmd:" + command_type + ":v1". G-5 discovers these constants
// by AST scan and pins them, exact-set, to the catalog.
const (
	ActionSignatureDomain        = "power-manage:cmd:action:v1"
	OsquerySignatureDomain       = "power-manage:cmd:osquery:v1"
	LogquerySignatureDomain      = "power-manage:cmd:logquery:v1"
	InventorySignatureDomain     = "power-manage:cmd:inventory:v1"
	LuksRevokeSignatureDomain    = "power-manage:cmd:luks-revoke:v1"
	LpsPubkeySignatureDomain     = "power-manage:cmd:lps-pubkey:v1"
	TerminalGrantSignatureDomain = "power-manage:cmd:terminal-grant:v1"
	SyncManifestSignatureDomain  = "power-manage:cmd:sync-manifest:v1"
)

const (
	// MaxInstantWindow bounds expires_at − issued_at for instant commands
	// ([WIRE-15]): replay closes at 15 minutes.
	MaxInstantWindow = 15 * time.Minute
	// MaxTerminalGrantWindow bounds every terminal-grant envelope
	// unconditionally ([WIRE-16]): a compromised gateway must never hold a
	// long-lived PTY grant, whatever freshness class the caller picked.
	MaxTerminalGrantWindow = 60 * time.Second
	// MaxFutureClockSkew bounds how far issued_at may be ahead of verification
	// time to accommodate bounded device-clock drift ([WIRE-15]).
	MaxFutureClockSkew = 5 * time.Minute

	terminalGrantType = "terminal-grant"
)

// commandDomains is the closed command_type → domain registry. CommandDomain
// fails on anything outside it, so an unknown type can never frame a
// preimage (fail-closed, [TM-5]).
var commandDomains = map[string]string{
	"action":          ActionSignatureDomain,
	"osquery":         OsquerySignatureDomain,
	"logquery":        LogquerySignatureDomain,
	"inventory":       InventorySignatureDomain,
	"luks-revoke":     LuksRevokeSignatureDomain,
	"lps-pubkey":      LpsPubkeySignatureDomain,
	terminalGrantType: TerminalGrantSignatureDomain,
	"sync-manifest":   SyncManifestSignatureDomain,
}

// VerifyOptions carries the verifier's context. Now is the clock seam —
// contract is a leaf library, so callers pass time explicitly. Instant
// selects the [WIRE-15] freshness class; WHICH commands are instant is the
// agent chokepoint's decision (SPEC-013).
type VerifyOptions struct {
	// DeviceID is the verifying agent's own ULID; the envelope's
	// target_device_id must equal it ([WIRE-18]: addressing, not
	// authentication).
	DeviceID string
	Now      time.Time
	Instant  bool
}

// CommandDomain maps a closed §3.4 command type to its [WIRE-14] signature
// domain and fails on anything else.
func CommandDomain(commandType string) (string, error) {
	domain, ok := commandDomains[commandType]
	if !ok {
		return "", fmt.Errorf("unknown command_type %q: not in the closed SPEC-003 §3.4 set", commandType)
	}
	return domain, nil
}

// ValidateSigningKey accepts only ECDSA and RSA key material — raw public
// keys or their signers — and refuses Ed25519 explicitly (AC-14): the boot
// path, SignCommand, and VerifyCommand all route through it, so an Ed25519
// key can never sign or verify a command.
func ValidateSigningKey(key crypto.PublicKey) error {
	if key == nil {
		return fmt.Errorf("nil command-signing key: a key must be wired before boot ([TM-5])")
	}
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return fmt.Errorf("nil ECDSA public key: typed-nil key material must never reach verification ([TM-5])")
		}
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
		default:
			return fmt.Errorf("unsupported ECDSA curve: use P-256, P-384, or P-521")
		}
		return validateECDSAPoint(k)
	case *rsa.PublicKey:
		if k == nil {
			return fmt.Errorf("nil RSA public key: typed-nil key material must never reach verification ([TM-5])")
		}
		if k.N == nil || k.N.Sign() <= 0 || k.N.BitLen() < 2048 || k.N.Bit(0) == 0 || k.E < 3 || k.E%2 == 0 {
			return fmt.Errorf("invalid RSA public key: use an odd modulus of at least 2048 bits and an odd exponent >= 3")
		}
		return nil
	case ed25519.PublicKey, ed25519.PrivateKey:
		return fmt.Errorf("ed25519 keys are refused for command signing ([WIRE-14], AC-14): use ECDSA or RSA")
	case crypto.Signer:
		// A typed-nil signer would panic inside Public(); refuse it here so
		// the boot path fails closed instead of crashing.
		if v := reflect.ValueOf(k); v.Kind() == reflect.Pointer && v.IsNil() {
			return fmt.Errorf("nil signing key of type %T ([TM-5])", k)
		}
		return ValidateSigningKey(k.Public())
	default:
		return fmt.Errorf("unsupported command-signing key type %T: use ECDSA or RSA", key)
	}
}

// validateECDSAPoint converts PublicKey.Bytes' nil-coordinate panic into the
// same fail-closed error returned for other malformed points.
func validateECDSAPoint(key *ecdsa.PublicKey) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("invalid ECDSA public key: malformed coordinates")
		}
	}()
	if _, err := key.Bytes(); err != nil {
		return fmt.Errorf("invalid ECDSA public key: %w", err)
	}
	return nil
}

// CommandPreimage builds the [WIRE-14] signing input for the envelope:
// length-prefixed, domain-separated covered fields in fixed order —
// lp(domain) || lp(command_type) || lp(target_device_id) ||
// lp(ts(issued_at)) || lp(ts(expires_at)) || lp(payload), where
// lp(x) = u64be(len(x)) || x and ts(t) = s64be(seconds) || u32be(nanos).
// It fails closed on an unknown command type, an empty payload ([WIRE-25]),
// or a missing timestamp.
func CommandPreimage(cmd *powermanagev1.SignedCommand) ([]byte, error) {
	domain, err := CommandDomain(cmd.GetCommandType())
	if err != nil {
		return nil, err
	}
	if len(cmd.GetPayload()) == 0 {
		return nil, fmt.Errorf("empty payload: signing inputs are never empty ([WIRE-25])")
	}
	if cmd.GetIssuedAt() == nil || cmd.GetExpiresAt() == nil {
		return nil, fmt.Errorf("issued_at and expires_at are required covered fields")
	}
	if !identity.IsCanonicalULID(cmd.GetTargetDeviceId()) {
		return nil, fmt.Errorf("target_device_id is not a ULID: a malformed address is never framed, signed, or verified ([WIRE-18])")
	}
	var buf bytes.Buffer
	lp(&buf, []byte(domain))
	lp(&buf, []byte(cmd.GetCommandType()))
	lp(&buf, []byte(cmd.GetTargetDeviceId()))
	lp(&buf, tsBytes(cmd.GetIssuedAt().GetSeconds(), cmd.GetIssuedAt().GetNanos()))
	lp(&buf, tsBytes(cmd.GetExpiresAt().GetSeconds(), cmd.GetExpiresAt().GetNanos()))
	lp(&buf, cmd.GetPayload())
	return buf.Bytes(), nil
}

func lp(buf *bytes.Buffer, x []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(x)))
	buf.Write(n[:])
	buf.Write(x)
}

func tsBytes(seconds int64, nanos int32) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint64(b[0:8], uint64(seconds))
	binary.BigEndian.PutUint32(b[8:12], uint32(nanos))
	return b
}

// SignCommand signs the envelope's covered fields at the one signing seam
// ([WIRE-14]) and fills its signature: ECDSA (ASN.1) or RSA PKCS#1 v1.5,
// both over the SHA-256 preimage digest.
func SignCommand(key crypto.Signer, cmd *powermanagev1.SignedCommand) error {
	if err := ValidateSigningKey(key); err != nil {
		return err
	}
	preimage, err := CommandPreimage(cmd)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(preimage)
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return fmt.Errorf("signing command preimage: %w", err)
	}
	cmd.Signature = sig
	return nil
}

// VerifyCommand runs every [WIRE-14..16] check fail-closed — key validity,
// closed command type, target addressing, signature under the type's
// domain, timestamp ordering, expiry, the instant window, and the
// unconditional terminal-grant window — and returns a copy of the exact
// verified payload bytes. Any failure returns a nil payload; the caller
// deserializes only what this returns.
func VerifyCommand(pub crypto.PublicKey, cmd *powermanagev1.SignedCommand, opts VerifyOptions) ([]byte, error) {
	if opts.Now.IsZero() {
		// time.Time{} is year 1: every real expires_at would pass the expiry
		// check, so a forgotten clock must fail closed, never open.
		return nil, fmt.Errorf("VerifyOptions.Now is unset: a verification time is required ([WIRE-15])")
	}
	if err := ValidateSigningKey(pub); err != nil {
		return nil, err
	}
	preimage, err := CommandPreimage(cmd)
	if err != nil {
		return nil, err
	}
	if cmd.GetTargetDeviceId() != opts.DeviceID {
		return nil, fmt.Errorf("target_device_id is not the verifying device: refusing a command addressed elsewhere ([WIRE-18])")
	}
	digest := sha256.Sum256(preimage)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest[:], cmd.GetSignature()) {
			return nil, fmt.Errorf("signature does not verify under domain for command_type %q", cmd.GetCommandType())
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], cmd.GetSignature()); err != nil {
			return nil, fmt.Errorf("signature does not verify under domain for command_type %q: %w", cmd.GetCommandType(), err)
		}
	default:
		// Unreachable after ValidateSigningKey; kept so a future key-type
		// addition cannot fall through to acceptance.
		return nil, fmt.Errorf("unsupported verifying key type %T", pub)
	}
	issued := cmd.GetIssuedAt().AsTime()
	expires := cmd.GetExpiresAt().AsTime()
	if issued.After(expires) {
		return nil, fmt.Errorf("issued_at is after expires_at: malformed validity window")
	}
	if issued.After(opts.Now) && issued.Sub(opts.Now) > MaxFutureClockSkew {
		return nil, fmt.Errorf("issued_at is more than %s in the future ([WIRE-15])", MaxFutureClockSkew)
	}
	if expires.Before(opts.Now) {
		return nil, fmt.Errorf("command expired: nothing executes or persists past expires_at ([WIRE-15])")
	}
	window := expires.Sub(issued)
	if opts.Instant && window > MaxInstantWindow {
		return nil, fmt.Errorf("instant command window %s exceeds the %s maximum ([WIRE-15])", window, MaxInstantWindow)
	}
	if cmd.GetCommandType() == terminalGrantType && window > MaxTerminalGrantWindow {
		return nil, fmt.Errorf("terminal-grant window %s exceeds the %s maximum ([WIRE-16])", window, MaxTerminalGrantWindow)
	}
	return append([]byte(nil), cmd.GetPayload()...), nil
}
