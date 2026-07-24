package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const testSubject = "01K0QJ3E5E8R4M0D8EV3Y4N6J7"
const testSessionVersion int64 = 1

var testNow = time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

func TestTokenService_MintsAndVerifiesPinnedTypesAndLifetimes(t *testing.T) {
	_, signer, verifier, clock := tokenService(t)
	want := Claims{Subject: testSubject, SessionVersion: testSessionVersion}

	access := mintAccess(t, signer, testSubject)
	refresh := mintRefresh(t, signer, testSubject)

	got, err := verifier.VerifyAccess(access)
	assertClaims(t, want, got, err)
	got, err = verifier.VerifyRefresh(refresh)
	assertClaims(t, want, got, err)
	clock.now = testNow.Add(5*time.Minute - time.Second)
	got, err = verifier.VerifyAccess(access)
	assertClaims(t, want, got, err)
	clock.now = testNow.Add(5 * time.Minute)
	assertTokenError(t, verifyAccessErr(verifier, access), ErrExpired)
	clock.now = testNow.Add(7*24*time.Hour - time.Second)
	got, err = verifier.VerifyRefresh(refresh)
	assertClaims(t, want, got, err)
	clock.now = testNow.Add(7 * 24 * time.Hour)
	assertTokenError(t, verifyRefreshErr(verifier, refresh), ErrInvalid)
}

func TestTokenService_RejectsNonES256AlgorithmsIncludingPublicKeyHMAC(t *testing.T) {
	key, signer, verifier, _ := tokenService(t)
	access := mintAccess(t, signer, testSubject)
	parts := strings.Split(access, ".")
	if len(parts) != 3 {
		t.Fatalf("minted token has %d segments, want 3", len(parts))
	}

	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	forged := map[string]string{
		"HS256 with public verification key": hmacToken(t, parts[1], publicDER),
		"ES384 header with P-256 signature":  signedToken(t, key, "ES384", parts[1]),
		"none":                               encodedHeader("none") + "." + parts[1] + ".",
	}
	for name, token := range forged {
		t.Run(name, func(t *testing.T) {
			assertTokenError(t, verifyAccessErr(verifier, token), ErrInvalid)
		})
	}
}

func TestTokenService_ExposesOnlyExpiryAsDistinct(t *testing.T) {
	key, signer, verifier, clock := tokenService(t)
	access := mintAccess(t, signer, testSubject)
	otherKey, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}

	clock.now = testNow.Add(5 * time.Minute)
	assertTokenError(t, verifyAccessErr(verifier, access), ErrExpired)
	invalid := map[string]string{
		"malformed":         "not.a.jwt",
		"bad signature":     corruptSignature(t, access),
		"wrong signing key": resignToken(t, otherKey, access, nil),
		"missing subject":   resignToken(t, key, access, func(claims map[string]any) { delete(claims, "sub") }),
		"missing session":   resignToken(t, key, access, func(claims map[string]any) { delete(claims, "session_version") }),
		"zero session":      resignToken(t, key, access, func(claims map[string]any) { claims["session_version"] = 0 }),
		"invalid session":   resignToken(t, key, access, func(claims map[string]any) { claims["session_version"] = "one" }),
		"missing expiry":    resignToken(t, key, access, func(claims map[string]any) { delete(claims, "exp") }),
		"invalid expiry":    resignToken(t, key, access, func(claims map[string]any) { claims["exp"] = "later" }),
	}
	for name, token := range invalid {
		t.Run(name, func(t *testing.T) {
			assertTokenError(t, verifyAccessErr(verifier, token), ErrInvalid)
		})
	}
}

func TestTokenService_RejectsCrossTypeUse(t *testing.T) {
	_, signer, verifier, clock := tokenService(t)
	access := mintAccess(t, signer, testSubject)
	refresh := mintRefresh(t, signer, testSubject)

	assertTokenError(t, verifyRefreshErr(verifier, access), ErrInvalid)
	assertTokenError(t, verifyAccessErr(verifier, refresh), ErrInvalid)
	clock.now = testNow.Add(8 * 24 * time.Hour)
	assertTokenError(t, verifyRefreshErr(verifier, access), ErrInvalid)
	assertTokenError(t, verifyAccessErr(verifier, refresh), ErrInvalid)
}

func TestTokenService_RejectsInvalidConstructionAndClaims(t *testing.T) {
	now := func() time.Time { return testNow }
	valid, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	mismatched, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("generate mismatched key: %v", err)
	}
	mismatched.PublicKey = valid.PublicKey

	for name, key := range map[string]*ecdsa.PrivateKey{
		"nil": nil, "wrong curve": p384, "missing scalar": {PublicKey: valid.PublicKey},
		"mismatched public key": mismatched,
	} {
		t.Run("signer/"+name, func(t *testing.T) {
			if _, err := NewSigner(key, now); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("NewSigner error = %v, want ErrInvalidKey", err)
			}
		})
	}
	for name, key := range map[string]*ecdsa.PublicKey{
		"nil": nil, "wrong curve": &p384.PublicKey,
		"off curve": {Curve: elliptic.P256()},
	} {
		t.Run("verifier/"+name, func(t *testing.T) {
			if _, err := NewVerifier(key, now); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("NewVerifier error = %v, want ErrInvalidKey", err)
			}
		})
	}
	if _, err := NewSigner(valid, nil); !errors.Is(err, ErrClockNotWired) {
		t.Fatalf("NewSigner nil-clock error = %v, want ErrClockNotWired", err)
	}
	if _, err := NewVerifier(&valid.PublicKey, nil); !errors.Is(err, ErrClockNotWired) {
		t.Fatalf("NewVerifier nil-clock error = %v, want ErrClockNotWired", err)
	}

	clock := &testClock{now: testNow}
	signer, err := NewSigner(valid, clock.Now)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	verifier, err := NewVerifier(&valid.PublicKey, clock.Now)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	for _, mint := range []func(string, int64) (string, error){signer.MintAccess, signer.MintRefresh} {
		if _, err := mint("", testSessionVersion); !errors.Is(err, ErrInvalid) {
			t.Fatalf("empty subject mint error = %v, want ErrInvalid", err)
		}
		clock.now = time.Time{}
		if _, err := mint(testSubject, testSessionVersion); !errors.Is(err, ErrInvalid) {
			t.Fatalf("zero mint time error = %v, want ErrInvalid", err)
		}
		clock.now = testNow
		if _, err := mint(testSubject, 0); !errors.Is(err, ErrInvalid) {
			t.Fatalf("zero session version mint error = %v, want ErrInvalid", err)
		}
	}
	if _, err := verifier.VerifyAccess(""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty token error = %v, want ErrInvalid", err)
	}
	access := mintAccess(t, signer, testSubject)
	clock.now = time.Time{}
	if _, err := verifier.VerifyAccess(access); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero verify time error = %v, want ErrInvalid", err)
	}
}

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }

func tokenService(t *testing.T) (*ecdsa.PrivateKey, *Signer, *Verifier, *testClock) {
	t.Helper()
	clock := &testClock{now: testNow}
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Fatalf("generated curve = %T, want P-256", key.Curve)
	}
	signer, err := NewSigner(key, clock.Now)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	verifier, err := NewVerifier(&key.PublicKey, clock.Now)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return key, signer, verifier, clock
}

func mintAccess(t *testing.T, signer *Signer, subject string) string {
	t.Helper()
	token, err := signer.MintAccess(subject, testSessionVersion)
	if err != nil {
		t.Fatalf("mint access: %v", err)
	}
	return token
}

func mintRefresh(t *testing.T, signer *Signer, subject string) string {
	t.Helper()
	token, err := signer.MintRefresh(subject, testSessionVersion)
	if err != nil {
		t.Fatalf("mint refresh: %v", err)
	}
	return token
}

func assertClaims(t *testing.T, want Claims, got Claims, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if got != want {
		t.Fatalf("claims = %+v, want %+v", got, want)
	}
}

func verifyAccessErr(verifier *Verifier, token string) error {
	_, err := verifier.VerifyAccess(token)
	return err
}

func verifyRefreshErr(verifier *Verifier, token string) error {
	_, err := verifier.VerifyRefresh(token)
	return err
}

func assertTokenError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if err == nil || err.Error() != want.Error() {
		t.Fatalf("error text = %q, want static %q", err, want)
	}
	if want == ErrInvalid && errors.Is(err, ErrExpired) {
		t.Fatalf("generic rejection also exposes ErrExpired: %v", err)
	}
}

func encodedHeader(algorithm string) string {
	header, _ := json.Marshal(map[string]string{"alg": algorithm, "typ": "JWT"})
	return base64.RawURLEncoding.EncodeToString(header)
}

func signedToken(t *testing.T, key *ecdsa.PrivateKey, algorithm, payload string) string {
	t.Helper()
	signingInput := encodedHeader(algorithm) + "." + payload
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func hmacToken(t *testing.T, payload string, key []byte) string {
	t.Helper()
	signingInput := encodedHeader("HS256") + "." + payload
	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write([]byte(signingInput)); err != nil {
		t.Fatalf("HMAC token: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func resignToken(t *testing.T, key *ecdsa.PrivateKey, token string, mutate func(map[string]any)) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if mutate != nil {
		mutate(claims)
	}
	payload, err = json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return signedToken(t, key, "ES256", base64.RawURLEncoding.EncodeToString(payload))
}

func corruptSignature(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) == 0 {
		t.Fatalf("decode signature: %v", err)
	}
	signature[0] ^= 0x80
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	return strings.Join(parts, ".")
}
