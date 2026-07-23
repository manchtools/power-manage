package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestOIDCIDTokenVerification_AcceptsConfiguredRS256AndES256Keys(t *testing.T) {
	now := time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)
	provider := oidcProvider{OIDCProvider: OIDCProvider{
		Issuer:   "https://identity.example.test",
		ClientID: "power-manage-test",
	}}
	claims := map[string]any{
		"iss":            provider.Issuer,
		"sub":            "external-subject",
		"aud":            provider.ClientID,
		"exp":            now.Add(5 * time.Minute).Unix(),
		"iat":            now.Unix(),
		"nonce":          "bound-nonce",
		"email":          "person@example.test",
		"email_verified": true,
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	rsaJWK := marshalOIDCTestJSON(t, map[string]string{
		"kty": "RSA",
		"kid": "rsa-key",
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(rsaKey.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(
			big.NewInt(int64(rsaKey.PublicKey.E)).Bytes(),
		),
	})
	rsaToken := signOIDCTestToken(t, "RS256", "rsa-key", claims, func(digest []byte) []byte {
		signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest)
		if err != nil {
			t.Fatalf("sign RSA ID token: %v", err)
		}
		return signature
	})

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	ecdsaJWK := marshalOIDCTestJSON(t, map[string]string{
		"kty": "EC",
		"kid": "ecdsa-key",
		"use": "sig",
		"alg": "ES256",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(ecdsaKey.X.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(ecdsaKey.Y.FillBytes(make([]byte, 32))),
	})
	ecdsaToken := signOIDCTestToken(t, "ES256", "ecdsa-key", claims, func(digest []byte) []byte {
		r, signatureS, err := ecdsa.Sign(rand.Reader, ecdsaKey, digest)
		if err != nil {
			t.Fatalf("sign ECDSA ID token: %v", err)
		}
		signature := make([]byte, 64)
		r.FillBytes(signature[:32])
		signatureS.FillBytes(signature[32:])
		return signature
	})

	for _, test := range []struct {
		name  string
		token string
		key   json.RawMessage
	}{
		{name: "RS256", token: rsaToken, key: rsaJWK},
		{name: "ES256", token: ecdsaToken, key: ecdsaJWK},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := verifyOIDCIDToken(
				test.token,
				provider,
				[]json.RawMessage{test.key},
				"bound-nonce",
				now,
			)
			if err != nil || got.Subject != "external-subject" || !got.EmailVerified {
				t.Fatalf("verify %s ID token = (%+v, %v); want verified claims", test.name, got, err)
			}
		})
	}
}

func TestOIDCIDTokenVerification_RejectsWeakRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate weak RSA key: %v", err)
	}
	raw := marshalOIDCTestJSON(t, map[string]string{
		"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(
			big.NewInt(int64(key.PublicKey.E)).Bytes(),
		),
	})
	if _, err := decodeOIDCRSAKey(raw); !errors.Is(err, ErrOIDCRejected) {
		t.Fatalf("decode 1024-bit OIDC RSA key error = %v; want %v", err, ErrOIDCRejected)
	}
}

func signOIDCTestToken(
	t *testing.T,
	algorithm string,
	keyID string,
	claims map[string]any,
	sign func([]byte) []byte,
) string {
	t.Helper()
	header := marshalOIDCTestJSON(t, map[string]string{
		"alg": algorithm,
		"kid": keyID,
		"typ": "JWT",
	})
	payload := marshalOIDCTestJSON(t, claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sign(digest[:]))
}

func marshalOIDCTestJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode OIDC test JSON: %v", err)
	}
	return encoded
}
