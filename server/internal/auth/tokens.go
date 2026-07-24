// Package auth provides control's human and API-consumer authentication
// primitives (SPEC-007).
package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	accessTokenLifetime  = 5 * time.Minute
	refreshTokenLifetime = 7 * 24 * time.Hour
	maxTokenBytes        = 8 << 10
	maxSubjectBytes      = 1 << 10
	tokenTypeAccess      = "access"
	tokenTypeRefresh     = "refresh"
)

var (
	// ErrExpired is returned only for an otherwise-valid expired access token.
	ErrExpired = errors.New("access token expired")
	// ErrInvalid is the static rejection for every other token failure.
	ErrInvalid = errors.New("authentication token rejected")
	// ErrInvalidKey identifies a malformed or non-ES256 constructor key.
	ErrInvalidKey = errors.New("auth: invalid ES256 key")
	// ErrClockNotWired identifies a missing constructor clock dependency.
	ErrClockNotWired = errors.New("auth: token clock is not wired")
)

// Claims are the authenticated values returned from a verified token.
type Claims struct {
	Subject        string
	SessionVersion int64
}

type tokenHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type tokenClaims struct {
	Subject        string `json:"sub"`
	TokenType      string `json:"token_type"`
	SessionVersion int64  `json:"session_version"`
	IssuedAt       int64  `json:"iat"`
	ExpiresAt      int64  `json:"exp"`
}

// Signer mints purpose-separated session tokens with the setup signing key.
type Signer struct {
	key *ecdsa.PrivateKey
	now func() time.Time
}

// Verifier authenticates session tokens using only the non-secret public key.
type Verifier struct {
	key *ecdsa.PublicKey
	now func() time.Time
}

// GenerateSigningKey creates the setup-time ES256 signing key.
func GenerateSigningKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("auth: generate ES256 signing key: %w", err)
	}
	return key, nil
}

// NewSigner validates and copies the setup-time ES256 private key.
func NewSigner(key *ecdsa.PrivateKey, now func() time.Time) (*Signer, error) {
	if !validPrivateKey(key) {
		return nil, ErrInvalidKey
	}
	if now == nil {
		return nil, ErrClockNotWired
	}
	keyCopy, err := copyPrivateKey(key)
	if err != nil {
		return nil, ErrInvalidKey
	}
	return &Signer{key: keyCopy, now: now}, nil
}

// NewVerifier validates and copies the non-secret ES256 verification key.
func NewVerifier(key *ecdsa.PublicKey, now func() time.Time) (*Verifier, error) {
	if !validPublicKey(key) {
		return nil, ErrInvalidKey
	}
	if now == nil {
		return nil, ErrClockNotWired
	}
	keyCopy, err := copyPublicKey(key)
	if err != nil {
		return nil, ErrInvalidKey
	}
	return &Verifier{key: keyCopy, now: now}, nil
}

// MintAccess mints a five-minute access token.
func (s *Signer) MintAccess(subject string, sessionVersion int64) (string, error) {
	return s.mint(subject, sessionVersion, tokenTypeAccess, accessTokenLifetime)
}

// MintRefresh mints a seven-day refresh token.
func (s *Signer) MintRefresh(subject string, sessionVersion int64) (string, error) {
	return s.mint(subject, sessionVersion, tokenTypeRefresh, refreshTokenLifetime)
}

func (s *Signer) mint(
	subject string,
	sessionVersion int64,
	tokenType string,
	lifetime time.Duration,
) (string, error) {
	if s == nil || s.key == nil || s.now == nil ||
		!validSubject(subject) || sessionVersion <= 0 {
		return "", ErrInvalid
	}
	now := s.now()
	if !validTime(now) {
		return "", ErrInvalid
	}
	issuedAt := now.Unix()
	expiresAt := now.Add(lifetime).Unix()
	if expiresAt <= issuedAt {
		return "", ErrInvalid
	}
	header, err := json.Marshal(tokenHeader{Algorithm: "ES256", Type: "JWT"})
	if err != nil {
		return "", fmt.Errorf("auth: encode token header: %w", err)
	}
	payload, err := json.Marshal(tokenClaims{
		Subject:        subject,
		TokenType:      tokenType,
		SessionVersion: sessionVersion,
		IssuedAt:       issuedAt,
		ExpiresAt:      expiresAt,
	})
	if err != nil {
		return "", fmt.Errorf("auth: encode token claims: %w", err)
	}
	signingInput := encodeSegment(header) + "." + encodeSegment(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, signatureS, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", fmt.Errorf("auth: sign token: %w", err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	signatureS.FillBytes(signature[32:])
	token := signingInput + "." + encodeSegment(signature)
	if len(token) > maxTokenBytes {
		return "", ErrInvalid
	}
	return token, nil
}

// VerifyAccess authenticates an access token. Expiry is its only distinct
// caller-visible validation failure.
func (v *Verifier) VerifyAccess(token string) (Claims, error) {
	return v.verify(token, tokenTypeAccess, accessTokenLifetime, true)
}

// VerifyRefresh authenticates a refresh token. All failures are generic.
func (v *Verifier) VerifyRefresh(token string) (Claims, error) {
	return v.verify(token, tokenTypeRefresh, refreshTokenLifetime, false)
}

func (v *Verifier) verify(
	token string,
	expectedType string,
	lifetime time.Duration,
	exposeExpiry bool,
) (Claims, error) {
	if v == nil || v.key == nil || v.now == nil || len(token) == 0 || len(token) > maxTokenBytes {
		return Claims{}, ErrInvalid
	}
	now := v.now()
	if !validTime(now) {
		return Claims{}, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Claims{}, ErrInvalid
	}
	var header tokenHeader
	if err := decodeSegmentJSON(parts[0], &header); err != nil ||
		header.Algorithm != "ES256" || header.Type != "JWT" {
		return Claims{}, ErrInvalid
	}
	signature, err := decodeSegment(parts[2])
	if err != nil || len(signature) != 64 {
		return Claims{}, ErrInvalid
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(signature[:32])
	signatureS := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(v.key, digest[:], r, signatureS) {
		return Claims{}, ErrInvalid
	}
	var raw tokenClaims
	if err := decodeSegmentJSON(parts[1], &raw); err != nil ||
		!validSubject(raw.Subject) ||
		raw.TokenType != expectedType ||
		raw.SessionVersion <= 0 ||
		raw.IssuedAt <= 0 ||
		raw.ExpiresAt <= raw.IssuedAt ||
		raw.ExpiresAt-raw.IssuedAt != int64(lifetime/time.Second) {
		return Claims{}, ErrInvalid
	}
	if now.Unix() >= raw.ExpiresAt {
		if exposeExpiry {
			return Claims{}, ErrExpired
		}
		return Claims{}, ErrInvalid
	}
	return Claims{Subject: raw.Subject, SessionVersion: raw.SessionVersion}, nil
}

func encodeSegment(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func decodeSegment(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || encodeSegment(decoded) != value {
		return nil, ErrInvalid
	}
	return decoded, nil
}

func decodeSegmentJSON(segment string, dst any) error {
	decoded, err := decodeSegment(segment)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func validSubject(subject string) bool {
	return len(subject) > 0 && len(subject) <= maxSubjectBytes && utf8.ValidString(subject)
}

func validTime(value time.Time) bool {
	return !value.IsZero() && value.Unix() > 0
}

func validPublicKey(key *ecdsa.PublicKey) bool {
	if key == nil || key.Curve != elliptic.P256() {
		return false
	}
	encoded, err := publicKeyBytes(key)
	if err != nil {
		return false
	}
	parsed, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
	return err == nil && parsed.Equal(key)
}

func validPrivateKey(key *ecdsa.PrivateKey) bool {
	if key == nil || !validPublicKey(&key.PublicKey) {
		return false
	}
	encoded, err := privateKeyBytes(key)
	if err != nil {
		return false
	}
	parsed, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), encoded)
	return err == nil && parsed.PublicKey.Equal(&key.PublicKey)
}

func copyPublicKey(key *ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
	encoded, err := publicKeyBytes(key)
	if err != nil {
		return nil, err
	}
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
}

func copyPrivateKey(key *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	encoded, err := privateKeyBytes(key)
	if err != nil {
		return nil, err
	}
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), encoded)
}

func publicKeyBytes(key *ecdsa.PublicKey) (encoded []byte, err error) {
	defer func() {
		if recover() != nil {
			encoded = nil
			err = errors.New("invalid ECDSA public key")
		}
	}()
	return key.Bytes()
}

func privateKeyBytes(key *ecdsa.PrivateKey) (encoded []byte, err error) {
	defer func() {
		if recover() != nil {
			encoded = nil
			err = errors.New("invalid ECDSA private key")
		}
	}()
	return key.Bytes()
}
