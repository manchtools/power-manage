package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/manchtools/power-manage/sdk/ulidx"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	oidcStateLifetime        = 10 * time.Minute
	oidcHTTPTimeout          = 12 * time.Second
	oidcFutureIssuedAtSkew   = 5 * time.Minute
	oidcSecretBytes          = 32
	maxOIDCCodeBytes         = 4096
	maxOIDCURLBytes          = 8192
	maxOIDCClientIDBytes     = 1024
	maxOIDCClientSecretBytes = 4096
	maxOIDCIDTokenBytes      = 16 << 10
	maxOIDCTokenBodyBytes    = 64 << 10
	maxOIDCJWKSBodyBytes     = 1 << 20
	maxOIDCSubjectBytes      = 1024
	maxOIDCEmailBytes        = 320
	maxOIDCJWKSKeys          = 128
)

var (
	// ErrOIDCRejected is the static failure for invalid OIDC input or claims.
	ErrOIDCRejected = errors.New("oidc sign-in rejected")
	// ErrOIDCUnavailable identifies an OIDC operation that could not reach a
	// durable conclusion.
	ErrOIDCUnavailable = errors.New("oidc sign-in unavailable")
	errOIDCRedirect    = errors.New("auth: oidc redirect refused")
)

// OIDCProvider is one immutable, operator-configured identity provider.
type OIDCProvider struct {
	Slug                  string
	Issuer                string
	ClientID              string
	ClientSecret          string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	RedirectURIs          []string
	TrustEmailAssertions  bool
}

type oidcProvider struct {
	OIDCProvider
	redirects map[string]struct{}
}

// OIDCService owns the authorization-code boundary and durable identity link.
type OIDCService struct {
	eventStore *store.Store
	refresh    *RefreshService
	providers  map[string]oidcProvider
	client     *http.Client
	random     io.Reader
	randomMu   sync.Mutex
	now        func() time.Time
}

// NewOIDCService validates and defensively copies all OIDC dependencies.
func NewOIDCService(
	eventStore *store.Store,
	refresh *RefreshService,
	providers []OIDCProvider,
	client *http.Client,
	random io.Reader,
	now func() time.Time,
) (*OIDCService, error) {
	switch {
	case eventStore == nil:
		return nil, errors.New("auth: oidc event store is not wired")
	case refresh == nil || refresh.ValidateWiring() != nil:
		return nil, errors.New("auth: oidc refresh service is not wired")
	case len(providers) == 0:
		return nil, errors.New("auth: oidc provider registry is empty")
	case client == nil:
		return nil, errors.New("auth: oidc HTTP client is not wired")
	case random == nil:
		return nil, errors.New("auth: oidc entropy source is not wired")
	case now == nil:
		return nil, errors.New("auth: oidc clock is not wired")
	}

	registry := make(map[string]oidcProvider, len(providers))
	for _, provider := range providers {
		validated, err := validateOIDCProvider(provider)
		if err != nil {
			return nil, err
		}
		if _, duplicate := registry[validated.Slug]; duplicate {
			return nil, fmt.Errorf("auth: oidc provider slug %q is duplicated", validated.Slug)
		}
		registry[validated.Slug] = validated
	}
	clientCopy := *client
	clientCopy.Timeout = oidcHTTPTimeout
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errOIDCRedirect
	}
	return &OIDCService{
		eventStore: eventStore,
		refresh:    refresh,
		providers:  registry,
		client:     &clientCopy,
		random:     random,
		now:        now,
	}, nil
}

// ValidateWiring rejects nil and partially initialized OIDC services.
func (s *OIDCService) ValidateWiring() error {
	if !s.wired() {
		return ErrOIDCUnavailable
	}
	return nil
}

// Start creates a one-shot server-held binding and returns the provider URL.
func (s *OIDCService) Start(
	ctx context.Context,
	providerSlug string,
	redirectURI string,
) (string, error) {
	if !s.wired() || ctx == nil {
		return "", ErrOIDCUnavailable
	}
	provider, ok := s.providers[providerSlug]
	if !ok {
		return "", ErrOIDCRejected
	}
	if _, ok := provider.redirects[redirectURI]; !ok {
		return "", ErrOIDCRejected
	}
	now := s.now()
	if !validTime(now) {
		return "", ErrOIDCUnavailable
	}
	if err := s.eventStore.DeleteExpiredOIDCLoginStates(ctx, now); err != nil {
		return "", fmt.Errorf("%w: clean login state", ErrOIDCUnavailable)
	}
	state, nonce, verifier, err := s.newAuthorizationSecrets()
	if err != nil {
		return "", fmt.Errorf("%w: generate authorization binding", ErrOIDCUnavailable)
	}
	stateHash := sha256.Sum256([]byte(state))
	if err := s.eventStore.StoreOIDCLoginState(ctx, stateHash, store.OIDCLoginState{
		ProviderSlug: provider.Slug,
		RedirectURI:  redirectURI,
		Nonce:        nonce,
		CodeVerifier: verifier,
		ExpiresAt:    now.Add(oidcStateLifetime),
	}); err != nil {
		return "", fmt.Errorf("%w: persist authorization binding", ErrOIDCUnavailable)
	}

	authorizationURL, err := url.Parse(provider.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("%w: invalid configured authorization endpoint", ErrOIDCUnavailable)
	}
	challenge := sha256.Sum256([]byte(verifier))
	query, err := url.ParseQuery(authorizationURL.RawQuery)
	if err != nil {
		return "", fmt.Errorf("%w: invalid configured authorization query", ErrOIDCUnavailable)
	}
	query.Set("response_type", "code")
	query.Set("client_id", provider.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", "openid email")
	query.Set("state", state)
	query.Set("nonce", nonce)
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	query.Set("code_challenge_method", "S256")
	authorizationURL.RawQuery = query.Encode()
	result := authorizationURL.String()
	if len(result) == 0 || len(result) > maxOIDCURLBytes {
		return "", fmt.Errorf("%w: authorization URL exceeds bound", ErrOIDCUnavailable)
	}
	return result, nil
}

// Complete atomically consumes state, verifies the configured provider's ID
// token, links the durable identity, and starts an ordinary rotating session.
func (s *OIDCService) Complete(
	ctx context.Context,
	rawState string,
	code string,
) (SessionTokens, error) {
	if !s.wired() || ctx == nil {
		return SessionTokens{}, ErrOIDCUnavailable
	}
	if !validOIDCSecret(rawState) || !validOIDCText(code, maxOIDCCodeBytes) {
		return SessionTokens{}, ErrOIDCRejected
	}
	now := s.now()
	if !validTime(now) {
		return SessionTokens{}, ErrOIDCUnavailable
	}
	stateHash := sha256.Sum256([]byte(rawState))
	state, err := s.eventStore.ConsumeOIDCLoginState(ctx, stateHash, now)
	if err != nil {
		if store.IsNotFound(err) || errors.Is(err, store.ErrOIDCLoginStateExpired) {
			return SessionTokens{}, ErrOIDCRejected
		}
		return SessionTokens{}, fmt.Errorf("%w: consume authorization binding", ErrOIDCUnavailable)
	}
	provider, ok := s.providers[state.ProviderSlug]
	if !ok {
		return SessionTokens{}, ErrOIDCRejected
	}

	outboundContext, cancel := context.WithTimeout(ctx, oidcHTTPTimeout)
	defer cancel()
	idToken, err := s.exchangeCode(outboundContext, provider, state, code)
	if err != nil {
		return SessionTokens{}, err
	}
	keys, err := s.fetchJWKS(outboundContext, provider)
	if err != nil {
		return SessionTokens{}, err
	}
	claims, err := verifyOIDCIDToken(idToken, provider, keys, state.Nonce, now)
	if err != nil {
		return SessionTokens{}, ErrOIDCRejected
	}
	user, err := s.resolveUser(ctx, provider, claims, now)
	if err != nil {
		return SessionTokens{}, err
	}
	tokens, err := s.refresh.StartSession(ctx, user.UserID)
	if err != nil {
		return SessionTokens{}, fmt.Errorf("%w: start durable session", ErrOIDCUnavailable)
	}
	return tokens, nil
}

func (s *OIDCService) exchangeCode(
	ctx context.Context,
	provider oidcProvider,
	state store.OIDCLoginState,
	code string,
) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {state.RedirectURI},
		"client_id":     {provider.ClientID},
		"code_verifier": {state.CodeVerifier},
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		provider.TokenEndpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("%w: create token request", ErrOIDCUnavailable)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if provider.ClientSecret != "" {
		request.SetBasicAuth(provider.ClientID, provider.ClientSecret)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("%w: exchange authorization code", ErrOIDCUnavailable)
	}
	var payload struct {
		IDToken string `json:"id_token"`
	}
	decodeErr := decodeBoundedResponse(response, maxOIDCTokenBodyBytes, &payload)
	switch {
	case response.StatusCode == http.StatusRequestTimeout,
		response.StatusCode == http.StatusTooManyRequests,
		response.StatusCode >= http.StatusInternalServerError:
		return "", fmt.Errorf("%w: token endpoint status %d", ErrOIDCUnavailable, response.StatusCode)
	case response.StatusCode != http.StatusOK:
		return "", ErrOIDCRejected
	case decodeErr != nil:
		return "", fmt.Errorf("%w: decode token response", ErrOIDCUnavailable)
	}
	if len(payload.IDToken) == 0 ||
		len(payload.IDToken) > maxOIDCIDTokenBytes {
		return "", ErrOIDCRejected
	}
	return payload.IDToken, nil
}

func (s *OIDCService) fetchJWKS(
	ctx context.Context,
	provider oidcProvider,
) ([]json.RawMessage, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.JWKSURI, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: create JWKS request", ErrOIDCUnavailable)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch JWKS", ErrOIDCUnavailable)
	}
	var payload struct {
		Keys []json.RawMessage `json:"keys"`
	}
	decodeErr := decodeBoundedResponse(response, maxOIDCJWKSBodyBytes, &payload)
	switch {
	case response.StatusCode == http.StatusRequestTimeout,
		response.StatusCode == http.StatusTooManyRequests,
		response.StatusCode >= http.StatusInternalServerError:
		return nil, fmt.Errorf(
			"%w: JWKS endpoint status %d",
			ErrOIDCUnavailable,
			response.StatusCode,
		)
	case response.StatusCode != http.StatusOK:
		return nil, ErrOIDCRejected
	case decodeErr != nil:
		return nil, fmt.Errorf("%w: decode JWKS", ErrOIDCUnavailable)
	}
	if len(payload.Keys) == 0 ||
		len(payload.Keys) > maxOIDCJWKSKeys {
		return nil, ErrOIDCRejected
	}
	return payload.Keys, nil
}

func (s *OIDCService) resolveUser(
	ctx context.Context,
	provider oidcProvider,
	claims oidcIDClaims,
	now time.Time,
) (store.User, error) {
	user, err := s.eventStore.UserByOIDCIdentity(ctx, claims.Issuer, claims.Subject)
	if err == nil {
		return user, nil
	}
	if !store.IsNotFound(err) {
		return store.User{}, fmt.Errorf("%w: resolve oidc identity", ErrOIDCUnavailable)
	}
	if !claims.EmailVerified {
		return store.User{}, ErrOIDCRejected
	}
	email, err := store.CanonicalUserEmail(claims.Email)
	if err != nil {
		return store.User{}, ErrOIDCRejected
	}

	user, err = s.eventStore.UserByEmail(ctx, email)
	switch {
	case err == nil:
		count, countErr := s.eventStore.UserOIDCIdentityCount(ctx, user.UserID)
		if countErr != nil {
			return store.User{}, fmt.Errorf("%w: count linked identities", ErrOIDCUnavailable)
		}
		if count > 0 && !provider.TrustEmailAssertions {
			return store.User{}, ErrOIDCRejected
		}
		link, linkErr := store.OIDCIdentityLinkedEvent(
			user.UserID,
			provider.Slug,
			claims.Issuer,
			claims.Subject,
			email,
		)
		if linkErr != nil {
			return store.User{}, ErrOIDCRejected
		}
		linkErr = s.eventStore.AppendEventWithVersion(ctx, link, user.ProjectionVersion)
		if linkErr == nil {
			user.ProjectionVersion++
			return user, nil
		}
		if store.IsVersionConflict(linkErr) {
			concurrent, readErr := s.eventStore.UserByOIDCIdentity(
				ctx,
				claims.Issuer,
				claims.Subject,
			)
			if readErr == nil && concurrent.UserID == user.UserID {
				return concurrent, nil
			}
			if readErr != nil && !store.IsNotFound(readErr) {
				return store.User{}, fmt.Errorf("%w: resolve concurrent identity link", ErrOIDCUnavailable)
			}
			return store.User{}, ErrOIDCRejected
		}
		return store.User{}, fmt.Errorf("%w: persist identity link", ErrOIDCUnavailable)
	case !store.IsNotFound(err):
		return store.User{}, fmt.Errorf("%w: resolve oidc email", ErrOIDCUnavailable)
	}

	userID, err := s.newUserID(now)
	if err != nil {
		return store.User{}, fmt.Errorf("%w: generate user ID", ErrOIDCUnavailable)
	}
	created, err := store.UserCreatedEvent(userID, email)
	if err != nil {
		return store.User{}, ErrOIDCRejected
	}
	linked, err := store.OIDCIdentityLinkedEvent(
		userID,
		provider.Slug,
		claims.Issuer,
		claims.Subject,
		email,
	)
	if err != nil {
		return store.User{}, ErrOIDCRejected
	}
	if err := s.eventStore.AppendEvents(ctx, []store.Event{created, linked}); err != nil {
		concurrent, readErr := s.eventStore.UserByOIDCIdentity(
			ctx,
			claims.Issuer,
			claims.Subject,
		)
		if readErr == nil {
			return concurrent, nil
		}
		return store.User{}, fmt.Errorf("%w: persist oidc user", ErrOIDCUnavailable)
	}
	return store.User{
		UserID:            userID,
		Email:             email,
		SessionVersion:    1,
		ProjectionVersion: 2,
	}, nil
}

func (s *OIDCService) newAuthorizationSecrets() (string, string, string, error) {
	random := make([]byte, oidcSecretBytes*3)
	s.randomMu.Lock()
	defer s.randomMu.Unlock()
	if _, err := io.ReadFull(s.random, random); err != nil {
		return "", "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(random[:oidcSecretBytes]),
		base64.RawURLEncoding.EncodeToString(random[oidcSecretBytes : 2*oidcSecretBytes]),
		base64.RawURLEncoding.EncodeToString(random[2*oidcSecretBytes:]),
		nil
}

func (s *OIDCService) newUserID(now time.Time) (string, error) {
	s.randomMu.Lock()
	defer s.randomMu.Unlock()
	return ulidx.NewWithReader(now, s.random)
}

func (s *OIDCService) wired() bool {
	return s != nil &&
		s.eventStore != nil &&
		s.refresh != nil &&
		s.refresh.ValidateWiring() == nil &&
		len(s.providers) > 0 &&
		s.client != nil &&
		s.client.Timeout == oidcHTTPTimeout &&
		s.client.CheckRedirect != nil &&
		s.random != nil &&
		s.now != nil
}

func validateOIDCProvider(provider OIDCProvider) (oidcProvider, error) {
	if !validOIDCProviderSlug(provider.Slug) {
		return oidcProvider{}, errors.New("auth: oidc provider slug is invalid")
	}
	if !validOIDCText(provider.ClientID, maxOIDCClientIDBytes) {
		return oidcProvider{}, fmt.Errorf("auth: oidc provider %q client ID is invalid", provider.Slug)
	}
	if provider.ClientSecret != "" &&
		!validOIDCText(provider.ClientSecret, maxOIDCClientSecretBytes) {
		return oidcProvider{}, fmt.Errorf("auth: oidc provider %q client secret is invalid", provider.Slug)
	}
	if !validOIDCIssuer(provider.Issuer) {
		return oidcProvider{}, fmt.Errorf("auth: oidc provider %q issuer is invalid", provider.Slug)
	}
	for name, raw := range map[string]string{
		"authorization endpoint": provider.AuthorizationEndpoint,
		"token endpoint":         provider.TokenEndpoint,
		"JWKS URI":               provider.JWKSURI,
	} {
		if !validOIDCHTTPEndpoint(raw) {
			return oidcProvider{}, fmt.Errorf("auth: oidc provider %q %s is invalid", provider.Slug, name)
		}
	}
	if len(provider.RedirectURIs) == 0 {
		return oidcProvider{}, fmt.Errorf("auth: oidc provider %q redirect allowlist is empty", provider.Slug)
	}
	redirects := make(map[string]struct{}, len(provider.RedirectURIs))
	for _, redirectURI := range provider.RedirectURIs {
		if !validOIDCRedirectURI(redirectURI) {
			return oidcProvider{}, fmt.Errorf("auth: oidc provider %q redirect URI is invalid", provider.Slug)
		}
		if _, duplicate := redirects[redirectURI]; duplicate {
			return oidcProvider{}, fmt.Errorf("auth: oidc provider %q repeats a redirect URI", provider.Slug)
		}
		redirects[redirectURI] = struct{}{}
	}
	provider.RedirectURIs = slices.Clone(provider.RedirectURIs)
	return oidcProvider{OIDCProvider: provider, redirects: redirects}, nil
}

func validOIDCProviderSlug(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range []byte(value[1:]) {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '-' {
			continue
		}
		return false
	}
	return true
}

func validOIDCIssuer(raw string) bool {
	if !validOIDCText(raw, maxOIDCURLBytes) {
		return false
	}
	parsed, err := url.Parse(raw)
	return err == nil &&
		parsed.Scheme == "https" &&
		parsed.Host != "" &&
		parsed.User == nil &&
		parsed.RawQuery == "" &&
		parsed.Fragment == ""
}

func validOIDCHTTPEndpoint(raw string) bool {
	if !validOIDCText(raw, maxOIDCURLBytes) {
		return false
	}
	parsed, err := url.Parse(raw)
	return err == nil &&
		parsed.Scheme == "https" &&
		parsed.Host != "" &&
		parsed.User == nil &&
		parsed.Fragment == ""
}

func validOIDCRedirectURI(raw string) bool {
	if !validOIDCText(raw, maxOIDCURLBytes) {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	switch parsed.Scheme {
	case "https":
		return true
	case "http":
		host := parsed.Hostname()
		if strings.EqualFold(host, "localhost") {
			return true
		}
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	default:
		return false
	}
}

func validOIDCText(value string, maximum int) bool {
	return len(value) > 0 &&
		len(value) <= maximum &&
		utf8.ValidString(value) &&
		!strings.ContainsRune(value, '\x00')
}

func validOIDCSecret(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil &&
		len(decoded) == oidcSecretBytes &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

type oidcTokenHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type oidcIDClaims struct {
	Issuer        string       `json:"iss"`
	Subject       string       `json:"sub"`
	Audience      oidcAudience `json:"aud"`
	Authorized    string       `json:"azp"`
	ExpiresAt     int64        `json:"exp"`
	IssuedAt      int64        `json:"iat"`
	Nonce         string       `json:"nonce"`
	Email         string       `json:"email"`
	EmailVerified bool         `json:"email_verified"`
}

type oidcAudience []string

func (audience *oidcAudience) UnmarshalJSON(data []byte) error {
	if audience == nil {
		return errors.New("auth: nil oidc audience")
	}
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*audience = oidcAudience{single}
		return nil
	}
	var multiple []string
	if err := json.Unmarshal(data, &multiple); err != nil {
		return errors.New("auth: oidc audience is invalid")
	}
	*audience = oidcAudience(multiple)
	return nil
}

func verifyOIDCIDToken(
	token string,
	provider oidcProvider,
	keys []json.RawMessage,
	nonce string,
	now time.Time,
) (oidcIDClaims, error) {
	if len(token) == 0 || len(token) > maxOIDCIDTokenBytes || !validTime(now) {
		return oidcIDClaims{}, ErrOIDCRejected
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return oidcIDClaims{}, ErrOIDCRejected
	}
	var header oidcTokenHeader
	if err := decodeOIDCSegmentJSON(parts[0], &header); err != nil ||
		(header.Algorithm != "RS256" && header.Algorithm != "ES256") ||
		header.KeyID == "" ||
		(header.Type != "" && header.Type != "JWT") {
		return oidcIDClaims{}, ErrOIDCRejected
	}
	key, err := oidcVerificationKey(keys, header)
	if err != nil {
		return oidcIDClaims{}, ErrOIDCRejected
	}
	signature, err := decodeOIDCSegment(parts[2])
	if err != nil {
		return oidcIDClaims{}, ErrOIDCRejected
	}
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	if !verifyOIDCSignature(header.Algorithm, key, digest, signature) {
		return oidcIDClaims{}, ErrOIDCRejected
	}

	var claims oidcIDClaims
	if err := decodeOIDCSegmentJSON(parts[1], &claims); err != nil ||
		claims.Issuer != provider.Issuer ||
		!validOIDCText(claims.Subject, maxOIDCSubjectBytes) ||
		!validOIDCText(claims.Email, maxOIDCEmailBytes) ||
		claims.Nonce != nonce ||
		claims.IssuedAt <= 0 ||
		claims.ExpiresAt <= claims.IssuedAt ||
		now.Unix() >= claims.ExpiresAt ||
		claims.IssuedAt > now.Add(oidcFutureIssuedAtSkew).Unix() ||
		!validOIDCAudience(claims.Audience, claims.Authorized, provider.ClientID) {
		return oidcIDClaims{}, ErrOIDCRejected
	}
	return claims, nil
}

func validOIDCAudience(audience []string, authorizedParty, clientID string) bool {
	if len(audience) == 0 || len(audience) > 16 {
		return false
	}
	found := false
	seen := make(map[string]struct{}, len(audience))
	for _, entry := range audience {
		if !validOIDCText(entry, maxOIDCClientIDBytes) {
			return false
		}
		if _, duplicate := seen[entry]; duplicate {
			return false
		}
		seen[entry] = struct{}{}
		if entry == clientID {
			found = true
		}
	}
	if !found {
		return false
	}
	if len(audience) > 1 {
		return authorizedParty == clientID
	}
	return authorizedParty == "" || authorizedParty == clientID
}

func oidcVerificationKey(keys []json.RawMessage, header oidcTokenHeader) (crypto.PublicKey, error) {
	var selected crypto.PublicKey
	for _, raw := range keys {
		var metadata struct {
			KeyType   string `json:"kty"`
			KeyID     string `json:"kid"`
			Use       string `json:"use"`
			Algorithm string `json:"alg"`
		}
		if err := json.Unmarshal(raw, &metadata); err != nil || metadata.KeyID != header.KeyID {
			continue
		}
		if selected != nil ||
			(metadata.Use != "" && metadata.Use != "sig") ||
			(metadata.Algorithm != "" && metadata.Algorithm != header.Algorithm) {
			return nil, ErrOIDCRejected
		}
		var err error
		switch header.Algorithm {
		case "RS256":
			if metadata.KeyType != "RSA" {
				return nil, ErrOIDCRejected
			}
			selected, err = decodeOIDCRSAKey(raw)
		case "ES256":
			if metadata.KeyType != "EC" {
				return nil, ErrOIDCRejected
			}
			selected, err = decodeOIDCECKey(raw)
		default:
			return nil, ErrOIDCRejected
		}
		if err != nil {
			return nil, err
		}
	}
	if selected == nil {
		return nil, ErrOIDCRejected
	}
	return selected, nil
}

func decodeOIDCRSAKey(raw []byte) (*rsa.PublicKey, error) {
	var key struct {
		Modulus  string `json:"n"`
		Exponent string `json:"e"`
	}
	if err := json.Unmarshal(raw, &key); err != nil {
		return nil, ErrOIDCRejected
	}
	modulus, err := decodeOIDCSegment(key.Modulus)
	if err != nil {
		return nil, ErrOIDCRejected
	}
	exponent, err := decodeOIDCSegment(key.Exponent)
	if err != nil || len(exponent) == 0 || len(exponent) > 4 {
		return nil, ErrOIDCRejected
	}
	n := new(big.Int).SetBytes(modulus)
	e := new(big.Int).SetBytes(exponent)
	if n.Sign() <= 0 || n.BitLen() < 2048 || !e.IsInt64() {
		return nil, ErrOIDCRejected
	}
	exponentValue := e.Int64()
	if exponentValue < 3 || exponentValue > int64(^uint(0)>>1) || exponentValue%2 == 0 {
		return nil, ErrOIDCRejected
	}
	return &rsa.PublicKey{N: n, E: int(exponentValue)}, nil
}

func decodeOIDCECKey(raw []byte) (*ecdsa.PublicKey, error) {
	var key struct {
		Curve string `json:"crv"`
		X     string `json:"x"`
		Y     string `json:"y"`
	}
	if err := json.Unmarshal(raw, &key); err != nil || key.Curve != "P-256" {
		return nil, ErrOIDCRejected
	}
	xBytes, err := decodeOIDCSegment(key.X)
	if err != nil || len(xBytes) != 32 {
		return nil, ErrOIDCRejected
	}
	yBytes, err := decodeOIDCSegment(key.Y)
	if err != nil || len(yBytes) != 32 {
		return nil, ErrOIDCRejected
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	encoded := make([]byte, 65)
	encoded[0] = 4
	copy(encoded[1:33], xBytes)
	copy(encoded[33:], yBytes)
	if _, err := ecdh.P256().NewPublicKey(encoded); err != nil {
		return nil, ErrOIDCRejected
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func verifyOIDCSignature(
	algorithm string,
	key crypto.PublicKey,
	digest [sha256.Size]byte,
	signature []byte,
) bool {
	switch algorithm {
	case "RS256":
		rsaKey, ok := key.(*rsa.PublicKey)
		return ok && rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], signature) == nil
	case "ES256":
		ecdsaKey, ok := key.(*ecdsa.PublicKey)
		if !ok || len(signature) != 64 {
			return false
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		return r.Sign() > 0 && s.Sign() > 0 && ecdsa.Verify(ecdsaKey, digest[:], r, s)
	default:
		return false
	}
}

func decodeOIDCSegment(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrOIDCRejected
	}
	return decoded, nil
}

func decodeOIDCSegmentJSON(segment string, destination any) error {
	decoded, err := decodeOIDCSegment(segment)
	if err != nil {
		return err
	}
	return decodeSingleJSON(decoded, destination)
}

func decodeBoundedResponse(response *http.Response, maximum int64, destination any) error {
	if response == nil || response.Body == nil {
		return errors.New("auth: oidc response body is not wired")
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if int64(len(body)) > maximum {
		return errors.New("auth: oidc response exceeds bound")
	}
	return decodeSingleJSON(body, destination)
}

func decodeSingleJSON(data []byte, destination any) error {
	if destination == nil {
		return errors.New("auth: nil oidc JSON destination")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("auth: oidc JSON has trailing data")
	}
	return nil
}
