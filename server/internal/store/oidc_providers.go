package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/manchtools/power-manage/sdk/ulidx"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	oidcProviderConfigStreamType  = "oidc-provider-config"
	oidcProviderConfigCreatedType = "OIDCProviderConfigCreated"
	oidcProviderConfigUpdatedType = "OIDCProviderConfigUpdated"
	oidcProviderConfigDeletedType = "OIDCProviderConfigDeleted"
	oidcProviderPayloadVersion    = 1
	maxOIDCProviderURLBytes       = 2048
	maxOIDCProviderClientIDBytes  = 512
	maxOIDCProviderRedirects      = 32

	// OIDCProviderConfigRebuildTarget is the CLI recovery target.
	OIDCProviderConfigRebuildTarget = "oidc-provider-configs"
)

var errOIDCProviderConfigExists = errors.New("store: OIDC provider config already exists")

// OIDCProviderMetadata is one public-client OIDC trust configuration.
type OIDCProviderMetadata struct {
	Slug                  string
	Issuer                string
	ClientID              string
	AuthorizationEndpoint string
	TokenURL              string
	JWKSURI               string
	RedirectURIs          []string
	TrustEmailAssertions  bool
	Disabled              bool
	ProjectionVersion     int64
}

type oidcProviderConfigPayload struct {
	ProviderSlug          string   `json:"provider_slug"`
	Issuer                string   `json:"issuer"`
	ClientID              string   `json:"client_id"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenURL              string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	RedirectURIs          []string `json:"redirect_uris"`
	TrustEmailAssertions  bool     `json:"trust_email_assertions"`
	Disabled              bool     `json:"disabled"`
}

type oidcProviderConfigDeletedPayload struct {
	ProviderSlug string `json:"provider_slug"`
}

// OIDCProviderConfigCreatedEvent records a public-client OIDC provider.
func OIDCProviderConfigCreatedEvent(config OIDCProviderMetadata) (Event, error) {
	return newOIDCProviderConfigEvent(config, oidcProviderConfigCreatedType)
}

// OIDCProviderConfigUpdatedEvent fully replaces public provider metadata.
func OIDCProviderConfigUpdatedEvent(config OIDCProviderMetadata) (Event, error) {
	return newOIDCProviderConfigEvent(config, oidcProviderConfigUpdatedType)
}

// OIDCProviderConfigDeletedEvent removes one configured provider.
func OIDCProviderConfigDeletedEvent(slug string) (Event, error) {
	if !validOIDCProviderSlug(slug) {
		return Event{}, errors.New("store: OIDC provider slug is invalid")
	}
	payload, err := json.Marshal(oidcProviderConfigDeletedPayload{ProviderSlug: slug})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode OIDC provider deletion: %w", err)
	}
	return oidcProviderConfigEvent(slug, oidcProviderConfigDeletedType, payload)
}

func newOIDCProviderConfigEvent(config OIDCProviderMetadata, eventType string) (Event, error) {
	config, err := normalizeOIDCProviderConfig(config, 1)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(oidcProviderConfigPayload{
		ProviderSlug:          config.Slug,
		Issuer:                config.Issuer,
		ClientID:              config.ClientID,
		AuthorizationEndpoint: config.AuthorizationEndpoint,
		TokenURL:              config.TokenURL,
		JWKSURI:               config.JWKSURI,
		RedirectURIs:          config.RedirectURIs,
		TrustEmailAssertions:  config.TrustEmailAssertions,
		Disabled:              config.Disabled,
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode OIDC provider config: %w", err)
	}
	return oidcProviderConfigEvent(config.Slug, eventType, payload)
}

// OIDCProviderConfigBySlug reads one provider configuration.
func (s *Store) OIDCProviderConfigBySlug(
	ctx context.Context,
	slug string,
) (OIDCProviderMetadata, error) {
	if s == nil || s.pool == nil || ctx == nil || !validOIDCProviderSlug(slug) {
		return OIDCProviderMetadata{}, errors.New("store: invalid OIDC provider lookup")
	}
	row, err := generated.New(s.pool).GetOIDCProviderConfig(ctx, slug)
	if err != nil {
		return OIDCProviderMetadata{}, fmt.Errorf("store: read OIDC provider config: %w", err)
	}
	return normalizeOIDCProviderConfig(OIDCProviderMetadata{
		Slug: row.ProviderSlug, Issuer: row.Issuer, ClientID: row.ClientID,
		AuthorizationEndpoint: row.AuthorizationEndpoint,
		TokenURL:              row.TokenUrl, JWKSURI: row.JwksUri,
		RedirectURIs:         row.RedirectUris,
		TrustEmailAssertions: row.TrustEmailAssertions, Disabled: row.Disabled,
	}, row.ProjectionVersion)
}

// ListOIDCProviderConfigs returns one deterministic provider page.
func (s *Store) ListOIDCProviderConfigs(
	ctx context.Context,
	limit int32,
) ([]OIDCProviderMetadata, error) {
	if s == nil || s.pool == nil || ctx == nil || limit < 1 || limit > 200 {
		return nil, errors.New("store: invalid OIDC provider list")
	}
	rows, err := generated.New(s.pool).ListOIDCProviderConfigs(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list OIDC provider configs: %w", err)
	}
	configs := make([]OIDCProviderMetadata, len(rows))
	for index, row := range rows {
		configs[index], err = normalizeOIDCProviderConfig(OIDCProviderMetadata{
			Slug: row.ProviderSlug, Issuer: row.Issuer, ClientID: row.ClientID,
			AuthorizationEndpoint: row.AuthorizationEndpoint,
			TokenURL:              row.TokenUrl, JWKSURI: row.JwksUri,
			RedirectURIs:         row.RedirectUris,
			TrustEmailAssertions: row.TrustEmailAssertions, Disabled: row.Disabled,
		}, row.ProjectionVersion)
		if err != nil {
			return nil, err
		}
	}
	return configs, nil
}

// IsOIDCProviderConfigExists recognizes duplicate provider creation.
func IsOIDCProviderConfigExists(err error) bool {
	return errors.Is(err, errOIDCProviderConfigExists)
}

// OIDCProviderConfigEventTypes returns exact provider mutation events.
func OIDCProviderConfigEventTypes() []string {
	return []string{
		oidcProviderConfigCreatedType,
		oidcProviderConfigUpdatedType,
		oidcProviderConfigDeletedType,
	}
}

func oidcProviderConfigEvent(slug, eventType string, payload []byte) (Event, error) {
	streamID, err := oidcProviderConfigStreamID(slug)
	if err != nil {
		return Event{}, err
	}
	return Event{
		StreamType: oidcProviderConfigStreamType, StreamID: streamID,
		EventType: eventType, PayloadVersion: oidcProviderPayloadVersion,
		Payload: payload,
	}, nil
}

func oidcProviderConfigStreamID(slug string) (string, error) {
	digest := sha256.Sum256([]byte(slug))
	streamID, err := ulidx.NewWithReader(time.Unix(0, 0), bytes.NewReader(digest[:10]))
	if err != nil {
		return "", fmt.Errorf("store: derive OIDC provider stream ID: %w", err)
	}
	return streamID, nil
}

func normalizeOIDCProviderConfig(
	config OIDCProviderMetadata,
	version int64,
) (OIDCProviderMetadata, error) {
	if !validOIDCProviderSlug(config.Slug) ||
		!validOIDCProviderText(config.ClientID, maxOIDCProviderClientIDBytes) ||
		!validOIDCIssuerURL(config.Issuer) ||
		!validOIDCEndpointURL(config.AuthorizationEndpoint) ||
		!validOIDCEndpointURL(config.TokenURL) ||
		!validOIDCEndpointURL(config.JWKSURI) ||
		len(config.RedirectURIs) == 0 ||
		len(config.RedirectURIs) > maxOIDCProviderRedirects ||
		version < 1 {
		return OIDCProviderMetadata{}, errors.New("store: OIDC provider config is invalid")
	}
	redirects := slices.Clone(config.RedirectURIs)
	for _, redirect := range redirects {
		if !validOIDCRedirectURL(redirect) {
			return OIDCProviderMetadata{}, errors.New("store: OIDC provider redirect is invalid")
		}
	}
	slices.Sort(redirects)
	if len(slices.Compact(slices.Clone(redirects))) != len(redirects) {
		return OIDCProviderMetadata{}, errors.New("store: OIDC provider redirects contain duplicates")
	}
	config.RedirectURIs = redirects
	config.ProjectionVersion = version
	return config, nil
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

func validOIDCProviderText(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && utf8.ValidString(value) &&
		!strings.ContainsRune(value, '\x00')
}

func validOIDCIssuerURL(raw string) bool {
	parsed, ok := parseOIDCURL(raw)
	return ok && parsed.RawQuery == ""
}

func validOIDCEndpointURL(raw string) bool {
	_, ok := parseOIDCURL(raw)
	return ok
}

func parseOIDCURL(raw string) (*url.URL, bool) {
	if !validOIDCProviderText(raw, maxOIDCProviderURLBytes) {
		return nil, false
	}
	parsed, err := url.Parse(raw)
	return parsed, err == nil && parsed.Scheme == "https" && parsed.Host != "" &&
		parsed.User == nil && parsed.Fragment == ""
}

func validOIDCRedirectURL(raw string) bool {
	if !validOIDCProviderText(raw, maxOIDCProviderURLBytes) {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func oidcProviderConfigEventDefinitions() map[string]eventDefinition {
	golden := OIDCProviderMetadata{
		Slug: "corporate", Issuer: "https://issuer.example",
		ClientID:              "power-manage",
		AuthorizationEndpoint: "https://issuer.example/authorize",
		TokenURL:              "https://issuer.example/token",
		JWKSURI:               "https://issuer.example/jwks",
		RedirectURIs:          []string{"https://control.example/callback"},
		TrustEmailAssertions:  true,
	}
	return map[string]eventDefinition{
		oidcProviderConfigCreatedType: {
			PayloadVersion: oidcProviderPayloadVersion,
			PayloadType:    oidcProviderConfigPayload{},
			GoldenPayload: func() ([]byte, error) {
				created := golden
				created.RedirectURIs = slices.Clone(golden.RedirectURIs)
				event, err := OIDCProviderConfigCreatedEvent(created)
				return event.Payload, err
			},
			Projector: projectOIDCProviderConfigCreate,
		},
		oidcProviderConfigUpdatedType: {
			PayloadVersion: oidcProviderPayloadVersion,
			PayloadType:    oidcProviderConfigPayload{},
			GoldenPayload: func() ([]byte, error) {
				updated := golden
				updated.RedirectURIs = slices.Clone(golden.RedirectURIs)
				updated.Disabled = true
				event, err := OIDCProviderConfigUpdatedEvent(updated)
				return event.Payload, err
			},
			Projector: projectOIDCProviderConfigUpdate,
		},
		oidcProviderConfigDeletedType: {
			PayloadVersion: oidcProviderPayloadVersion,
			PayloadType:    oidcProviderConfigDeletedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(oidcProviderConfigDeletedPayload{ProviderSlug: golden.Slug})
			},
			Projector: projectOIDCProviderConfigDelete,
		},
	}
}

func oidcProviderConfigGoldenCorpus() map[string]goldenEvent {
	return map[string]goldenEvent{
		oidcProviderConfigCreatedType: {
			PayloadVersion: 1,
			Payload:        []byte(`{"provider_slug":"corporate","issuer":"https://issuer.example","client_id":"power-manage","authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/jwks","redirect_uris":["https://control.example/callback"],"trust_email_assertions":true,"disabled":false}`),
		},
		oidcProviderConfigUpdatedType: {
			PayloadVersion: 1,
			Payload:        []byte(`{"provider_slug":"corporate","issuer":"https://issuer.example","client_id":"power-manage","authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/jwks","redirect_uris":["https://control.example/callback"],"trust_email_assertions":true,"disabled":true}`),
		},
		oidcProviderConfigDeletedType: {
			PayloadVersion: 1,
			Payload:        []byte(`{"provider_slug":"corporate"}`),
		},
	}
}

func projectOIDCProviderConfigCreate(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion != 1 {
		return errOIDCProviderConfigExists
	}
	config, err := oidcProviderConfigFromEvent(event)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).InsertOIDCProviderConfig(
		ctx,
		generated.InsertOIDCProviderConfigParams{
			ProviderSlug: config.Slug, Issuer: config.Issuer, ClientID: config.ClientID,
			AuthorizationEndpoint: config.AuthorizationEndpoint,
			TokenUrl:              config.TokenURL, JwksUri: config.JWKSURI,
			RedirectUris:         config.RedirectURIs,
			TrustEmailAssertions: config.TrustEmailAssertions,
			Disabled:             config.Disabled, ProjectionVersion: event.StreamVersion,
			UpdatedAt: event.CreatedAt,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project OIDC provider creation: %w", err)
	}
	if affected != 1 {
		return errOIDCProviderConfigExists
	}
	return nil
}

func projectOIDCProviderConfigUpdate(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: OIDC provider update requires creation")
	}
	config, err := oidcProviderConfigFromEvent(event)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).ReplaceOIDCProviderConfig(
		ctx,
		generated.ReplaceOIDCProviderConfigParams{
			Issuer: config.Issuer, ClientID: config.ClientID,
			AuthorizationEndpoint: config.AuthorizationEndpoint,
			TokenUrl:              config.TokenURL, JwksUri: config.JWKSURI,
			RedirectUris:         config.RedirectURIs,
			TrustEmailAssertions: config.TrustEmailAssertions,
			Disabled:             config.Disabled, ProjectionVersion: event.StreamVersion,
			UpdatedAt: event.CreatedAt, ProviderSlug: config.Slug,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project OIDC provider update: %w", err)
	}
	if affected != 1 {
		return errors.New("store: OIDC provider update conflicts with projection")
	}
	return nil
}

func projectOIDCProviderConfigDelete(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: OIDC provider deletion requires creation")
	}
	payload, err := decodeEventPayload[oidcProviderConfigDeletedPayload](
		event,
		oidcProviderPayloadVersion,
	)
	if err != nil {
		return err
	}
	streamID, err := oidcProviderConfigStreamID(payload.ProviderSlug)
	if err != nil || streamID != event.StreamID {
		return errors.New("store: OIDC provider deletion slug is invalid")
	}
	affected, err := generated.New(tx).DeleteOIDCProviderConfig(
		ctx,
		generated.DeleteOIDCProviderConfigParams{
			ProviderSlug:              payload.ProviderSlug,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project OIDC provider deletion: %w", err)
	}
	if affected != 1 {
		return errors.New("store: OIDC provider deletion conflicts with projection")
	}
	return nil
}

func oidcProviderConfigFromEvent(event PersistedEvent) (OIDCProviderMetadata, error) {
	payload, err := decodeEventPayload[oidcProviderConfigPayload](
		event,
		oidcProviderPayloadVersion,
	)
	if err != nil {
		return OIDCProviderMetadata{}, err
	}
	streamID, err := oidcProviderConfigStreamID(payload.ProviderSlug)
	if err != nil || streamID != event.StreamID {
		return OIDCProviderMetadata{}, errors.New("store: OIDC provider event stream is invalid")
	}
	return normalizeOIDCProviderConfig(OIDCProviderMetadata{
		Slug: payload.ProviderSlug, Issuer: payload.Issuer, ClientID: payload.ClientID,
		AuthorizationEndpoint: payload.AuthorizationEndpoint,
		TokenURL:              payload.TokenURL, JWKSURI: payload.JWKSURI,
		RedirectURIs:         payload.RedirectURIs,
		TrustEmailAssertions: payload.TrustEmailAssertions,
		Disabled:             payload.Disabled,
	}, event.StreamVersion)
}

func resetOIDCProviderConfigs(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetOIDCProviderConfigs(ctx); err != nil {
		return fmt.Errorf("store: reset OIDC provider configs: %w", err)
	}
	return nil
}
