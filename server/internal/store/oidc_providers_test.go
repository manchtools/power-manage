package store

import (
	"testing"
)

func TestManagedOIDCProviderConfig_CRUDAndRebuild(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	config := OIDCProviderMetadata{
		Slug:                  "corporate",
		Issuer:                "https://issuer.example",
		ClientID:              "power-manage",
		AuthorizationEndpoint: "https://issuer.example/authorize?audience=control",
		TokenURL:              "https://issuer.example/token",
		JWKSURI:               "https://issuer.example/jwks?tenant=corporate",
		RedirectURIs: []string{
			"https://control.example/callback",
			"http://127.0.0.1:8080/callback",
		},
		TrustEmailAssertions: true,
	}
	created, err := OIDCProviderConfigCreatedEvent(config)
	if err != nil {
		t.Fatalf("create OIDC provider event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), created, 0); err != nil {
		t.Fatalf("append OIDC provider creation: %v", err)
	}

	got, err := eventStore.OIDCProviderConfigBySlug(t.Context(), config.Slug)
	if err != nil || got.ProjectionVersion != 1 ||
		got.AuthorizationEndpoint != config.AuthorizationEndpoint ||
		!got.TrustEmailAssertions {
		t.Fatalf("created OIDC provider = (%#v, %v); want version-one config", got, err)
	}
	listed, err := eventStore.ListOIDCProviderConfigs(t.Context(), 100)
	if err != nil || len(listed) != 1 || listed[0].Slug != config.Slug {
		t.Fatalf("OIDC provider list = (%#v, %v); want corporate provider", listed, err)
	}

	config.Disabled = true
	config.TrustEmailAssertions = false
	updated, err := OIDCProviderConfigUpdatedEvent(config)
	if err != nil {
		t.Fatalf("create OIDC provider update: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), updated, 1); err != nil {
		t.Fatalf("append OIDC provider update: %v", err)
	}
	if _, err := pool.Exec(
		t.Context(),
		`UPDATE oidc_providers
		 SET client_id = 'corrupt', disabled = false
		 WHERE provider_slug = $1`,
		config.Slug,
	); err != nil {
		t.Fatalf("corrupt OIDC provider projection: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), OIDCProviderConfigRebuildTarget); err != nil {
		t.Fatalf("rebuild OIDC provider projection: %v", err)
	}
	got, err = eventStore.OIDCProviderConfigBySlug(t.Context(), config.Slug)
	if err != nil || got.ClientID != config.ClientID || !got.Disabled ||
		got.TrustEmailAssertions || got.ProjectionVersion != 2 {
		t.Fatalf("rebuilt OIDC provider = (%#v, %v); want version-two config", got, err)
	}

	deleted, err := OIDCProviderConfigDeletedEvent(config.Slug)
	if err != nil {
		t.Fatalf("create OIDC provider deletion: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), deleted, 2); err != nil {
		t.Fatalf("append OIDC provider deletion: %v", err)
	}
	if _, err := eventStore.OIDCProviderConfigBySlug(
		t.Context(),
		config.Slug,
	); !IsNotFound(err) {
		t.Fatalf("deleted OIDC provider error = %v; want not found", err)
	}
	if err := eventStore.RebuildAll(t.Context(), OIDCProviderConfigRebuildTarget); err != nil {
		t.Fatalf("rebuild deleted OIDC provider: %v", err)
	}
	if _, err := eventStore.OIDCProviderConfigBySlug(
		t.Context(),
		config.Slug,
	); !IsNotFound(err) {
		t.Fatalf("rebuilt deleted OIDC provider error = %v; want not found", err)
	}
}

func TestOIDCProviderConfigEvent_RejectsCredentialsAndDuplicateRedirects(t *testing.T) {
	config := OIDCProviderMetadata{
		Slug:                  "corporate",
		Issuer:                "https://issuer.example",
		ClientID:              "power-manage",
		AuthorizationEndpoint: "https://issuer.example/authorize",
		TokenURL:              "https://issuer.example/token",
		JWKSURI:               "https://issuer.example/jwks",
		RedirectURIs:          []string{"https://control.example/callback"},
	}
	tests := []struct {
		name   string
		mutate func(*OIDCProviderMetadata)
		want   string
	}{
		{
			name: "endpoint credentials",
			mutate: func(candidate *OIDCProviderMetadata) {
				candidate.TokenURL = "https://user:secret@issuer.example/token"
			},
			want: "store: OIDC provider config is invalid",
		},
		{
			name: "duplicate redirects",
			mutate: func(candidate *OIDCProviderMetadata) {
				candidate.RedirectURIs = append(
					candidate.RedirectURIs,
					candidate.RedirectURIs[0],
				)
			},
			want: "store: OIDC provider redirects contain duplicates",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := config
			candidate.RedirectURIs = append([]string(nil), config.RedirectURIs...)
			test.mutate(&candidate)
			if _, err := OIDCProviderConfigCreatedEvent(candidate); err == nil ||
				err.Error() != test.want {
				t.Fatalf("create invalid OIDC provider error = %v; want %q", err, test.want)
			}
		})
	}
}
