package store

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestOIDCState_ConsumesOnceExpiresAndStoresOnlyHash(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	now := time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)
	const rawState = "raw-oidc-state-never-store"
	stateHash := sha256.Sum256([]byte(rawState))
	state := OIDCLoginState{
		ProviderSlug: "corporate",
		RedirectURI:  "https://console.example.test/callback",
		Nonce:        "bound-nonce",
		CodeVerifier: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
		ExpiresAt:    now.Add(10 * time.Minute),
	}
	if err := eventStore.StoreOIDCLoginState(t.Context(), stateHash, state); err != nil {
		t.Fatalf("store OIDC login state: %v", err)
	}

	var storedHash []byte
	var rawStateOccurrences int
	if err := pool.QueryRow(t.Context(), `
		SELECT state_hash,
		       count(*) FILTER (WHERE provider_slug = $2
		                          OR redirect_uri = $2
		                          OR nonce = $2
		                          OR code_verifier = $2) OVER ()
		FROM oidc_login_states
		WHERE state_hash = $1`, stateHash[:], rawState).Scan(
		&storedHash,
		&rawStateOccurrences,
	); err != nil {
		t.Fatalf("inspect OIDC login state: %v", err)
	}
	if string(storedHash) != string(stateHash[:]) || rawStateOccurrences != 0 {
		t.Fatalf("stored OIDC state = (%x, %d raw occurrences); want digest only", storedHash, rawStateOccurrences)
	}

	consumed, err := eventStore.ConsumeOIDCLoginState(t.Context(), stateHash, now)
	if err != nil {
		t.Fatalf("consume OIDC login state: %v", err)
	}
	assertOIDCLoginState(t, consumed, state)
	if _, err := eventStore.ConsumeOIDCLoginState(t.Context(), stateHash, now); !IsNotFound(err) {
		t.Fatalf("replayed OIDC state error = %v; want not found", err)
	}

	expiredHash := sha256.Sum256([]byte("expired-state"))
	expired := state
	expired.ExpiresAt = now
	if err := eventStore.StoreOIDCLoginState(t.Context(), expiredHash, expired); err != nil {
		t.Fatalf("store expired OIDC login state: %v", err)
	}
	if _, err := eventStore.ConsumeOIDCLoginState(t.Context(), expiredHash, now); !errors.Is(err, ErrOIDCLoginStateExpired) {
		t.Fatalf("expired OIDC state error = %v; want %v", err, ErrOIDCLoginStateExpired)
	}
	if _, err := eventStore.ConsumeOIDCLoginState(t.Context(), expiredHash, now); !IsNotFound(err) {
		t.Fatalf("replayed expired OIDC state error = %v; want not found", err)
	}
}

func assertOIDCLoginState(t *testing.T, got, want OIDCLoginState) {
	t.Helper()
	if got.ProviderSlug != want.ProviderSlug ||
		got.RedirectURI != want.RedirectURI ||
		got.Nonce != want.Nonce ||
		got.CodeVerifier != want.CodeVerifier ||
		!got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("OIDC login state = %+v; want %+v", got, want)
	}
}
