package store

import (
	"context"
	"crypto/sha256"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	testRegistrationTokenID        = "01J00000000000000000000002"
	testGatewayRegistrationTokenID = "01J00000000000000000000003"
)

// TestRegistrationTokenProjection_RebuildsCompleteState pins the M3 event and
// projection model, including monotonic use count and the durable kill switch.
func TestRegistrationTokenProjection_RebuildsCompleteState(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	digest := sha256.Sum256([]byte("registration secret"))
	expiresAt := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	minted, err := RegistrationTokenMintedEvent(
		testRegistrationTokenID,
		digest,
		3,
		expiresAt,
		"owner@example.com",
	)
	if err != nil {
		t.Fatalf("create mint event: %v", err)
	}
	consumed, err := RegistrationTokenConsumedEvent(testRegistrationTokenID)
	if err != nil {
		t.Fatalf("create consume event: %v", err)
	}
	disabled, err := RegistrationTokenDisabledEvent(testRegistrationTokenID)
	if err != nil {
		t.Fatalf("create disable event: %v", err)
	}
	ctx := context.Background()
	for index, event := range []Event{minted, consumed, consumed, disabled} {
		if err := eventStore.AppendEventWithVersion(ctx, event, int64(index)); err != nil {
			t.Fatalf("append registration-token event %d: %v", index, err)
		}
	}

	want := RegistrationToken{
		TokenID:           testRegistrationTokenID,
		Hash:              digest,
		Purpose:           RegistrationTokenPurposeAgent,
		MaxUses:           3,
		Uses:              2,
		ExpiresAt:         expiresAt,
		Owner:             "owner@example.com",
		Disabled:          true,
		ProjectionVersion: 4,
	}
	assertRegistrationToken(t, eventStore, want)
	if _, err := pool.Exec(ctx, `
		UPDATE registration_tokens
		SET token_hash = decode(repeat('00', 32), 'hex'),
		    max_uses = 99,
		    uses = 0,
		    expires_at = '2040-01-01T00:00:00Z',
		    owner = '',
		    disabled = false
		WHERE token_id = $1`, testRegistrationTokenID); err != nil {
		t.Fatalf("corrupt registration-token projection: %v", err)
	}
	if err := eventStore.RebuildAll(ctx, RegistrationTokenRebuildTarget); err != nil {
		t.Fatalf("rebuild registration-token projection: %v", err)
	}
	assertRegistrationToken(t, eventStore, want)
}

func TestGatewayRegistrationToken_RebuildPreservesPurposeAndDNSNames(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	expiresAt := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	agentHash := sha256.Sum256([]byte("agent registration secret"))
	agentEvent, err := RegistrationTokenMintedEvent(
		testRegistrationTokenID,
		agentHash,
		1,
		expiresAt,
		"agent-owner@example.com",
	)
	if err != nil {
		t.Fatalf("create agent token mint event: %v", err)
	}
	gatewayHash := sha256.Sum256([]byte("gateway registration secret"))
	gatewayDNSNames := []string{"gateway-1.internal.example", "gateway-1.backup.internal.example"}
	gatewayEvent, err := GatewayRegistrationTokenMintedEvent(
		testGatewayRegistrationTokenID,
		gatewayHash,
		2,
		expiresAt,
		"gateway-owner@example.com",
		gatewayDNSNames,
	)
	if err != nil {
		t.Fatalf("create gateway token mint event: %v", err)
	}
	ctx := context.Background()
	for _, event := range []Event{agentEvent, gatewayEvent} {
		if err := eventStore.AppendEventWithVersion(ctx, event, 0); err != nil {
			t.Fatalf("append %s registration-token event: %v", event.StreamID, err)
		}
	}

	wantAgent := RegistrationToken{
		TokenID:           testRegistrationTokenID,
		Hash:              agentHash,
		Purpose:           RegistrationTokenPurposeAgent,
		MaxUses:           1,
		ExpiresAt:         expiresAt,
		Owner:             "agent-owner@example.com",
		ProjectionVersion: 1,
	}
	wantGateway := RegistrationToken{
		TokenID:           testGatewayRegistrationTokenID,
		Hash:              gatewayHash,
		Purpose:           RegistrationTokenPurposeGateway,
		DNSNames:          gatewayDNSNames,
		MaxUses:           2,
		ExpiresAt:         expiresAt,
		Owner:             "gateway-owner@example.com",
		ProjectionVersion: 1,
	}
	assertRegistrationToken(t, eventStore, wantAgent)
	assertRegistrationToken(t, eventStore, wantGateway)
	if _, err := pool.Exec(ctx, `DELETE FROM registration_tokens`); err != nil {
		t.Fatalf("delete registration-token projections: %v", err)
	}
	if err := eventStore.RebuildAll(ctx, RegistrationTokenRebuildTarget); err != nil {
		t.Fatalf("rebuild registration-token projections: %v", err)
	}
	assertRegistrationToken(t, eventStore, wantAgent)
	assertRegistrationToken(t, eventStore, wantGateway)
}

func TestManagedRegistrationToken_ListReplaceDeleteAndRebuild(t *testing.T) {
	eventStore, err := NewProduction(testPostgres(t))
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	digest := sha256.Sum256([]byte("managed registration secret"))
	expiresAt := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	minted, err := RegistrationTokenMintedEvent(
		testRegistrationTokenID,
		digest,
		3,
		expiresAt,
		"owner@example.com",
	)
	if err != nil {
		t.Fatalf("create token mint: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), minted, 0); err != nil {
		t.Fatalf("append token mint: %v", err)
	}
	tokens, err := eventStore.ListRegistrationTokens(t.Context(), 100)
	if err != nil || len(tokens) != 1 ||
		tokens[0].TokenID != testRegistrationTokenID ||
		tokens[0].ProjectionVersion != 1 {
		t.Fatalf("registration-token list = (%#v, %v); want minted token", tokens, err)
	}

	replacement, err := RegistrationTokenUpdatedEvent(
		testRegistrationTokenID,
		5,
		expiresAt.Add(time.Hour),
		"updated@example.com",
		true,
	)
	if err != nil {
		t.Fatalf("create token replacement: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), replacement, 1); err != nil {
		t.Fatalf("append token replacement: %v", err)
	}
	updated, err := eventStore.RegistrationToken(t.Context(), testRegistrationTokenID)
	if err != nil || updated.Hash != digest || updated.MaxUses != 5 ||
		updated.Owner != "updated@example.com" || !updated.Disabled ||
		updated.ProjectionVersion != 2 {
		t.Fatalf("updated registration token = (%#v, %v); want verifier-preserving version two", updated, err)
	}

	deleted, err := RegistrationTokenDeletedEvent(testRegistrationTokenID)
	if err != nil {
		t.Fatalf("create token deletion: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), deleted, 2); err != nil {
		t.Fatalf("append token deletion: %v", err)
	}
	if _, err := eventStore.RegistrationToken(
		t.Context(),
		testRegistrationTokenID,
	); !IsNotFound(err) {
		t.Fatalf("deleted registration token error = %v; want not found", err)
	}
	if err := eventStore.RebuildAll(t.Context(), RegistrationTokenRebuildTarget); err != nil {
		t.Fatalf("rebuild deleted registration token: %v", err)
	}
	if _, err := eventStore.RegistrationToken(
		t.Context(),
		testRegistrationTokenID,
	); !IsNotFound(err) {
		t.Fatalf("rebuilt deleted registration token error = %v; want not found", err)
	}
}

func TestManagedRegistrationToken_RejectsMaxUsesBelowConsumption(t *testing.T) {
	eventStore, err := NewProduction(testPostgres(t))
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	digest := sha256.Sum256([]byte("consumed registration secret"))
	expiresAt := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	minted, err := RegistrationTokenMintedEvent(
		testRegistrationTokenID,
		digest,
		3,
		expiresAt,
		"owner@example.com",
	)
	if err != nil {
		t.Fatalf("create registration-token mint: %v", err)
	}
	consumed, err := RegistrationTokenConsumedEvent(testRegistrationTokenID)
	if err != nil {
		t.Fatalf("create registration-token consume: %v", err)
	}
	for expectedVersion, event := range []Event{minted, consumed, consumed} {
		if err := eventStore.AppendEventWithVersion(
			t.Context(),
			event,
			int64(expectedVersion),
		); err != nil {
			t.Fatalf("append registration-token event %d: %v", expectedVersion, err)
		}
	}
	update, err := RegistrationTokenUpdatedEvent(
		testRegistrationTokenID,
		1,
		expiresAt.Add(time.Hour),
		"owner@example.com",
		false,
	)
	if err != nil {
		t.Fatalf("create registration-token update: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(
		t.Context(),
		update,
		3,
	); err == nil || !strings.Contains(err.Error(), "cannot be lower than current uses") {
		t.Fatalf("lower max-uses update error = %v; want consumption conflict", err)
	}
	assertRegistrationToken(t, eventStore, RegistrationToken{
		TokenID:           testRegistrationTokenID,
		Hash:              digest,
		Purpose:           RegistrationTokenPurposeAgent,
		MaxUses:           3,
		Uses:              2,
		ExpiresAt:         expiresAt,
		Owner:             "owner@example.com",
		ProjectionVersion: 3,
	})
}

func TestRegistrationTokenEvents_ValidateAndCanonicalize(t *testing.T) {
	digest := sha256.Sum256([]byte("registration secret"))
	expiresAt := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	event, err := RegistrationTokenMintedEvent(
		strings.ToLower(testRegistrationTokenID), digest, 1, expiresAt, "",
	)
	if err != nil {
		t.Fatalf("create lowercase registration-token event: %v", err)
	}
	if event.StreamID != testRegistrationTokenID {
		t.Fatalf("canonical token stream ID = %q; want %q", event.StreamID, testRegistrationTokenID)
	}

	tests := []struct {
		name  string
		build func() error
		want  string
	}{
		{name: "invalid token ID", build: func() error {
			_, err := RegistrationTokenMintedEvent("not-a-ulid", digest, 1, expiresAt, "")
			return err
		}, want: "token ID"},
		{name: "zero max uses", build: func() error {
			_, err := RegistrationTokenMintedEvent(testRegistrationTokenID, digest, 0, expiresAt, "")
			return err
		}, want: "max uses"},
		{name: "zero expiry", build: func() error {
			_, err := RegistrationTokenMintedEvent(testRegistrationTokenID, digest, 1, time.Time{}, "")
			return err
		}, want: "expiry"},
		{name: "invalid owner", build: func() error {
			_, err := RegistrationTokenMintedEvent(testRegistrationTokenID, digest, 1, expiresAt, "bad\x00owner")
			return err
		}, want: "owner"},
		{name: "consume invalid ID", build: func() error {
			_, err := RegistrationTokenConsumedEvent("not-a-ulid")
			return err
		}, want: "token ID"},
		{name: "disable invalid ID", build: func() error {
			_, err := RegistrationTokenDisabledEvent("not-a-ulid")
			return err
		}, want: "token ID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.build()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("event validation error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestRegistrationTokenProjection_RejectsInvalidTransitions(t *testing.T) {
	digest := sha256.Sum256([]byte("registration secret"))
	expiresAt := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name string
		run  func(*testing.T, *Store)
	}{
		{name: "consume before mint", run: func(t *testing.T, eventStore *Store) {
			event, err := RegistrationTokenConsumedEvent(testRegistrationTokenID)
			if err != nil {
				t.Fatalf("create consume event: %v", err)
			}
			err = eventStore.AppendEventWithVersion(context.Background(), event, 0)
			if err == nil {
				t.Fatal("consume-before-mint event committed")
			}
			if !strings.Contains(err.Error(), "consume requires a prior mint") {
				t.Fatalf("consume-before-mint error = %v; want prior-mint rejection", err)
			}
		}},
		{name: "disable before mint", run: func(t *testing.T, eventStore *Store) {
			event, err := RegistrationTokenDisabledEvent(testRegistrationTokenID)
			if err != nil {
				t.Fatalf("create disable event: %v", err)
			}
			err = eventStore.AppendEventWithVersion(context.Background(), event, 0)
			if err == nil {
				t.Fatal("disable-before-mint event committed")
			}
			if !strings.Contains(err.Error(), "disable requires a prior mint") {
				t.Fatalf("disable-before-mint error = %v; want prior-mint rejection", err)
			}
		}},
		{name: "second mint", run: func(t *testing.T, eventStore *Store) {
			first, err := RegistrationTokenMintedEvent(testRegistrationTokenID, digest, 2, expiresAt, "owner")
			if err != nil {
				t.Fatalf("create first mint event: %v", err)
			}
			if err := eventStore.AppendEventWithVersion(context.Background(), first, 0); err != nil {
				t.Fatalf("append first mint event: %v", err)
			}
			secondHash := sha256.Sum256([]byte("replacement secret"))
			second, err := RegistrationTokenMintedEvent(testRegistrationTokenID, secondHash, 99, expiresAt.Add(time.Hour), "replacement")
			if err != nil {
				t.Fatalf("create second mint event: %v", err)
			}
			err = eventStore.AppendEventWithVersion(context.Background(), second, 1)
			if err == nil {
				t.Fatal("second mint event committed")
			}
			if !strings.Contains(err.Error(), "mint must be stream version 1") {
				t.Fatalf("second-mint error = %v; want version-one rejection", err)
			}
			state, err := eventStore.RegistrationToken(context.Background(), testRegistrationTokenID)
			if err != nil {
				t.Fatalf("read token after rejected remint: %v", err)
			}
			if state.Hash != digest || state.MaxUses != 2 || state.Owner != "owner" || state.ProjectionVersion != 1 {
				t.Fatalf("token changed after rejected remint: %+v", state)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := testPostgres(t)
			eventStore, err := NewProduction(pool)
			if err != nil {
				t.Fatalf("create production store: %v", err)
			}
			test.run(t, eventStore)
		})
	}
}

func assertRegistrationToken(t *testing.T, eventStore *Store, want RegistrationToken) {
	t.Helper()
	got, err := eventStore.RegistrationToken(context.Background(), want.TokenID)
	if err != nil {
		t.Fatalf("read registration token: %v", err)
	}
	if got.TokenID != want.TokenID ||
		got.Hash != want.Hash ||
		got.Purpose != want.Purpose ||
		!slices.Equal(got.DNSNames, want.DNSNames) ||
		got.MaxUses != want.MaxUses ||
		got.Uses != want.Uses ||
		!got.ExpiresAt.Equal(want.ExpiresAt) ||
		got.Owner != want.Owner ||
		got.Disabled != want.Disabled ||
		got.ProjectionVersion != want.ProjectionVersion {
		t.Fatalf("registration token = %+v; want %+v", got, want)
	}
}
