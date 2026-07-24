package store

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	testPATID           = "01J00000000000000000000005"
	testPATSubject      = "01K0QJ3E5E8R4M0D8EV3Y4N6J8"
	testPATOtherSubject = "01K0QJ3E5E8R4M0D8EV3Y4N6J9"
)

var testPATExpiry = time.Date(2031, time.February, 3, 4, 5, 6, 0, time.UTC)

func TestPersonalAccessTokenProjection_MintsRevokesAndRebuilds(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	tokenHash := sha256.Sum256([]byte("pm_pat_raw-secret"))
	scopes := []string{"actions.read", "devices.write"}
	minted, err := PersonalAccessTokenMintedEvent(
		testPATID,
		testPATSubject,
		scopes,
		tokenHash,
		testPATExpiry,
	)
	if err != nil {
		t.Fatalf("create PAT mint event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), minted, 0); err != nil {
		t.Fatalf("append PAT mint event: %v", err)
	}
	assertPersonalAccessToken(t, eventStore, tokenHash, PersonalAccessToken{
		TokenID:           testPATID,
		Subject:           testPATSubject,
		Hash:              tokenHash,
		Scopes:            scopes,
		ExpiresAt:         testPATExpiry,
		ProjectionVersion: 1,
	})

	revoked, err := PersonalAccessTokenRevokedEvent(testPATID)
	if err != nil {
		t.Fatalf("create PAT revoke event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), revoked, 1); err != nil {
		t.Fatalf("append PAT revoke event: %v", err)
	}
	want := PersonalAccessToken{
		TokenID:           testPATID,
		Subject:           testPATSubject,
		Hash:              tokenHash,
		Scopes:            scopes,
		ExpiresAt:         testPATExpiry,
		Revoked:           true,
		ProjectionVersion: 2,
	}
	assertPersonalAccessToken(t, eventStore, tokenHash, want)
	byID, err := eventStore.PersonalAccessTokenByID(t.Context(), strings.ToLower(testPATID))
	if err != nil {
		t.Fatalf("read PAT by lowercase ID: %v", err)
	}
	assertPersonalAccessTokenValue(t, byID, want)

	if _, err := pool.Exec(t.Context(), `DELETE FROM personal_access_tokens`); err != nil {
		t.Fatalf("delete PAT projections: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), PersonalAccessTokenRebuildTarget); err != nil {
		t.Fatalf("rebuild PAT projections: %v", err)
	}
	assertPersonalAccessToken(t, eventStore, tokenHash, want)
}

func TestPersonalAccessTokenProjection_RejectsInvalidTransitions(t *testing.T) {
	tokenHash := sha256.Sum256([]byte("pm_pat_raw-secret"))
	for _, test := range []struct {
		name string
		run  func(*testing.T, *Store)
	}{
		{
			name: "revoke before mint",
			run: func(t *testing.T, eventStore *Store) {
				event, err := PersonalAccessTokenRevokedEvent(testPATID)
				if err != nil {
					t.Fatalf("create PAT revoke event: %v", err)
				}
				err = eventStore.AppendEventWithVersion(t.Context(), event, 0)
				assertPATTransitionError(t, err, "revocation requires a prior mint")
			},
		},
		{
			name: "mint twice",
			run: func(t *testing.T, eventStore *Store) {
				appendPersonalAccessTokenMint(t, eventStore, tokenHash)
				event, err := PersonalAccessTokenMintedEvent(
					testPATID,
					testPATSubject,
					[]string{"actions.read"},
					sha256.Sum256([]byte("second-secret")),
					testPATExpiry,
				)
				if err != nil {
					t.Fatalf("create duplicate PAT mint event: %v", err)
				}
				err = eventStore.AppendEventWithVersion(t.Context(), event, 1)
				assertPATTransitionError(t, err, "mint must be stream version 1")
			},
		},
		{
			name: "revoke twice",
			run: func(t *testing.T, eventStore *Store) {
				appendPersonalAccessTokenMint(t, eventStore, tokenHash)
				event, err := PersonalAccessTokenRevokedEvent(testPATID)
				if err != nil {
					t.Fatalf("create PAT revoke event: %v", err)
				}
				if err := eventStore.AppendEventWithVersion(t.Context(), event, 1); err != nil {
					t.Fatalf("append first PAT revoke event: %v", err)
				}
				err = eventStore.AppendEventWithVersion(t.Context(), event, 2)
				assertPATTransitionError(t, err, "PAT is already revoked")
				assertPersonalAccessToken(t, eventStore, tokenHash, PersonalAccessToken{
					TokenID:           testPATID,
					Subject:           testPATSubject,
					Hash:              tokenHash,
					Scopes:            []string{"actions.read"},
					ExpiresAt:         testPATExpiry,
					Revoked:           true,
					ProjectionVersion: 2,
				})
			},
		},
		{
			name: "change subject while retaining credential",
			run: func(t *testing.T, eventStore *Store) {
				appendPersonalAccessTokenMint(t, eventStore, tokenHash)
				event, err := PersonalAccessTokenUpdatedEvent(
					testPATID,
					testPATOtherSubject,
					[]string{"actions.read"},
					testPATExpiry,
					false,
				)
				if err != nil {
					t.Fatalf("create PAT subject-change event: %v", err)
				}
				err = eventStore.AppendEventWithVersion(t.Context(), event, 1)
				assertPATTransitionError(t, err, "conflicts with the current projection")
				assertPersonalAccessToken(t, eventStore, tokenHash, PersonalAccessToken{
					TokenID:           testPATID,
					Subject:           testPATSubject,
					Hash:              tokenHash,
					Scopes:            []string{"actions.read"},
					ExpiresAt:         testPATExpiry,
					ProjectionVersion: 1,
				})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool := testPostgres(t)
			eventStore, err := NewProduction(pool)
			if err != nil {
				t.Fatalf("create production store: %v", err)
			}
			test.run(t, eventStore)
		})
	}

	for name, scopes := range map[string][]string{
		"empty":     nil,
		"duplicate": {"actions.read", "actions.read"},
		"unsorted":  {"devices.write", "actions.read"},
		"invalid":   {"Actions.Read"},
	} {
		t.Run("scope/"+name, func(t *testing.T) {
			if _, err := PersonalAccessTokenMintedEvent(
				testPATID,
				testPATSubject,
				scopes,
				tokenHash,
				testPATExpiry,
			); err == nil || !strings.Contains(err.Error(), "PAT scopes are invalid") {
				t.Fatalf("PAT mint scopes %v error = %v; want scope validation error", scopes, err)
			}
		})
	}
}

func TestPersonalAccessTokenEvents_ContainHashesButNeverRawSecrets(t *testing.T) {
	const secret = "pm_pat_raw-secret-do-not-persist"
	tokenHash := sha256.Sum256([]byte(secret))
	minted, err := PersonalAccessTokenMintedEvent(
		testPATID,
		testPATSubject,
		[]string{"actions.read"},
		tokenHash,
		testPATExpiry,
	)
	if err != nil {
		t.Fatalf("create PAT mint event: %v", err)
	}
	revoked, err := PersonalAccessTokenRevokedEvent(testPATID)
	if err != nil {
		t.Fatalf("create PAT revoke event: %v", err)
	}
	for _, event := range []Event{minted, revoked} {
		if bytes.Contains(event.Payload, []byte(secret)) {
			t.Fatalf("%s payload persisted raw PAT secret", event.EventType)
		}
	}
}

func appendPersonalAccessTokenMint(t *testing.T, eventStore *Store, hash [sha256.Size]byte) {
	t.Helper()
	event, err := PersonalAccessTokenMintedEvent(
		testPATID,
		testPATSubject,
		[]string{"actions.read"},
		hash,
		testPATExpiry,
	)
	if err != nil {
		t.Fatalf("create PAT mint event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), event, 0); err != nil {
		t.Fatalf("append PAT mint event: %v", err)
	}
}

func assertPersonalAccessToken(
	t *testing.T,
	eventStore *Store,
	hash [sha256.Size]byte,
	want PersonalAccessToken,
) {
	t.Helper()
	got, err := eventStore.PersonalAccessTokenByHash(t.Context(), hash)
	if err != nil {
		t.Fatalf("read PAT by hash: %v", err)
	}
	assertPersonalAccessTokenValue(t, got, want)
}

func assertPersonalAccessTokenValue(t *testing.T, got, want PersonalAccessToken) {
	t.Helper()
	if got.TokenID != want.TokenID ||
		got.Subject != want.Subject ||
		got.Hash != want.Hash ||
		!slices.Equal(got.Scopes, want.Scopes) ||
		!got.ExpiresAt.Equal(want.ExpiresAt) ||
		got.Revoked != want.Revoked ||
		got.ProjectionVersion != want.ProjectionVersion {
		t.Fatalf("PAT projection = %+v; want %+v", got, want)
	}
}

func assertPATTransitionError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("PAT transition error = %v; want %q", err, want)
	}
}
