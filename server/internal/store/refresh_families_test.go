package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

const (
	testRefreshFamilyID = "01J00000000000000000000004"
	testRefreshSubject  = "01K0QJ3E5E8R4M0D8EV3Y4N6J7"
)

var testRefreshTime = time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)

func TestRefreshFamilyProjection_RotatesRevokesAndRebuilds(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	firstHash := sha256.Sum256([]byte("refresh-r1"))
	secondHash := sha256.Sum256([]byte("refresh-r2"))
	firstExpiry := testRefreshTime.Add(7 * 24 * time.Hour)
	secondExpiry := firstExpiry.Add(time.Hour)

	started, err := RefreshFamilyStartedEvent(
		testRefreshFamilyID,
		testRefreshSubject,
		firstHash,
		firstExpiry,
	)
	if err != nil {
		t.Fatalf("create refresh-family start event: %v", err)
	}
	rotated, err := RefreshTokenRotatedEvent(
		testRefreshFamilyID,
		firstHash,
		secondHash,
		secondExpiry,
	)
	if err != nil {
		t.Fatalf("create refresh-token rotation event: %v", err)
	}
	revoked, err := RefreshFamilyRevokedEvent(testRefreshFamilyID, firstHash)
	if err != nil {
		t.Fatalf("create refresh-family revocation event: %v", err)
	}
	ctx := context.Background()
	for index, event := range []Event{started, rotated, revoked} {
		if err := eventStore.AppendEventWithVersion(ctx, event, int64(index)); err != nil {
			t.Fatalf("append refresh-family event %d: %v", index, err)
		}
	}

	wantFirst := RefreshFamilyToken{
		FamilyID:          testRefreshFamilyID,
		Subject:           testRefreshSubject,
		Hash:              firstHash,
		ActiveHash:        secondHash,
		ExpiresAt:         firstExpiry,
		Superseded:        true,
		Revoked:           true,
		ProjectionVersion: 3,
	}
	wantSecond := RefreshFamilyToken{
		FamilyID:          testRefreshFamilyID,
		Subject:           testRefreshSubject,
		Hash:              secondHash,
		ActiveHash:        secondHash,
		ExpiresAt:         secondExpiry,
		Revoked:           true,
		ProjectionVersion: 3,
	}
	assertRefreshFamilyToken(t, eventStore, firstHash, wantFirst)
	assertRefreshFamilyToken(t, eventStore, secondHash, wantSecond)

	if _, err := pool.Exec(ctx, `DELETE FROM refresh_families`); err != nil {
		t.Fatalf("delete refresh-family projections: %v", err)
	}
	if err := eventStore.RebuildAll(ctx, RefreshFamilyRebuildTarget); err != nil {
		t.Fatalf("rebuild refresh-family projections: %v", err)
	}
	assertRefreshFamilyToken(t, eventStore, firstHash, wantFirst)
	assertRefreshFamilyToken(t, eventStore, secondHash, wantSecond)
}

func TestRefreshFamilyProjection_RejectsInvalidTransitions(t *testing.T) {
	firstHash := sha256.Sum256([]byte("refresh-r1"))
	secondHash := sha256.Sum256([]byte("refresh-r2"))
	thirdHash := sha256.Sum256([]byte("refresh-r3"))
	wrongHash := sha256.Sum256([]byte("not-the-active-token"))
	expiresAt := testRefreshTime.Add(7 * 24 * time.Hour)

	for _, test := range []struct {
		name string
		run  func(*testing.T, *Store)
	}{
		{
			name: "rotate before start",
			run: func(t *testing.T, eventStore *Store) {
				event, err := RefreshTokenRotatedEvent(
					testRefreshFamilyID,
					firstHash,
					secondHash,
					expiresAt,
				)
				if err != nil {
					t.Fatalf("create rotation event: %v", err)
				}
				err = eventStore.AppendEventWithVersion(t.Context(), event, 0)
				assertRefreshTransitionError(t, err, "rotation requires a prior family start")
			},
		},
		{
			name: "revoke before start",
			run: func(t *testing.T, eventStore *Store) {
				event, err := RefreshFamilyRevokedEvent(testRefreshFamilyID, firstHash)
				if err != nil {
					t.Fatalf("create revocation event: %v", err)
				}
				err = eventStore.AppendEventWithVersion(t.Context(), event, 0)
				assertRefreshTransitionError(t, err, "revocation requires a prior family start")
			},
		},
		{
			name: "rotate a non-active token",
			run: func(t *testing.T, eventStore *Store) {
				appendRefreshFamilyStart(t, eventStore, firstHash, expiresAt)
				event, err := RefreshTokenRotatedEvent(
					testRefreshFamilyID,
					wrongHash,
					secondHash,
					expiresAt.Add(time.Hour),
				)
				if err != nil {
					t.Fatalf("create rotation event: %v", err)
				}
				err = eventStore.AppendEventWithVersion(t.Context(), event, 1)
				assertRefreshTransitionError(t, err, "rotation does not match the active token")
				assertRefreshFamilyToken(t, eventStore, firstHash, RefreshFamilyToken{
					FamilyID:          testRefreshFamilyID,
					Subject:           testRefreshSubject,
					Hash:              firstHash,
					ActiveHash:        firstHash,
					ExpiresAt:         expiresAt,
					ProjectionVersion: 1,
				})
			},
		},
		{
			name: "rotate a revoked family",
			run: func(t *testing.T, eventStore *Store) {
				appendRefreshFamilyStart(t, eventStore, firstHash, expiresAt)
				firstRotation, err := RefreshTokenRotatedEvent(
					testRefreshFamilyID,
					firstHash,
					secondHash,
					expiresAt.Add(time.Hour),
				)
				if err != nil {
					t.Fatalf("create first rotation event: %v", err)
				}
				if err := eventStore.AppendEventWithVersion(t.Context(), firstRotation, 1); err != nil {
					t.Fatalf("append first rotation event: %v", err)
				}
				revoked, err := RefreshFamilyRevokedEvent(testRefreshFamilyID, firstHash)
				if err != nil {
					t.Fatalf("create revocation event: %v", err)
				}
				if err := eventStore.AppendEventWithVersion(t.Context(), revoked, 2); err != nil {
					t.Fatalf("append revocation event: %v", err)
				}
				rotated, err := RefreshTokenRotatedEvent(
					testRefreshFamilyID,
					secondHash,
					thirdHash,
					expiresAt.Add(2*time.Hour),
				)
				if err != nil {
					t.Fatalf("create rotation event: %v", err)
				}
				err = eventStore.AppendEventWithVersion(t.Context(), rotated, 3)
				assertRefreshTransitionError(t, err, "revoked refresh family")
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
}

func TestRefreshFamilyEvents_ContainHashesButNeverRawSecrets(t *testing.T) {
	firstSecret := "refresh-secret-r1-do-not-persist"
	secondSecret := "refresh-secret-r2-do-not-persist"
	firstHash := sha256.Sum256([]byte(firstSecret))
	secondHash := sha256.Sum256([]byte(secondSecret))
	events := make([]Event, 0, 3)
	started, err := RefreshFamilyStartedEvent(
		testRefreshFamilyID,
		testRefreshSubject,
		firstHash,
		testRefreshTime.Add(7*24*time.Hour),
	)
	if err != nil {
		t.Fatalf("create refresh-family start event: %v", err)
	}
	events = append(events, started)
	rotated, err := RefreshTokenRotatedEvent(
		testRefreshFamilyID,
		firstHash,
		secondHash,
		testRefreshTime.Add(8*24*time.Hour),
	)
	if err != nil {
		t.Fatalf("create refresh-token rotation event: %v", err)
	}
	events = append(events, rotated)
	revoked, err := RefreshFamilyRevokedEvent(testRefreshFamilyID, firstHash)
	if err != nil {
		t.Fatalf("create refresh-family revocation event: %v", err)
	}
	events = append(events, revoked)

	for _, event := range events {
		for _, secret := range []string{firstSecret, secondSecret} {
			if bytes.Contains(event.Payload, []byte(secret)) {
				t.Fatalf("%s payload persisted raw refresh secret %q", event.EventType, secret)
			}
		}
	}
}

func appendRefreshFamilyStart(
	t *testing.T,
	eventStore *Store,
	hash [sha256.Size]byte,
	expiresAt time.Time,
) {
	t.Helper()
	event, err := RefreshFamilyStartedEvent(
		testRefreshFamilyID,
		testRefreshSubject,
		hash,
		expiresAt,
	)
	if err != nil {
		t.Fatalf("create refresh-family start event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), event, 0); err != nil {
		t.Fatalf("append refresh-family start event: %v", err)
	}
}

func assertRefreshFamilyToken(
	t *testing.T,
	eventStore *Store,
	hash [sha256.Size]byte,
	want RefreshFamilyToken,
) {
	t.Helper()
	got, err := eventStore.RefreshFamilyToken(t.Context(), hash)
	if err != nil {
		t.Fatalf("read refresh-family token: %v", err)
	}
	if got != want {
		t.Fatalf("refresh-family token = %+v; want %+v", got, want)
	}
}

func assertRefreshTransitionError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("refresh-family transition error = %v; want %q", err, want)
	}
}
