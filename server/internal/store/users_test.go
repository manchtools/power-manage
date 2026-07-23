package store

import (
	"strings"
	"testing"
)

const (
	testOIDCUserID  = "01K0QJ3E5E8R4M0D8EV3Y4N6K0"
	testOIDCIssuer  = "https://identity.example.test"
	testOIDCSubject = "external-subject-1"
	testOIDCEmail   = "person@example.test"
)

func TestUserProjection_CreatesLinksAndRebuildsAtomically(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	created, err := UserCreatedEvent(testOIDCUserID, strings.ToUpper(testOIDCEmail))
	if err != nil {
		t.Fatalf("create user event: %v", err)
	}
	linked, err := OIDCIdentityLinkedEvent(
		testOIDCUserID,
		"corporate",
		testOIDCIssuer,
		testOIDCSubject,
		testOIDCEmail,
	)
	if err != nil {
		t.Fatalf("create OIDC identity-link event: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{created, linked}); err != nil {
		t.Fatalf("append atomic user and identity link: %v", err)
	}
	want := User{
		UserID:            testOIDCUserID,
		Email:             testOIDCEmail,
		ProjectionVersion: 2,
	}
	assertUser(t, eventStore, want)
	byIdentity, err := eventStore.UserByOIDCIdentity(t.Context(), testOIDCIssuer, testOIDCSubject)
	if err != nil {
		t.Fatalf("read user by OIDC identity: %v", err)
	}
	if byIdentity != want {
		t.Fatalf("user by OIDC identity = %+v; want %+v", byIdentity, want)
	}
	count, err := eventStore.UserOIDCIdentityCount(t.Context(), testOIDCUserID)
	if err != nil || count != 1 {
		t.Fatalf("OIDC identity count = (%d, %v); want (1, nil)", count, err)
	}

	if _, err := pool.Exec(t.Context(), `DELETE FROM oidc_identities`); err != nil {
		t.Fatalf("delete OIDC identity projections: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM users`); err != nil {
		t.Fatalf("delete user projections: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), UserRebuildTarget); err != nil {
		t.Fatalf("rebuild user projections: %v", err)
	}
	assertUser(t, eventStore, want)

	invalidUserID := "01K0QJ3E5E8R4M0D8EV3Y4N6K1"
	invalidCreated, err := UserCreatedEvent(invalidUserID, "other@example.test")
	if err != nil {
		t.Fatalf("create invalid-batch user event: %v", err)
	}
	mismatchedLink, err := OIDCIdentityLinkedEvent(
		invalidUserID,
		"corporate",
		testOIDCIssuer,
		"external-subject-2",
		"different@example.test",
	)
	if err != nil {
		t.Fatalf("create mismatched identity-link event: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{invalidCreated, mismatchedLink}); err == nil ||
		!strings.Contains(err.Error(), "email does not match") {
		t.Fatalf("mismatched user/link batch error = %v; want email mismatch", err)
	}
	if _, err := eventStore.UserByID(t.Context(), invalidUserID); !IsNotFound(err) {
		t.Fatalf("partially projected invalid user error = %v; want not found", err)
	}
	var persistedEvents int
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*)
		FROM events
		WHERE stream_type = 'user'
		  AND stream_id = $1`, invalidUserID).Scan(&persistedEvents); err != nil {
		t.Fatalf("count invalid-batch user events: %v", err)
	}
	if persistedEvents != 0 {
		t.Fatalf("invalid user/link batch persisted %d events; want zero", persistedEvents)
	}
}

func TestUserProjection_RejectsInvalidTransitions(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	link, err := OIDCIdentityLinkedEvent(
		testOIDCUserID,
		"corporate",
		testOIDCIssuer,
		testOIDCSubject,
		testOIDCEmail,
	)
	if err != nil {
		t.Fatalf("create OIDC identity-link event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), link, 0); err == nil ||
		!strings.Contains(err.Error(), "requires a prior user") {
		t.Fatalf("link-before-user error = %v; want prior-user rejection", err)
	}
	if _, err := eventStore.UserByOIDCIdentity(t.Context(), testOIDCIssuer, testOIDCSubject); !IsNotFound(err) {
		t.Fatalf("identity after rejected transition error = %v; want not found", err)
	}
}

func assertUser(t *testing.T, eventStore *Store, want User) {
	t.Helper()
	byID, err := eventStore.UserByID(t.Context(), want.UserID)
	if err != nil {
		t.Fatalf("read user by ID: %v", err)
	}
	if byID != want {
		t.Fatalf("user by ID = %+v; want %+v", byID, want)
	}
	byEmail, err := eventStore.UserByEmail(t.Context(), strings.ToUpper(want.Email))
	if err != nil {
		t.Fatalf("read user by canonicalized email: %v", err)
	}
	if byEmail != want {
		t.Fatalf("user by email = %+v; want %+v", byEmail, want)
	}
}
