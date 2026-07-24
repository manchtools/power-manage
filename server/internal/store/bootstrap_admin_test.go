package store

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

const (
	testBootstrapLoginID = "01K0QJ3E5E8R4M0D8EV3Y4N6K2"
	testBootstrapUserID  = "01K0QJ3E5E8R4M0D8EV3Y4N6K3"
)

var testBootstrapExpiry = time.Date(2032, time.March, 4, 5, 6, 7, 0, time.UTC)

func TestBootstrapAdminProjection_FirstBootAndLoginRebuild(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	created, err := UserCreatedEvent(testBootstrapUserID, "admin@example.test")
	if err != nil {
		t.Fatalf("create bootstrap user event: %v", err)
	}
	granted, err := BootstrapAdminRoleGrantedEvent(testBootstrapUserID)
	if err != nil {
		t.Fatalf("create bootstrap admin grant event: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{created, granted}); err != nil {
		t.Fatalf("append first-boot identity and admin grant: %v", err)
	}
	user, err := eventStore.UserByID(t.Context(), testBootstrapUserID)
	if err != nil {
		t.Fatalf("read bootstrap user: %v", err)
	}
	if user.ProjectionVersion != 2 {
		t.Fatalf("bootstrap user projection version = %d; want two ordinary events", user.ProjectionVersion)
	}

	rawSecret := "pm_bootstrap_raw-secret-that-must-not-persist"
	tokenHash := sha256.Sum256([]byte(rawSecret))
	minted, err := BootstrapLoginMintedEvent(
		testBootstrapLoginID,
		testBootstrapUserID,
		tokenHash,
		testBootstrapExpiry,
	)
	if err != nil {
		t.Fatalf("create bootstrap login mint event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), minted, 0); err != nil {
		t.Fatalf("append bootstrap login mint: %v", err)
	}
	assertBootstrapLogin(t, eventStore, tokenHash, BootstrapLogin{
		LoginID:           testBootstrapLoginID,
		UserID:            testBootstrapUserID,
		Hash:              tokenHash,
		ExpiresAt:         testBootstrapExpiry,
		ProjectionVersion: 1,
	})

	consumed, err := BootstrapLoginConsumedEvent(testBootstrapLoginID)
	if err != nil {
		t.Fatalf("create bootstrap login consume event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), consumed, 1); err != nil {
		t.Fatalf("append bootstrap login consume: %v", err)
	}
	want := BootstrapLogin{
		LoginID:           testBootstrapLoginID,
		UserID:            testBootstrapUserID,
		Hash:              tokenHash,
		ExpiresAt:         testBootstrapExpiry,
		Consumed:          true,
		ProjectionVersion: 2,
	}
	assertBootstrapLogin(t, eventStore, tokenHash, want)

	var payloads []byte
	rows, err := pool.Query(t.Context(), `
		SELECT payload::text
		FROM events
		WHERE event_type IN ('BootstrapLoginMinted', 'BootstrapLoginConsumed')
		ORDER BY global_position`)
	if err != nil {
		t.Fatalf("read bootstrap audit payloads: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			t.Fatalf("scan bootstrap audit payload: %v", err)
		}
		payloads = append(payloads, payload...)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate bootstrap audit payloads: %v", err)
	}
	if bytes.Contains(payloads, []byte(rawSecret)) {
		t.Fatal("raw bootstrap secret persisted in an audit payload")
	}

	if _, err := pool.Exec(t.Context(), `DELETE FROM bootstrap_logins`); err != nil {
		t.Fatalf("delete bootstrap login projection: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), BootstrapLoginRebuildTarget); err != nil {
		t.Fatalf("rebuild bootstrap login projection: %v", err)
	}
	assertBootstrapLogin(t, eventStore, tokenHash, want)
}

func TestBootstrapAdminProjection_RejectsInvalidTransitions(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	consume, err := BootstrapLoginConsumedEvent(testBootstrapLoginID)
	if err != nil {
		t.Fatalf("create bootstrap login consume event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), consume, 0); err == nil ||
		!strings.Contains(err.Error(), "consume requires a prior mint") {
		t.Fatalf("consume-before-mint error = %v; want prior-mint rejection", err)
	}

	invalidUserID := "01K0QJ3E5E8R4M0D8EV3Y4N6K4"
	created, err := UserCreatedEvent(invalidUserID, "invalid-admin@example.test")
	if err != nil {
		t.Fatalf("create invalid-batch user event: %v", err)
	}
	invalidGrant := userEvent(
		invalidUserID,
		bootstrapAdminGrantedType,
		[]byte(`{"role":"viewer"}`),
	)
	if err := eventStore.AppendEvents(t.Context(), []Event{created, invalidGrant}); err == nil ||
		!strings.Contains(err.Error(), "role grant is invalid") {
		t.Fatalf("invalid bootstrap role batch error = %v; want role rejection", err)
	}
	if _, err := eventStore.UserByID(t.Context(), invalidUserID); !IsNotFound(err) {
		t.Fatalf("user from rolled-back bootstrap batch error = %v; want not found", err)
	}
	var persisted int
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*)
		FROM events
		WHERE stream_type = 'user'
		  AND stream_id = $1`, invalidUserID).Scan(&persisted); err != nil {
		t.Fatalf("count invalid bootstrap batch events: %v", err)
	}
	if persisted != 0 {
		t.Fatalf("invalid bootstrap batch persisted %d events; want zero", persisted)
	}
}

func TestBootstrapAdminProjection_RejectsSecondConsumeAtLatestVersion(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	created, err := UserCreatedEvent(testBootstrapUserID, "admin@example.test")
	if err != nil {
		t.Fatalf("create bootstrap user event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), created, 0); err != nil {
		t.Fatalf("append bootstrap user: %v", err)
	}
	tokenHash := sha256.Sum256([]byte("second-consume-regression"))
	minted, err := BootstrapLoginMintedEvent(
		testBootstrapLoginID,
		testBootstrapUserID,
		tokenHash,
		testBootstrapExpiry,
	)
	if err != nil {
		t.Fatalf("create bootstrap login mint event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), minted, 0); err != nil {
		t.Fatalf("append bootstrap login mint: %v", err)
	}
	consumed, err := BootstrapLoginConsumedEvent(testBootstrapLoginID)
	if err != nil {
		t.Fatalf("create bootstrap login consume event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), consumed, 1); err != nil {
		t.Fatalf("append first bootstrap login consume: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), consumed, 2); err == nil ||
		!strings.Contains(err.Error(), "affected 0 rows") {
		t.Fatalf("second consume error = %v; want unconsumed-state rejection", err)
	}
}

func assertBootstrapLogin(
	t *testing.T,
	eventStore *Store,
	tokenHash [sha256.Size]byte,
	want BootstrapLogin,
) {
	t.Helper()
	got, err := eventStore.BootstrapLoginByHash(t.Context(), tokenHash)
	if err != nil {
		t.Fatalf("read bootstrap login: %v", err)
	}
	if got != want {
		t.Fatalf("bootstrap login = %+v; want %+v", got, want)
	}
}
