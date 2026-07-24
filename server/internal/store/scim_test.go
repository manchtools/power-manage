package store

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

const (
	testSCIMProviderSlug = "corporate"
	testSCIMGroupID      = "01K0QJ3E5E8R4M0D8EV3Y4N6M0"
	testSCIMSecondUserID = "01K0QJ3E5E8R4M0D8EV3Y4N6M1"
)

func TestSCIMProviderProjection_RotatesDisablesAndRebuildsHashOnly(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	firstSecret := []byte("first-scim-secret-that-must-not-persist")
	secondSecret := []byte("second-scim-secret-that-must-not-persist")
	firstHash, err := bcrypt.GenerateFromPassword(firstSecret, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash first SCIM secret: %v", err)
	}
	secondHash, err := bcrypt.GenerateFromPassword(secondSecret, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash second SCIM secret: %v", err)
	}
	created, err := SCIMProviderCreatedEvent(testSCIMProviderSlug, firstHash)
	if err != nil {
		t.Fatalf("create SCIM provider event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), created, 0); err != nil {
		t.Fatalf("append SCIM provider creation: %v", err)
	}
	rotated, err := SCIMProviderTokenRotatedEvent(testSCIMProviderSlug, secondHash)
	if err != nil {
		t.Fatalf("create SCIM token rotation event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), rotated, 1); err != nil {
		t.Fatalf("append SCIM token rotation: %v", err)
	}
	disabled, err := SCIMProviderDisabledEvent(testSCIMProviderSlug)
	if err != nil {
		t.Fatalf("create SCIM provider disable event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), disabled, 2); err != nil {
		t.Fatalf("append SCIM provider disable: %v", err)
	}
	want := SCIMProvider{
		Slug:              testSCIMProviderSlug,
		TokenHash:         string(secondHash),
		Disabled:          true,
		ProjectionVersion: 3,
	}
	assertSCIMProvider(t, eventStore, want)

	var payloads []byte
	rows, err := pool.Query(t.Context(), `
		SELECT payload::text
		FROM events
		WHERE stream_type = 'scim-provider'
		ORDER BY global_position`)
	if err != nil {
		t.Fatalf("read SCIM provider payloads: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			t.Fatalf("scan SCIM provider payload: %v", err)
		}
		payloads = append(payloads, payload...)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate SCIM provider payloads: %v", err)
	}
	if bytes.Contains(payloads, firstSecret) || bytes.Contains(payloads, secondSecret) {
		t.Fatal("raw SCIM provider secret persisted in event payloads")
	}

	if _, err := pool.Exec(t.Context(), `DELETE FROM scim_providers`); err != nil {
		t.Fatalf("delete SCIM provider projection: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), SCIMProviderRebuildTarget); err != nil {
		t.Fatalf("rebuild SCIM provider projection: %v", err)
	}
	assertSCIMProvider(t, eventStore, want)
}

func TestSCIMIdentityProjection_UnlinksOneOfTwoAndDeletesLastLink(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	created, err := UserCreatedEvent(testBootstrapUserID, "linked@example.test")
	if err != nil {
		t.Fatalf("create linked user: %v", err)
	}
	oidcLinked, err := OIDCIdentityLinkedEvent(
		testBootstrapUserID,
		"workforce",
		"https://identity.example.test",
		"oidc-subject",
		"linked@example.test",
	)
	if err != nil {
		t.Fatalf("create OIDC link: %v", err)
	}
	scimLinked, err := SCIMIdentityLinkedEvent(
		testBootstrapUserID,
		testSCIMProviderSlug,
		"scim-subject",
		"linked@example.test",
	)
	if err != nil {
		t.Fatalf("create SCIM link: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{created, oidcLinked, scimLinked}); err != nil {
		t.Fatalf("append two-link user: %v", err)
	}
	if count, err := eventStore.UserIdentityLinkCount(t.Context(), testBootstrapUserID); err != nil || count != 2 {
		t.Fatalf("two-link user count = (%d, %v); want (2, nil)", count, err)
	}
	unlinked, err := SCIMIdentityUnlinkedEvent(
		testBootstrapUserID,
		testSCIMProviderSlug,
		"scim-subject",
	)
	if err != nil {
		t.Fatalf("create SCIM unlink: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), unlinked, 3); err != nil {
		t.Fatalf("unlink one of two identities: %v", err)
	}
	if _, err := eventStore.UserByID(t.Context(), testBootstrapUserID); err != nil {
		t.Fatalf("two-link deprovision deleted user: %v", err)
	}
	if count, err := eventStore.UserIdentityLinkCount(t.Context(), testBootstrapUserID); err != nil || count != 1 {
		t.Fatalf("remaining user links = (%d, %v); want (1, nil)", count, err)
	}

	lastCreated, err := UserCreatedEvent(testSCIMSecondUserID, "last@example.test")
	if err != nil {
		t.Fatalf("create last-link user: %v", err)
	}
	lastLinked, err := SCIMIdentityLinkedEvent(
		testSCIMSecondUserID,
		testSCIMProviderSlug,
		"last-scim-subject",
		"last@example.test",
	)
	if err != nil {
		t.Fatalf("create last SCIM link: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{lastCreated, lastLinked}); err != nil {
		t.Fatalf("append last-link user: %v", err)
	}
	lastUnlinked, err := SCIMIdentityUnlinkedEvent(
		testSCIMSecondUserID,
		testSCIMProviderSlug,
		"last-scim-subject",
	)
	if err != nil {
		t.Fatalf("create last SCIM unlink: %v", err)
	}
	deprovisioned, err := SCIMUserDeprovisionedEvent(testSCIMSecondUserID)
	if err != nil {
		t.Fatalf("create terminal SCIM deprovision: %v", err)
	}
	if err := eventStore.AppendEvents(
		t.Context(),
		[]Event{lastUnlinked, deprovisioned},
	); err != nil {
		t.Fatalf("append terminal SCIM deprovision: %v", err)
	}
	if _, err := eventStore.UserByID(t.Context(), testSCIMSecondUserID); !IsNotFound(err) {
		t.Fatalf("last-link deprovision user error = %v; want not found", err)
	}
	var livePII int
	if err := pool.QueryRow(t.Context(), `
		SELECT
			(SELECT count(*) FROM users WHERE email = 'last@example.test') +
			(SELECT count(*) FROM scim_identities WHERE email = 'last@example.test')`).
		Scan(&livePII); err != nil {
		t.Fatalf("count live deprovisioned PII: %v", err)
	}
	if livePII != 0 {
		t.Fatalf("last-link deprovision left %d live PII rows; want zero", livePII)
	}
}

func TestSCIMGroupProjection_AtomicMembershipReplaceAndRebuild(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	for _, user := range []struct {
		id    string
		email string
	}{
		{id: testBootstrapUserID, email: "member-one@example.test"},
		{id: testSCIMSecondUserID, email: "member-two@example.test"},
	} {
		created, err := UserCreatedEvent(user.id, user.email)
		if err != nil {
			t.Fatalf("create group member %s: %v", user.id, err)
		}
		if err := eventStore.AppendEventWithVersion(t.Context(), created, 0); err != nil {
			t.Fatalf("append group member %s: %v", user.id, err)
		}
	}
	created, err := SCIMGroupCreatedEvent(
		testSCIMGroupID,
		testSCIMProviderSlug,
		"external-group",
		"Operators",
	)
	if err != nil {
		t.Fatalf("create SCIM group event: %v", err)
	}
	members, err := SCIMGroupMembershipsReplacedEvent(
		testSCIMGroupID,
		[]string{testBootstrapUserID},
	)
	if err != nil {
		t.Fatalf("create SCIM group members event: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{created, members}); err != nil {
		t.Fatalf("append SCIM group and members: %v", err)
	}
	assertSCIMGroup(t, eventStore, "Operators", []string{testBootstrapUserID}, 2)

	updated, err := SCIMGroupUpdatedEvent(
		testSCIMGroupID,
		testSCIMProviderSlug,
		"external-group",
		"Platform Operators",
	)
	if err != nil {
		t.Fatalf("create SCIM group update: %v", err)
	}
	replaced, err := SCIMGroupMembershipsReplacedEvent(
		testSCIMGroupID,
		[]string{testBootstrapUserID, testSCIMSecondUserID},
	)
	if err != nil {
		t.Fatalf("create SCIM group replacement: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{updated, replaced}); err != nil {
		t.Fatalf("replace SCIM group and members: %v", err)
	}
	assertSCIMGroup(
		t,
		eventStore,
		"Platform Operators",
		[]string{testBootstrapUserID, testSCIMSecondUserID},
		4,
	)

	invalidUpdate, err := SCIMGroupUpdatedEvent(
		testSCIMGroupID,
		testSCIMProviderSlug,
		"external-group",
		"Must Roll Back",
	)
	if err != nil {
		t.Fatalf("create invalid group update: %v", err)
	}
	invalidMembers, err := SCIMGroupMembershipsReplacedEvent(
		testSCIMGroupID,
		[]string{"01K0QJ3E5E8R4M0D8EV3Y4N6M2"},
	)
	if err != nil {
		t.Fatalf("create invalid group members event: %v", err)
	}
	if err := eventStore.AppendEvents(
		t.Context(),
		[]Event{invalidUpdate, invalidMembers},
	); err == nil || !strings.Contains(err.Error(), "requires existing users") {
		t.Fatalf("invalid group replacement error = %v; want missing-user rejection", err)
	}
	assertSCIMGroup(
		t,
		eventStore,
		"Platform Operators",
		[]string{testBootstrapUserID, testSCIMSecondUserID},
		4,
	)

	if _, err := pool.Exec(t.Context(), `DELETE FROM scim_groups`); err != nil {
		t.Fatalf("delete SCIM group projection: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), SCIMGroupRebuildTarget); err != nil {
		t.Fatalf("rebuild SCIM groups: %v", err)
	}
	assertSCIMGroup(
		t,
		eventStore,
		"Platform Operators",
		[]string{testBootstrapUserID, testSCIMSecondUserID},
		4,
	)
}

func TestSCIMGroupRebuild_SkipsMembershipsForDeprovisionedUsers(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	created, err := UserCreatedEvent(testBootstrapUserID, "former-member@example.test")
	if err != nil {
		t.Fatalf("create former group member: %v", err)
	}
	linked, err := SCIMIdentityLinkedEvent(
		testBootstrapUserID,
		testSCIMProviderSlug,
		"former-member",
		"former-member@example.test",
	)
	if err != nil {
		t.Fatalf("create former member identity link: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{created, linked}); err != nil {
		t.Fatalf("append former member: %v", err)
	}
	groupCreated, err := SCIMGroupCreatedEvent(
		testSCIMGroupID,
		testSCIMProviderSlug,
		"former-members",
		"Former Members",
	)
	if err != nil {
		t.Fatalf("create former-members group: %v", err)
	}
	members, err := SCIMGroupMembershipsReplacedEvent(
		testSCIMGroupID,
		[]string{testBootstrapUserID},
	)
	if err != nil {
		t.Fatalf("create former-members mapping: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{groupCreated, members}); err != nil {
		t.Fatalf("append former-members group: %v", err)
	}
	unlinked, err := SCIMIdentityUnlinkedEvent(
		testBootstrapUserID,
		testSCIMProviderSlug,
		"former-member",
	)
	if err != nil {
		t.Fatalf("create former member unlink: %v", err)
	}
	deprovisioned, err := SCIMUserDeprovisionedEvent(testBootstrapUserID)
	if err != nil {
		t.Fatalf("create former member deprovision: %v", err)
	}
	if err := eventStore.AppendEvents(
		t.Context(),
		[]Event{unlinked, deprovisioned},
	); err != nil {
		t.Fatalf("deprovision former member: %v", err)
	}
	assertSCIMGroup(t, eventStore, "Former Members", nil, 2)

	if err := eventStore.RebuildAll(t.Context(), SCIMGroupRebuildTarget); err != nil {
		t.Fatalf("rebuild SCIM groups after user deprovision: %v", err)
	}
	assertSCIMGroup(t, eventStore, "Former Members", nil, 2)
}

func assertSCIMProvider(t *testing.T, eventStore *Store, want SCIMProvider) {
	t.Helper()
	got, err := eventStore.SCIMProvider(t.Context(), want.Slug)
	if err != nil {
		t.Fatalf("read SCIM provider: %v", err)
	}
	if got != want {
		t.Fatalf("SCIM provider = %+v; want %+v", got, want)
	}
}

func assertSCIMGroup(
	t *testing.T,
	eventStore *Store,
	wantName string,
	wantMembers []string,
	wantVersion int64,
) {
	t.Helper()
	got, err := eventStore.SCIMGroup(t.Context(), testSCIMProviderSlug, testSCIMGroupID)
	if err != nil {
		t.Fatalf("read SCIM group: %v", err)
	}
	if got.DisplayName != wantName ||
		got.ProjectionVersion != wantVersion ||
		!slices.Equal(got.Members, wantMembers) {
		t.Fatalf(
			"SCIM group = %+v; want display %q members %v version %d",
			got,
			wantName,
			wantMembers,
			wantVersion,
		)
	}
}

func TestSCIMEventsRejectInvalidProviderAndMembershipInputs(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash SCIM fixture: %v", err)
	}
	if _, err := SCIMProviderCreatedEvent(
		"INVALID",
		hash,
	); err == nil || !strings.Contains(err.Error(), "slug is invalid") {
		t.Fatalf("invalid SCIM provider slug error = %v; want slug rejection", err)
	}
	if _, err := SCIMGroupMembershipsReplacedEvent(
		testSCIMGroupID,
		[]string{testBootstrapUserID, testBootstrapUserID},
	); err == nil || !strings.Contains(err.Error(), "contains duplicates") {
		t.Fatalf("duplicate SCIM group member error = %v; want duplicate rejection", err)
	}
	if _, err := SCIMProviderCreatedEvent(
		testSCIMProviderSlug,
		[]byte("plaintext"),
	); err == nil || !strings.Contains(err.Error(), "token hash is invalid") {
		t.Fatalf("non-bcrypt SCIM provider hash error = %v; want hash rejection", err)
	}
	var missing *Store
	if _, err := missing.SCIMProvider(
		t.Context(),
		testSCIMProviderSlug,
	); err == nil || !strings.Contains(err.Error(), "nil store") {
		t.Fatalf("nil SCIM store lookup error = %v; want nil-store rejection", err)
	}
}
