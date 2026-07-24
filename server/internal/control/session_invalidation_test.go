package control

import (
	"errors"
	"testing"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

func TestSessionAuthenticator_InvalidatingEventsRejectExistingAccess(t *testing.T) {
	for _, test := range []struct {
		name               string
		setup              func(*testing.T) []store.Event
		invalidate         func(*testing.T) []store.Event
		needsFallbackAdmin bool
	}{
		{
			name: "user disabled",
			setup: func(t *testing.T) []store.Event {
				return []store.Event{sessionUserCreated(t)}
			},
			invalidate: func(t *testing.T) []store.Event {
				event, err := store.UserDisabledEvent(refreshTestSubject)
				if err != nil {
					t.Fatalf("create user-disabled event: %v", err)
				}
				return []store.Event{event}
			},
		},
		{
			name:               "role revoked",
			needsFallbackAdmin: true,
			setup: func(t *testing.T) []store.Event {
				granted, err := store.BootstrapAdminRoleGrantedEvent(refreshTestSubject)
				if err != nil {
					t.Fatalf("create role grant: %v", err)
				}
				return []store.Event{sessionUserCreated(t), granted}
			},
			invalidate: func(t *testing.T) []store.Event {
				event, err := store.RoleRevokedEvent(refreshTestSubject, "admin")
				if err != nil {
					t.Fatalf("create role-revoked event: %v", err)
				}
				return []store.Event{event}
			},
		},
		{
			name: "OIDC identity unlinked",
			setup: func(t *testing.T) []store.Event {
				linked, err := store.OIDCIdentityLinkedEvent(
					refreshTestSubject,
					"workforce",
					"https://identity.example.test",
					"session-subject",
					"session@example.test",
				)
				if err != nil {
					t.Fatalf("create OIDC identity link: %v", err)
				}
				return []store.Event{sessionUserCreated(t), linked}
			},
			invalidate: func(t *testing.T) []store.Event {
				event, err := store.OIDCIdentityUnlinkedEvent(
					refreshTestSubject,
					"workforce",
					"https://identity.example.test",
					"session-subject",
				)
				if err != nil {
					t.Fatalf("create OIDC identity unlink: %v", err)
				}
				return []store.Event{event}
			},
		},
		{
			name: "SCIM user deprovisioned",
			setup: func(t *testing.T) []store.Event {
				linked, err := store.SCIMIdentityLinkedEvent(
					refreshTestSubject,
					"corporate",
					"session-subject",
					"session@example.test",
				)
				if err != nil {
					t.Fatalf("create SCIM identity link: %v", err)
				}
				return []store.Event{sessionUserCreated(t), linked}
			},
			invalidate: func(t *testing.T) []store.Event {
				unlinked, err := store.SCIMIdentityUnlinkedEvent(
					refreshTestSubject,
					"corporate",
					"session-subject",
				)
				if err != nil {
					t.Fatalf("create SCIM identity unlink: %v", err)
				}
				deprovisioned, err := store.SCIMUserDeprovisionedEvent(refreshTestSubject)
				if err != nil {
					t.Fatalf("create SCIM user deprovision: %v", err)
				}
				return []store.Event{unlinked, deprovisioned}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, signer, verifier, _, eventStore, _ := newTestRefreshService(t)
			setup := test.setup(t)
			if err := eventStore.AppendEvents(t.Context(), setup); err != nil {
				t.Fatalf("append session setup: %v", err)
			}
			if test.needsFallbackAdmin {
				appendSessionFallbackAdmin(t, eventStore)
			}
			user, err := eventStore.UserByID(t.Context(), refreshTestSubject)
			if err != nil {
				t.Fatalf("read session user: %v", err)
			}
			token, err := signer.MintAccess(user.UserID, user.SessionVersion)
			if err != nil {
				t.Fatalf("mint access token: %v", err)
			}
			authenticator, err := auth.NewSessionAuthenticator(eventStore, verifier)
			if err != nil {
				t.Fatalf("create session authenticator: %v", err)
			}
			if claims, err := authenticator.AuthenticateAccess(
				t.Context(),
				token,
			); err != nil || claims.Subject != user.UserID {
				t.Fatalf("authenticate current session = (%+v, %v)", claims, err)
			}

			if err := eventStore.AppendEventsWithVersion(
				t.Context(),
				test.invalidate(t),
				int64(len(setup)),
			); err != nil {
				t.Fatalf("append session invalidation: %v", err)
			}
			if _, err := authenticator.AuthenticateAccess(
				t.Context(),
				token,
			); !errors.Is(err, auth.ErrInvalid) {
				t.Fatalf("authenticate invalidated session error = %v; want %v", err, auth.ErrInvalid)
			}
		})
	}
}

func TestSessionAuthenticator_NonInvalidatingSCIMUnlinkKeepsAccess(t *testing.T) {
	_, signer, verifier, _, eventStore, _ := newTestRefreshService(t)
	oidcLinked, err := store.OIDCIdentityLinkedEvent(
		refreshTestSubject,
		"workforce",
		"https://identity.example.test",
		"session-subject",
		"session@example.test",
	)
	if err != nil {
		t.Fatalf("create OIDC identity link: %v", err)
	}
	scimLinked, err := store.SCIMIdentityLinkedEvent(
		refreshTestSubject,
		"corporate",
		"session-subject",
		"session@example.test",
	)
	if err != nil {
		t.Fatalf("create SCIM identity link: %v", err)
	}
	if err := eventStore.AppendEvents(
		t.Context(),
		[]store.Event{sessionUserCreated(t), oidcLinked, scimLinked},
	); err != nil {
		t.Fatalf("append two-link session user: %v", err)
	}
	user, err := eventStore.UserByID(t.Context(), refreshTestSubject)
	if err != nil {
		t.Fatalf("read two-link session user: %v", err)
	}
	token, err := signer.MintAccess(user.UserID, user.SessionVersion)
	if err != nil {
		t.Fatalf("mint access token: %v", err)
	}
	unlinked, err := store.SCIMIdentityUnlinkedEvent(
		refreshTestSubject,
		"corporate",
		"session-subject",
	)
	if err != nil {
		t.Fatalf("create non-invalidating SCIM unlink: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), unlinked, 3); err != nil {
		t.Fatalf("append non-invalidating SCIM unlink: %v", err)
	}
	authenticator, err := auth.NewSessionAuthenticator(eventStore, verifier)
	if err != nil {
		t.Fatalf("create session authenticator: %v", err)
	}
	claims, err := authenticator.AuthenticateAccess(t.Context(), token)
	if err != nil || claims.Subject != refreshTestSubject || claims.SessionVersion != 1 {
		t.Fatalf("authenticate non-invalidated session = (%+v, %v)", claims, err)
	}
}

func TestRefreshService_InvalidatedSessionCannotRotate(t *testing.T) {
	service, _, _, _, eventStore, _ := newTestRefreshService(t)
	granted, err := store.BootstrapAdminRoleGrantedEvent(refreshTestSubject)
	if err != nil {
		t.Fatalf("create refresh-session role grant: %v", err)
	}
	if err := eventStore.AppendEvents(
		t.Context(),
		[]store.Event{sessionUserCreated(t), granted},
	); err != nil {
		t.Fatalf("append refresh session user and role: %v", err)
	}
	tokens, err := service.StartSession(t.Context(), refreshTestSubject)
	if err != nil {
		t.Fatalf("start refresh session: %v", err)
	}
	appendSessionFallbackAdmin(t, eventStore)
	revoked, err := store.RoleRevokedEvent(refreshTestSubject, "admin")
	if err != nil {
		t.Fatalf("create refresh-session role revocation: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), revoked, 2); err != nil {
		t.Fatalf("revoke refresh session role: %v", err)
	}
	if _, err := service.Rotate(
		t.Context(),
		tokens.RefreshToken,
	); !errors.Is(err, auth.ErrRefreshRejected) {
		t.Fatalf("rotate invalidated refresh token error = %v; want %v", err, auth.ErrRefreshRejected)
	}
}

func sessionUserCreated(t *testing.T) store.Event {
	t.Helper()
	event, err := store.UserCreatedEvent(refreshTestSubject, "session@example.test")
	if err != nil {
		t.Fatalf("create session user: %v", err)
	}
	return event
}

func appendSessionFallbackAdmin(t *testing.T, eventStore *store.Store) {
	t.Helper()
	const fallbackID = "01J00000000000000000000221"
	created, err := store.UserCreatedEvent(fallbackID, "fallback-admin@example.test")
	if err != nil {
		t.Fatalf("create fallback admin: %v", err)
	}
	granted, err := store.BootstrapAdminRoleGrantedEvent(fallbackID)
	if err != nil {
		t.Fatalf("create fallback admin role: %v", err)
	}
	if err := eventStore.AppendEvents(
		t.Context(),
		[]store.Event{created, granted},
	); err != nil {
		t.Fatalf("append fallback admin: %v", err)
	}
}
