package store

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"testing"

	"github.com/manchtools/power-manage/sdk/guardtest"
)

func TestSessionInvalidationProjection_ExactEventsBumpOrDeleteUser(t *testing.T) {
	for _, test := range []struct {
		name               string
		setup              func(*testing.T) []Event
		invalidate         func(*testing.T) []Event
		needsFallbackAdmin bool
		wantDisabled       bool
		wantDeleted        bool
	}{
		{
			name: "user disabled",
			setup: func(t *testing.T) []Event {
				return []Event{sessionTestUserCreated(t)}
			},
			invalidate: func(t *testing.T) []Event {
				event, err := UserDisabledEvent(testBootstrapUserID)
				if err != nil {
					t.Fatalf("create user-disabled event: %v", err)
				}
				return []Event{event}
			},
			wantDisabled: true,
		},
		{
			name:               "role revoked",
			needsFallbackAdmin: true,
			setup: func(t *testing.T) []Event {
				created := sessionTestUserCreated(t)
				granted, err := BootstrapAdminRoleGrantedEvent(testBootstrapUserID)
				if err != nil {
					t.Fatalf("create role grant: %v", err)
				}
				return []Event{created, granted}
			},
			invalidate: func(t *testing.T) []Event {
				event, err := RoleRevokedEvent(testBootstrapUserID, "admin")
				if err != nil {
					t.Fatalf("create role-revoked event: %v", err)
				}
				return []Event{event}
			},
		},
		{
			name: "OIDC identity unlinked",
			setup: func(t *testing.T) []Event {
				created := sessionTestUserCreated(t)
				linked, err := OIDCIdentityLinkedEvent(
					testBootstrapUserID,
					"workforce",
					"https://identity.example.test",
					"session-subject",
					"session@example.test",
				)
				if err != nil {
					t.Fatalf("create OIDC identity link: %v", err)
				}
				return []Event{created, linked}
			},
			invalidate: func(t *testing.T) []Event {
				event, err := OIDCIdentityUnlinkedEvent(
					testBootstrapUserID,
					"workforce",
					"https://identity.example.test",
					"session-subject",
				)
				if err != nil {
					t.Fatalf("create OIDC identity unlink: %v", err)
				}
				return []Event{event}
			},
		},
		{
			name: "SCIM user deprovisioned",
			setup: func(t *testing.T) []Event {
				created := sessionTestUserCreated(t)
				linked, err := SCIMIdentityLinkedEvent(
					testBootstrapUserID,
					testSCIMProviderSlug,
					"session-subject",
					"session@example.test",
				)
				if err != nil {
					t.Fatalf("create SCIM identity link: %v", err)
				}
				return []Event{created, linked}
			},
			invalidate: func(t *testing.T) []Event {
				unlinked, err := SCIMIdentityUnlinkedEvent(
					testBootstrapUserID,
					testSCIMProviderSlug,
					"session-subject",
				)
				if err != nil {
					t.Fatalf("create SCIM identity unlink: %v", err)
				}
				deprovisioned, err := SCIMUserDeprovisionedEvent(testBootstrapUserID)
				if err != nil {
					t.Fatalf("create SCIM deprovision event: %v", err)
				}
				return []Event{unlinked, deprovisioned}
			},
			wantDeleted: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			eventStore := sessionTestStore(t)
			setup := test.setup(t)
			if err := eventStore.AppendEvents(t.Context(), setup); err != nil {
				t.Fatalf("append invalidation setup: %v", err)
			}
			if test.needsFallbackAdmin {
				seedFallbackAdmin(t, eventStore)
			}
			before, err := eventStore.UserByID(t.Context(), testBootstrapUserID)
			if err != nil {
				t.Fatalf("read user before invalidation: %v", err)
			}
			if before.SessionVersion != 1 || before.Disabled {
				t.Fatalf("initial session state = %+v; want version one enabled", before)
			}

			invalidating := test.invalidate(t)
			if err := eventStore.AppendEventsWithVersion(
				t.Context(),
				invalidating,
				int64(len(setup)),
			); err != nil {
				t.Fatalf("append invalidation events: %v", err)
			}
			after, err := eventStore.UserByID(t.Context(), testBootstrapUserID)
			if test.wantDeleted {
				if !IsNotFound(err) {
					t.Fatalf("terminal invalidation user error = %v; want not found", err)
				}
			} else {
				if err != nil {
					t.Fatalf("read user after invalidation: %v", err)
				}
				if after.SessionVersion != 2 || after.Disabled != test.wantDisabled {
					t.Fatalf(
						"session state after invalidation = %+v; want version two disabled=%t",
						after,
						test.wantDisabled,
					)
				}
			}

			if err := eventStore.RebuildAll(t.Context(), UserRebuildTarget); err != nil {
				t.Fatalf("rebuild invalidated user: %v", err)
			}
			rebuilt, err := eventStore.UserByID(t.Context(), testBootstrapUserID)
			if test.wantDeleted {
				if !IsNotFound(err) {
					t.Fatalf("rebuilt terminal invalidation user error = %v; want not found", err)
				}
			} else if err != nil ||
				rebuilt.SessionVersion != 2 ||
				rebuilt.Disabled != test.wantDisabled {
				t.Fatalf(
					"rebuilt session state = (%+v, %v); want version two disabled=%t",
					rebuilt,
					err,
					test.wantDisabled,
				)
			}
		})
	}
}

func TestSessionInvalidationProjection_NonTerminalSCIMUnlinkKeepsVersion(t *testing.T) {
	eventStore := sessionTestStore(t)
	created := sessionTestUserCreated(t)
	oidcLinked, err := OIDCIdentityLinkedEvent(
		testBootstrapUserID,
		"workforce",
		"https://identity.example.test",
		"session-subject",
		"session@example.test",
	)
	if err != nil {
		t.Fatalf("create OIDC link: %v", err)
	}
	scimLinked, err := SCIMIdentityLinkedEvent(
		testBootstrapUserID,
		testSCIMProviderSlug,
		"session-subject",
		"session@example.test",
	)
	if err != nil {
		t.Fatalf("create SCIM link: %v", err)
	}
	if err := eventStore.AppendEvents(
		t.Context(),
		[]Event{created, oidcLinked, scimLinked},
	); err != nil {
		t.Fatalf("append two-link user: %v", err)
	}
	unlinked, err := SCIMIdentityUnlinkedEvent(
		testBootstrapUserID,
		testSCIMProviderSlug,
		"session-subject",
	)
	if err != nil {
		t.Fatalf("create non-terminal unlink: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), unlinked, 3); err != nil {
		t.Fatalf("append non-terminal unlink: %v", err)
	}
	user, err := eventStore.UserByID(t.Context(), testBootstrapUserID)
	if err != nil {
		t.Fatalf("read non-terminally unlinked user: %v", err)
	}
	if user.SessionVersion != 1 || user.Disabled {
		t.Fatalf("non-invalidating unlink session state = %+v; want version one enabled", user)
	}
}

func TestGuard_SessionInvalidatingEventsUseOneProjector(t *testing.T) {
	definitions := productionEventDefinitions()
	want := []string{
		oidcIdentityUnlinkedEventType,
		roleRevokedEventType,
		scimUserDeprovisionedEventType,
		userDisabledEventType,
	}
	slices.Sort(want)
	projector := reflect.ValueOf(projectSessionInvalidation).Pointer()
	got := guardtest.Discover(t, "central session-invalidation event registrations", 4, func() ([]string, error) {
		var eventTypes []string
		for eventType, definition := range definitions {
			if reflect.ValueOf(definition.Projector).Pointer() == projector {
				eventTypes = append(eventTypes, eventType)
			}
		}
		return eventTypes, nil
	})
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("central invalidation event set = %v; want %v", got, want)
	}

	caseNames := guardtest.Discover(t, "central session-invalidation switch cases", 4, func() ([]string, error) {
		return sessionInvalidationSwitchCases("session_invalidation.go")
	})
	wantCases := []string{
		"oidcIdentityUnlinkedEventType",
		"roleRevokedEventType",
		"scimUserDeprovisionedEventType",
		"userDisabledEventType",
	}
	slices.Sort(wantCases)
	if !slices.Equal(caseNames, wantCases) {
		t.Fatalf("central invalidation switch cases = %v; want %v", caseNames, wantCases)
	}

	writers := guardtest.Discover(t, "session-version SQL writers", 1, sessionVersionSQLWriters)
	if !slices.Equal(writers, []string{"session_invalidation.sql"}) {
		t.Fatalf("session-version SQL writers = %v; want only session_invalidation.sql", writers)
	}
}

func sessionInvalidationSwitchCases(path string) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}
	caseNames := make(map[string]struct{})
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "projectSessionInvalidation" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			clause, ok := node.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, expression := range clause.List {
				identifier, ok := expression.(*ast.Ident)
				if ok {
					caseNames[identifier.Name] = struct{}{}
				}
			}
			return true
		})
	}
	result := make([]string, 0, len(caseNames))
	for name := range caseNames {
		result = append(result, name)
	}
	slices.Sort(result)
	return result, nil
}

func TestGuard_BootstrapAdminRevocationPayloadMatchesLastAdminSQL(t *testing.T) {
	const literal = `{"role":"admin"}`

	guardtest.Discover(t, "bootstrap-admin revocation payload contracts", 1, func() ([]string, error) {
		event, ok := sessionInvalidationGoldenCorpus()[roleRevokedEventType]
		if !ok {
			return nil, fmt.Errorf("golden corpus lacks %q", roleRevokedEventType)
		}
		if !bytes.Equal(event.Payload, []byte(literal)) {
			return nil, fmt.Errorf(
				"role-revoked payload = %q; want %q",
				event.Payload,
				literal,
			)
		}

		query, err := os.ReadFile(filepath.Join("queries", "authorization.sql"))
		if err != nil {
			return nil, fmt.Errorf("read authorization query: %w", err)
		}
		wantClause := []byte(
			"revoked.payload = convert_to('" + literal + "', 'UTF8')",
		)
		if !bytes.Contains(query, wantClause) {
			return nil, fmt.Errorf(
				"authorization query lacks canonical %q payload comparison",
				roleRevokedEventType,
			)
		}
		return []string{roleRevokedEventType}, nil
	})
}

func sessionVersionSQLWriters() ([]string, error) {
	paths, err := filepath.Glob(filepath.Join("queries", "*.sql"))
	if err != nil {
		return nil, err
	}
	pattern := regexp.MustCompile(`(?i)\bSET\s+session_version\s*=`)
	var writers []string
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		for range pattern.FindAll(content, -1) {
			writers = append(writers, filepath.Base(path))
		}
	}
	slices.Sort(writers)
	return writers, nil
}

func sessionTestStore(t *testing.T) *Store {
	t.Helper()
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	return eventStore
}

func sessionTestUserCreated(t *testing.T) Event {
	t.Helper()
	event, err := UserCreatedEvent(testBootstrapUserID, "session@example.test")
	if err != nil {
		t.Fatalf("create session test user: %v", err)
	}
	return event
}
