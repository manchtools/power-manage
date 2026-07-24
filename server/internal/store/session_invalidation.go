package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	userDisabledEventType         = "UserDisabled"
	roleRevokedEventType          = "RoleRevoked"
	oidcIdentityUnlinkedEventType = "OIDCIdentityUnlinked"
	maxRoleNameBytes              = 64
)

type userDisabledPayload struct{}

type roleRevokedPayload struct {
	Role string `json:"role"`
}

type oidcIdentityUnlinkedPayload struct {
	ProviderSlug    string `json:"provider_slug"`
	Issuer          string `json:"issuer"`
	ExternalSubject string `json:"external_subject"`
}

// UserDisabledEvent records an account disable that invalidates all sessions.
func UserDisabledEvent(userID string) (Event, error) {
	userID, err := canonicalUserID(userID)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(userDisabledPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode user disable: %w", err)
	}
	return userEvent(userID, userDisabledEventType, payload), nil
}

// RoleRevokedEvent records a role removal that invalidates all sessions.
func RoleRevokedEvent(userID, role string) (Event, error) {
	userID, err := canonicalUserID(userID)
	if err != nil {
		return Event{}, err
	}
	role = strings.TrimSpace(role)
	if !validRoleName(role) {
		return Event{}, errors.New("store: revoked role is invalid")
	}
	payload, err := json.Marshal(roleRevokedPayload{Role: role})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode role revocation: %w", err)
	}
	return userEvent(userID, roleRevokedEventType, payload), nil
}

// OIDCIdentityUnlinkedEvent records an IdP unlink that invalidates all sessions.
func OIDCIdentityUnlinkedEvent(
	userID string,
	providerSlug string,
	issuer string,
	externalSubject string,
) (Event, error) {
	userID, err := canonicalUserID(userID)
	if err != nil {
		return Event{}, err
	}
	if !validProviderSlug(providerSlug) {
		return Event{}, errors.New("store: OIDC provider slug is invalid")
	}
	issuer, err = canonicalOIDCIssuer(issuer)
	if err != nil {
		return Event{}, err
	}
	if !validBoundedText(externalSubject, maxOIDCExternalSubjectBytes) {
		return Event{}, errors.New("store: OIDC external subject is invalid")
	}
	payload, err := json.Marshal(oidcIdentityUnlinkedPayload{
		ProviderSlug:    providerSlug,
		Issuer:          issuer,
		ExternalSubject: externalSubject,
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode OIDC identity unlink: %w", err)
	}
	return userEvent(userID, oidcIdentityUnlinkedEventType, payload), nil
}

func sessionInvalidationEventDefinitions() map[string]eventDefinition {
	return map[string]eventDefinition{
		userDisabledEventType: {
			PayloadVersion: userPayloadVersion,
			PayloadType:    userDisabledPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(userDisabledPayload{})
			},
			Projector: projectSessionInvalidation,
		},
		roleRevokedEventType: {
			PayloadVersion: userPayloadVersion,
			PayloadType:    roleRevokedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(roleRevokedPayload{Role: "admin"})
			},
			Projector: projectSessionInvalidation,
		},
		oidcIdentityUnlinkedEventType: {
			PayloadVersion: userPayloadVersion,
			PayloadType:    oidcIdentityUnlinkedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(oidcIdentityUnlinkedPayload{
					ProviderSlug:    "corporate",
					Issuer:          "https://identity.example.test",
					ExternalSubject: "external-subject-1",
				})
			},
			Projector: projectSessionInvalidation,
		},
		scimUserDeprovisionedEventType: {
			PayloadVersion: scimPayloadVersion,
			PayloadType:    scimUserDeprovisionedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(scimUserDeprovisionedPayload{})
			},
			Projector: projectSessionInvalidation,
		},
	}
}

func sessionInvalidationGoldenCorpus() map[string]goldenEvent {
	return map[string]goldenEvent{
		userDisabledEventType: {
			PayloadVersion: userPayloadVersion,
			Payload:        []byte(`{}`),
		},
		roleRevokedEventType: {
			PayloadVersion: userPayloadVersion,
			Payload:        []byte(`{"role":"admin"}`),
		},
		oidcIdentityUnlinkedEventType: {
			PayloadVersion: userPayloadVersion,
			Payload: []byte(
				`{"provider_slug":"corporate","issuer":"https://identity.example.test","external_subject":"external-subject-1"}`,
			),
		},
		scimUserDeprovisionedEventType: {
			PayloadVersion: scimPayloadVersion,
			Payload:        []byte(`{}`),
		},
	}
}

func projectSessionInvalidation(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: session invalidation requires a prior user")
	}
	userID, err := canonicalUserID(event.StreamID)
	if err != nil || userID != event.StreamID {
		return errors.New("store: session invalidation user ID is invalid")
	}
	queries := generated.New(tx)
	user, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("store: session invalidation requires a prior user: %w", err)
	}
	if user.ProjectionVersion != event.StreamVersion-1 {
		return errors.New("store: session invalidation user version is inconsistent")
	}

	disableUser := false
	var oidcPayload oidcIdentityUnlinkedPayload
	switch event.EventType {
	case userDisabledEventType:
		if _, err := decodeEventPayload[userDisabledPayload](event, userPayloadVersion); err != nil {
			return err
		}
		disableUser = true
	case roleRevokedEventType:
		payload, err := decodeEventPayload[roleRevokedPayload](event, userPayloadVersion)
		if err != nil {
			return err
		}
		if !validRoleName(payload.Role) {
			return errors.New("store: revoked role is invalid")
		}
	case oidcIdentityUnlinkedEventType:
		oidcPayload, err = validateOIDCIdentityUnlink(event)
		if err != nil {
			return err
		}
	case scimUserDeprovisionedEventType:
		if _, err := decodeEventPayload[scimUserDeprovisionedPayload](
			event,
			scimPayloadVersion,
		); err != nil {
			return err
		}
		count, err := queries.CountUserIdentityLinks(ctx, userID)
		if err != nil {
			return fmt.Errorf("store: count links before SCIM user deprovision: %w", err)
		}
		if count != 0 {
			return errors.New("store: SCIM user deprovision requires zero remaining links")
		}
	default:
		return fmt.Errorf("store: event %q cannot invalidate sessions", event.EventType)
	}

	affected, err := queries.InvalidateUserSession(
		ctx,
		generated.InvalidateUserSessionParams{
			DisableUser:               disableUser,
			ProjectionVersion:         event.StreamVersion,
			UpdatedAt:                 event.CreatedAt,
			UserID:                    userID,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: invalidate user session: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: session invalidation affected %d users; want one", affected)
	}

	switch event.EventType {
	case oidcIdentityUnlinkedEventType:
		affected, err := queries.DeleteOIDCIdentityForInvalidation(
			ctx,
			generated.DeleteOIDCIdentityForInvalidationParams{
				Issuer:          oidcPayload.Issuer,
				ExternalSubject: oidcPayload.ExternalSubject,
				ProviderSlug:    oidcPayload.ProviderSlug,
				UserID:          userID,
			},
		)
		if err != nil {
			return fmt.Errorf("store: project OIDC identity unlink: %w", err)
		}
		if affected != 1 {
			return fmt.Errorf("store: OIDC identity unlink affected %d identities; want one", affected)
		}
	case scimUserDeprovisionedEventType:
		if err := deleteSCIMGroupMembershipsForUserProjection(
			ctx,
			queries,
			userID,
		); err != nil {
			return fmt.Errorf("store: delete SCIM memberships for deprovisioned user: %w", err)
		}
		affected, err := queries.DeleteUserProjectionAfterInvalidation(
			ctx,
			generated.DeleteUserProjectionAfterInvalidationParams{
				UserID:            userID,
				ProjectionVersion: event.StreamVersion,
			},
		)
		if err != nil {
			return fmt.Errorf("store: project SCIM user deprovision: %w", err)
		}
		if affected != 1 {
			return fmt.Errorf("store: SCIM user deprovision affected %d users; want one", affected)
		}
	}
	return nil
}

func validateOIDCIdentityUnlink(event PersistedEvent) (oidcIdentityUnlinkedPayload, error) {
	payload, err := decodeEventPayload[oidcIdentityUnlinkedPayload](event, userPayloadVersion)
	if err != nil {
		return oidcIdentityUnlinkedPayload{}, err
	}
	issuer, err := canonicalOIDCIssuer(payload.Issuer)
	if err != nil || issuer != payload.Issuer ||
		!validProviderSlug(payload.ProviderSlug) ||
		!validBoundedText(payload.ExternalSubject, maxOIDCExternalSubjectBytes) {
		return oidcIdentityUnlinkedPayload{}, errors.New("store: OIDC identity unlink is invalid")
	}
	return payload, nil
}

func validRoleName(role string) bool {
	if role == "" || role != strings.TrimSpace(role) || len(role) > maxRoleNameBytes ||
		role[0] < 'a' || role[0] > 'z' {
		return false
	}
	for _, character := range []byte(role[1:]) {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}
