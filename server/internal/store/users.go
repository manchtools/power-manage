package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	userStreamType              = "user"
	userCreatedEventType        = "UserCreated"
	bootstrapAdminGrantedType   = "BootstrapAdminRoleGranted"
	oidcIdentityLinkedEventType = "OIDCIdentityLinked"
	userPayloadVersion          = 1
	maxOIDCIssuerBytes          = 2048
	maxOIDCExternalSubjectBytes = 1024
	maxCanonicalUserEmailBytes  = 320
)

// UserRebuildTarget is the CLI-only production user recovery target.
const UserRebuildTarget = "users"

// User is one event-derived human account projection.
type User struct {
	UserID            string
	Email             string
	ProjectionVersion int64
}

type userCreatedPayload struct {
	Email string `json:"email"`
}

type bootstrapAdminRoleGrantedPayload struct {
	Role string `json:"role"`
}

type oidcIdentityLinkedPayload struct {
	ProviderSlug    string `json:"provider_slug"`
	Issuer          string `json:"issuer"`
	ExternalSubject string `json:"external_subject"`
	Email           string `json:"email"`
}

// UserCreatedEvent creates one canonical user stream.
func UserCreatedEvent(userID, email string) (Event, error) {
	userID, err := canonicalUserID(userID)
	if err != nil {
		return Event{}, err
	}
	email, err = CanonicalUserEmail(email)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(userCreatedPayload{Email: email})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode user creation: %w", err)
	}
	return userEvent(userID, userCreatedEventType, payload), nil
}

// BootstrapAdminRoleGrantedEvent records the first-boot admin grant before a
// break-glass URL can be minted.
func BootstrapAdminRoleGrantedEvent(userID string) (Event, error) {
	userID, err := canonicalUserID(userID)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(bootstrapAdminRoleGrantedPayload{Role: "admin"})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode bootstrap admin role grant: %w", err)
	}
	return userEvent(userID, bootstrapAdminGrantedType, payload), nil
}

// OIDCIdentityLinkedEvent links one configured provider identity to a user.
func OIDCIdentityLinkedEvent(
	userID string,
	providerSlug string,
	issuer string,
	externalSubject string,
	email string,
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
	email, err = CanonicalUserEmail(email)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(oidcIdentityLinkedPayload{
		ProviderSlug:    providerSlug,
		Issuer:          issuer,
		ExternalSubject: externalSubject,
		Email:           email,
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode OIDC identity link: %w", err)
	}
	return userEvent(userID, oidcIdentityLinkedEventType, payload), nil
}

// UserByID reads one validated user projection.
func (s *Store) UserByID(ctx context.Context, userID string) (User, error) {
	if s == nil || s.pool == nil {
		return User{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return User{}, errors.New("store: nil user context")
	}
	userID, err := canonicalUserID(userID)
	if err != nil {
		return User{}, err
	}
	row, err := generated.New(s.pool).GetUserByID(ctx, userID)
	if err != nil {
		return User{}, fmt.Errorf("store: read user by ID: %w", err)
	}
	return validateUserProjection(row.UserID, row.Email, row.ProjectionVersion)
}

// UserByEmail reads one user by canonicalized email.
func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	if s == nil || s.pool == nil {
		return User{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return User{}, errors.New("store: nil user context")
	}
	email, err := CanonicalUserEmail(email)
	if err != nil {
		return User{}, err
	}
	row, err := generated.New(s.pool).GetUserByEmail(ctx, email)
	if err != nil {
		return User{}, fmt.Errorf("store: read user by email: %w", err)
	}
	return validateUserProjection(row.UserID, row.Email, row.ProjectionVersion)
}

// UserByOIDCIdentity resolves one exact issuer/subject pair.
func (s *Store) UserByOIDCIdentity(
	ctx context.Context,
	issuer string,
	externalSubject string,
) (User, error) {
	if s == nil || s.pool == nil {
		return User{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return User{}, errors.New("store: nil user context")
	}
	issuer, err := canonicalOIDCIssuer(issuer)
	if err != nil {
		return User{}, err
	}
	if !validBoundedText(externalSubject, maxOIDCExternalSubjectBytes) {
		return User{}, errors.New("store: OIDC external subject is invalid")
	}
	row, err := generated.New(s.pool).GetUserByOIDCIdentity(
		ctx,
		generated.GetUserByOIDCIdentityParams{
			Issuer:          issuer,
			ExternalSubject: externalSubject,
		},
	)
	if err != nil {
		return User{}, fmt.Errorf("store: read user by OIDC identity: %w", err)
	}
	return validateUserProjection(row.UserID, row.Email, row.ProjectionVersion)
}

// UserOIDCIdentityCount returns the number of configured-provider links.
func (s *Store) UserOIDCIdentityCount(ctx context.Context, userID string) (int64, error) {
	if s == nil || s.pool == nil {
		return 0, errors.New("store: nil store")
	}
	if ctx == nil {
		return 0, errors.New("store: nil user context")
	}
	userID, err := canonicalUserID(userID)
	if err != nil {
		return 0, err
	}
	count, err := generated.New(s.pool).CountUserOIDCIdentities(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("store: count user OIDC identities: %w", err)
	}
	if count < 0 {
		return 0, errors.New("store: user OIDC identity count is invalid")
	}
	return count, nil
}

func userEvent(userID, eventType string, payload []byte) Event {
	return Event{
		StreamType:     userStreamType,
		StreamID:       userID,
		EventType:      eventType,
		PayloadVersion: userPayloadVersion,
		Payload:        payload,
	}
}

func canonicalUserID(userID string) (string, error) {
	if err := validate.ULIDPathID(userID); err != nil {
		return "", fmt.Errorf("store: user ID is invalid: %w", err)
	}
	return strings.ToUpper(userID), nil
}

// CanonicalUserEmail validates and normalizes an OIDC or SCIM email key.
func CanonicalUserEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !utf8.ValidString(email) ||
		len(email) < 3 || len(email) > maxCanonicalUserEmailBytes ||
		strings.Count(email, "@") != 1 {
		return "", errors.New("store: user email is invalid")
	}
	local, domain, _ := strings.Cut(email, "@")
	if local == "" || domain == "" || strings.HasPrefix(domain, ".") ||
		strings.HasSuffix(domain, ".") {
		return "", errors.New("store: user email is invalid")
	}
	for _, character := range email {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return "", errors.New("store: user email is invalid")
		}
	}
	return email, nil
}

func canonicalOIDCIssuer(issuer string) (string, error) {
	if !validBoundedText(issuer, maxOIDCIssuerBytes) {
		return "", errors.New("store: OIDC issuer is invalid")
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("store: OIDC issuer is invalid")
	}
	return parsed.String(), nil
}

func userEventDefinitions() map[string]eventDefinition {
	return map[string]eventDefinition{
		userCreatedEventType: {
			PayloadVersion: userPayloadVersion,
			PayloadType:    userCreatedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(userCreatedPayload{Email: "person@example.test"})
			},
			Projector: projectUserCreation,
		},
		bootstrapAdminGrantedType: {
			PayloadVersion: userPayloadVersion,
			PayloadType:    bootstrapAdminRoleGrantedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(bootstrapAdminRoleGrantedPayload{Role: "admin"})
			},
			Projector: projectBootstrapAdminRoleGrant,
		},
		oidcIdentityLinkedEventType: {
			PayloadVersion: userPayloadVersion,
			PayloadType:    oidcIdentityLinkedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(oidcIdentityLinkedPayload{
					ProviderSlug:    "corporate",
					Issuer:          "https://identity.example.test",
					ExternalSubject: "external-subject-1",
					Email:           "person@example.test",
				})
			},
			Projector: projectOIDCIdentityLink,
		},
	}
}

func userGoldenCorpus() map[string]goldenEvent {
	return map[string]goldenEvent{
		userCreatedEventType: {
			PayloadVersion: userPayloadVersion,
			Payload:        []byte(`{"email":"person@example.test"}`),
		},
		bootstrapAdminGrantedType: {
			PayloadVersion: userPayloadVersion,
			Payload:        []byte(`{"role":"admin"}`),
		},
		oidcIdentityLinkedEventType: {
			PayloadVersion: userPayloadVersion,
			Payload: []byte(
				`{"provider_slug":"corporate","issuer":"https://identity.example.test","external_subject":"external-subject-1","email":"person@example.test"}`,
			),
		},
	}
}

func projectBootstrapAdminRoleGrant(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	// This event belongs only to the atomic first-boot create batch. General
	// grants on existing user streams are owned by SPEC-008.
	if event.StreamVersion != 2 {
		return fmt.Errorf(
			"store: bootstrap admin role grant must be stream version 2, got %d",
			event.StreamVersion,
		)
	}
	userID, err := canonicalUserID(event.StreamID)
	if err != nil || userID != event.StreamID {
		return errors.New("store: bootstrap admin role-grant stream ID is not canonical")
	}
	payload, err := decodeEventPayload[bootstrapAdminRoleGrantedPayload](
		event,
		userPayloadVersion,
	)
	if err != nil {
		return err
	}
	if payload.Role != "admin" {
		return errors.New("store: bootstrap admin role grant is invalid")
	}
	queries := generated.New(tx)
	user, err := queries.GetUserByID(ctx, event.StreamID)
	if err != nil {
		return fmt.Errorf("store: bootstrap admin role grant requires a prior user: %w", err)
	}
	if user.ProjectionVersion != event.StreamVersion-1 {
		return errors.New("store: user projection version is inconsistent")
	}
	affected, err := queries.AdvanceUserProjectionVersionForBootstrapAdmin(
		ctx,
		generated.AdvanceUserProjectionVersionForBootstrapAdminParams{
			ProjectionVersion:         event.StreamVersion,
			UpdatedAt:                 event.CreatedAt,
			UserID:                    event.StreamID,
			Email:                     user.Email,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project bootstrap admin role grant: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: bootstrap admin role grant advanced %d users; want one", affected)
	}
	return nil
}

func projectUserCreation(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion != 1 {
		return fmt.Errorf("store: user creation must be stream version 1, got %d", event.StreamVersion)
	}
	userID, err := canonicalUserID(event.StreamID)
	if err != nil || userID != event.StreamID {
		return errors.New("store: user creation stream ID is not canonical")
	}
	payload, err := decodeEventPayload[userCreatedPayload](event, userPayloadVersion)
	if err != nil {
		return err
	}
	email, err := CanonicalUserEmail(payload.Email)
	if err != nil || email != payload.Email {
		return errors.New("store: user creation email is not canonical")
	}
	affected, err := generated.New(tx).InsertUser(ctx, generated.InsertUserParams{
		UserID:            event.StreamID,
		Email:             email,
		ProjectionVersion: event.StreamVersion,
		UpdatedAt:         event.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("store: project user creation: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: user creation affected %d users; want one", affected)
	}
	return nil
}

func projectOIDCIdentityLink(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: OIDC identity link requires a prior user")
	}
	userID, err := canonicalUserID(event.StreamID)
	if err != nil || userID != event.StreamID {
		return errors.New("store: OIDC identity link stream ID is not canonical")
	}
	payload, err := decodeEventPayload[oidcIdentityLinkedPayload](event, userPayloadVersion)
	if err != nil {
		return err
	}
	if !validProviderSlug(payload.ProviderSlug) {
		return errors.New("store: OIDC provider slug is invalid")
	}
	issuer, err := canonicalOIDCIssuer(payload.Issuer)
	if err != nil || issuer != payload.Issuer {
		return errors.New("store: OIDC issuer is not canonical")
	}
	if !validBoundedText(payload.ExternalSubject, maxOIDCExternalSubjectBytes) {
		return errors.New("store: OIDC external subject is invalid")
	}
	email, err := CanonicalUserEmail(payload.Email)
	if err != nil || email != payload.Email {
		return errors.New("store: OIDC identity email is not canonical")
	}
	queries := generated.New(tx)
	user, err := queries.GetUserByID(ctx, event.StreamID)
	if err != nil {
		if IsNotFound(err) {
			return errors.New("store: OIDC identity link requires a prior user")
		}
		return fmt.Errorf("store: inspect user before OIDC identity link: %w", err)
	}
	if user.ProjectionVersion != event.StreamVersion-1 {
		return errors.New("store: user projection version is inconsistent")
	}
	if user.Email != email {
		return errors.New("store: OIDC identity email does not match user")
	}
	affected, err := queries.InsertOIDCIdentity(ctx, generated.InsertOIDCIdentityParams{
		Issuer:            issuer,
		ExternalSubject:   payload.ExternalSubject,
		ProviderSlug:      payload.ProviderSlug,
		UserID:            event.StreamID,
		Email:             email,
		ProjectionVersion: event.StreamVersion,
		UpdatedAt:         event.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("store: project OIDC identity link: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: OIDC identity link affected %d identities; want one", affected)
	}
	affected, err = queries.AdvanceUserProjectionVersion(
		ctx,
		generated.AdvanceUserProjectionVersionParams{
			ProjectionVersion:         event.StreamVersion,
			UpdatedAt:                 event.CreatedAt,
			UserID:                    event.StreamID,
			Email:                     email,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: advance user after OIDC identity link: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: OIDC identity link advanced %d users; want one", affected)
	}
	return nil
}

func validateUserProjection(userID, email string, version int64) (User, error) {
	canonicalID, err := canonicalUserID(userID)
	if err != nil || canonicalID != userID {
		return User{}, errors.New("store: user projection has an invalid user ID")
	}
	canonicalEmail, err := CanonicalUserEmail(email)
	if err != nil || canonicalEmail != email {
		return User{}, errors.New("store: user projection has an invalid email")
	}
	if version <= 0 {
		return User{}, errors.New("store: user projection has an invalid version")
	}
	return User{UserID: userID, Email: email, ProjectionVersion: version}, nil
}

func resetUsers(ctx context.Context, tx ProjectionTx) error {
	queries := generated.New(tx)
	if err := queries.ResetOIDCIdentities(ctx); err != nil {
		return fmt.Errorf("store: reset OIDC identities: %w", err)
	}
	if err := queries.ResetUsers(ctx); err != nil {
		return fmt.Errorf("store: reset users: %w", err)
	}
	return nil
}
