package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	userStreamType              = "user"
	userCreatedEventType        = "UserCreated"
	userManagedUpdatedEventType = "UserManagedUpdated"
	userManagedDeletedEventType = "UserManagedDeleted"
	bootstrapAdminGrantedType   = "BootstrapAdminRoleGranted"
	oidcIdentityLinkedEventType = "OIDCIdentityLinked"
	userPayloadVersion          = 1
	maxOIDCIssuerBytes          = 2048
	maxOIDCExternalSubjectBytes = 1024
	maxCanonicalUserEmailBytes  = 320
)

var errUserExists = errors.New("store: user already exists")

// UserRebuildTarget is the CLI-only production user recovery target.
const UserRebuildTarget = "users"

// User is one event-derived human account projection.
type User struct {
	UserID            string
	Email             string
	SessionVersion    int64
	Disabled          bool
	ProjectionVersion int64
}

type userCreatedPayload struct {
	Email string `json:"email"`
}

type userManagedDeletedPayload struct{}

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

// UserManagedUpdatedEvent records a full replacement of management-owned user fields.
func UserManagedUpdatedEvent(userID, email string) (Event, error) {
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
		return Event{}, fmt.Errorf("store: encode managed user update: %w", err)
	}
	return userEvent(userID, userManagedUpdatedEventType, payload), nil
}

// UserManagedDeletedEvent removes one user projection.
func UserManagedDeletedEvent(userID string) (Event, error) {
	userID, err := canonicalUserID(userID)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(userManagedDeletedPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode managed user deletion: %w", err)
	}
	return userEvent(userID, userManagedDeletedEventType, payload), nil
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
	return validateUserProjection(
		row.UserID,
		row.Email,
		row.SessionVersion,
		row.Disabled,
		row.ProjectionVersion,
	)
}

// ScopedUserByID reads one user through the kernel's explicit scope predicate.
func (s *Store) ScopedUserByID(
	ctx context.Context,
	userID string,
	global bool,
	userGroupIDs []string,
	selfID string,
) (User, error) {
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
	userGroupIDs, err = normalizeUserScopeIDs(userGroupIDs)
	if err != nil {
		return User{}, err
	}
	if selfID != "" {
		selfID, err = canonicalUserID(selfID)
		if err != nil {
			return User{}, err
		}
	}
	row, err := generated.New(s.pool).GetScopedUserByID(
		ctx,
		generated.GetScopedUserByIDParams{
			UserID:       userID,
			GlobalScope:  global,
			SelfID:       selfID,
			UserGroupIds: userGroupIDs,
		},
	)
	if err != nil {
		return User{}, fmt.Errorf("store: read scoped user: %w", err)
	}
	return validateUserProjection(
		row.UserID,
		row.Email,
		row.SessionVersion,
		row.Disabled,
		row.ProjectionVersion,
	)
}

// ListScopedUsers returns one explicitly scope-confined user page.
func (s *Store) ListScopedUsers(
	ctx context.Context,
	global bool,
	userGroupIDs []string,
	selfID string,
	limit int32,
) ([]User, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("store: nil store")
	}
	if ctx == nil || limit < 1 || limit > 200 {
		return nil, errors.New("store: invalid user list")
	}
	userGroupIDs, err := normalizeUserScopeIDs(userGroupIDs)
	if err != nil {
		return nil, err
	}
	if selfID != "" {
		selfID, err = canonicalUserID(selfID)
		if err != nil {
			return nil, err
		}
	}
	rows, err := generated.New(s.pool).ListScopedUsers(
		ctx,
		generated.ListScopedUsersParams{
			GlobalScope:  global,
			SelfID:       selfID,
			UserGroupIds: userGroupIDs,
			PageLimit:    limit,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("store: list scoped users: %w", err)
	}
	users := make([]User, len(rows))
	for index, row := range rows {
		users[index], err = validateUserProjection(
			row.UserID,
			row.Email,
			row.SessionVersion,
			row.Disabled,
			row.ProjectionVersion,
		)
		if err != nil {
			return nil, err
		}
	}
	return users, nil
}

// IsUserExists recognizes a duplicate user creation.
func IsUserExists(err error) bool {
	return errors.Is(err, errUserExists)
}

// UserManagementEventTypes returns the exact user CRUD event set.
func UserManagementEventTypes() []string {
	return []string{
		userCreatedEventType,
		userManagedUpdatedEventType,
		userManagedDeletedEventType,
	}
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
	return validateUserProjection(
		row.UserID,
		row.Email,
		row.SessionVersion,
		row.Disabled,
		row.ProjectionVersion,
	)
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
	return validateUserProjection(
		row.UserID,
		row.Email,
		row.SessionVersion,
		row.Disabled,
		row.ProjectionVersion,
	)
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

func normalizeUserScopeIDs(ids []string) ([]string, error) {
	normalized := make([]string, len(ids))
	for index, id := range ids {
		var err error
		normalized[index], err = canonicalUserID(id)
		if err != nil {
			return nil, err
		}
	}
	slices.Sort(normalized)
	return slices.Compact(normalized), nil
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
	definitions := map[string]eventDefinition{
		userCreatedEventType: {
			PayloadVersion: userPayloadVersion,
			PayloadType:    userCreatedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(userCreatedPayload{Email: "person@example.test"})
			},
			Projector: projectUserCreation,
		},
		userManagedUpdatedEventType: {
			PayloadVersion: userPayloadVersion,
			PayloadType:    userCreatedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(userCreatedPayload{Email: "updated@example.test"})
			},
			Projector: projectManagedUserUpdate,
		},
		userManagedDeletedEventType: {
			PayloadVersion: userPayloadVersion,
			PayloadType:    userManagedDeletedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(userManagedDeletedPayload{})
			},
			Projector: projectManagedUserDeletion,
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
	for eventType, definition := range scimUserEventDefinitions() {
		definitions[eventType] = definition
	}
	for eventType, definition := range sessionInvalidationEventDefinitions() {
		definitions[eventType] = definition
	}
	return definitions
}

func userGoldenCorpus() map[string]goldenEvent {
	corpus := map[string]goldenEvent{
		userCreatedEventType: {
			PayloadVersion: userPayloadVersion,
			Payload:        []byte(`{"email":"person@example.test"}`),
		},
		userManagedUpdatedEventType: {
			PayloadVersion: userPayloadVersion,
			Payload:        []byte(`{"email":"updated@example.test"}`),
		},
		userManagedDeletedEventType: {
			PayloadVersion: userPayloadVersion,
			Payload:        []byte(`{}`),
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
	for eventType, event := range scimUserGoldenCorpus() {
		corpus[eventType] = event
	}
	for eventType, event := range sessionInvalidationGoldenCorpus() {
		corpus[eventType] = event
	}
	return corpus
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
		return errors.New("store: bootstrap admin role grant stream ID is not canonical")
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
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project bootstrap admin role grant: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: bootstrap admin role grant affected %d users; want one", affected)
	}
	return nil
}

func projectUserCreation(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion != 1 {
		return errUserExists
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
		return errUserExists
	}
	return nil
}

func projectManagedUserUpdate(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion < 2 {
		return errors.New("store: managed user update version is invalid")
	}
	userID, err := canonicalUserID(event.StreamID)
	if err != nil || userID != event.StreamID {
		return errors.New("store: managed user update stream ID is not canonical")
	}
	payload, err := decodeEventPayload[userCreatedPayload](event, userPayloadVersion)
	if err != nil {
		return err
	}
	email, err := CanonicalUserEmail(payload.Email)
	if err != nil || email != payload.Email {
		return errors.New("store: managed user email is not canonical")
	}
	queries := generated.New(tx)
	affected, err := queries.ReplaceManagedUser(ctx, generated.ReplaceManagedUserParams{
		Email:                     email,
		ProjectionVersion:         event.StreamVersion,
		UpdatedAt:                 event.CreatedAt,
		UserID:                    userID,
		PreviousProjectionVersion: event.StreamVersion - 1,
	})
	if err != nil {
		return fmt.Errorf("store: project managed user update: %w", err)
	}
	if affected != 1 {
		return errors.New("store: managed user update projection version mismatch")
	}
	if err := queries.ReplaceOIDCIdentityEmailsForManagedUser(
		ctx,
		generated.ReplaceOIDCIdentityEmailsForManagedUserParams{
			Email:     email,
			UpdatedAt: event.CreatedAt,
			UserID:    userID,
		},
	); err != nil {
		return fmt.Errorf("store: update managed user's OIDC identities: %w", err)
	}
	if err := queries.ReplaceSCIMIdentityEmailsForManagedUser(
		ctx,
		generated.ReplaceSCIMIdentityEmailsForManagedUserParams{
			Email:     email,
			UpdatedAt: event.CreatedAt,
			UserID:    userID,
		},
	); err != nil {
		return fmt.Errorf("store: update managed user's SCIM identities: %w", err)
	}
	return nil
}

func projectManagedUserDeletion(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion < 2 {
		return errors.New("store: managed user deletion version is invalid")
	}
	if _, err := decodeEventPayload[userManagedDeletedPayload](event, userPayloadVersion); err != nil {
		return err
	}
	userID, err := canonicalUserID(event.StreamID)
	if err != nil || userID != event.StreamID {
		return errors.New("store: managed user deletion stream ID is not canonical")
	}
	queries := generated.New(tx)
	if err := queries.DeleteManagedUserGroupMembershipsForUser(ctx, userID); err != nil {
		return fmt.Errorf("store: delete managed user-group memberships: %w", err)
	}
	if err := deleteSCIMGroupMembershipsForUserProjection(
		ctx,
		queries,
		userID,
	); err != nil {
		return fmt.Errorf("store: delete SCIM group memberships for managed user: %w", err)
	}
	// Identity rows cascade with the user. Credential and grant projections
	// remain owned by their own event streams; every authorization path first
	// resolves this live user projection and therefore fails closed after deletion.
	affected, err := queries.DeleteManagedUser(
		ctx,
		generated.DeleteManagedUserParams{
			UserID:            userID,
			ProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project managed user deletion: %w", err)
	}
	if affected != 1 {
		return errors.New("store: managed user deletion projection version mismatch")
	}
	return nil
}

func deleteSCIMGroupMembershipsForUserProjection(
	ctx context.Context,
	queries *generated.Queries,
	userID string,
) error {
	return queries.DeleteSCIMGroupMembershipsForUser(ctx, userID)
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

func validateUserProjection(
	userID, email string,
	sessionVersion int64,
	disabled bool,
	version int64,
) (User, error) {
	canonicalID, err := canonicalUserID(userID)
	if err != nil || canonicalID != userID {
		return User{}, errors.New("store: user projection has an invalid user ID")
	}
	canonicalEmail, err := CanonicalUserEmail(email)
	if err != nil || canonicalEmail != email {
		return User{}, errors.New("store: user projection has an invalid email")
	}
	if sessionVersion <= 0 || version <= 0 {
		return User{}, errors.New("store: user projection has an invalid version")
	}
	return User{
		UserID:            userID,
		Email:             email,
		SessionVersion:    sessionVersion,
		Disabled:          disabled,
		ProjectionVersion: version,
	}, nil
}

func resetUsers(ctx context.Context, tx ProjectionTx) error {
	queries := generated.New(tx)
	if err := queries.ResetSCIMIdentities(ctx); err != nil {
		return fmt.Errorf("store: reset SCIM identities: %w", err)
	}
	if err := queries.ResetOIDCIdentities(ctx); err != nil {
		return fmt.Errorf("store: reset OIDC identities: %w", err)
	}
	if err := queries.ResetUsers(ctx); err != nil {
		return fmt.Errorf("store: reset users: %w", err)
	}
	return nil
}
