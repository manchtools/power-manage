package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/authz"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	apiTokenDomainName = "api-tokens"
	apiTokenSecretSize = 32
)

func apiTokenDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          apiTokenDomainName,
		permission:    "users.manage",
		objectMessage: (&powermanagev1.ApiToken{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudCreate: (&powermanagev1.CreateApiTokenRequest{}).ProtoReflect().Descriptor().FullName(),
			crudGet:    (&powermanagev1.GetApiTokenRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList:   (&powermanagev1.ListApiTokensRequest{}).ProtoReflect().Descriptor().FullName(),
			crudUpdate: (&powermanagev1.UpdateApiTokenRequest{}).ProtoReflect().Descriptor().FullName(),
			crudDelete: (&powermanagev1.DeleteApiTokenRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudCreate: powermanagev1connect.ControlServiceCreateApiTokenProcedure,
			crudGet:    powermanagev1connect.ControlServiceGetApiTokenProcedure,
			crudList:   powermanagev1connect.ControlServiceListApiTokensProcedure,
			crudUpdate: powermanagev1connect.ControlServiceUpdateApiTokenProcedure,
			crudDelete: powermanagev1connect.ControlServiceDeleteApiTokenProcedure,
		},
		projectorEvents:   store.PersonalAccessTokenManagementEventTypes(),
		searchableColumns: []string{"subject"},
		alreadyExists:     store.IsPersonalAccessTokenExists,
		scopeRelation:     crudScopeUserOwned,
		scope: func(reach authz.Reach) (CRUDScope, error) {
			return CRUDScope{
				Global:       reach.Global,
				UserGroupIDs: slices.Clone(reach.UserGroupIDs),
			}, nil
		},
		validateScope: func(
			ctx context.Context,
			operation crudOperation,
			message proto.Message,
			scope CRUDScope,
		) error {
			if eventStore == nil {
				return errors.New("control: management store is not wired")
			}
			if operation != crudCreate && operation != crudUpdate {
				return nil
			}
			var subjectID string
			switch request := message.(type) {
			case *powermanagev1.CreateApiTokenRequest:
				subjectID = request.GetSubjectId()
			case *powermanagev1.UpdateApiTokenRequest:
				subjectID = request.GetSubjectId()
			default:
				return errCRUDInvalid
			}
			_, err := eventStore.ScopedUserByID(
				ctx,
				subjectID,
				scope.Global,
				scope.UserGroupIDs,
				scope.SelfID,
			)
			return err
		},
		createEvent: func(
			_ context.Context,
			message proto.Message,
		) (store.Event, string, error) {
			request, ok := message.(*powermanagev1.CreateApiTokenRequest)
			if !ok {
				return store.Event{}, "", errors.New("control: wrong API-token request for create")
			}
			expiresAt, err := registrationTokenExpiry(request.GetExpiresAt())
			if err != nil {
				return store.Event{}, "", errCRUDInvalid
			}
			var secret [apiTokenSecretSize]byte
			if _, err := io.ReadFull(rand.Reader, secret[:]); err != nil {
				return store.Event{}, "", errors.New("control: generate API-token secret")
			}
			credential := "pm_pat_" + base64.RawURLEncoding.EncodeToString(secret[:])
			hash := sha256.Sum256([]byte(credential))
			scopes := slices.Clone(request.GetScopes())
			slices.Sort(scopes)
			event, err := store.PersonalAccessTokenMintedEvent(
				request.GetId(),
				request.GetSubjectId(),
				scopes,
				hash,
				expiresAt,
			)
			if err != nil {
				return store.Event{}, "", fmt.Errorf("%w: API-token metadata", errCRUDInvalid)
			}
			return event, credential, nil
		},
		updateEvent: func(ctx context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.UpdateApiTokenRequest)
			if !ok || eventStore == nil {
				return store.Event{}, errors.New("control: wrong API-token request for update")
			}
			expiresAt, err := registrationTokenExpiry(request.GetExpiresAt())
			if err != nil {
				return store.Event{}, errCRUDInvalid
			}
			current, err := eventStore.PersonalAccessTokenByID(ctx, request.GetId())
			if err != nil {
				return store.Event{}, err
			}
			if request.GetSubjectId() != current.Subject {
				return store.Event{}, errCRUDInvalid
			}
			revoked := false
			switch request.GetState() {
			case powermanagev1.ApiTokenState_API_TOKEN_STATE_ACTIVE:
				if current.Revoked {
					return store.Event{}, errCRUDInvalid
				}
			case powermanagev1.ApiTokenState_API_TOKEN_STATE_REVOKED:
				revoked = true
			default:
				return store.Event{}, errCRUDInvalid
			}
			scopes := slices.Clone(request.GetScopes())
			slices.Sort(scopes)
			return store.PersonalAccessTokenUpdatedEvent(
				request.GetId(),
				request.GetSubjectId(),
				scopes,
				expiresAt,
				revoked,
			)
		},
		deleteEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.DeleteApiTokenRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong API-token request for delete")
			}
			return store.PersonalAccessTokenDeletedEvent(request.GetId())
		},
		get: func(ctx context.Context, id string, scope CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			token, err := eventStore.ScopedPersonalAccessTokenByID(
				ctx,
				id,
				scope.Global,
				scope.UserGroupIDs,
				scope.SelfID,
			)
			if err != nil {
				return nil, err
			}
			return apiTokenMessage(token), nil
		},
		list: func(ctx context.Context, scope CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			tokens, err := eventStore.ListScopedPersonalAccessTokens(
				ctx,
				scope.Global,
				scope.UserGroupIDs,
				scope.SelfID,
				limit,
			)
			if err != nil {
				return nil, err
			}
			messages := make([]proto.Message, len(tokens))
			for index, token := range tokens {
				messages[index] = apiTokenMessage(token)
			}
			return messages, nil
		},
	}
}

func apiTokenMessage(token store.PersonalAccessTokenMetadata) *powermanagev1.ApiToken {
	state := powermanagev1.ApiTokenState_API_TOKEN_STATE_ACTIVE
	if token.Revoked {
		state = powermanagev1.ApiTokenState_API_TOKEN_STATE_REVOKED
	}
	return &powermanagev1.ApiToken{
		Id:        token.TokenID,
		SubjectId: token.Subject,
		Scopes:    slices.Clone(token.Scopes),
		ExpiresAt: timestamppb.New(token.ExpiresAt),
		State:     state,
		Version:   uint64(token.ProjectionVersion),
	}
}
