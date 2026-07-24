package control

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	scimConfigurationDomainName = "scim-configurations"
	scimCredentialBytes         = 32
)

func scimConfigurationDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          scimConfigurationDomainName,
		permission:    "scim_configuration.manage",
		objectMessage: (&powermanagev1.ScimConfiguration{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudCreate: (&powermanagev1.CreateScimConfigurationRequest{}).ProtoReflect().Descriptor().FullName(),
			crudGet:    (&powermanagev1.GetScimConfigurationRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList:   (&powermanagev1.ListScimConfigurationsRequest{}).ProtoReflect().Descriptor().FullName(),
			crudUpdate: (&powermanagev1.UpdateScimConfigurationRequest{}).ProtoReflect().Descriptor().FullName(),
			crudDelete: (&powermanagev1.DeleteScimConfigurationRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudCreate: powermanagev1connect.ControlServiceCreateScimConfigurationProcedure,
			crudGet:    powermanagev1connect.ControlServiceGetScimConfigurationProcedure,
			crudList:   powermanagev1connect.ControlServiceListScimConfigurationsProcedure,
			crudUpdate: powermanagev1connect.ControlServiceUpdateScimConfigurationProcedure,
			crudDelete: powermanagev1connect.ControlServiceDeleteScimConfigurationProcedure,
		},
		projectorEvents:   store.SCIMProviderManagementEventTypes(),
		searchableColumns: []string{"provider_slug"},
		alreadyExists:     store.IsSCIMProviderExists,
		scopeRelation:     crudScopeGlobal,
		scope:             globalCRUDScope,
		requestID:         scimConfigurationRequestID,
		createEvent: func(
			_ context.Context,
			message proto.Message,
		) (store.Event, string, error) {
			request, ok := message.(*powermanagev1.CreateScimConfigurationRequest)
			if !ok {
				return store.Event{}, "", errors.New("control: wrong SCIM configuration request for create")
			}
			credential, hash, err := newSCIMCredential()
			if err != nil {
				return store.Event{}, "", err
			}
			event, err := store.SCIMProviderCreatedEvent(request.GetProviderSlug(), hash)
			if err != nil {
				return store.Event{}, "", fmt.Errorf("%w: SCIM configuration metadata", errCRUDInvalid)
			}
			return event, credential, nil
		},
		updateCredentialEvent: func(
			ctx context.Context,
			message proto.Message,
		) (store.Event, string, error) {
			request, ok := message.(*powermanagev1.UpdateScimConfigurationRequest)
			if !ok || eventStore == nil {
				return store.Event{}, "", errors.New("control: wrong SCIM configuration request for update")
			}
			current, err := eventStore.SCIMProvider(ctx, request.GetId())
			if err != nil {
				return store.Event{}, "", err
			}
			if current.Disabled {
				return store.Event{}, "", errCRUDInvalid
			}
			switch {
			case request.GetState() ==
				powermanagev1.ScimConfigurationState_SCIM_CONFIGURATION_STATE_ENABLED &&
				request.GetCredentialAction() ==
					powermanagev1.ScimCredentialAction_SCIM_CREDENTIAL_ACTION_ROTATE:
				credential, hash, err := newSCIMCredential()
				if err != nil {
					return store.Event{}, "", err
				}
				event, err := store.SCIMProviderTokenRotatedEvent(request.GetId(), hash)
				if err != nil {
					return store.Event{}, "", fmt.Errorf("%w: SCIM configuration rotation", errCRUDInvalid)
				}
				return event, credential, nil
			case request.GetState() ==
				powermanagev1.ScimConfigurationState_SCIM_CONFIGURATION_STATE_DISABLED &&
				request.GetCredentialAction() ==
					powermanagev1.ScimCredentialAction_SCIM_CREDENTIAL_ACTION_KEEP:
				event, err := store.SCIMProviderDisabledEvent(request.GetId())
				if err != nil {
					return store.Event{}, "", fmt.Errorf("%w: SCIM configuration disable", errCRUDInvalid)
				}
				return event, "", nil
			default:
				return store.Event{}, "", errCRUDInvalid
			}
		},
		deleteEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.DeleteScimConfigurationRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong SCIM configuration request for delete")
			}
			return store.SCIMProviderDeletedEvent(request.GetId())
		},
		get: func(ctx context.Context, id string, _ CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			provider, err := eventStore.SCIMProviderMetadataBySlug(ctx, id)
			if err != nil {
				return nil, err
			}
			return scimConfigurationMessage(provider), nil
		},
		list: func(ctx context.Context, _ CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			providers, err := eventStore.ListSCIMProviders(ctx, limit)
			if err != nil {
				return nil, err
			}
			messages := make([]proto.Message, len(providers))
			for index, provider := range providers {
				messages[index] = scimConfigurationMessage(provider)
			}
			return messages, nil
		},
	}
}

func scimConfigurationRequestID(message proto.Message) (string, error) {
	if request, ok := message.(*powermanagev1.CreateScimConfigurationRequest); ok {
		return request.GetProviderSlug(), nil
	}
	return crudStringField(message, "id")
}

func newSCIMCredential() (string, []byte, error) {
	var secret [scimCredentialBytes]byte
	if _, err := io.ReadFull(rand.Reader, secret[:]); err != nil {
		return "", nil, errors.New("control: generate SCIM credential")
	}
	credential := "pm_scim_" + base64.RawURLEncoding.EncodeToString(secret[:])
	hash, err := bcrypt.GenerateFromPassword([]byte(credential), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, errors.New("control: hash SCIM credential")
	}
	return credential, hash, nil
}

func scimConfigurationMessage(provider store.SCIMProviderMetadata) *powermanagev1.ScimConfiguration {
	state := powermanagev1.ScimConfigurationState_SCIM_CONFIGURATION_STATE_ENABLED
	if provider.Disabled {
		state = powermanagev1.ScimConfigurationState_SCIM_CONFIGURATION_STATE_DISABLED
	}
	return &powermanagev1.ScimConfiguration{
		Id:      provider.Slug,
		State:   state,
		Version: uint64(provider.ProjectionVersion),
	}
}
