package control

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/store"
)

const identityProviderDomainName = "identity-providers"

func identityProviderDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          identityProviderDomainName,
		permission:    "identity_providers.manage",
		objectMessage: (&powermanagev1.IdentityProvider{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudCreate: (&powermanagev1.CreateIdentityProviderRequest{}).ProtoReflect().Descriptor().FullName(),
			crudGet:    (&powermanagev1.GetIdentityProviderRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList:   (&powermanagev1.ListIdentityProvidersRequest{}).ProtoReflect().Descriptor().FullName(),
			crudUpdate: (&powermanagev1.UpdateIdentityProviderRequest{}).ProtoReflect().Descriptor().FullName(),
			crudDelete: (&powermanagev1.DeleteIdentityProviderRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudCreate: powermanagev1connect.ControlServiceCreateIdentityProviderProcedure,
			crudGet:    powermanagev1connect.ControlServiceGetIdentityProviderProcedure,
			crudList:   powermanagev1connect.ControlServiceListIdentityProvidersProcedure,
			crudUpdate: powermanagev1connect.ControlServiceUpdateIdentityProviderProcedure,
			crudDelete: powermanagev1connect.ControlServiceDeleteIdentityProviderProcedure,
		},
		projectorEvents:   store.OIDCProviderConfigEventTypes(),
		searchableColumns: []string{"issuer", "client_id"},
		alreadyExists:     store.IsOIDCProviderConfigExists,
		scopeRelation:     crudScopeGlobal,
		scope:             globalCRUDScope,
		createEvent: func(
			_ context.Context,
			message proto.Message,
		) (store.Event, string, error) {
			request, ok := message.(*powermanagev1.CreateIdentityProviderRequest)
			if !ok {
				return store.Event{}, "", errors.New("control: wrong identity-provider request for create")
			}
			config, err := identityProviderConfig(
				request.GetId(),
				request.GetIssuer(),
				request.GetClientId(),
				request.GetAuthorizationEndpoint(),
				request.GetTokenEndpoint(),
				request.GetJwksUri(),
				request.GetRedirectUris(),
				request.GetEmailAssertionPolicy(),
				powermanagev1.IdentityProviderState_IDENTITY_PROVIDER_STATE_ENABLED,
			)
			if err != nil {
				return store.Event{}, "", err
			}
			event, err := store.OIDCProviderConfigCreatedEvent(config)
			if err != nil {
				return store.Event{}, "", fmt.Errorf("%w: identity-provider metadata", errCRUDInvalid)
			}
			return event, "", nil
		},
		updateEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.UpdateIdentityProviderRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong identity-provider request for update")
			}
			config, err := identityProviderConfig(
				request.GetId(),
				request.GetIssuer(),
				request.GetClientId(),
				request.GetAuthorizationEndpoint(),
				request.GetTokenEndpoint(),
				request.GetJwksUri(),
				request.GetRedirectUris(),
				request.GetEmailAssertionPolicy(),
				request.GetState(),
			)
			if err != nil {
				return store.Event{}, err
			}
			event, err := store.OIDCProviderConfigUpdatedEvent(config)
			if err != nil {
				return store.Event{}, fmt.Errorf("%w: identity-provider metadata", errCRUDInvalid)
			}
			return event, nil
		},
		deleteEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.DeleteIdentityProviderRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong identity-provider request for delete")
			}
			return store.OIDCProviderConfigDeletedEvent(request.GetId())
		},
		get: func(ctx context.Context, id string, _ CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			config, err := eventStore.OIDCProviderConfigBySlug(ctx, id)
			if err != nil {
				return nil, err
			}
			return identityProviderMessage(config), nil
		},
		list: func(ctx context.Context, _ CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			configs, err := eventStore.ListOIDCProviderConfigs(ctx, limit)
			if err != nil {
				return nil, err
			}
			messages := make([]proto.Message, len(configs))
			for index, config := range configs {
				messages[index] = identityProviderMessage(config)
			}
			return messages, nil
		},
	}
}

func identityProviderConfig(
	id string,
	issuer string,
	clientID string,
	authorizationEndpoint string,
	tokenEndpoint string,
	jwksURI string,
	redirectURIs []string,
	emailPolicy powermanagev1.EmailAssertionPolicy,
	state powermanagev1.IdentityProviderState,
) (store.OIDCProviderMetadata, error) {
	var trustEmailAssertions bool
	switch emailPolicy {
	case powermanagev1.EmailAssertionPolicy_EMAIL_ASSERTION_POLICY_REQUIRE_EXPLICIT_LINK:
	case powermanagev1.EmailAssertionPolicy_EMAIL_ASSERTION_POLICY_TRUST_VERIFIED_EMAIL:
		trustEmailAssertions = true
	default:
		return store.OIDCProviderMetadata{}, errCRUDInvalid
	}
	var disabled bool
	switch state {
	case powermanagev1.IdentityProviderState_IDENTITY_PROVIDER_STATE_ENABLED:
	case powermanagev1.IdentityProviderState_IDENTITY_PROVIDER_STATE_DISABLED:
		disabled = true
	default:
		return store.OIDCProviderMetadata{}, errCRUDInvalid
	}
	return store.OIDCProviderMetadata{
		Slug:                  id,
		Issuer:                issuer,
		ClientID:              clientID,
		AuthorizationEndpoint: authorizationEndpoint,
		TokenURL:              tokenEndpoint,
		JWKSURI:               jwksURI,
		RedirectURIs:          slices.Clone(redirectURIs),
		TrustEmailAssertions:  trustEmailAssertions,
		Disabled:              disabled,
	}, nil
}

func identityProviderMessage(config store.OIDCProviderMetadata) *powermanagev1.IdentityProvider {
	emailPolicy := powermanagev1.EmailAssertionPolicy_EMAIL_ASSERTION_POLICY_REQUIRE_EXPLICIT_LINK
	if config.TrustEmailAssertions {
		emailPolicy = powermanagev1.EmailAssertionPolicy_EMAIL_ASSERTION_POLICY_TRUST_VERIFIED_EMAIL
	}
	state := powermanagev1.IdentityProviderState_IDENTITY_PROVIDER_STATE_ENABLED
	if config.Disabled {
		state = powermanagev1.IdentityProviderState_IDENTITY_PROVIDER_STATE_DISABLED
	}
	return &powermanagev1.IdentityProvider{
		Id:                    config.Slug,
		Issuer:                config.Issuer,
		ClientId:              config.ClientID,
		AuthorizationEndpoint: config.AuthorizationEndpoint,
		TokenEndpoint:         config.TokenURL,
		JwksUri:               config.JWKSURI,
		RedirectUris:          slices.Clone(config.RedirectURIs),
		EmailAssertionPolicy:  emailPolicy,
		State:                 state,
		Version:               uint64(config.ProjectionVersion),
	}
}
