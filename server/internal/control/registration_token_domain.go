package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	registrationTokenDomainName = "registration-tokens"
	registrationTokenSecretSize = 32
)

func registrationTokenDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          registrationTokenDomainName,
		permission:    "pki.manage",
		objectMessage: (&powermanagev1.RegistrationToken{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudCreate: (&powermanagev1.CreateRegistrationTokenRequest{}).ProtoReflect().Descriptor().FullName(),
			crudGet:    (&powermanagev1.GetRegistrationTokenRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList:   (&powermanagev1.ListRegistrationTokensRequest{}).ProtoReflect().Descriptor().FullName(),
			crudUpdate: (&powermanagev1.UpdateRegistrationTokenRequest{}).ProtoReflect().Descriptor().FullName(),
			crudDelete: (&powermanagev1.DeleteRegistrationTokenRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudCreate: powermanagev1connect.ControlServiceCreateRegistrationTokenProcedure,
			crudGet:    powermanagev1connect.ControlServiceGetRegistrationTokenProcedure,
			crudList:   powermanagev1connect.ControlServiceListRegistrationTokensProcedure,
			crudUpdate: powermanagev1connect.ControlServiceUpdateRegistrationTokenProcedure,
			crudDelete: powermanagev1connect.ControlServiceDeleteRegistrationTokenProcedure,
		},
		projectorEvents:   store.RegistrationTokenManagementEventTypes(),
		searchableColumns: []string{"owner"},
		alreadyExists:     store.IsRegistrationTokenExists,
		scopeRelation:     crudScopeGlobal,
		scope:             globalCRUDScope,
		createEvent: func(
			_ context.Context,
			message proto.Message,
		) (store.Event, string, error) {
			request, ok := message.(*powermanagev1.CreateRegistrationTokenRequest)
			if !ok {
				return store.Event{}, "", errors.New("control: wrong registration-token request for create")
			}
			expiresAt, err := registrationTokenExpiry(request.GetExpiresAt())
			if err != nil {
				return store.Event{}, "", errCRUDInvalid
			}
			maxUses := request.GetMaxUses()
			if maxUses == 0 || maxUses > math.MaxInt32 {
				return store.Event{}, "", errCRUDInvalid
			}
			var secret [registrationTokenSecretSize]byte
			if _, err := io.ReadFull(rand.Reader, secret[:]); err != nil {
				return store.Event{}, "", errors.New("control: generate registration-token secret")
			}
			hash := sha256.Sum256(secret[:])
			var event store.Event
			switch request.GetPurpose() {
			case powermanagev1.RegistrationTokenPurpose_REGISTRATION_TOKEN_PURPOSE_AGENT:
				if len(request.GetDnsNames()) != 0 {
					return store.Event{}, "", errCRUDInvalid
				}
				event, err = store.RegistrationTokenMintedEvent(
					request.GetId(),
					hash,
					int32(maxUses),
					expiresAt,
					request.GetOwner(),
				)
			case powermanagev1.RegistrationTokenPurpose_REGISTRATION_TOKEN_PURPOSE_GATEWAY:
				if len(request.GetDnsNames()) == 0 {
					return store.Event{}, "", errCRUDInvalid
				}
				event, err = store.GatewayRegistrationTokenMintedEvent(
					request.GetId(),
					hash,
					int32(maxUses),
					expiresAt,
					request.GetOwner(),
					request.GetDnsNames(),
				)
			default:
				return store.Event{}, "", errCRUDInvalid
			}
			if err != nil {
				return store.Event{}, "", fmt.Errorf("%w: registration-token metadata", errCRUDInvalid)
			}
			credential := request.GetId() + "." +
				base64.RawURLEncoding.EncodeToString(secret[:])
			return event, credential, nil
		},
		updateEvent: func(ctx context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.UpdateRegistrationTokenRequest)
			if !ok || eventStore == nil {
				return store.Event{}, errors.New("control: wrong registration-token request for update")
			}
			expiresAt, err := registrationTokenExpiry(request.GetExpiresAt())
			if err != nil {
				return store.Event{}, errCRUDInvalid
			}
			current, err := eventStore.RegistrationToken(ctx, request.GetId())
			if err != nil {
				return store.Event{}, err
			}
			disabled := false
			switch request.GetState() {
			case powermanagev1.RegistrationTokenState_REGISTRATION_TOKEN_STATE_ACTIVE:
				if current.Disabled {
					return store.Event{}, errCRUDInvalid
				}
			case powermanagev1.RegistrationTokenState_REGISTRATION_TOKEN_STATE_DISABLED:
				disabled = true
			default:
				return store.Event{}, errCRUDInvalid
			}
			maxUses := request.GetMaxUses()
			if maxUses == 0 ||
				maxUses > math.MaxInt32 ||
				current.Uses < 0 ||
				maxUses < uint32(current.Uses) {
				return store.Event{}, errCRUDInvalid
			}
			return store.RegistrationTokenUpdatedEvent(
				request.GetId(),
				int32(maxUses),
				expiresAt,
				request.GetOwner(),
				disabled,
			)
		},
		deleteEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.DeleteRegistrationTokenRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong registration-token request for delete")
			}
			return store.RegistrationTokenDeletedEvent(request.GetId())
		},
		get: func(ctx context.Context, id string, _ CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			token, err := eventStore.RegistrationTokenMetadataByID(ctx, id)
			if err != nil {
				return nil, err
			}
			return registrationTokenMessage(token), nil
		},
		list: func(ctx context.Context, _ CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			tokens, err := eventStore.ListRegistrationTokens(ctx, limit)
			if err != nil {
				return nil, err
			}
			messages := make([]proto.Message, len(tokens))
			for index, token := range tokens {
				messages[index] = registrationTokenMessage(token)
			}
			return messages, nil
		},
	}
}

func registrationTokenExpiry(value *timestamppb.Timestamp) (time.Time, error) {
	if value == nil || value.CheckValid() != nil {
		return time.Time{}, errCRUDInvalid
	}
	return value.AsTime(), nil
}

func registrationTokenMessage(token store.RegistrationTokenMetadata) *powermanagev1.RegistrationToken {
	purpose := powermanagev1.RegistrationTokenPurpose_REGISTRATION_TOKEN_PURPOSE_UNSPECIFIED
	switch token.Purpose {
	case store.RegistrationTokenPurposeAgent:
		purpose = powermanagev1.RegistrationTokenPurpose_REGISTRATION_TOKEN_PURPOSE_AGENT
	case store.RegistrationTokenPurposeGateway:
		purpose = powermanagev1.RegistrationTokenPurpose_REGISTRATION_TOKEN_PURPOSE_GATEWAY
	}
	state := powermanagev1.RegistrationTokenState_REGISTRATION_TOKEN_STATE_ACTIVE
	if token.Disabled {
		state = powermanagev1.RegistrationTokenState_REGISTRATION_TOKEN_STATE_DISABLED
	}
	return &powermanagev1.RegistrationToken{
		Id:        token.TokenID,
		Purpose:   purpose,
		DnsNames:  slices.Clone(token.DNSNames),
		MaxUses:   uint32(token.MaxUses),
		Uses:      uint32(token.Uses),
		ExpiresAt: timestamppb.New(token.ExpiresAt),
		Owner:     token.Owner,
		State:     state,
		Version:   uint64(token.ProjectionVersion),
	}
}
