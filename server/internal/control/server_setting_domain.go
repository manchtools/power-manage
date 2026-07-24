package control

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/store"
)

const serverSettingDomainName = "server-settings"

func serverSettingDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          serverSettingDomainName,
		permission:    "server_settings.manage",
		objectMessage: (&powermanagev1.ServerSetting{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudCreate: (&powermanagev1.CreateServerSettingRequest{}).ProtoReflect().Descriptor().FullName(),
			crudGet:    (&powermanagev1.GetServerSettingRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList:   (&powermanagev1.ListServerSettingsRequest{}).ProtoReflect().Descriptor().FullName(),
			crudUpdate: (&powermanagev1.UpdateServerSettingRequest{}).ProtoReflect().Descriptor().FullName(),
			crudDelete: (&powermanagev1.DeleteServerSettingRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudCreate: powermanagev1connect.ControlServiceCreateServerSettingProcedure,
			crudGet:    powermanagev1connect.ControlServiceGetServerSettingProcedure,
			crudList:   powermanagev1connect.ControlServiceListServerSettingsProcedure,
			crudUpdate: powermanagev1connect.ControlServiceUpdateServerSettingProcedure,
			crudDelete: powermanagev1connect.ControlServiceDeleteServerSettingProcedure,
		},
		projectorEvents:   store.ServerSettingEventTypes(),
		searchableColumns: []string{"name", "value"},
		alreadyExists:     store.IsServerSettingExists,
		scopeRelation:     crudScopeGlobal,
		scope:             globalCRUDScope,
		createEvent: func(
			_ context.Context,
			message proto.Message,
		) (store.Event, string, error) {
			request, ok := message.(*powermanagev1.CreateServerSettingRequest)
			if !ok {
				return store.Event{}, "", errors.New("control: wrong server-setting request for create")
			}
			event, err := store.ServerSettingCreatedEvent(
				request.GetId(),
				request.GetName(),
				request.GetValue(),
			)
			if err != nil {
				return store.Event{}, "", fmt.Errorf("%w: server-setting metadata", errCRUDInvalid)
			}
			return event, "", nil
		},
		updateEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.UpdateServerSettingRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong server-setting request for update")
			}
			event, err := store.ServerSettingUpdatedEvent(
				request.GetId(),
				request.GetName(),
				request.GetValue(),
			)
			if err != nil {
				return store.Event{}, fmt.Errorf("%w: server-setting metadata", errCRUDInvalid)
			}
			return event, nil
		},
		deleteEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.DeleteServerSettingRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong server-setting request for delete")
			}
			return store.ServerSettingDeletedEvent(request.GetId())
		},
		get: func(ctx context.Context, id string, _ CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			setting, err := eventStore.ServerSettingByID(ctx, id)
			if err != nil {
				return nil, err
			}
			return serverSettingMessage(setting), nil
		},
		list: func(ctx context.Context, _ CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			settings, err := eventStore.ListServerSettings(ctx, limit)
			if err != nil {
				return nil, err
			}
			messages := make([]proto.Message, len(settings))
			for index, setting := range settings {
				messages[index] = serverSettingMessage(setting)
			}
			return messages, nil
		},
	}
}

func serverSettingMessage(setting store.ServerSetting) *powermanagev1.ServerSetting {
	return &powermanagev1.ServerSetting{
		Id:      setting.ID,
		Name:    setting.Name,
		Value:   setting.Value,
		Version: uint64(setting.ProjectionVersion),
	}
}
