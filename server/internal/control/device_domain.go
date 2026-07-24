package control

import (
	"context"
	"errors"
	"slices"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/authz"
	"github.com/manchtools/power-manage/server/internal/store"
)

const deviceDomainName = "devices"

func deviceDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          deviceDomainName,
		permission:    "devices.manage",
		objectMessage: (&powermanagev1.Device{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudGet:    (&powermanagev1.GetDeviceRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList:   (&powermanagev1.ListDevicesRequest{}).ProtoReflect().Descriptor().FullName(),
			crudUpdate: (&powermanagev1.UpdateDeviceRequest{}).ProtoReflect().Descriptor().FullName(),
			crudDelete: (&powermanagev1.DeleteDeviceRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudGet:    powermanagev1connect.ControlServiceGetDeviceProcedure,
			crudList:   powermanagev1connect.ControlServiceListDevicesProcedure,
			crudUpdate: powermanagev1connect.ControlServiceUpdateDeviceProcedure,
			crudDelete: powermanagev1connect.ControlServiceDeleteDeviceProcedure,
		},
		projectorEvents:   store.DeviceManagementEventTypes(),
		searchableColumns: []string{"owner"},
		scopeRelation:     crudScopeDevice,
		scope: func(reach authz.Reach) (CRUDScope, error) {
			return CRUDScope{
				Global:         reach.Global,
				DeviceGroupIDs: slices.Clone(reach.DeviceGroupIDs),
			}, nil
		},
		updateEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.UpdateDeviceRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong device request for update")
			}
			return store.AgentOwnerUpdatedEvent(request.GetId(), request.GetOwner())
		},
		deleteEvent: func(ctx context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.DeleteDeviceRequest)
			if !ok || eventStore == nil {
				return store.Event{}, errors.New("control: wrong device request for delete")
			}
			device, err := eventStore.Device(ctx, request.GetId())
			if err != nil {
				return store.Event{}, err
			}
			return store.AgentDeletedEvent(device.DeviceID, device.CertificateDER)
		},
		get: func(ctx context.Context, id string, scope CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			device, err := eventStore.ScopedDevice(
				ctx,
				id,
				scope.Global,
				scope.DeviceGroupIDs,
			)
			if err != nil {
				return nil, err
			}
			return deviceMessage(device), nil
		},
		list: func(ctx context.Context, scope CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			devices, err := eventStore.ListScopedDevices(
				ctx,
				scope.Global,
				scope.DeviceGroupIDs,
				limit,
			)
			if err != nil {
				return nil, err
			}
			messages := make([]proto.Message, len(devices))
			for index, device := range devices {
				messages[index] = deviceMessage(device)
			}
			return messages, nil
		},
	}
}

func deviceMessage(device store.Device) *powermanagev1.Device {
	state := powermanagev1.DeviceState_DEVICE_STATE_UNSPECIFIED
	switch device.LifecycleState {
	case store.DeviceLifecycleActive:
		state = powermanagev1.DeviceState_DEVICE_STATE_ACTIVE
	case store.DeviceLifecycleForceRenewal:
		state = powermanagev1.DeviceState_DEVICE_STATE_FORCE_RENEWAL
	case store.DeviceLifecycleRevoked:
		state = powermanagev1.DeviceState_DEVICE_STATE_REVOKED
	}
	return &powermanagev1.Device{
		Id:      device.DeviceID,
		Owner:   device.Owner,
		State:   state,
		Version: uint64(device.ProjectionVersion),
	}
}
