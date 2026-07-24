package control

import (
	"context"
	"errors"
	"slices"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/authz"
	"github.com/manchtools/power-manage/server/internal/store"
)

const deviceGroupDomainName = "device-groups"

type crudDomainStoreFuncs struct {
	createEvent func(*powermanagev1.CreateDeviceGroupRequest) (store.Event, error)
	updateEvent func(*powermanagev1.UpdateDeviceGroupRequest) (store.Event, error)
	deleteEvent func(*powermanagev1.DeleteDeviceGroupRequest) (store.Event, error)
	get         func(context.Context, string, CRUDScope) (store.DeviceGroup, error)
	list        func(context.Context, CRUDScope, int32) ([]store.DeviceGroup, error)
}

// ManagementService serves permission-gated ControlService domains.
type ManagementService struct {
	powermanagev1connect.UnimplementedControlServiceHandler
	kernel *CRUDKernel
}

// NewManagementService wires the registered management domains to one kernel.
func NewManagementService(
	eventStore *store.Store,
	gate *auth.AuthorizationGate,
) (*ManagementService, error) {
	if eventStore == nil {
		return nil, errors.New("control: management store is not wired")
	}
	kernel, err := newCRUDKernel(eventStore, gate, managementDomains(eventStore))
	if err != nil {
		return nil, err
	}
	return &ManagementService{kernel: kernel}, nil
}

func managementDomains(eventStore *store.Store) []crudDomain {
	domains := []crudDomain{deviceGroupDomain(crudDomainStoreFuncs{
		createEvent: func(request *powermanagev1.CreateDeviceGroupRequest) (store.Event, error) {
			return store.DeviceGroupCreatedWithMembersEvent(
				request.GetId(),
				request.GetName(),
				request.GetDynamicQuery(),
				request.GetStaticDeviceIds(),
			)
		},
		updateEvent: func(request *powermanagev1.UpdateDeviceGroupRequest) (store.Event, error) {
			return store.DeviceGroupUpdatedWithMembersEvent(
				request.GetId(),
				request.GetName(),
				request.GetDynamicQuery(),
				request.GetStaticDeviceIds(),
			)
		},
		deleteEvent: func(request *powermanagev1.DeleteDeviceGroupRequest) (store.Event, error) {
			return store.DeviceGroupDeletedEvent(request.GetId())
		},
		get: func(ctx context.Context, id string, scope CRUDScope) (store.DeviceGroup, error) {
			if eventStore == nil {
				return store.DeviceGroup{}, errors.New("control: management store is not wired")
			}
			return eventStore.DeviceGroupByID(
				ctx,
				id,
				scope.Global,
				scope.DeviceGroupIDs,
			)
		},
		list: func(
			ctx context.Context,
			scope CRUDScope,
			limit int32,
		) ([]store.DeviceGroup, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			return eventStore.ListDeviceGroups(
				ctx,
				scope.Global,
				scope.DeviceGroupIDs,
				limit,
			)
		},
	})}
	domains = append(domains, identityDomains(eventStore)...)
	domains = append(domains, deviceDomain(eventStore))
	domains = append(domains, registrationTokenDomain(eventStore))
	domains = append(domains, apiTokenDomain(eventStore))
	domains = append(domains, identityProviderDomain(eventStore))
	domains = append(domains, scimConfigurationDomain(eventStore))
	domains = append(domains, serverSettingDomain(eventStore))
	domains = append(domains, actionDomain(eventStore))
	domains = append(domains, actionSetDomain(eventStore))
	domains = append(domains, assignmentDomain(eventStore))
	domains = append(domains, compliancePolicyDomain(eventStore))
	domains = append(domains, auditDomain(eventStore))
	domains = append(domains, executionDomain(eventStore))
	domains = append(domains, inventoryDomain(eventStore))
	return append(domains, gatewayDomain(eventStore))
}

// CreateDeviceGroup delegates device-group creation to the shared CRUD kernel.
func (s *ManagementService) CreateDeviceGroup(
	ctx context.Context,
	request *connect.Request[powermanagev1.CreateDeviceGroupRequest],
) (*connect.Response[powermanagev1.CreateDeviceGroupResponse], error) {
	message, err := requestMessage(request)
	if err != nil || s == nil || s.kernel == nil {
		return nil, invalidCRUDRequest()
	}
	result, err := s.kernel.create(
		ctx,
		powermanagev1connect.ControlServiceCreateDeviceGroupProcedure,
		deviceGroupDomainName,
		message,
	)
	if err != nil {
		return nil, err
	}
	group, ok := result.object.(*powermanagev1.DeviceGroup)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(
		&powermanagev1.CreateDeviceGroupResponse{DeviceGroup: group},
	), nil
}

// GetDeviceGroup delegates a scoped detail read to the shared CRUD kernel.
func (s *ManagementService) GetDeviceGroup(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetDeviceGroupRequest],
) (*connect.Response[powermanagev1.GetDeviceGroupResponse], error) {
	message, err := requestMessage(request)
	if err != nil || s == nil || s.kernel == nil {
		return nil, invalidCRUDRequest()
	}
	result, err := s.kernel.get(
		ctx,
		powermanagev1connect.ControlServiceGetDeviceGroupProcedure,
		deviceGroupDomainName,
		message,
	)
	if err != nil {
		return nil, err
	}
	group, ok := result.(*powermanagev1.DeviceGroup)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(
		&powermanagev1.GetDeviceGroupResponse{DeviceGroup: group},
	), nil
}

// ListDeviceGroups delegates a scoped page read to the shared CRUD kernel.
func (s *ManagementService) ListDeviceGroups(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListDeviceGroupsRequest],
) (*connect.Response[powermanagev1.ListDeviceGroupsResponse], error) {
	message, err := requestMessage(request)
	if err != nil || s == nil || s.kernel == nil {
		return nil, invalidCRUDRequest()
	}
	results, err := s.kernel.list(
		ctx,
		powermanagev1connect.ControlServiceListDeviceGroupsProcedure,
		deviceGroupDomainName,
		message,
	)
	if err != nil {
		return nil, err
	}
	groups := make([]*powermanagev1.DeviceGroup, len(results))
	for index, result := range results {
		var ok bool
		groups[index], ok = result.(*powermanagev1.DeviceGroup)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(
		&powermanagev1.ListDeviceGroupsResponse{DeviceGroups: groups},
	), nil
}

// UpdateDeviceGroup delegates full replacement to the shared CRUD kernel.
func (s *ManagementService) UpdateDeviceGroup(
	ctx context.Context,
	request *connect.Request[powermanagev1.UpdateDeviceGroupRequest],
) (*connect.Response[powermanagev1.UpdateDeviceGroupResponse], error) {
	message, err := requestMessage(request)
	if err != nil || s == nil || s.kernel == nil {
		return nil, invalidCRUDRequest()
	}
	result, err := s.kernel.update(
		ctx,
		powermanagev1connect.ControlServiceUpdateDeviceGroupProcedure,
		deviceGroupDomainName,
		message,
	)
	if err != nil {
		return nil, err
	}
	group, ok := result.object.(*powermanagev1.DeviceGroup)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(
		&powermanagev1.UpdateDeviceGroupResponse{DeviceGroup: group},
	), nil
}

// DeleteDeviceGroup delegates version-pinned deletion to the shared CRUD kernel.
func (s *ManagementService) DeleteDeviceGroup(
	ctx context.Context,
	request *connect.Request[powermanagev1.DeleteDeviceGroupRequest],
) (*connect.Response[powermanagev1.DeleteDeviceGroupResponse], error) {
	message, err := requestMessage(request)
	if err != nil || s == nil || s.kernel == nil {
		return nil, invalidCRUDRequest()
	}
	deletedID, err := s.kernel.delete(
		ctx,
		powermanagev1connect.ControlServiceDeleteDeviceGroupProcedure,
		deviceGroupDomainName,
		message,
	)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(
		&powermanagev1.DeleteDeviceGroupResponse{DeletedId: deletedID},
	), nil
}

func deviceGroupDomain(functions crudDomainStoreFuncs) crudDomain {
	domain := crudDomain{
		name:          deviceGroupDomainName,
		permission:    "devices.manage",
		objectMessage: (&powermanagev1.DeviceGroup{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudCreate: (&powermanagev1.CreateDeviceGroupRequest{}).ProtoReflect().Descriptor().FullName(),
			crudGet:    (&powermanagev1.GetDeviceGroupRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList:   (&powermanagev1.ListDeviceGroupsRequest{}).ProtoReflect().Descriptor().FullName(),
			crudUpdate: (&powermanagev1.UpdateDeviceGroupRequest{}).ProtoReflect().Descriptor().FullName(),
			crudDelete: (&powermanagev1.DeleteDeviceGroupRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudCreate: powermanagev1connect.ControlServiceCreateDeviceGroupProcedure,
			crudGet:    powermanagev1connect.ControlServiceGetDeviceGroupProcedure,
			crudList:   powermanagev1connect.ControlServiceListDeviceGroupsProcedure,
			crudUpdate: powermanagev1connect.ControlServiceUpdateDeviceGroupProcedure,
			crudDelete: powermanagev1connect.ControlServiceDeleteDeviceGroupProcedure,
		},
		projectorEvents:   store.DeviceGroupEventTypes(),
		searchableColumns: []string{"name", "dynamic_query"},
		alreadyExists:     store.IsDeviceGroupExists,
		scopeRelation:     crudScopeDeviceGroup,
		scope: func(reach authz.Reach) (CRUDScope, error) {
			return CRUDScope{
				Global:         reach.Global,
				DeviceGroupIDs: slices.Clone(reach.DeviceGroupIDs),
			}, nil
		},
	}
	if functions.createEvent != nil {
		domain.createEvent = func(_ context.Context, message proto.Message) (store.Event, string, error) {
			request, ok := message.(*powermanagev1.CreateDeviceGroupRequest)
			if !ok {
				return store.Event{}, "", errors.New("control: wrong device-group request for create")
			}
			event, err := functions.createEvent(request)
			return event, "", err
		}
	}
	if functions.updateEvent != nil {
		domain.updateEvent = func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.UpdateDeviceGroupRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong device-group request for update")
			}
			return functions.updateEvent(request)
		}
	}
	if functions.deleteEvent != nil {
		domain.deleteEvent = func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.DeleteDeviceGroupRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong device-group request for delete")
			}
			return functions.deleteEvent(request)
		}
	}
	if functions.get != nil {
		domain.get = func(
			ctx context.Context,
			id string,
			scope CRUDScope,
		) (proto.Message, error) {
			group, err := functions.get(ctx, id, scope)
			if err != nil {
				return nil, err
			}
			return deviceGroupMessage(group), nil
		}
	}
	if functions.list != nil {
		domain.list = func(
			ctx context.Context,
			scope CRUDScope,
			limit int32,
		) ([]proto.Message, error) {
			groups, err := functions.list(ctx, scope, limit)
			if err != nil {
				return nil, err
			}
			messages := make([]proto.Message, len(groups))
			for index, group := range groups {
				messages[index] = deviceGroupMessage(group)
			}
			return messages, nil
		}
	}
	return domain
}

func deviceGroupMessage(group store.DeviceGroup) *powermanagev1.DeviceGroup {
	return &powermanagev1.DeviceGroup{
		Id:              group.ID,
		Name:            group.Name,
		DynamicQuery:    group.DynamicQuery,
		Version:         uint64(group.ProjectionVersion),
		StaticDeviceIds: slices.Clone(group.StaticDeviceIDs),
	}
}

func requestMessage[T any](request *connect.Request[T]) (proto.Message, error) {
	if request == nil || request.Msg == nil {
		return nil, errCRUDInvalid
	}
	message, ok := any(request.Msg).(proto.Message)
	if !ok {
		return nil, errCRUDInvalid
	}
	return message, nil
}
