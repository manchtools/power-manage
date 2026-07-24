package control

import (
	"context"
	"errors"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	auditDomainName     = "audit"
	executionDomainName = "executions"
	inventoryDomainName = "inventory"
	gatewayDomainName   = "gateways"
)

func auditDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:              auditDomainName,
		permission:        "audit.read",
		objectMessage:     (&powermanagev1.AuditEvent{}).ProtoReflect().Descriptor().FullName(),
		requestMessages:   readRequestMessages((&powermanagev1.ListAuditEventsRequest{}).ProtoReflect().Descriptor().FullName()),
		procedures:        readProcedures(powermanagev1connect.ControlServiceListAuditEventsProcedure),
		searchableColumns: []string{"stream_type", "stream_id", "event_type"},
		scopeRelation:     crudScopeUserOwned,
		scope:             resourceCRUDScope,
		list: func(ctx context.Context, scope CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			events, err := eventStore.ListAuditEvents(
				ctx,
				scope.Global,
				scope.DeviceGroupIDs,
				scope.UserGroupIDs,
				scope.SelfID,
				limit,
			)
			if err != nil {
				return nil, err
			}
			messages := make([]proto.Message, len(events))
			for index, event := range events {
				messages[index] = &powermanagev1.AuditEvent{
					StreamType: event.StreamType, StreamId: event.StreamID,
					StreamVersion: uint64(event.StreamVersion), EventType: event.EventType,
					PayloadVersion: uint32(event.PayloadVersion),
					CreatedAt:      timestamppb.New(event.CreatedAt),
					GlobalPosition: uint64(event.GlobalPosition),
				}
			}
			return messages, nil
		},
	}
}

func executionDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          executionDomainName,
		permission:    "executions.read",
		objectMessage: (&powermanagev1.Execution{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudGet:  (&powermanagev1.GetExecutionRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList: (&powermanagev1.ListExecutionsRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudGet:  powermanagev1connect.ControlServiceGetExecutionProcedure,
			crudList: powermanagev1connect.ControlServiceListExecutionsProcedure,
		},
		searchableColumns: []string{"execution_id", "device_id"},
		scopeRelation:     crudScopeDevice,
		scope:             resourceCRUDScope,
		get: func(ctx context.Context, id string, scope CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			execution, err := eventStore.ExecutionByID(
				ctx,
				id,
				scope.Global,
				scope.DeviceGroupIDs,
			)
			if err != nil {
				return nil, err
			}
			return executionMessage(execution), nil
		},
		list: func(ctx context.Context, scope CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			executions, err := eventStore.ListExecutions(
				ctx,
				scope.Global,
				scope.DeviceGroupIDs,
				limit,
			)
			if err != nil {
				return nil, err
			}
			messages := make([]proto.Message, len(executions))
			for index, execution := range executions {
				messages[index] = executionMessage(execution)
			}
			return messages, nil
		},
	}
}

func inventoryDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          inventoryDomainName,
		permission:    "devices.manage",
		objectMessage: (&powermanagev1.InventorySnapshot{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudGet:  (&powermanagev1.GetInventorySnapshotRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList: (&powermanagev1.ListInventorySnapshotsRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudGet:  powermanagev1connect.ControlServiceGetInventorySnapshotProcedure,
			crudList: powermanagev1connect.ControlServiceListInventorySnapshotsProcedure,
		},
		searchableColumns: []string{"agent_id"},
		scopeRelation:     crudScopeDevice,
		scope:             resourceCRUDScope,
		get: func(ctx context.Context, id string, scope CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			snapshot, err := eventStore.InventorySnapshotByID(
				ctx,
				id,
				scope.Global,
				scope.DeviceGroupIDs,
			)
			if err != nil {
				return nil, err
			}
			return inventorySnapshotMessage(snapshot), nil
		},
		list: func(ctx context.Context, scope CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			snapshots, err := eventStore.ListInventorySnapshots(
				ctx,
				scope.Global,
				scope.DeviceGroupIDs,
				limit,
			)
			if err != nil {
				return nil, err
			}
			messages := make([]proto.Message, len(snapshots))
			for index, snapshot := range snapshots {
				messages[index] = inventorySnapshotMessage(snapshot)
			}
			return messages, nil
		},
	}
}

func gatewayDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          gatewayDomainName,
		permission:    "pki.manage",
		objectMessage: (&powermanagev1.Gateway{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudGet:  (&powermanagev1.GetGatewayRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList: (&powermanagev1.ListGatewaysRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudGet:  powermanagev1connect.ControlServiceGetGatewayProcedure,
			crudList: powermanagev1connect.ControlServiceListGatewaysProcedure,
		},
		searchableColumns: []string{"gateway_id", "owner", "dns_names"},
		scopeRelation:     crudScopeGlobal,
		scope:             resourceCRUDScope,
		get: func(ctx context.Context, id string, scope CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			gateway, err := eventStore.GatewaySummaryByID(ctx, id, scope.Global)
			if err != nil {
				return nil, err
			}
			return gatewayMessage(gateway), nil
		},
		list: func(ctx context.Context, scope CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			gateways, err := eventStore.ListGatewaySummaries(ctx, scope.Global, limit)
			if err != nil {
				return nil, err
			}
			messages := make([]proto.Message, len(gateways))
			for index, gateway := range gateways {
				messages[index] = gatewayMessage(gateway)
			}
			return messages, nil
		},
	}
}

func readRequestMessages(list protoreflect.FullName) map[crudOperation]protoreflect.FullName {
	return map[crudOperation]protoreflect.FullName{crudList: list}
}

func readProcedures(list string) map[crudOperation]string {
	return map[crudOperation]string{crudList: list}
}

func executionMessage(execution store.Execution) *powermanagev1.Execution {
	return &powermanagev1.Execution{
		Id: execution.ExecutionID, DeviceId: execution.DeviceID,
		OutputBytes:  uint64(execution.OutputBytes),
		OutputChunks: uint32(execution.OutputChunks), Truncated: execution.Truncated,
		UpdatedAt: timestamppb.New(execution.UpdatedAt),
	}
}

func inventorySnapshotMessage(snapshot store.InventorySnapshot) *powermanagev1.InventorySnapshot {
	return &powermanagev1.InventorySnapshot{
		AgentId: snapshot.AgentID, Version: uint64(snapshot.ProjectionVersion),
		PayloadVersion: uint32(snapshot.PayloadVersion), Snapshot: snapshot.Snapshot,
		UpdatedAt: timestamppb.New(snapshot.UpdatedAt),
	}
}

func gatewayMessage(gateway store.GatewaySummary) *powermanagev1.Gateway {
	state := powermanagev1.GatewayState_GATEWAY_STATE_ACTIVE
	if gateway.LifecycleState == store.GatewayLifecycleRevoked {
		state = powermanagev1.GatewayState_GATEWAY_STATE_REVOKED
	}
	return &powermanagev1.Gateway{
		Id: gateway.GatewayID, CertificateFingerprint: gateway.CertificateFingerprint,
		RegistrationTokenId: gateway.RegistrationTokenID, Owner: gateway.Owner,
		DnsNames: gateway.DNSNames, State: state,
		Version:   uint64(gateway.ProjectionVersion),
		UpdatedAt: timestamppb.New(gateway.UpdatedAt),
	}
}
