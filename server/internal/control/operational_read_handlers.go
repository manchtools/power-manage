package control

import (
	"context"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
)

func (s *ManagementService) ListAuditEvents(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListAuditEventsRequest],
) (*connect.Response[powermanagev1.ListAuditEventsResponse], error) {
	results, err := listIdentity(s, ctx, request, powermanagev1connect.ControlServiceListAuditEventsProcedure, auditDomainName)
	if err != nil {
		return nil, err
	}
	events := make([]*powermanagev1.AuditEvent, len(results))
	for index, result := range results {
		var ok bool
		events[index], ok = result.(*powermanagev1.AuditEvent)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(&powermanagev1.ListAuditEventsResponse{AuditEvents: events}), nil
}

func (s *ManagementService) GetExecution(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetExecutionRequest],
) (*connect.Response[powermanagev1.GetExecutionResponse], error) {
	result, err := getIdentity(s, ctx, request, powermanagev1connect.ControlServiceGetExecutionProcedure, executionDomainName)
	if err != nil {
		return nil, err
	}
	execution, ok := result.(*powermanagev1.Execution)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.GetExecutionResponse{Execution: execution}), nil
}

func (s *ManagementService) ListExecutions(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListExecutionsRequest],
) (*connect.Response[powermanagev1.ListExecutionsResponse], error) {
	results, err := listIdentity(s, ctx, request, powermanagev1connect.ControlServiceListExecutionsProcedure, executionDomainName)
	if err != nil {
		return nil, err
	}
	executions := make([]*powermanagev1.Execution, len(results))
	for index, result := range results {
		var ok bool
		executions[index], ok = result.(*powermanagev1.Execution)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(&powermanagev1.ListExecutionsResponse{Executions: executions}), nil
}

func (s *ManagementService) GetInventorySnapshot(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetInventorySnapshotRequest],
) (*connect.Response[powermanagev1.GetInventorySnapshotResponse], error) {
	result, err := getIdentity(s, ctx, request, powermanagev1connect.ControlServiceGetInventorySnapshotProcedure, inventoryDomainName)
	if err != nil {
		return nil, err
	}
	snapshot, ok := result.(*powermanagev1.InventorySnapshot)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.GetInventorySnapshotResponse{InventorySnapshot: snapshot}), nil
}

func (s *ManagementService) ListInventorySnapshots(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListInventorySnapshotsRequest],
) (*connect.Response[powermanagev1.ListInventorySnapshotsResponse], error) {
	results, err := listIdentity(s, ctx, request, powermanagev1connect.ControlServiceListInventorySnapshotsProcedure, inventoryDomainName)
	if err != nil {
		return nil, err
	}
	snapshots := make([]*powermanagev1.InventorySnapshot, len(results))
	for index, result := range results {
		var ok bool
		snapshots[index], ok = result.(*powermanagev1.InventorySnapshot)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(
		&powermanagev1.ListInventorySnapshotsResponse{InventorySnapshots: snapshots},
	), nil
}

func (s *ManagementService) GetGateway(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetGatewayRequest],
) (*connect.Response[powermanagev1.GetGatewayResponse], error) {
	result, err := getIdentity(s, ctx, request, powermanagev1connect.ControlServiceGetGatewayProcedure, gatewayDomainName)
	if err != nil {
		return nil, err
	}
	gateway, ok := result.(*powermanagev1.Gateway)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.GetGatewayResponse{Gateway: gateway}), nil
}

func (s *ManagementService) ListGateways(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListGatewaysRequest],
) (*connect.Response[powermanagev1.ListGatewaysResponse], error) {
	results, err := listIdentity(s, ctx, request, powermanagev1connect.ControlServiceListGatewaysProcedure, gatewayDomainName)
	if err != nil {
		return nil, err
	}
	gateways := make([]*powermanagev1.Gateway, len(results))
	for index, result := range results {
		var ok bool
		gateways[index], ok = result.(*powermanagev1.Gateway)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(&powermanagev1.ListGatewaysResponse{Gateways: gateways}), nil
}
