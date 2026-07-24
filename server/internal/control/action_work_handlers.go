package control

import (
	"context"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
)

func (s *ManagementService) CreateAction(
	ctx context.Context,
	request *connect.Request[powermanagev1.CreateActionRequest],
) (*connect.Response[powermanagev1.CreateActionResponse], error) {
	result, err := createIdentity(s, ctx, request, powermanagev1connect.ControlServiceCreateActionProcedure, actionDomainName)
	if err != nil {
		return nil, err
	}
	action, ok := result.(*powermanagev1.ManagedAction)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.CreateActionResponse{ManagedAction: action}), nil
}

func (s *ManagementService) GetAction(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetActionRequest],
) (*connect.Response[powermanagev1.GetActionResponse], error) {
	result, err := getIdentity(s, ctx, request, powermanagev1connect.ControlServiceGetActionProcedure, actionDomainName)
	if err != nil {
		return nil, err
	}
	action, ok := result.(*powermanagev1.ManagedAction)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.GetActionResponse{ManagedAction: action}), nil
}

func (s *ManagementService) ListActions(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListActionsRequest],
) (*connect.Response[powermanagev1.ListActionsResponse], error) {
	results, err := listIdentity(s, ctx, request, powermanagev1connect.ControlServiceListActionsProcedure, actionDomainName)
	if err != nil {
		return nil, err
	}
	actions := make([]*powermanagev1.ManagedAction, len(results))
	for index, result := range results {
		var ok bool
		actions[index], ok = result.(*powermanagev1.ManagedAction)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(&powermanagev1.ListActionsResponse{ManagedActions: actions}), nil
}

func (s *ManagementService) UpdateAction(
	ctx context.Context,
	request *connect.Request[powermanagev1.UpdateActionRequest],
) (*connect.Response[powermanagev1.UpdateActionResponse], error) {
	result, err := updateIdentity(s, ctx, request, powermanagev1connect.ControlServiceUpdateActionProcedure, actionDomainName)
	if err != nil {
		return nil, err
	}
	action, ok := result.(*powermanagev1.ManagedAction)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.UpdateActionResponse{ManagedAction: action}), nil
}

func (s *ManagementService) DeleteAction(
	ctx context.Context,
	request *connect.Request[powermanagev1.DeleteActionRequest],
) (*connect.Response[powermanagev1.DeleteActionResponse], error) {
	id, err := deleteIdentity(s, ctx, request, powermanagev1connect.ControlServiceDeleteActionProcedure, actionDomainName)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&powermanagev1.DeleteActionResponse{DeletedId: id}), nil
}

func (s *ManagementService) CreateActionSet(
	ctx context.Context,
	request *connect.Request[powermanagev1.CreateActionSetRequest],
) (*connect.Response[powermanagev1.CreateActionSetResponse], error) {
	result, err := createIdentity(s, ctx, request, powermanagev1connect.ControlServiceCreateActionSetProcedure, actionSetDomainName)
	if err != nil {
		return nil, err
	}
	actionSet, ok := result.(*powermanagev1.ActionSet)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.CreateActionSetResponse{ActionSet: actionSet}), nil
}

func (s *ManagementService) GetActionSet(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetActionSetRequest],
) (*connect.Response[powermanagev1.GetActionSetResponse], error) {
	result, err := getIdentity(s, ctx, request, powermanagev1connect.ControlServiceGetActionSetProcedure, actionSetDomainName)
	if err != nil {
		return nil, err
	}
	actionSet, ok := result.(*powermanagev1.ActionSet)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.GetActionSetResponse{ActionSet: actionSet}), nil
}

func (s *ManagementService) ListActionSets(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListActionSetsRequest],
) (*connect.Response[powermanagev1.ListActionSetsResponse], error) {
	results, err := listIdentity(s, ctx, request, powermanagev1connect.ControlServiceListActionSetsProcedure, actionSetDomainName)
	if err != nil {
		return nil, err
	}
	actionSets := make([]*powermanagev1.ActionSet, len(results))
	for index, result := range results {
		var ok bool
		actionSets[index], ok = result.(*powermanagev1.ActionSet)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(&powermanagev1.ListActionSetsResponse{ActionSets: actionSets}), nil
}

func (s *ManagementService) UpdateActionSet(
	ctx context.Context,
	request *connect.Request[powermanagev1.UpdateActionSetRequest],
) (*connect.Response[powermanagev1.UpdateActionSetResponse], error) {
	result, err := updateIdentity(s, ctx, request, powermanagev1connect.ControlServiceUpdateActionSetProcedure, actionSetDomainName)
	if err != nil {
		return nil, err
	}
	actionSet, ok := result.(*powermanagev1.ActionSet)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.UpdateActionSetResponse{ActionSet: actionSet}), nil
}

func (s *ManagementService) DeleteActionSet(
	ctx context.Context,
	request *connect.Request[powermanagev1.DeleteActionSetRequest],
) (*connect.Response[powermanagev1.DeleteActionSetResponse], error) {
	id, err := deleteIdentity(s, ctx, request, powermanagev1connect.ControlServiceDeleteActionSetProcedure, actionSetDomainName)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&powermanagev1.DeleteActionSetResponse{DeletedId: id}), nil
}

func (s *ManagementService) CreateAssignment(
	ctx context.Context,
	request *connect.Request[powermanagev1.CreateAssignmentRequest],
) (*connect.Response[powermanagev1.CreateAssignmentResponse], error) {
	result, err := createIdentity(s, ctx, request, powermanagev1connect.ControlServiceCreateAssignmentProcedure, assignmentDomainName)
	if err != nil {
		return nil, err
	}
	assignment, ok := result.(*powermanagev1.Assignment)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.CreateAssignmentResponse{Assignment: assignment}), nil
}

func (s *ManagementService) GetAssignment(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetAssignmentRequest],
) (*connect.Response[powermanagev1.GetAssignmentResponse], error) {
	result, err := getIdentity(s, ctx, request, powermanagev1connect.ControlServiceGetAssignmentProcedure, assignmentDomainName)
	if err != nil {
		return nil, err
	}
	assignment, ok := result.(*powermanagev1.Assignment)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.GetAssignmentResponse{Assignment: assignment}), nil
}

func (s *ManagementService) ListAssignments(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListAssignmentsRequest],
) (*connect.Response[powermanagev1.ListAssignmentsResponse], error) {
	results, err := listIdentity(s, ctx, request, powermanagev1connect.ControlServiceListAssignmentsProcedure, assignmentDomainName)
	if err != nil {
		return nil, err
	}
	assignments := make([]*powermanagev1.Assignment, len(results))
	for index, result := range results {
		var ok bool
		assignments[index], ok = result.(*powermanagev1.Assignment)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(&powermanagev1.ListAssignmentsResponse{Assignments: assignments}), nil
}

func (s *ManagementService) DeleteAssignment(
	ctx context.Context,
	request *connect.Request[powermanagev1.DeleteAssignmentRequest],
) (*connect.Response[powermanagev1.DeleteAssignmentResponse], error) {
	id, err := deleteIdentity(s, ctx, request, powermanagev1connect.ControlServiceDeleteAssignmentProcedure, assignmentDomainName)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&powermanagev1.DeleteAssignmentResponse{DeletedId: id}), nil
}

func (s *ManagementService) CreateCompliancePolicy(
	ctx context.Context,
	request *connect.Request[powermanagev1.CreateCompliancePolicyRequest],
) (*connect.Response[powermanagev1.CreateCompliancePolicyResponse], error) {
	result, err := createIdentity(s, ctx, request, powermanagev1connect.ControlServiceCreateCompliancePolicyProcedure, compliancePolicyDomainName)
	if err != nil {
		return nil, err
	}
	policy, ok := result.(*powermanagev1.CompliancePolicy)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.CreateCompliancePolicyResponse{CompliancePolicy: policy}), nil
}

func (s *ManagementService) GetCompliancePolicy(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetCompliancePolicyRequest],
) (*connect.Response[powermanagev1.GetCompliancePolicyResponse], error) {
	result, err := getIdentity(s, ctx, request, powermanagev1connect.ControlServiceGetCompliancePolicyProcedure, compliancePolicyDomainName)
	if err != nil {
		return nil, err
	}
	policy, ok := result.(*powermanagev1.CompliancePolicy)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.GetCompliancePolicyResponse{CompliancePolicy: policy}), nil
}

func (s *ManagementService) ListCompliancePolicies(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListCompliancePoliciesRequest],
) (*connect.Response[powermanagev1.ListCompliancePoliciesResponse], error) {
	results, err := listIdentity(s, ctx, request, powermanagev1connect.ControlServiceListCompliancePoliciesProcedure, compliancePolicyDomainName)
	if err != nil {
		return nil, err
	}
	policies := make([]*powermanagev1.CompliancePolicy, len(results))
	for index, result := range results {
		var ok bool
		policies[index], ok = result.(*powermanagev1.CompliancePolicy)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(&powermanagev1.ListCompliancePoliciesResponse{CompliancePolicies: policies}), nil
}

func (s *ManagementService) UpdateCompliancePolicy(
	ctx context.Context,
	request *connect.Request[powermanagev1.UpdateCompliancePolicyRequest],
) (*connect.Response[powermanagev1.UpdateCompliancePolicyResponse], error) {
	result, err := updateIdentity(s, ctx, request, powermanagev1connect.ControlServiceUpdateCompliancePolicyProcedure, compliancePolicyDomainName)
	if err != nil {
		return nil, err
	}
	policy, ok := result.(*powermanagev1.CompliancePolicy)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.UpdateCompliancePolicyResponse{CompliancePolicy: policy}), nil
}

func (s *ManagementService) DeleteCompliancePolicy(
	ctx context.Context,
	request *connect.Request[powermanagev1.DeleteCompliancePolicyRequest],
) (*connect.Response[powermanagev1.DeleteCompliancePolicyResponse], error) {
	id, err := deleteIdentity(s, ctx, request, powermanagev1connect.ControlServiceDeleteCompliancePolicyProcedure, compliancePolicyDomainName)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&powermanagev1.DeleteCompliancePolicyResponse{DeletedId: id}), nil
}
