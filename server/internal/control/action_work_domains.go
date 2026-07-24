package control

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/authz"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	actionDomainName           = "actions"
	actionSetDomainName        = "action-sets"
	assignmentDomainName       = "assignments"
	compliancePolicyDomainName = "compliance-policies"
)

func actionDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          actionDomainName,
		permission:    "actions.manage",
		objectMessage: (&powermanagev1.ManagedAction{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudCreate: (&powermanagev1.CreateActionRequest{}).ProtoReflect().Descriptor().FullName(),
			crudGet:    (&powermanagev1.GetActionRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList:   (&powermanagev1.ListActionsRequest{}).ProtoReflect().Descriptor().FullName(),
			crudUpdate: (&powermanagev1.UpdateActionRequest{}).ProtoReflect().Descriptor().FullName(),
			crudDelete: (&powermanagev1.DeleteActionRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudCreate: powermanagev1connect.ControlServiceCreateActionProcedure,
			crudGet:    powermanagev1connect.ControlServiceGetActionProcedure,
			crudList:   powermanagev1connect.ControlServiceListActionsProcedure,
			crudUpdate: powermanagev1connect.ControlServiceUpdateActionProcedure,
			crudDelete: powermanagev1connect.ControlServiceDeleteActionProcedure,
		},
		projectorEvents:   store.ManagedActionEventTypes(),
		searchableColumns: []string{"name"},
		alreadyExists:     store.IsManagedActionExists,
		scopeRelation:     crudScopeTransitiveDefinition,
		scope:             resourceCRUDScope,
		requestID:         managedActionRequestID,
		createEvent: func(
			_ context.Context,
			message proto.Message,
		) (store.Event, string, error) {
			request, ok := message.(*powermanagev1.CreateActionRequest)
			if !ok || request.GetAction() == nil {
				return store.Event{}, "", errors.New("control: wrong action request for create")
			}
			params, err := marshalActionParams(request.GetAction().GetParams())
			if err != nil {
				return store.Event{}, "", err
			}
			event, err := store.ManagedActionCreatedEvent(
				request.GetAction().GetId(),
				request.GetAction().GetName(),
				params,
			)
			if err != nil {
				return store.Event{}, "", fmt.Errorf("%w: action metadata", errCRUDInvalid)
			}
			return event, "", nil
		},
		updateEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.UpdateActionRequest)
			if !ok || request.GetAction() == nil {
				return store.Event{}, errors.New("control: wrong action request for update")
			}
			params, err := marshalActionParams(request.GetAction().GetParams())
			if err != nil {
				return store.Event{}, err
			}
			event, err := store.ManagedActionUpdatedEvent(
				request.GetAction().GetId(),
				request.GetAction().GetName(),
				params,
			)
			if err != nil {
				return store.Event{}, fmt.Errorf("%w: action metadata", errCRUDInvalid)
			}
			return event, nil
		},
		deleteEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.DeleteActionRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong action request for delete")
			}
			return store.ManagedActionDeletedEvent(request.GetId())
		},
		get: func(ctx context.Context, id string, scope CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			action, err := eventStore.ManagedActionByID(
				ctx,
				id,
				scope.Global,
				scope.DeviceGroupIDs,
				scope.UserGroupIDs,
				scope.SelfID,
			)
			if err != nil {
				return nil, err
			}
			return managedActionMessage(action)
		},
		list: func(ctx context.Context, scope CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			actions, err := eventStore.ListManagedActions(
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
			messages := make([]proto.Message, len(actions))
			for index, action := range actions {
				messages[index], err = managedActionMessage(action)
				if err != nil {
					return nil, err
				}
			}
			return messages, nil
		},
	}
}

func actionSetDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          actionSetDomainName,
		permission:    "action_sets.manage",
		objectMessage: (&powermanagev1.ActionSet{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudCreate: (&powermanagev1.CreateActionSetRequest{}).ProtoReflect().Descriptor().FullName(),
			crudGet:    (&powermanagev1.GetActionSetRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList:   (&powermanagev1.ListActionSetsRequest{}).ProtoReflect().Descriptor().FullName(),
			crudUpdate: (&powermanagev1.UpdateActionSetRequest{}).ProtoReflect().Descriptor().FullName(),
			crudDelete: (&powermanagev1.DeleteActionSetRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudCreate: powermanagev1connect.ControlServiceCreateActionSetProcedure,
			crudGet:    powermanagev1connect.ControlServiceGetActionSetProcedure,
			crudList:   powermanagev1connect.ControlServiceListActionSetsProcedure,
			crudUpdate: powermanagev1connect.ControlServiceUpdateActionSetProcedure,
			crudDelete: powermanagev1connect.ControlServiceDeleteActionSetProcedure,
		},
		projectorEvents:   store.ManagedActionSetEventTypes(),
		searchableColumns: []string{"name"},
		alreadyExists:     store.IsManagedActionSetExists,
		scopeRelation:     crudScopeTransitiveDefinition,
		scope:             resourceCRUDScope,
		createEvent: func(
			_ context.Context,
			message proto.Message,
		) (store.Event, string, error) {
			request, ok := message.(*powermanagev1.CreateActionSetRequest)
			if !ok {
				return store.Event{}, "", errors.New("control: wrong action-set request for create")
			}
			event, err := store.ManagedActionSetCreatedEvent(request.GetId(), request.GetName())
			if err != nil {
				return store.Event{}, "", fmt.Errorf("%w: action-set metadata", errCRUDInvalid)
			}
			return event, "", nil
		},
		updateEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.UpdateActionSetRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong action-set request for update")
			}
			event, err := store.ManagedActionSetUpdatedEvent(request.GetId(), request.GetName())
			if err != nil {
				return store.Event{}, fmt.Errorf("%w: action-set metadata", errCRUDInvalid)
			}
			return event, nil
		},
		deleteEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.DeleteActionSetRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong action-set request for delete")
			}
			return store.ManagedActionSetDeletedEvent(request.GetId())
		},
		get: func(ctx context.Context, id string, scope CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			set, err := eventStore.ManagedActionSetByID(
				ctx,
				id,
				scope.Global,
				scope.DeviceGroupIDs,
				scope.UserGroupIDs,
				scope.SelfID,
			)
			if err != nil {
				return nil, err
			}
			return actionSetMessage(set), nil
		},
		list: func(ctx context.Context, scope CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			sets, err := eventStore.ListManagedActionSets(
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
			messages := make([]proto.Message, len(sets))
			for index, set := range sets {
				messages[index] = actionSetMessage(set)
			}
			return messages, nil
		},
	}
}

func assignmentDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          assignmentDomainName,
		permission:    "actions.manage",
		objectMessage: (&powermanagev1.Assignment{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudCreate: (&powermanagev1.CreateAssignmentRequest{}).ProtoReflect().Descriptor().FullName(),
			crudGet:    (&powermanagev1.GetAssignmentRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList:   (&powermanagev1.ListAssignmentsRequest{}).ProtoReflect().Descriptor().FullName(),
			crudDelete: (&powermanagev1.DeleteAssignmentRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudCreate: powermanagev1connect.ControlServiceCreateAssignmentProcedure,
			crudGet:    powermanagev1connect.ControlServiceGetAssignmentProcedure,
			crudList:   powermanagev1connect.ControlServiceListAssignmentsProcedure,
			crudDelete: powermanagev1connect.ControlServiceDeleteAssignmentProcedure,
		},
		projectorEvents:   store.AssignmentEventTypes(),
		searchableColumns: []string{"source_id", "target_id"},
		alreadyExists:     store.IsAssignmentExists,
		scopeRelation:     crudScopeAssignment,
		scope:             resourceCRUDScope,
		validateScope: func(
			ctx context.Context,
			operation crudOperation,
			message proto.Message,
			scope CRUDScope,
		) error {
			if operation != crudCreate {
				return nil
			}
			request, ok := message.(*powermanagev1.CreateAssignmentRequest)
			if !ok || eventStore == nil {
				return errCRUDInvalid
			}
			if err := validateAssignmentTargetScope(ctx, eventStore, request, scope); err != nil {
				return err
			}
			switch request.GetSourceKind() {
			case powermanagev1.AssignmentSourceKind_ASSIGNMENT_SOURCE_KIND_ACTION:
				_, err := eventStore.ManagedActionByID(
					ctx,
					request.GetSourceId(),
					scope.Global,
					scope.DeviceGroupIDs,
					scope.UserGroupIDs,
					scope.SelfID,
				)
				return err
			case powermanagev1.AssignmentSourceKind_ASSIGNMENT_SOURCE_KIND_ACTION_SET:
				_, err := eventStore.ManagedActionSetByID(
					ctx,
					request.GetSourceId(),
					scope.Global,
					scope.DeviceGroupIDs,
					scope.UserGroupIDs,
					scope.SelfID,
				)
				return err
			default:
				return errCRUDInvalid
			}
		},
		createEvent: func(
			_ context.Context,
			message proto.Message,
		) (store.Event, string, error) {
			request, ok := message.(*powermanagev1.CreateAssignmentRequest)
			if !ok {
				return store.Event{}, "", errors.New("control: wrong assignment request for create")
			}
			assignment, err := assignmentFromRequest(request)
			if err != nil {
				return store.Event{}, "", err
			}
			event, err := store.AssignmentCreatedEvent(assignment)
			if err != nil {
				return store.Event{}, "", fmt.Errorf("%w: assignment metadata", errCRUDInvalid)
			}
			return event, "", nil
		},
		deleteEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.DeleteAssignmentRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong assignment request for delete")
			}
			return store.AssignmentDeletedEvent(request.GetId())
		},
		get: func(ctx context.Context, id string, scope CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			assignment, err := eventStore.AssignmentByID(
				ctx,
				id,
				scope.Global,
				scope.DeviceGroupIDs,
				scope.UserGroupIDs,
				scope.SelfID,
			)
			if err != nil {
				return nil, err
			}
			return assignmentMessage(assignment), nil
		},
		list: func(ctx context.Context, scope CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			assignments, err := eventStore.ListAssignments(
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
			messages := make([]proto.Message, len(assignments))
			for index, assignment := range assignments {
				messages[index] = assignmentMessage(assignment)
			}
			return messages, nil
		},
	}
}

func compliancePolicyDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          compliancePolicyDomainName,
		permission:    "actions.manage",
		objectMessage: (&powermanagev1.CompliancePolicy{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudCreate: (&powermanagev1.CreateCompliancePolicyRequest{}).ProtoReflect().Descriptor().FullName(),
			crudGet:    (&powermanagev1.GetCompliancePolicyRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList:   (&powermanagev1.ListCompliancePoliciesRequest{}).ProtoReflect().Descriptor().FullName(),
			crudUpdate: (&powermanagev1.UpdateCompliancePolicyRequest{}).ProtoReflect().Descriptor().FullName(),
			crudDelete: (&powermanagev1.DeleteCompliancePolicyRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudCreate: powermanagev1connect.ControlServiceCreateCompliancePolicyProcedure,
			crudGet:    powermanagev1connect.ControlServiceGetCompliancePolicyProcedure,
			crudList:   powermanagev1connect.ControlServiceListCompliancePoliciesProcedure,
			crudUpdate: powermanagev1connect.ControlServiceUpdateCompliancePolicyProcedure,
			crudDelete: powermanagev1connect.ControlServiceDeleteCompliancePolicyProcedure,
		},
		projectorEvents:   store.CompliancePolicyEventTypes(),
		searchableColumns: []string{"name"},
		alreadyExists:     store.IsCompliancePolicyExists,
		scopeRelation:     crudScopeGlobal,
		scope:             resourceCRUDScope,
		validateScope: func(
			ctx context.Context,
			operation crudOperation,
			message proto.Message,
			scope CRUDScope,
		) error {
			if operation != crudCreate && operation != crudUpdate {
				return nil
			}
			if eventStore == nil || !scope.Global {
				return store.ErrNotFound
			}
			var actionIDs []string
			switch request := message.(type) {
			case *powermanagev1.CreateCompliancePolicyRequest:
				actionIDs = request.GetRuleActionIds()
			case *powermanagev1.UpdateCompliancePolicyRequest:
				actionIDs = request.GetRuleActionIds()
			default:
				return errCRUDInvalid
			}
			for _, actionID := range actionIDs {
				if _, err := eventStore.ManagedActionByID(
					ctx,
					actionID,
					true,
					nil,
					nil,
					"",
				); err != nil {
					return err
				}
			}
			return nil
		},
		createEvent: func(
			_ context.Context,
			message proto.Message,
		) (store.Event, string, error) {
			request, ok := message.(*powermanagev1.CreateCompliancePolicyRequest)
			if !ok {
				return store.Event{}, "", errors.New("control: wrong compliance-policy request for create")
			}
			policy, err := compliancePolicyInput(
				request.GetId(),
				request.GetName(),
				request.GetRuleActionIds(),
				request.GetGraceHours(),
			)
			if err != nil {
				return store.Event{}, "", err
			}
			event, err := store.CompliancePolicyCreatedEvent(policy)
			if err != nil {
				return store.Event{}, "", fmt.Errorf("%w: compliance-policy metadata", errCRUDInvalid)
			}
			return event, "", nil
		},
		updateEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.UpdateCompliancePolicyRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong compliance-policy request for update")
			}
			policy, err := compliancePolicyInput(
				request.GetId(),
				request.GetName(),
				request.GetRuleActionIds(),
				request.GetGraceHours(),
			)
			if err != nil {
				return store.Event{}, err
			}
			event, err := store.CompliancePolicyUpdatedEvent(policy)
			if err != nil {
				return store.Event{}, fmt.Errorf("%w: compliance-policy metadata", errCRUDInvalid)
			}
			return event, nil
		},
		deleteEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.DeleteCompliancePolicyRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong compliance-policy request for delete")
			}
			return store.CompliancePolicyDeletedEvent(request.GetId())
		},
		get: func(ctx context.Context, id string, scope CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			policy, err := eventStore.CompliancePolicyByID(ctx, id, scope.Global)
			if err != nil {
				return nil, err
			}
			return compliancePolicyMessage(policy), nil
		},
		list: func(ctx context.Context, scope CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			policies, err := eventStore.ListCompliancePolicies(ctx, scope.Global, limit)
			if err != nil {
				return nil, err
			}
			messages := make([]proto.Message, len(policies))
			for index, policy := range policies {
				messages[index] = compliancePolicyMessage(policy)
			}
			return messages, nil
		},
	}
}

func compliancePolicyInput(
	id string,
	name string,
	actionIDs []string,
	graceHours uint32,
) (store.CompliancePolicy, error) {
	if graceHours > math.MaxInt32 {
		return store.CompliancePolicy{}, fmt.Errorf("%w: grace hours", errCRUDInvalid)
	}
	return store.CompliancePolicy{
		ID:            id,
		Name:          name,
		RuleActionIDs: slices.Clone(actionIDs),
		GraceHours:    int32(graceHours),
	}, nil
}

func resourceCRUDScope(reach authz.Reach) (CRUDScope, error) {
	return CRUDScope{
		Global:         reach.Global,
		DeviceGroupIDs: slices.Clone(reach.DeviceGroupIDs),
		UserGroupIDs:   slices.Clone(reach.UserGroupIDs),
	}, nil
}

func managedActionRequestID(message proto.Message) (string, error) {
	switch request := message.(type) {
	case *powermanagev1.CreateActionRequest:
		if request.GetAction() != nil {
			return request.GetAction().GetId(), nil
		}
	case *powermanagev1.UpdateActionRequest:
		if request.GetAction() != nil {
			return request.GetAction().GetId(), nil
		}
	default:
		return crudStringField(message, "id")
	}
	return "", errCRUDInvalid
}

func marshalActionParams(params *powermanagev1.ActionParams) ([]byte, error) {
	if params == nil {
		return nil, errCRUDInvalid
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(params)
	if err != nil || len(encoded) == 0 {
		return nil, errCRUDInvalid
	}
	return encoded, nil
}

func managedActionMessage(action store.ManagedAction) (*powermanagev1.ManagedAction, error) {
	params := &powermanagev1.ActionParams{}
	if err := proto.Unmarshal(action.Params, params); err != nil {
		return nil, errors.New("control: decode managed action")
	}
	return &powermanagev1.ManagedAction{
		Action: &powermanagev1.Action{
			Id: action.ID, Name: action.Name, Params: params,
		},
		Version: uint64(action.ProjectionVersion),
	}, nil
}

func actionSetMessage(set store.ManagedActionSet) *powermanagev1.ActionSet {
	return &powermanagev1.ActionSet{
		Id: set.ID, Name: set.Name, Version: uint64(set.ProjectionVersion),
	}
}

func assignmentFromRequest(
	request *powermanagev1.CreateAssignmentRequest,
) (store.Assignment, error) {
	var sourceKind store.AssignmentSourceKind
	switch request.GetSourceKind() {
	case powermanagev1.AssignmentSourceKind_ASSIGNMENT_SOURCE_KIND_ACTION:
		sourceKind = store.AssignmentSourceAction
	case powermanagev1.AssignmentSourceKind_ASSIGNMENT_SOURCE_KIND_ACTION_SET:
		sourceKind = store.AssignmentSourceActionSet
	default:
		return store.Assignment{}, errCRUDInvalid
	}
	var targetKind store.AssignmentTargetKind
	switch request.GetTargetKind() {
	case powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_DEVICE:
		targetKind = store.AssignmentTargetDevice
	case powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_USER:
		targetKind = store.AssignmentTargetUser
	case powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_DEVICE_GROUP:
		targetKind = store.AssignmentTargetDeviceGroup
	case powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_USER_GROUP:
		targetKind = store.AssignmentTargetUserGroup
	default:
		return store.Assignment{}, errCRUDInvalid
	}
	var mode store.AssignmentMode
	switch request.GetMode() {
	case powermanagev1.AssignmentMode_ASSIGNMENT_MODE_APPLY:
		mode = store.AssignmentModeApply
	case powermanagev1.AssignmentMode_ASSIGNMENT_MODE_UNINSTALL:
		mode = store.AssignmentModeUninstall
	default:
		return store.Assignment{}, errCRUDInvalid
	}
	return store.Assignment{
		ID: request.GetId(), SourceKind: sourceKind, SourceID: request.GetSourceId(),
		TargetKind: targetKind, TargetID: request.GetTargetId(), Mode: mode,
	}, nil
}

func validateAssignmentTargetScope(
	ctx context.Context,
	eventStore *store.Store,
	request *powermanagev1.CreateAssignmentRequest,
	scope CRUDScope,
) error {
	switch request.GetTargetKind() {
	case powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_DEVICE_GROUP:
		_, err := eventStore.DeviceGroupByID(
			ctx,
			request.GetTargetId(),
			scope.Global,
			scope.DeviceGroupIDs,
		)
		return err
	case powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_USER_GROUP:
		_, err := eventStore.UserGroupByID(
			ctx,
			request.GetTargetId(),
			scope.Global,
			scope.UserGroupIDs,
		)
		return err
	case powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_USER:
		_, err := eventStore.ScopedUserByID(
			ctx,
			request.GetTargetId(),
			scope.Global,
			scope.UserGroupIDs,
			scope.SelfID,
		)
		return err
	case powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_DEVICE:
		_, err := eventStore.ScopedDevice(
			ctx,
			request.GetTargetId(),
			scope.Global,
			scope.DeviceGroupIDs,
		)
		return err
	default:
		return errCRUDInvalid
	}
}

func assignmentMessage(assignment store.Assignment) *powermanagev1.Assignment {
	var sourceKind powermanagev1.AssignmentSourceKind
	switch assignment.SourceKind {
	case store.AssignmentSourceAction:
		sourceKind = powermanagev1.AssignmentSourceKind_ASSIGNMENT_SOURCE_KIND_ACTION
	case store.AssignmentSourceActionSet:
		sourceKind = powermanagev1.AssignmentSourceKind_ASSIGNMENT_SOURCE_KIND_ACTION_SET
	}
	var targetKind powermanagev1.AssignmentTargetKind
	switch assignment.TargetKind {
	case store.AssignmentTargetDevice:
		targetKind = powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_DEVICE
	case store.AssignmentTargetUser:
		targetKind = powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_USER
	case store.AssignmentTargetDeviceGroup:
		targetKind = powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_DEVICE_GROUP
	case store.AssignmentTargetUserGroup:
		targetKind = powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_USER_GROUP
	}
	var mode powermanagev1.AssignmentMode
	switch assignment.Mode {
	case store.AssignmentModeApply:
		mode = powermanagev1.AssignmentMode_ASSIGNMENT_MODE_APPLY
	case store.AssignmentModeUninstall:
		mode = powermanagev1.AssignmentMode_ASSIGNMENT_MODE_UNINSTALL
	}
	return &powermanagev1.Assignment{
		Id: assignment.ID, SourceKind: sourceKind, SourceId: assignment.SourceID,
		TargetKind: targetKind, TargetId: assignment.TargetID, Mode: mode,
		Version: uint64(assignment.ProjectionVersion),
	}
}

func compliancePolicyMessage(policy store.CompliancePolicy) *powermanagev1.CompliancePolicy {
	return &powermanagev1.CompliancePolicy{
		Id: policy.ID, Name: policy.Name,
		RuleActionIds: slices.Clone(policy.RuleActionIDs),
		GraceHours:    uint32(policy.GraceHours),
		Version:       uint64(policy.ProjectionVersion),
	}
}
