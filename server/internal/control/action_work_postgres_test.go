package control

import (
	"testing"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	managementActionID           = "01J00000000000000000000161"
	managementActionSetID        = "01J00000000000000000000162"
	managementAssignmentID       = "01J00000000000000000000163"
	managementScopedAssignmentID = "01J00000000000000000000164"
	managementSetAssignmentID    = "01J00000000000000000000165"
	managementPolicyID           = "01J00000000000000000000166"
	managementInvalidObjectID    = "01J00000000000000000000167"
	managementMissingTargetID    = "01J00000000000000000000168"
)

func TestActionWorkHandlers_CRUDScopeAndRebuild(t *testing.T) {
	eventStore, service := identityManagementService(t)
	admin := identityContext(t, identityAdminID)
	scoped := identityContext(t, identityScopedID)
	params := &powermanagev1.ActionParams{
		Params: &powermanagev1.ActionParams_Package{
			Package: &powermanagev1.PackageParams{},
		},
	}

	createdAction, err := service.CreateAction(admin, connect.NewRequest(
		&powermanagev1.CreateActionRequest{Action: &powermanagev1.Action{
			Id: managementActionID, Name: "install agent", Params: params,
		}},
	))
	if err != nil || createdAction.Msg.GetManagedAction().GetVersion() != 1 {
		t.Fatalf("create action = (%#v, %v); want version one", createdAction, err)
	}
	createdSet, err := service.CreateActionSet(admin, connect.NewRequest(
		&powermanagev1.CreateActionSetRequest{
			Id: managementActionSetID, Name: "base workstation",
		},
	))
	if err != nil || createdSet.Msg.GetActionSet().GetVersion() != 1 {
		t.Fatalf("create action set = (%#v, %v); want version one", createdSet, err)
	}
	if _, err := service.CreateAssignment(admin, connect.NewRequest(
		&powermanagev1.CreateAssignmentRequest{
			Id:         managementInvalidObjectID,
			SourceKind: powermanagev1.AssignmentSourceKind_ASSIGNMENT_SOURCE_KIND_ACTION,
			SourceId:   managementActionID,
			TargetKind: powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_USER_GROUP,
			TargetId:   managementMissingTargetID,
			Mode:       powermanagev1.AssignmentMode_ASSIGNMENT_MODE_APPLY,
		},
	)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("missing assignment target code = %v; want NotFound", connect.CodeOf(err))
	}
	for _, request := range []*powermanagev1.CreateAssignmentRequest{
		{
			Id:         managementAssignmentID,
			SourceKind: powermanagev1.AssignmentSourceKind_ASSIGNMENT_SOURCE_KIND_ACTION,
			SourceId:   managementActionID,
			TargetKind: powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_USER_GROUP,
			TargetId:   identityGroupID,
			Mode:       powermanagev1.AssignmentMode_ASSIGNMENT_MODE_APPLY,
		},
		{
			Id:         managementSetAssignmentID,
			SourceKind: powermanagev1.AssignmentSourceKind_ASSIGNMENT_SOURCE_KIND_ACTION_SET,
			SourceId:   managementActionSetID,
			TargetKind: powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_USER_GROUP,
			TargetId:   identityGroupID,
			Mode:       powermanagev1.AssignmentMode_ASSIGNMENT_MODE_APPLY,
		},
	} {
		if _, err := service.CreateAssignment(admin, connect.NewRequest(request)); err != nil {
			t.Fatalf("create assignment %s: %v", request.GetId(), err)
		}
	}

	scopedActions, err := service.ListActions(scoped, connect.NewRequest(
		&powermanagev1.ListActionsRequest{Limit: 100},
	))
	if err != nil || len(scopedActions.Msg.GetManagedActions()) != 1 ||
		scopedActions.Msg.GetManagedActions()[0].GetAction().GetId() != managementActionID {
		t.Fatalf("scoped actions = (%#v, %v); want assigned action", scopedActions, err)
	}
	scopedSets, err := service.ListActionSets(scoped, connect.NewRequest(
		&powermanagev1.ListActionSetsRequest{Limit: 100},
	))
	if err != nil || len(scopedSets.Msg.GetActionSets()) != 1 ||
		scopedSets.Msg.GetActionSets()[0].GetId() != managementActionSetID {
		t.Fatalf("scoped action sets = (%#v, %v); want assigned set", scopedSets, err)
	}
	if _, err := service.UpdateAction(scoped, connect.NewRequest(
		&powermanagev1.UpdateActionRequest{
			Action: &powermanagev1.Action{
				Id: managementActionID, Name: "forbidden", Params: params,
			},
			ExpectedVersion: 1,
		},
	)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("scoped action update code = %v; want NotFound", connect.CodeOf(err))
	}
	if _, err := service.CreateAssignment(scoped, connect.NewRequest(
		&powermanagev1.CreateAssignmentRequest{
			Id:         managementScopedAssignmentID,
			SourceKind: powermanagev1.AssignmentSourceKind_ASSIGNMENT_SOURCE_KIND_ACTION,
			SourceId:   managementActionID,
			TargetKind: powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_USER_GROUP,
			TargetId:   identityGroupID,
			Mode:       powermanagev1.AssignmentMode_ASSIGNMENT_MODE_UNINSTALL,
		},
	)); err != nil {
		t.Fatalf("create scoped assignment: %v", err)
	}
	if _, err := service.DeleteAssignment(scoped, connect.NewRequest(
		&powermanagev1.DeleteAssignmentRequest{
			Id: managementScopedAssignmentID, ExpectedVersion: 1,
		},
	)); err != nil {
		t.Fatalf("delete scoped assignment: %v", err)
	}

	updatedAction, err := service.UpdateAction(admin, connect.NewRequest(
		&powermanagev1.UpdateActionRequest{
			Action: &powermanagev1.Action{
				Id: managementActionID, Name: "install managed agent", Params: params,
			},
			ExpectedVersion: 1,
		},
	))
	if err != nil || updatedAction.Msg.GetManagedAction().GetVersion() != 2 {
		t.Fatalf("update action = (%#v, %v); want version two", updatedAction, err)
	}
	updatedSet, err := service.UpdateActionSet(admin, connect.NewRequest(
		&powermanagev1.UpdateActionSetRequest{
			Id: managementActionSetID, Name: "managed workstation", ExpectedVersion: 1,
		},
	))
	if err != nil || updatedSet.Msg.GetActionSet().GetVersion() != 2 {
		t.Fatalf("update action set = (%#v, %v); want version two", updatedSet, err)
	}
	createdPolicy, err := service.CreateCompliancePolicy(admin, connect.NewRequest(
		&powermanagev1.CreateCompliancePolicyRequest{
			Id: managementPolicyID, Name: "managed baseline",
			RuleActionIds: []string{managementActionID}, GraceHours: 24,
		},
	))
	if err != nil || createdPolicy.Msg.GetCompliancePolicy().GetVersion() != 1 {
		t.Fatalf("create compliance policy = (%#v, %v); want version one", createdPolicy, err)
	}
	if _, err := service.CreateCompliancePolicy(admin, connect.NewRequest(
		&powermanagev1.CreateCompliancePolicyRequest{
			Id: managementInvalidObjectID, Name: "invalid",
			RuleActionIds: []string{managementMissingTargetID},
		},
	)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("missing policy action code = %v; want NotFound", connect.CodeOf(err))
	}
	if _, err := service.GetCompliancePolicy(scoped, connect.NewRequest(
		&powermanagev1.GetCompliancePolicyRequest{Id: managementPolicyID},
	)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("scoped compliance-policy code = %v; want NotFound", connect.CodeOf(err))
	}
	scopedPolicies, err := service.ListCompliancePolicies(scoped, connect.NewRequest(
		&powermanagev1.ListCompliancePoliciesRequest{Limit: 100},
	))
	if err != nil || len(scopedPolicies.Msg.GetCompliancePolicies()) != 0 {
		t.Fatalf("scoped compliance policies = (%#v, %v); want empty", scopedPolicies, err)
	}
	updatedPolicy, err := service.UpdateCompliancePolicy(admin, connect.NewRequest(
		&powermanagev1.UpdateCompliancePolicyRequest{
			Id: managementPolicyID, Name: "managed baseline",
			RuleActionIds: []string{managementActionID}, GraceHours: 48,
			ExpectedVersion: 1,
		},
	))
	if err != nil || updatedPolicy.Msg.GetCompliancePolicy().GetVersion() != 2 {
		t.Fatalf("update compliance policy = (%#v, %v); want version two", updatedPolicy, err)
	}

	for _, target := range []string{
		store.ActionRebuildTarget,
		store.ActionSetRebuildTarget,
		store.AssignmentRebuildTarget,
		store.CompliancePolicyRebuildTarget,
	} {
		if err := eventStore.RebuildAll(t.Context(), target); err != nil {
			t.Fatalf("rebuild %s: %v", target, err)
		}
	}
	action, err := eventStore.ManagedActionByID(
		t.Context(), managementActionID, true, nil, nil, "",
	)
	if err != nil || action.Name != "install managed agent" ||
		action.ProjectionVersion != 2 {
		t.Fatalf("rebuilt action = (%#v, %v); want updated action", action, err)
	}
	actionSet, err := eventStore.ManagedActionSetByID(
		t.Context(), managementActionSetID, true, nil, nil, "",
	)
	if err != nil || actionSet.Name != "managed workstation" ||
		actionSet.ProjectionVersion != 2 {
		t.Fatalf("rebuilt action set = (%#v, %v); want updated set", actionSet, err)
	}
	assignments, err := eventStore.ListAssignments(
		t.Context(), true, nil, nil, "", 100,
	)
	if err != nil || len(assignments) != 2 {
		t.Fatalf("rebuilt assignments = (%#v, %v); want two live assignments", assignments, err)
	}
	policy, err := eventStore.CompliancePolicyByID(
		t.Context(), managementPolicyID, true,
	)
	if err != nil || policy.GraceHours != 48 || policy.ProjectionVersion != 2 {
		t.Fatalf("rebuilt compliance policy = (%#v, %v); want version two", policy, err)
	}

	for _, assignmentID := range []string{managementAssignmentID, managementSetAssignmentID} {
		if _, err := service.DeleteAssignment(admin, connect.NewRequest(
			&powermanagev1.DeleteAssignmentRequest{
				Id: assignmentID, ExpectedVersion: 1,
			},
		)); err != nil {
			t.Fatalf("delete assignment %s: %v", assignmentID, err)
		}
	}
	if _, err := service.DeleteCompliancePolicy(admin, connect.NewRequest(
		&powermanagev1.DeleteCompliancePolicyRequest{
			Id: managementPolicyID, ExpectedVersion: 2,
		},
	)); err != nil {
		t.Fatalf("delete compliance policy: %v", err)
	}
	if _, err := service.DeleteAction(admin, connect.NewRequest(
		&powermanagev1.DeleteActionRequest{
			Id: managementActionID, ExpectedVersion: 2,
		},
	)); err != nil {
		t.Fatalf("delete action: %v", err)
	}
	if _, err := service.DeleteActionSet(admin, connect.NewRequest(
		&powermanagev1.DeleteActionSetRequest{
			Id: managementActionSetID, ExpectedVersion: 2,
		},
	)); err != nil {
		t.Fatalf("delete action set: %v", err)
	}
	for _, target := range []string{
		store.ActionRebuildTarget,
		store.ActionSetRebuildTarget,
		store.AssignmentRebuildTarget,
		store.CompliancePolicyRebuildTarget,
	} {
		if err := eventStore.RebuildAll(t.Context(), target); err != nil {
			t.Fatalf("rebuild deleted %s: %v", target, err)
		}
	}
	if _, err := eventStore.ManagedActionByID(
		t.Context(), managementActionID, true, nil, nil, "",
	); !store.IsNotFound(err) {
		t.Fatalf("rebuilt deleted action error = %v; want NotFound", err)
	}
	if _, err := eventStore.ManagedActionSetByID(
		t.Context(), managementActionSetID, true, nil, nil, "",
	); !store.IsNotFound(err) {
		t.Fatalf("rebuilt deleted action set error = %v; want NotFound", err)
	}
	if assignments, err := eventStore.ListAssignments(
		t.Context(), true, nil, nil, "", 100,
	); err != nil || len(assignments) != 0 {
		t.Fatalf("rebuilt deleted assignments = (%#v, %v); want empty", assignments, err)
	}
	if _, err := eventStore.CompliancePolicyByID(
		t.Context(), managementPolicyID, true,
	); !store.IsNotFound(err) {
		t.Fatalf("rebuilt deleted policy error = %v; want NotFound", err)
	}
}
