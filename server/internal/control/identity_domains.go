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

const (
	userDomainName      = "users"
	roleDomainName      = "roles"
	grantDomainName     = "grants"
	userGroupDomainName = "user-groups"
)

func identityDomains(eventStore *store.Store) []crudDomain {
	return []crudDomain{
		userDomain(eventStore),
		roleDomain(eventStore),
		grantDomain(eventStore),
		userGroupDomain(eventStore),
	}
}

func userGroupDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          userGroupDomainName,
		permission:    "user_groups.manage",
		objectMessage: (&powermanagev1.UserGroup{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudCreate: (&powermanagev1.CreateUserGroupRequest{}).ProtoReflect().Descriptor().FullName(),
			crudGet:    (&powermanagev1.GetUserGroupRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList:   (&powermanagev1.ListUserGroupsRequest{}).ProtoReflect().Descriptor().FullName(),
			crudUpdate: (&powermanagev1.UpdateUserGroupRequest{}).ProtoReflect().Descriptor().FullName(),
			crudDelete: (&powermanagev1.DeleteUserGroupRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudCreate: powermanagev1connect.ControlServiceCreateUserGroupProcedure,
			crudGet:    powermanagev1connect.ControlServiceGetUserGroupProcedure,
			crudList:   powermanagev1connect.ControlServiceListUserGroupsProcedure,
			crudUpdate: powermanagev1connect.ControlServiceUpdateUserGroupProcedure,
			crudDelete: powermanagev1connect.ControlServiceDeleteUserGroupProcedure,
		},
		projectorEvents:   store.UserGroupEventTypes(),
		searchableColumns: []string{"name"},
		alreadyExists:     store.IsUserGroupExists,
		scopeRelation:     crudScopeUserGroup,
		scope: func(reach authz.Reach) (CRUDScope, error) {
			return CRUDScope{
				Global:       reach.Global,
				UserGroupIDs: slices.Clone(reach.UserGroupIDs),
			}, nil
		},
		createEvent: func(_ context.Context, message proto.Message) (store.Event, string, error) {
			request, ok := message.(*powermanagev1.CreateUserGroupRequest)
			if !ok {
				return store.Event{}, "", errors.New("control: wrong user-group request for create")
			}
			return createWithoutCredential(
				store.UserGroupCreatedEvent(request.GetId(), request.GetName(), nil),
			)
		},
		updateEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.UpdateUserGroupRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong user-group request for update")
			}
			return store.UserGroupMetadataUpdatedEvent(request.GetId(), request.GetName())
		},
		deleteEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.DeleteUserGroupRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong user-group request for delete")
			}
			return store.UserGroupDeletedEvent(request.GetId())
		},
		get: func(ctx context.Context, id string, scope CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			group, err := eventStore.UserGroupByID(
				ctx,
				id,
				scope.Global,
				scope.UserGroupIDs,
			)
			if err != nil {
				return nil, err
			}
			return userGroupMessage(group), nil
		},
		list: func(ctx context.Context, scope CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			groups, err := eventStore.ListUserGroups(
				ctx,
				scope.Global,
				scope.UserGroupIDs,
				limit,
			)
			if err != nil {
				return nil, err
			}
			messages := make([]proto.Message, len(groups))
			for index, group := range groups {
				messages[index] = userGroupMessage(group)
			}
			return messages, nil
		},
	}
}

func userDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          userDomainName,
		permission:    "users.manage",
		objectMessage: (&powermanagev1.User{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudCreate: (&powermanagev1.CreateUserRequest{}).ProtoReflect().Descriptor().FullName(),
			crudGet:    (&powermanagev1.GetUserRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList:   (&powermanagev1.ListUsersRequest{}).ProtoReflect().Descriptor().FullName(),
			crudUpdate: (&powermanagev1.UpdateUserRequest{}).ProtoReflect().Descriptor().FullName(),
			crudDelete: (&powermanagev1.DeleteUserRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudCreate: powermanagev1connect.ControlServiceCreateUserProcedure,
			crudGet:    powermanagev1connect.ControlServiceGetUserProcedure,
			crudList:   powermanagev1connect.ControlServiceListUsersProcedure,
			crudUpdate: powermanagev1connect.ControlServiceUpdateUserProcedure,
			crudDelete: powermanagev1connect.ControlServiceDeleteUserProcedure,
		},
		projectorEvents:   store.UserManagementEventTypes(),
		searchableColumns: []string{"email"},
		alreadyExists:     store.IsUserExists,
		scopeRelation:     crudScopeUser,
		scope: func(reach authz.Reach) (CRUDScope, error) {
			return CRUDScope{
				Global:       reach.Global,
				UserGroupIDs: slices.Clone(reach.UserGroupIDs),
			}, nil
		},
		createEvent: func(_ context.Context, message proto.Message) (store.Event, string, error) {
			request, ok := message.(*powermanagev1.CreateUserRequest)
			if !ok {
				return store.Event{}, "", errors.New("control: wrong user request for create")
			}
			return createWithoutCredential(
				store.UserCreatedEvent(request.GetId(), request.GetEmail()),
			)
		},
		updateEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.UpdateUserRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong user request for update")
			}
			return store.UserManagedUpdatedEvent(request.GetId(), request.GetEmail())
		},
		deleteEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.DeleteUserRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong user request for delete")
			}
			return store.UserManagedDeletedEvent(request.GetId())
		},
		get: func(ctx context.Context, id string, scope CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			user, err := eventStore.ScopedUserByID(
				ctx,
				id,
				scope.Global,
				scope.UserGroupIDs,
				scope.SelfID,
			)
			if err != nil {
				return nil, err
			}
			return userMessage(user), nil
		},
		list: func(ctx context.Context, scope CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			users, err := eventStore.ListScopedUsers(
				ctx,
				scope.Global,
				scope.UserGroupIDs,
				scope.SelfID,
				limit,
			)
			if err != nil {
				return nil, err
			}
			messages := make([]proto.Message, len(users))
			for index, user := range users {
				messages[index] = userMessage(user)
			}
			return messages, nil
		},
	}
}

func roleDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          roleDomainName,
		permission:    "roles.manage",
		objectMessage: (&powermanagev1.Role{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudCreate: (&powermanagev1.CreateRoleRequest{}).ProtoReflect().Descriptor().FullName(),
			crudGet:    (&powermanagev1.GetRoleRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList:   (&powermanagev1.ListRolesRequest{}).ProtoReflect().Descriptor().FullName(),
			crudUpdate: (&powermanagev1.UpdateRoleRequest{}).ProtoReflect().Descriptor().FullName(),
			crudDelete: (&powermanagev1.DeleteRoleRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudCreate: powermanagev1connect.ControlServiceCreateRoleProcedure,
			crudGet:    powermanagev1connect.ControlServiceGetRoleProcedure,
			crudList:   powermanagev1connect.ControlServiceListRolesProcedure,
			crudUpdate: powermanagev1connect.ControlServiceUpdateRoleProcedure,
			crudDelete: powermanagev1connect.ControlServiceDeleteRoleProcedure,
		},
		projectorEvents:   store.AuthorizationRoleEventTypes(),
		searchableColumns: []string{"name"},
		alreadyExists:     store.IsAuthorizationRoleExists,
		scopeRelation:     crudScopeGlobal,
		scope:             globalCRUDScope,
		createEvent: func(_ context.Context, message proto.Message) (store.Event, string, error) {
			request, ok := message.(*powermanagev1.CreateRoleRequest)
			if !ok {
				return store.Event{}, "", errors.New("control: wrong role request for create")
			}
			return createWithoutCredential(
				store.AuthorizationRoleCreatedEvent(
					request.GetId(),
					request.GetName(),
					permissions(request.GetPermissions()),
				),
			)
		},
		updateEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.UpdateRoleRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong role request for update")
			}
			return store.AuthorizationRoleUpdatedEvent(
				request.GetId(),
				request.GetName(),
				permissions(request.GetPermissions()),
			)
		},
		deleteEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.DeleteRoleRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong role request for delete")
			}
			return store.AuthorizationRoleDeletedEvent(request.GetId())
		},
		get: func(ctx context.Context, id string, _ CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			role, err := eventStore.AuthorizationRoleByID(ctx, id)
			if err != nil {
				return nil, err
			}
			return roleMessage(role), nil
		},
		list: func(ctx context.Context, _ CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			roles, err := eventStore.ListAuthorizationRoles(ctx, limit)
			if err != nil {
				return nil, err
			}
			messages := make([]proto.Message, len(roles))
			for index, role := range roles {
				messages[index] = roleMessage(role)
			}
			return messages, nil
		},
	}
}

func grantDomain(eventStore *store.Store) crudDomain {
	return crudDomain{
		name:          grantDomainName,
		permission:    "roles.manage",
		objectMessage: (&powermanagev1.GrantView{}).ProtoReflect().Descriptor().FullName(),
		requestMessages: map[crudOperation]protoreflect.FullName{
			crudCreate: (&powermanagev1.CreateGrantRequest{}).ProtoReflect().Descriptor().FullName(),
			crudGet:    (&powermanagev1.GetGrantRequest{}).ProtoReflect().Descriptor().FullName(),
			crudList:   (&powermanagev1.ListGrantsRequest{}).ProtoReflect().Descriptor().FullName(),
			crudUpdate: (&powermanagev1.UpdateGrantRequest{}).ProtoReflect().Descriptor().FullName(),
			crudDelete: (&powermanagev1.DeleteGrantRequest{}).ProtoReflect().Descriptor().FullName(),
		},
		procedures: map[crudOperation]string{
			crudCreate: powermanagev1connect.ControlServiceCreateGrantProcedure,
			crudGet:    powermanagev1connect.ControlServiceGetGrantProcedure,
			crudList:   powermanagev1connect.ControlServiceListGrantsProcedure,
			crudUpdate: powermanagev1connect.ControlServiceUpdateGrantProcedure,
			crudDelete: powermanagev1connect.ControlServiceDeleteGrantProcedure,
		},
		projectorEvents:   store.AuthorizationGrantEventTypes(),
		searchableColumns: []string{"principal_id", "role_id"},
		alreadyExists:     store.IsAuthorizationGrantExists,
		scopeRelation:     crudScopeGlobal,
		scope:             globalCRUDScope,
		createEvent: func(_ context.Context, message proto.Message) (store.Event, string, error) {
			request, ok := message.(*powermanagev1.CreateGrantRequest)
			if !ok {
				return store.Event{}, "", errors.New("control: wrong grant request for create")
			}
			principal, scope, err := grantInput(
				request.GetPrincipalType(),
				request.GetScope(),
			)
			if err != nil {
				return store.Event{}, "", err
			}
			return createWithoutCredential(
				store.AuthorizationGrantCreatedEvent(
					request.GetId(),
					principal,
					request.GetPrincipalId(),
					request.GetRoleId(),
					scope,
				),
			)
		},
		updateEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.UpdateGrantRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong grant request for update")
			}
			principal, scope, err := grantInput(
				request.GetPrincipalType(),
				request.GetScope(),
			)
			if err != nil {
				return store.Event{}, err
			}
			return store.AuthorizationGrantUpdatedEvent(
				request.GetId(),
				principal,
				request.GetPrincipalId(),
				request.GetRoleId(),
				scope,
			)
		},
		deleteEvent: func(_ context.Context, message proto.Message) (store.Event, error) {
			request, ok := message.(*powermanagev1.DeleteGrantRequest)
			if !ok {
				return store.Event{}, errors.New("control: wrong grant request for delete")
			}
			return store.AuthorizationGrantDeletedEvent(request.GetId())
		},
		get: func(ctx context.Context, id string, _ CRUDScope) (proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			grant, err := eventStore.AuthorizationGrantByID(ctx, id)
			if err != nil {
				return nil, err
			}
			return grantMessage(ctx, eventStore, grant)
		},
		list: func(ctx context.Context, _ CRUDScope, limit int32) ([]proto.Message, error) {
			if eventStore == nil {
				return nil, errors.New("control: management store is not wired")
			}
			grants, err := eventStore.ListAuthorizationGrants(ctx, limit)
			if err != nil {
				return nil, err
			}
			messages := make([]proto.Message, len(grants))
			for index, grant := range grants {
				messages[index], err = grantMessage(ctx, eventStore, grant)
				if err != nil {
					return nil, err
				}
			}
			return messages, nil
		},
	}
}

func globalCRUDScope(reach authz.Reach) (CRUDScope, error) {
	if !reach.Global {
		return CRUDScope{}, errors.New("control: global CRUD permission has scoped reach")
	}
	return CRUDScope{Global: true}, nil
}

func userMessage(user store.User) *powermanagev1.User {
	state := powermanagev1.UserState_USER_STATE_ENABLED
	if user.Disabled {
		state = powermanagev1.UserState_USER_STATE_DISABLED
	}
	return &powermanagev1.User{
		Id:      user.UserID,
		Email:   user.Email,
		State:   state,
		Version: uint64(user.ProjectionVersion),
	}
}

func roleMessage(role store.AuthorizationRole) *powermanagev1.Role {
	values := make([]string, len(role.Permissions))
	for index, permission := range role.Permissions {
		values[index] = string(permission)
	}
	return &powermanagev1.Role{
		Id:          role.ID,
		Name:        role.Name,
		Permissions: values,
		Version:     uint64(role.ProjectionVersion),
	}
}

func userGroupMessage(group store.UserGroup) *powermanagev1.UserGroup {
	return &powermanagev1.UserGroup{
		Id:      group.ID,
		Name:    group.Name,
		Version: uint64(group.ProjectionVersion),
	}
}

func grantMessage(
	ctx context.Context,
	eventStore *store.Store,
	grant store.AuthorizationGrant,
) (*powermanagev1.GrantView, error) {
	role, err := eventStore.AuthorizationRoleByID(ctx, grant.RoleID)
	if err != nil {
		return nil, err
	}
	effective, err := authz.Resolve([]authz.Grant{{
		ID:            grant.ID,
		PrincipalType: grant.PrincipalType,
		PrincipalID:   grant.PrincipalID,
		RoleID:        grant.RoleID,
		Permissions:   role.Permissions,
		Scope:         grant.Scope,
	}})
	if err != nil || len(effective.Grants) != 1 {
		return nil, errors.New("control: invalid projected grant")
	}
	access := effective.Grants[0]
	return &powermanagev1.GrantView{
		GrantId:             grant.ID,
		PrincipalType:       principalTypeMessage(grant.PrincipalType),
		PrincipalId:         grant.PrincipalID,
		RoleId:              grant.RoleID,
		Scope:               grantScopeMessage(grant.Scope),
		ActivePermissions:   permissionStrings(access.ActivePermissions),
		StrippedPermissions: permissionStrings(access.StrippedPermissions),
		ProjectionVersion:   uint64(grant.ProjectionVersion),
	}, nil
}

func permissions(values []string) []authz.Permission {
	result := make([]authz.Permission, len(values))
	for index, value := range values {
		result[index] = authz.Permission(value)
	}
	return result
}

func createWithoutCredential(event store.Event, err error) (store.Event, string, error) {
	return event, "", err
}

func permissionStrings(values []authz.Permission) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

func grantInput(
	principal powermanagev1.AuthorizationPrincipalType,
	scope *powermanagev1.GrantScope,
) (authz.PrincipalType, authz.Scope, error) {
	principalValue, ok := principalTypeStore(principal)
	if !ok || scope == nil {
		return "", authz.Scope{}, errors.New("control: grant input is invalid")
	}
	scopeKind, ok := scopeKindStore(scope.GetKind())
	if !ok {
		return "", authz.Scope{}, errors.New("control: grant scope is invalid")
	}
	return principalValue, authz.Scope{
		Kind: scopeKind,
		IDs:  slices.Clone(scope.GetResourceIds()),
	}, nil
}

func principalTypeStore(
	value powermanagev1.AuthorizationPrincipalType,
) (authz.PrincipalType, bool) {
	switch value {
	case powermanagev1.AuthorizationPrincipalType_AUTHORIZATION_PRINCIPAL_TYPE_USER:
		return authz.PrincipalUser, true
	case powermanagev1.AuthorizationPrincipalType_AUTHORIZATION_PRINCIPAL_TYPE_USER_GROUP:
		return authz.PrincipalUserGroup, true
	default:
		return "", false
	}
}

func principalTypeMessage(value authz.PrincipalType) powermanagev1.AuthorizationPrincipalType {
	switch value {
	case authz.PrincipalUser:
		return powermanagev1.AuthorizationPrincipalType_AUTHORIZATION_PRINCIPAL_TYPE_USER
	case authz.PrincipalUserGroup:
		return powermanagev1.AuthorizationPrincipalType_AUTHORIZATION_PRINCIPAL_TYPE_USER_GROUP
	default:
		return powermanagev1.AuthorizationPrincipalType_AUTHORIZATION_PRINCIPAL_TYPE_UNSPECIFIED
	}
}

func scopeKindStore(value powermanagev1.AuthorizationScopeKind) (authz.ScopeKind, bool) {
	switch value {
	case powermanagev1.AuthorizationScopeKind_AUTHORIZATION_SCOPE_KIND_GLOBAL:
		return authz.ScopeGlobal, true
	case powermanagev1.AuthorizationScopeKind_AUTHORIZATION_SCOPE_KIND_DEVICE_GROUPS:
		return authz.ScopeDeviceGroups, true
	case powermanagev1.AuthorizationScopeKind_AUTHORIZATION_SCOPE_KIND_USER_GROUPS:
		return authz.ScopeUserGroups, true
	case powermanagev1.AuthorizationScopeKind_AUTHORIZATION_SCOPE_KIND_SELF:
		return authz.ScopeSelf, true
	default:
		return "", false
	}
}

func grantScopeMessage(scope authz.Scope) *powermanagev1.GrantScope {
	var kind powermanagev1.AuthorizationScopeKind
	switch scope.Kind {
	case authz.ScopeGlobal:
		kind = powermanagev1.AuthorizationScopeKind_AUTHORIZATION_SCOPE_KIND_GLOBAL
	case authz.ScopeDeviceGroups:
		kind = powermanagev1.AuthorizationScopeKind_AUTHORIZATION_SCOPE_KIND_DEVICE_GROUPS
	case authz.ScopeUserGroups:
		kind = powermanagev1.AuthorizationScopeKind_AUTHORIZATION_SCOPE_KIND_USER_GROUPS
	case authz.ScopeSelf:
		kind = powermanagev1.AuthorizationScopeKind_AUTHORIZATION_SCOPE_KIND_SELF
	}
	return &powermanagev1.GrantScope{
		Kind:        kind,
		ResourceIds: slices.Clone(scope.IDs),
	}
}
