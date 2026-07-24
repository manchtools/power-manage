package control

import (
	"context"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
)

func (s *ManagementService) CreateUser(
	ctx context.Context,
	request *connect.Request[powermanagev1.CreateUserRequest],
) (*connect.Response[powermanagev1.CreateUserResponse], error) {
	result, err := createIdentity(s, ctx, request, powermanagev1connect.ControlServiceCreateUserProcedure, userDomainName)
	if err != nil {
		return nil, err
	}
	user, ok := result.(*powermanagev1.User)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.CreateUserResponse{User: user}), nil
}

func (s *ManagementService) GetUser(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetUserRequest],
) (*connect.Response[powermanagev1.GetUserResponse], error) {
	result, err := getIdentity(s, ctx, request, powermanagev1connect.ControlServiceGetUserProcedure, userDomainName)
	if err != nil {
		return nil, err
	}
	user, ok := result.(*powermanagev1.User)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.GetUserResponse{User: user}), nil
}

func (s *ManagementService) ListUsers(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListUsersRequest],
) (*connect.Response[powermanagev1.ListUsersResponse], error) {
	results, err := listIdentity(s, ctx, request, powermanagev1connect.ControlServiceListUsersProcedure, userDomainName)
	if err != nil {
		return nil, err
	}
	users := make([]*powermanagev1.User, len(results))
	for index, result := range results {
		var ok bool
		users[index], ok = result.(*powermanagev1.User)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(&powermanagev1.ListUsersResponse{Users: users}), nil
}

func (s *ManagementService) UpdateUser(
	ctx context.Context,
	request *connect.Request[powermanagev1.UpdateUserRequest],
) (*connect.Response[powermanagev1.UpdateUserResponse], error) {
	result, err := updateIdentity(s, ctx, request, powermanagev1connect.ControlServiceUpdateUserProcedure, userDomainName)
	if err != nil {
		return nil, err
	}
	user, ok := result.(*powermanagev1.User)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.UpdateUserResponse{User: user}), nil
}

func (s *ManagementService) DeleteUser(
	ctx context.Context,
	request *connect.Request[powermanagev1.DeleteUserRequest],
) (*connect.Response[powermanagev1.DeleteUserResponse], error) {
	id, err := deleteIdentity(s, ctx, request, powermanagev1connect.ControlServiceDeleteUserProcedure, userDomainName)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&powermanagev1.DeleteUserResponse{DeletedId: id}), nil
}

func (s *ManagementService) CreateRole(
	ctx context.Context,
	request *connect.Request[powermanagev1.CreateRoleRequest],
) (*connect.Response[powermanagev1.CreateRoleResponse], error) {
	result, err := createIdentity(s, ctx, request, powermanagev1connect.ControlServiceCreateRoleProcedure, roleDomainName)
	if err != nil {
		return nil, err
	}
	role, ok := result.(*powermanagev1.Role)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.CreateRoleResponse{Role: role}), nil
}

func (s *ManagementService) GetRole(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetRoleRequest],
) (*connect.Response[powermanagev1.GetRoleResponse], error) {
	result, err := getIdentity(s, ctx, request, powermanagev1connect.ControlServiceGetRoleProcedure, roleDomainName)
	if err != nil {
		return nil, err
	}
	role, ok := result.(*powermanagev1.Role)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.GetRoleResponse{Role: role}), nil
}

func (s *ManagementService) ListRoles(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListRolesRequest],
) (*connect.Response[powermanagev1.ListRolesResponse], error) {
	results, err := listIdentity(s, ctx, request, powermanagev1connect.ControlServiceListRolesProcedure, roleDomainName)
	if err != nil {
		return nil, err
	}
	roles := make([]*powermanagev1.Role, len(results))
	for index, result := range results {
		var ok bool
		roles[index], ok = result.(*powermanagev1.Role)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(&powermanagev1.ListRolesResponse{Roles: roles}), nil
}

func (s *ManagementService) UpdateRole(
	ctx context.Context,
	request *connect.Request[powermanagev1.UpdateRoleRequest],
) (*connect.Response[powermanagev1.UpdateRoleResponse], error) {
	result, err := updateIdentity(s, ctx, request, powermanagev1connect.ControlServiceUpdateRoleProcedure, roleDomainName)
	if err != nil {
		return nil, err
	}
	role, ok := result.(*powermanagev1.Role)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.UpdateRoleResponse{Role: role}), nil
}

func (s *ManagementService) DeleteRole(
	ctx context.Context,
	request *connect.Request[powermanagev1.DeleteRoleRequest],
) (*connect.Response[powermanagev1.DeleteRoleResponse], error) {
	id, err := deleteIdentity(s, ctx, request, powermanagev1connect.ControlServiceDeleteRoleProcedure, roleDomainName)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&powermanagev1.DeleteRoleResponse{DeletedId: id}), nil
}

func (s *ManagementService) CreateGrant(
	ctx context.Context,
	request *connect.Request[powermanagev1.CreateGrantRequest],
) (*connect.Response[powermanagev1.CreateGrantResponse], error) {
	result, err := createIdentity(s, ctx, request, powermanagev1connect.ControlServiceCreateGrantProcedure, grantDomainName)
	if err != nil {
		return nil, err
	}
	grant, ok := result.(*powermanagev1.GrantView)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.CreateGrantResponse{Grant: grant}), nil
}

func (s *ManagementService) GetGrant(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetGrantRequest],
) (*connect.Response[powermanagev1.GetGrantResponse], error) {
	result, err := getIdentity(s, ctx, request, powermanagev1connect.ControlServiceGetGrantProcedure, grantDomainName)
	if err != nil {
		return nil, err
	}
	grant, ok := result.(*powermanagev1.GrantView)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.GetGrantResponse{Grant: grant}), nil
}

func (s *ManagementService) ListGrants(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListGrantsRequest],
) (*connect.Response[powermanagev1.ListGrantsResponse], error) {
	results, err := listIdentity(s, ctx, request, powermanagev1connect.ControlServiceListGrantsProcedure, grantDomainName)
	if err != nil {
		return nil, err
	}
	grants := make([]*powermanagev1.GrantView, len(results))
	for index, result := range results {
		var ok bool
		grants[index], ok = result.(*powermanagev1.GrantView)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(&powermanagev1.ListGrantsResponse{Grants: grants}), nil
}

func (s *ManagementService) UpdateGrant(
	ctx context.Context,
	request *connect.Request[powermanagev1.UpdateGrantRequest],
) (*connect.Response[powermanagev1.UpdateGrantResponse], error) {
	result, err := updateIdentity(s, ctx, request, powermanagev1connect.ControlServiceUpdateGrantProcedure, grantDomainName)
	if err != nil {
		return nil, err
	}
	grant, ok := result.(*powermanagev1.GrantView)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.UpdateGrantResponse{Grant: grant}), nil
}

func (s *ManagementService) DeleteGrant(
	ctx context.Context,
	request *connect.Request[powermanagev1.DeleteGrantRequest],
) (*connect.Response[powermanagev1.DeleteGrantResponse], error) {
	id, err := deleteIdentity(s, ctx, request, powermanagev1connect.ControlServiceDeleteGrantProcedure, grantDomainName)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&powermanagev1.DeleteGrantResponse{DeletedId: id}), nil
}

func (s *ManagementService) CreateUserGroup(
	ctx context.Context,
	request *connect.Request[powermanagev1.CreateUserGroupRequest],
) (*connect.Response[powermanagev1.CreateUserGroupResponse], error) {
	result, err := createIdentity(s, ctx, request, powermanagev1connect.ControlServiceCreateUserGroupProcedure, userGroupDomainName)
	if err != nil {
		return nil, err
	}
	group, ok := result.(*powermanagev1.UserGroup)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.CreateUserGroupResponse{UserGroup: group}), nil
}

func (s *ManagementService) GetUserGroup(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetUserGroupRequest],
) (*connect.Response[powermanagev1.GetUserGroupResponse], error) {
	result, err := getIdentity(s, ctx, request, powermanagev1connect.ControlServiceGetUserGroupProcedure, userGroupDomainName)
	if err != nil {
		return nil, err
	}
	group, ok := result.(*powermanagev1.UserGroup)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.GetUserGroupResponse{UserGroup: group}), nil
}

func (s *ManagementService) ListUserGroups(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListUserGroupsRequest],
) (*connect.Response[powermanagev1.ListUserGroupsResponse], error) {
	results, err := listIdentity(s, ctx, request, powermanagev1connect.ControlServiceListUserGroupsProcedure, userGroupDomainName)
	if err != nil {
		return nil, err
	}
	groups := make([]*powermanagev1.UserGroup, len(results))
	for index, result := range results {
		var ok bool
		groups[index], ok = result.(*powermanagev1.UserGroup)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(&powermanagev1.ListUserGroupsResponse{UserGroups: groups}), nil
}

func (s *ManagementService) UpdateUserGroup(
	ctx context.Context,
	request *connect.Request[powermanagev1.UpdateUserGroupRequest],
) (*connect.Response[powermanagev1.UpdateUserGroupResponse], error) {
	result, err := updateIdentity(s, ctx, request, powermanagev1connect.ControlServiceUpdateUserGroupProcedure, userGroupDomainName)
	if err != nil {
		return nil, err
	}
	group, ok := result.(*powermanagev1.UserGroup)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.UpdateUserGroupResponse{UserGroup: group}), nil
}

func (s *ManagementService) DeleteUserGroup(
	ctx context.Context,
	request *connect.Request[powermanagev1.DeleteUserGroupRequest],
) (*connect.Response[powermanagev1.DeleteUserGroupResponse], error) {
	id, err := deleteIdentity(s, ctx, request, powermanagev1connect.ControlServiceDeleteUserGroupProcedure, userGroupDomainName)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&powermanagev1.DeleteUserGroupResponse{DeletedId: id}), nil
}

func createIdentity[T any](
	s *ManagementService,
	ctx context.Context,
	request *connect.Request[T],
	procedure string,
	domain string,
) (any, error) {
	message, err := requestMessage(request)
	if err != nil || s == nil || s.kernel == nil {
		return nil, invalidCRUDRequest()
	}
	result, err := s.kernel.create(ctx, procedure, domain, message)
	if err != nil {
		return nil, err
	}
	return result.object, nil
}

func getIdentity[T any](
	s *ManagementService,
	ctx context.Context,
	request *connect.Request[T],
	procedure string,
	domain string,
) (any, error) {
	message, err := requestMessage(request)
	if err != nil || s == nil || s.kernel == nil {
		return nil, invalidCRUDRequest()
	}
	return s.kernel.get(ctx, procedure, domain, message)
}

func listIdentity[T any](
	s *ManagementService,
	ctx context.Context,
	request *connect.Request[T],
	procedure string,
	domain string,
) ([]any, error) {
	message, err := requestMessage(request)
	if err != nil || s == nil || s.kernel == nil {
		return nil, invalidCRUDRequest()
	}
	results, err := s.kernel.list(ctx, procedure, domain, message)
	if err != nil {
		return nil, err
	}
	values := make([]any, len(results))
	for index, result := range results {
		values[index] = result
	}
	return values, nil
}

func updateIdentity[T any](
	s *ManagementService,
	ctx context.Context,
	request *connect.Request[T],
	procedure string,
	domain string,
) (any, error) {
	message, err := requestMessage(request)
	if err != nil || s == nil || s.kernel == nil {
		return nil, invalidCRUDRequest()
	}
	result, err := s.kernel.update(ctx, procedure, domain, message)
	if err != nil {
		return nil, err
	}
	return result.object, nil
}

func deleteIdentity[T any](
	s *ManagementService,
	ctx context.Context,
	request *connect.Request[T],
	procedure string,
	domain string,
) (string, error) {
	message, err := requestMessage(request)
	if err != nil || s == nil || s.kernel == nil {
		return "", invalidCRUDRequest()
	}
	return s.kernel.delete(ctx, procedure, domain, message)
}
