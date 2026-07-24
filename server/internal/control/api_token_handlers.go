package control

import (
	"context"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
)

func (s *ManagementService) CreateApiToken(
	ctx context.Context,
	request *connect.Request[powermanagev1.CreateApiTokenRequest],
) (*connect.Response[powermanagev1.CreateApiTokenResponse], error) {
	message, err := requestMessage(request)
	if err != nil || s == nil || s.kernel == nil {
		return nil, invalidCRUDRequest()
	}
	result, err := s.kernel.create(
		ctx,
		powermanagev1connect.ControlServiceCreateApiTokenProcedure,
		apiTokenDomainName,
		message,
	)
	if err != nil {
		return nil, err
	}
	token, ok := result.object.(*powermanagev1.ApiToken)
	if !ok || result.credential == "" {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.CreateApiTokenResponse{
		ApiToken:   token,
		Credential: result.credential,
	}), nil
}

func (s *ManagementService) GetApiToken(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetApiTokenRequest],
) (*connect.Response[powermanagev1.GetApiTokenResponse], error) {
	result, err := getIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceGetApiTokenProcedure,
		apiTokenDomainName,
	)
	if err != nil {
		return nil, err
	}
	token, ok := result.(*powermanagev1.ApiToken)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.GetApiTokenResponse{ApiToken: token}), nil
}

func (s *ManagementService) ListApiTokens(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListApiTokensRequest],
) (*connect.Response[powermanagev1.ListApiTokensResponse], error) {
	results, err := listIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceListApiTokensProcedure,
		apiTokenDomainName,
	)
	if err != nil {
		return nil, err
	}
	tokens := make([]*powermanagev1.ApiToken, len(results))
	for index, result := range results {
		var ok bool
		tokens[index], ok = result.(*powermanagev1.ApiToken)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(&powermanagev1.ListApiTokensResponse{ApiTokens: tokens}), nil
}

func (s *ManagementService) UpdateApiToken(
	ctx context.Context,
	request *connect.Request[powermanagev1.UpdateApiTokenRequest],
) (*connect.Response[powermanagev1.UpdateApiTokenResponse], error) {
	result, err := updateIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceUpdateApiTokenProcedure,
		apiTokenDomainName,
	)
	if err != nil {
		return nil, err
	}
	token, ok := result.(*powermanagev1.ApiToken)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.UpdateApiTokenResponse{ApiToken: token}), nil
}

func (s *ManagementService) DeleteApiToken(
	ctx context.Context,
	request *connect.Request[powermanagev1.DeleteApiTokenRequest],
) (*connect.Response[powermanagev1.DeleteApiTokenResponse], error) {
	id, err := deleteIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceDeleteApiTokenProcedure,
		apiTokenDomainName,
	)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&powermanagev1.DeleteApiTokenResponse{DeletedId: id}), nil
}
