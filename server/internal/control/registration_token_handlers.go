package control

import (
	"context"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
)

func (s *ManagementService) CreateRegistrationToken(
	ctx context.Context,
	request *connect.Request[powermanagev1.CreateRegistrationTokenRequest],
) (*connect.Response[powermanagev1.CreateRegistrationTokenResponse], error) {
	message, err := requestMessage(request)
	if err != nil || s == nil || s.kernel == nil {
		return nil, invalidCRUDRequest()
	}
	result, err := s.kernel.create(
		ctx,
		powermanagev1connect.ControlServiceCreateRegistrationTokenProcedure,
		registrationTokenDomainName,
		message,
	)
	if err != nil {
		return nil, err
	}
	token, ok := result.object.(*powermanagev1.RegistrationToken)
	if !ok || result.credential == "" {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.CreateRegistrationTokenResponse{
		RegistrationToken: token,
		Credential:        result.credential,
	}), nil
}

func (s *ManagementService) GetRegistrationToken(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetRegistrationTokenRequest],
) (*connect.Response[powermanagev1.GetRegistrationTokenResponse], error) {
	result, err := getIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceGetRegistrationTokenProcedure,
		registrationTokenDomainName,
	)
	if err != nil {
		return nil, err
	}
	token, ok := result.(*powermanagev1.RegistrationToken)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.GetRegistrationTokenResponse{
		RegistrationToken: token,
	}), nil
}

func (s *ManagementService) ListRegistrationTokens(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListRegistrationTokensRequest],
) (*connect.Response[powermanagev1.ListRegistrationTokensResponse], error) {
	results, err := listIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceListRegistrationTokensProcedure,
		registrationTokenDomainName,
	)
	if err != nil {
		return nil, err
	}
	tokens := make([]*powermanagev1.RegistrationToken, len(results))
	for index, result := range results {
		var ok bool
		tokens[index], ok = result.(*powermanagev1.RegistrationToken)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(&powermanagev1.ListRegistrationTokensResponse{
		RegistrationTokens: tokens,
	}), nil
}

func (s *ManagementService) UpdateRegistrationToken(
	ctx context.Context,
	request *connect.Request[powermanagev1.UpdateRegistrationTokenRequest],
) (*connect.Response[powermanagev1.UpdateRegistrationTokenResponse], error) {
	result, err := updateIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceUpdateRegistrationTokenProcedure,
		registrationTokenDomainName,
	)
	if err != nil {
		return nil, err
	}
	token, ok := result.(*powermanagev1.RegistrationToken)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.UpdateRegistrationTokenResponse{
		RegistrationToken: token,
	}), nil
}

func (s *ManagementService) DeleteRegistrationToken(
	ctx context.Context,
	request *connect.Request[powermanagev1.DeleteRegistrationTokenRequest],
) (*connect.Response[powermanagev1.DeleteRegistrationTokenResponse], error) {
	id, err := deleteIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceDeleteRegistrationTokenProcedure,
		registrationTokenDomainName,
	)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(
		&powermanagev1.DeleteRegistrationTokenResponse{DeletedId: id},
	), nil
}
