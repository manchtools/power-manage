package control

import (
	"context"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
)

func (s *ManagementService) CreateIdentityProvider(
	ctx context.Context,
	request *connect.Request[powermanagev1.CreateIdentityProviderRequest],
) (*connect.Response[powermanagev1.CreateIdentityProviderResponse], error) {
	message, err := requestMessage(request)
	if err != nil || s == nil || s.kernel == nil {
		return nil, invalidCRUDRequest()
	}
	result, err := s.kernel.create(
		ctx,
		powermanagev1connect.ControlServiceCreateIdentityProviderProcedure,
		identityProviderDomainName,
		message,
	)
	if err != nil {
		return nil, err
	}
	provider, ok := result.object.(*powermanagev1.IdentityProvider)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(
		&powermanagev1.CreateIdentityProviderResponse{IdentityProvider: provider},
	), nil
}

func (s *ManagementService) GetIdentityProvider(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetIdentityProviderRequest],
) (*connect.Response[powermanagev1.GetIdentityProviderResponse], error) {
	result, err := getIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceGetIdentityProviderProcedure,
		identityProviderDomainName,
	)
	if err != nil {
		return nil, err
	}
	provider, ok := result.(*powermanagev1.IdentityProvider)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(
		&powermanagev1.GetIdentityProviderResponse{IdentityProvider: provider},
	), nil
}

func (s *ManagementService) ListIdentityProviders(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListIdentityProvidersRequest],
) (*connect.Response[powermanagev1.ListIdentityProvidersResponse], error) {
	results, err := listIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceListIdentityProvidersProcedure,
		identityProviderDomainName,
	)
	if err != nil {
		return nil, err
	}
	providers := make([]*powermanagev1.IdentityProvider, len(results))
	for index, result := range results {
		var ok bool
		providers[index], ok = result.(*powermanagev1.IdentityProvider)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(
		&powermanagev1.ListIdentityProvidersResponse{IdentityProviders: providers},
	), nil
}

func (s *ManagementService) UpdateIdentityProvider(
	ctx context.Context,
	request *connect.Request[powermanagev1.UpdateIdentityProviderRequest],
) (*connect.Response[powermanagev1.UpdateIdentityProviderResponse], error) {
	result, err := updateIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceUpdateIdentityProviderProcedure,
		identityProviderDomainName,
	)
	if err != nil {
		return nil, err
	}
	provider, ok := result.(*powermanagev1.IdentityProvider)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(
		&powermanagev1.UpdateIdentityProviderResponse{IdentityProvider: provider},
	), nil
}

func (s *ManagementService) DeleteIdentityProvider(
	ctx context.Context,
	request *connect.Request[powermanagev1.DeleteIdentityProviderRequest],
) (*connect.Response[powermanagev1.DeleteIdentityProviderResponse], error) {
	id, err := deleteIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceDeleteIdentityProviderProcedure,
		identityProviderDomainName,
	)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(
		&powermanagev1.DeleteIdentityProviderResponse{DeletedId: id},
	), nil
}
