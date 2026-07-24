package control

import (
	"context"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
)

func (s *ManagementService) CreateScimConfiguration(
	ctx context.Context,
	request *connect.Request[powermanagev1.CreateScimConfigurationRequest],
) (*connect.Response[powermanagev1.CreateScimConfigurationResponse], error) {
	message, err := requestMessage(request)
	if err != nil || s == nil || s.kernel == nil {
		return nil, invalidCRUDRequest()
	}
	result, err := s.kernel.create(
		ctx,
		powermanagev1connect.ControlServiceCreateScimConfigurationProcedure,
		scimConfigurationDomainName,
		message,
	)
	if err != nil {
		return nil, err
	}
	config, ok := result.object.(*powermanagev1.ScimConfiguration)
	if !ok || result.credential == "" {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.CreateScimConfigurationResponse{
		ScimConfiguration: config,
		Credential:        result.credential,
	}), nil
}

func (s *ManagementService) GetScimConfiguration(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetScimConfigurationRequest],
) (*connect.Response[powermanagev1.GetScimConfigurationResponse], error) {
	result, err := getIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceGetScimConfigurationProcedure,
		scimConfigurationDomainName,
	)
	if err != nil {
		return nil, err
	}
	config, ok := result.(*powermanagev1.ScimConfiguration)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(
		&powermanagev1.GetScimConfigurationResponse{ScimConfiguration: config},
	), nil
}

func (s *ManagementService) ListScimConfigurations(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListScimConfigurationsRequest],
) (*connect.Response[powermanagev1.ListScimConfigurationsResponse], error) {
	results, err := listIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceListScimConfigurationsProcedure,
		scimConfigurationDomainName,
	)
	if err != nil {
		return nil, err
	}
	configs := make([]*powermanagev1.ScimConfiguration, len(results))
	for index, result := range results {
		var ok bool
		configs[index], ok = result.(*powermanagev1.ScimConfiguration)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(&powermanagev1.ListScimConfigurationsResponse{
		ScimConfigurations: configs,
	}), nil
}

func (s *ManagementService) UpdateScimConfiguration(
	ctx context.Context,
	request *connect.Request[powermanagev1.UpdateScimConfigurationRequest],
) (*connect.Response[powermanagev1.UpdateScimConfigurationResponse], error) {
	message, err := requestMessage(request)
	if err != nil || s == nil || s.kernel == nil {
		return nil, invalidCRUDRequest()
	}
	result, err := s.kernel.update(
		ctx,
		powermanagev1connect.ControlServiceUpdateScimConfigurationProcedure,
		scimConfigurationDomainName,
		message,
	)
	if err != nil {
		return nil, err
	}
	config, ok := result.object.(*powermanagev1.ScimConfiguration)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.UpdateScimConfigurationResponse{
		ScimConfiguration: config,
		Credential:        result.credential,
	}), nil
}

func (s *ManagementService) DeleteScimConfiguration(
	ctx context.Context,
	request *connect.Request[powermanagev1.DeleteScimConfigurationRequest],
) (*connect.Response[powermanagev1.DeleteScimConfigurationResponse], error) {
	id, err := deleteIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceDeleteScimConfigurationProcedure,
		scimConfigurationDomainName,
	)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(
		&powermanagev1.DeleteScimConfigurationResponse{DeletedId: id},
	), nil
}
