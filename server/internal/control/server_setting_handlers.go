package control

import (
	"context"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
)

func (s *ManagementService) CreateServerSetting(
	ctx context.Context,
	request *connect.Request[powermanagev1.CreateServerSettingRequest],
) (*connect.Response[powermanagev1.CreateServerSettingResponse], error) {
	result, err := createIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceCreateServerSettingProcedure,
		serverSettingDomainName,
	)
	if err != nil {
		return nil, err
	}
	setting, ok := result.(*powermanagev1.ServerSetting)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(
		&powermanagev1.CreateServerSettingResponse{ServerSetting: setting},
	), nil
}

func (s *ManagementService) GetServerSetting(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetServerSettingRequest],
) (*connect.Response[powermanagev1.GetServerSettingResponse], error) {
	result, err := getIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceGetServerSettingProcedure,
		serverSettingDomainName,
	)
	if err != nil {
		return nil, err
	}
	setting, ok := result.(*powermanagev1.ServerSetting)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(
		&powermanagev1.GetServerSettingResponse{ServerSetting: setting},
	), nil
}

func (s *ManagementService) ListServerSettings(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListServerSettingsRequest],
) (*connect.Response[powermanagev1.ListServerSettingsResponse], error) {
	results, err := listIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceListServerSettingsProcedure,
		serverSettingDomainName,
	)
	if err != nil {
		return nil, err
	}
	settings := make([]*powermanagev1.ServerSetting, len(results))
	for index, result := range results {
		var ok bool
		settings[index], ok = result.(*powermanagev1.ServerSetting)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(
		&powermanagev1.ListServerSettingsResponse{ServerSettings: settings},
	), nil
}

func (s *ManagementService) UpdateServerSetting(
	ctx context.Context,
	request *connect.Request[powermanagev1.UpdateServerSettingRequest],
) (*connect.Response[powermanagev1.UpdateServerSettingResponse], error) {
	result, err := updateIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceUpdateServerSettingProcedure,
		serverSettingDomainName,
	)
	if err != nil {
		return nil, err
	}
	setting, ok := result.(*powermanagev1.ServerSetting)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(
		&powermanagev1.UpdateServerSettingResponse{ServerSetting: setting},
	), nil
}

func (s *ManagementService) DeleteServerSetting(
	ctx context.Context,
	request *connect.Request[powermanagev1.DeleteServerSettingRequest],
) (*connect.Response[powermanagev1.DeleteServerSettingResponse], error) {
	id, err := deleteIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceDeleteServerSettingProcedure,
		serverSettingDomainName,
	)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(
		&powermanagev1.DeleteServerSettingResponse{DeletedId: id},
	), nil
}
