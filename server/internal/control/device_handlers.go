package control

import (
	"context"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
)

func (s *ManagementService) GetDevice(
	ctx context.Context,
	request *connect.Request[powermanagev1.GetDeviceRequest],
) (*connect.Response[powermanagev1.GetDeviceResponse], error) {
	result, err := getIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceGetDeviceProcedure,
		deviceDomainName,
	)
	if err != nil {
		return nil, err
	}
	device, ok := result.(*powermanagev1.Device)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.GetDeviceResponse{Device: device}), nil
}

func (s *ManagementService) ListDevices(
	ctx context.Context,
	request *connect.Request[powermanagev1.ListDevicesRequest],
) (*connect.Response[powermanagev1.ListDevicesResponse], error) {
	results, err := listIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceListDevicesProcedure,
		deviceDomainName,
	)
	if err != nil {
		return nil, err
	}
	devices := make([]*powermanagev1.Device, len(results))
	for index, result := range results {
		var ok bool
		devices[index], ok = result.(*powermanagev1.Device)
		if !ok {
			return nil, unavailableCRUD()
		}
	}
	return connect.NewResponse(&powermanagev1.ListDevicesResponse{Devices: devices}), nil
}

func (s *ManagementService) UpdateDevice(
	ctx context.Context,
	request *connect.Request[powermanagev1.UpdateDeviceRequest],
) (*connect.Response[powermanagev1.UpdateDeviceResponse], error) {
	result, err := updateIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceUpdateDeviceProcedure,
		deviceDomainName,
	)
	if err != nil {
		return nil, err
	}
	device, ok := result.(*powermanagev1.Device)
	if !ok {
		return nil, unavailableCRUD()
	}
	return connect.NewResponse(&powermanagev1.UpdateDeviceResponse{Device: device}), nil
}

func (s *ManagementService) DeleteDevice(
	ctx context.Context,
	request *connect.Request[powermanagev1.DeleteDeviceRequest],
) (*connect.Response[powermanagev1.DeleteDeviceResponse], error) {
	id, err := deleteIdentity(
		s,
		ctx,
		request,
		powermanagev1connect.ControlServiceDeleteDeviceProcedure,
		deviceDomainName,
	)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&powermanagev1.DeleteDeviceResponse{DeletedId: id}), nil
}
