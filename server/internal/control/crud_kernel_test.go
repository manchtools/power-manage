package control

import (
	"context"
	"errors"
	"slices"
	"testing"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/authz"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	kernelTestSubject = "01J00000000000000000000081"
	kernelTestGroupID = "01J00000000000000000000082"
)

type kernelTestResolver struct {
	access authz.EffectiveAccess
	calls  int
}

func (r *kernelTestResolver) ResolveEffectiveAccess(context.Context, string) (authz.EffectiveAccess, error) {
	r.calls++
	return r.access, nil
}

type kernelTestStore struct {
	appends int
}

func (s *kernelTestStore) AppendEvent(context.Context, store.Event) error {
	s.appends++
	return nil
}

func (s *kernelTestStore) AppendEventWithVersion(context.Context, store.Event, int64) error {
	s.appends++
	return nil
}

func TestCRUDKernel_ValidationPrecedesAuthorizationAndDomainWork(t *testing.T) {
	resolver := &kernelTestResolver{
		access: authz.EffectiveAccess{
			Permissions: map[authz.Permission]authz.Reach{
				"devices.manage": {Global: true},
			},
		},
	}
	appender := &kernelTestStore{}
	domainCalls := 0
	domain := completeKernelTestDeviceGroupDomain(crudDomainStoreFuncs{
		createEvent: func(*powermanagev1.CreateDeviceGroupRequest) (store.Event, error) {
			domainCalls++
			return store.Event{}, nil
		},
		get: func(context.Context, string, CRUDScope) (store.DeviceGroup, error) {
			domainCalls++
			return store.DeviceGroup{}, errors.New("unexpected get")
		},
	})
	gate, err := auth.NewAuthorizationGate(resolver)
	if err != nil {
		t.Fatalf("create authorization gate: %v", err)
	}
	kernel, err := newCRUDKernel(appender, gate, []crudDomain{domain})
	if err != nil {
		t.Fatalf("create CRUD kernel: %v", err)
	}
	ctx, err := auth.ContextWithSessionClaims(t.Context(), auth.Claims{
		Subject:        kernelTestSubject,
		SessionVersion: 1,
	})
	if err != nil {
		t.Fatalf("attach session claims: %v", err)
	}

	_, err = kernel.create(
		ctx,
		powermanagev1connect.ControlServiceCreateDeviceGroupProcedure,
		deviceGroupDomainName,
		&powermanagev1.CreateDeviceGroupRequest{},
	)
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid create code = %v; want InvalidArgument", connect.CodeOf(err))
	}
	if resolver.calls != 0 || domainCalls != 0 || appender.appends != 0 {
		t.Fatalf(
			"invalid create effects = resolver %d, domain %d, appends %d; want all zero",
			resolver.calls,
			domainCalls,
			appender.appends,
		)
	}
}

func TestCRUDKernel_AuthorizationPrecedesDomainWorkAndAppend(t *testing.T) {
	resolver := &kernelTestResolver{
		access: authz.EffectiveAccess{Permissions: map[authz.Permission]authz.Reach{}},
	}
	appender := &kernelTestStore{}
	domainCalls := 0
	domain := completeKernelTestDeviceGroupDomain(crudDomainStoreFuncs{
		createEvent: func(*powermanagev1.CreateDeviceGroupRequest) (store.Event, error) {
			domainCalls++
			return store.Event{}, nil
		},
	})
	gate, err := auth.NewAuthorizationGate(resolver)
	if err != nil {
		t.Fatalf("create authorization gate: %v", err)
	}
	kernel, err := newCRUDKernel(appender, gate, []crudDomain{domain})
	if err != nil {
		t.Fatalf("create CRUD kernel: %v", err)
	}
	ctx, err := auth.ContextWithSessionClaims(t.Context(), auth.Claims{
		Subject:        kernelTestSubject,
		SessionVersion: 1,
	})
	if err != nil {
		t.Fatalf("attach session claims: %v", err)
	}

	_, err = kernel.create(
		ctx,
		powermanagev1connect.ControlServiceCreateDeviceGroupProcedure,
		deviceGroupDomainName,
		&powermanagev1.CreateDeviceGroupRequest{
			Id:   kernelTestGroupID,
			Name: "production",
		},
	)
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("unauthorized create code = %v; want PermissionDenied", connect.CodeOf(err))
	}
	if resolver.calls != 1 || domainCalls != 0 || appender.appends != 0 {
		t.Fatalf(
			"unauthorized effects = resolver %d, domain %d, appends %d; want (1, 0, 0)",
			resolver.calls,
			domainCalls,
			appender.appends,
		)
	}
}

func completeKernelTestDeviceGroupDomain(
	functions crudDomainStoreFuncs,
) crudDomain {
	if functions.createEvent == nil {
		functions.createEvent = func(*powermanagev1.CreateDeviceGroupRequest) (store.Event, error) {
			return store.Event{}, nil
		}
	}
	if functions.updateEvent == nil {
		functions.updateEvent = func(*powermanagev1.UpdateDeviceGroupRequest) (store.Event, error) {
			return store.Event{}, nil
		}
	}
	if functions.deleteEvent == nil {
		functions.deleteEvent = func(*powermanagev1.DeleteDeviceGroupRequest) (store.Event, error) {
			return store.Event{}, nil
		}
	}
	if functions.get == nil {
		functions.get = func(
			context.Context,
			string,
			CRUDScope,
		) (store.DeviceGroup, error) {
			return store.DeviceGroup{
				ID:                kernelTestGroupID,
				Name:              "production",
				ProjectionVersion: 1,
			}, nil
		}
	}
	if functions.list == nil {
		functions.list = func(
			context.Context,
			CRUDScope,
			int32,
		) ([]store.DeviceGroup, error) {
			return nil, nil
		}
	}
	return deviceGroupDomain(functions)
}

func TestCRUDKernel_RejectsIncompleteAndDuplicateRegistrations(t *testing.T) {
	resolver := &kernelTestResolver{}
	gate, err := auth.NewAuthorizationGate(resolver)
	if err != nil {
		t.Fatalf("create authorization gate: %v", err)
	}
	valid := deviceGroupDomain(crudDomainStoreFuncs{
		createEvent: func(*powermanagev1.CreateDeviceGroupRequest) (store.Event, error) {
			return store.Event{}, nil
		},
		updateEvent: func(*powermanagev1.UpdateDeviceGroupRequest) (store.Event, error) {
			return store.Event{}, nil
		},
		deleteEvent: func(*powermanagev1.DeleteDeviceGroupRequest) (store.Event, error) {
			return store.Event{}, nil
		},
		get: func(context.Context, string, CRUDScope) (store.DeviceGroup, error) {
			return store.DeviceGroup{}, nil
		},
		list: func(context.Context, CRUDScope, int32) ([]store.DeviceGroup, error) {
			return nil, nil
		},
	})
	tests := map[string]struct {
		domains []crudDomain
		want    error
	}{
		"empty": {
			want: errCRUDRegistryEmpty,
		},
		"duplicate": {
			domains: []crudDomain{valid, valid},
			want:    errCRUDDomainDuplicate,
		},
		"incomplete": {
			domains: []crudDomain{deviceGroupDomain(crudDomainStoreFuncs{})},
			want:    errCRUDDomainIncomplete,
		},
		"permission mismatch": {
			domains: []crudDomain{func() crudDomain {
				mismatched := valid
				mismatched.permission = "audit.read"
				return mismatched
			}()},
			want: errCRUDDomainAuthorization,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := newCRUDKernel(&kernelTestStore{}, gate, test.domains)
			if !errors.Is(err, test.want) {
				t.Fatalf("newCRUDKernel error = %v; want %v", err, test.want)
			}
		})
	}
}

func TestCRUDKernel_AcceptsNormativeOperationSubsets(t *testing.T) {
	tests := map[string][]crudOperation{
		"read only":          {crudGet, crudList},
		"list only":          {crudList},
		"immutable":          {crudCreate, crudGet, crudList, crudDelete},
		"externally created": {crudGet, crudList, crudUpdate, crudDelete},
	}
	for name, operations := range tests {
		t.Run(name, func(t *testing.T) {
			domain := completeKernelTestDeviceGroupDomain(crudDomainStoreFuncs{})
			domain.requestMessages = cloneRequestMessages(domain.requestMessages)
			domain.procedures = cloneProcedures(domain.procedures)
			for operation := crudCreate; operation <= crudDelete; operation++ {
				if slices.Contains(operations, operation) {
					continue
				}
				delete(domain.requestMessages, operation)
				delete(domain.procedures, operation)
				switch operation {
				case crudCreate:
					domain.createEvent = nil
				case crudGet:
					domain.get = nil
				case crudList:
					domain.list = nil
				case crudUpdate:
					domain.updateEvent = nil
				case crudDelete:
					domain.deleteEvent = nil
				}
			}
			if !domainHasMutation(domain) {
				domain.projectorEvents = nil
			}
			if err := validateCRUDDomain(domain); err != nil {
				t.Fatalf("validate %s domain: %v", name, err)
			}
		})
	}
}

func TestCRUDKernel_ScopedCreateRequiresStructuralValidator(t *testing.T) {
	for _, relation := range []crudScopeRelation{crudScopeUserOwned, crudScopeAssignment} {
		domain := completeKernelTestDeviceGroupDomain(crudDomainStoreFuncs{})
		domain.scopeRelation = relation
		domain.validateScope = nil
		if err := validateCRUDDomain(domain); !errors.Is(err, errCRUDDomainIncomplete) {
			t.Fatalf(
				"relation %d create without scope validator error = %v; want incomplete",
				relation,
				err,
			)
		}
	}
}

func TestCRUDKernel_MutatingDomainRequiresProjectorEvents(t *testing.T) {
	domain := completeKernelTestDeviceGroupDomain(crudDomainStoreFuncs{})
	domain.projectorEvents = nil
	if err := validateCRUDDomain(domain); !errors.Is(err, errCRUDDomainIncomplete) {
		t.Fatalf("mutation domain without projector events error = %v; want incomplete", err)
	}
}
