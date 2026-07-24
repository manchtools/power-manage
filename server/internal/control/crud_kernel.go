package control

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/manchtools/power-manage/sdk/nilcheck"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/authz"
	"github.com/manchtools/power-manage/server/internal/store"
)

const maxCRUDPageSize = 200

var (
	errCRUDInvalid             = errors.New("request is invalid")
	errCRUDNotFound            = errors.New("resource not found")
	errCRUDConflict            = errors.New("resource version conflict")
	errCRUDExists              = errors.New("resource already exists")
	errCRUDUnavailable         = errors.New("management service unavailable")
	errCRUDKernelNotWired      = errors.New("control: CRUD kernel is not wired")
	errCRUDRegistryEmpty       = errors.New("control: CRUD domain registry is empty")
	errCRUDDomainDuplicate     = errors.New("control: CRUD domain is duplicated")
	errCRUDDomainIncomplete    = errors.New("control: CRUD domain is incomplete")
	errCRUDDomainAuthorization = errors.New("control: CRUD domain authorization is invalid")
	errCRUDDomainMetadata      = errors.New("control: CRUD domain metadata is invalid")
)

type crudOperation uint8

const (
	crudCreate crudOperation = iota + 1
	crudGet
	crudList
	crudUpdate
	crudDelete
)

type crudAppender interface {
	AppendEvent(context.Context, store.Event) error
	AppendEventWithVersion(context.Context, store.Event, int64) error
}

// CRUDScope is the immutable object predicate passed to every domain read.
type CRUDScope struct {
	Global         bool
	DeviceGroupIDs []string
}

type crudDomain struct {
	name              string
	permission        authz.Permission
	objectMessage     protoreflect.FullName
	requestMessages   map[crudOperation]protoreflect.FullName
	procedures        map[crudOperation]string
	projectorEvents   []string
	searchableColumns []string
	alreadyExists     func(error) bool
	scope             func(authz.Reach) (CRUDScope, error)
	createEvent       func(proto.Message) (store.Event, error)
	updateEvent       func(proto.Message) (store.Event, error)
	deleteEvent       func(proto.Message) (store.Event, error)
	get               func(context.Context, string, CRUDScope) (proto.Message, error)
	list              func(context.Context, CRUDScope, int32) ([]proto.Message, error)
}

// CRUDKernel owns the single management-domain request pipeline.
type CRUDKernel struct {
	appender crudAppender
	gate     *auth.AuthorizationGate
	domains  map[string]crudDomain
}

func newCRUDKernel(
	appender crudAppender,
	gate *auth.AuthorizationGate,
	domains []crudDomain,
) (*CRUDKernel, error) {
	if nilcheck.Interface(appender) || gate == nil || gate.ValidateWiring() != nil {
		return nil, errCRUDKernelNotWired
	}
	if len(domains) == 0 {
		return nil, errCRUDRegistryEmpty
	}
	registry := make(map[string]crudDomain, len(domains))
	for _, domain := range domains {
		if err := validateCRUDDomain(domain); err != nil {
			return nil, err
		}
		if _, duplicate := registry[domain.name]; duplicate {
			return nil, fmt.Errorf("%w: %q", errCRUDDomainDuplicate, domain.name)
		}
		domain.requestMessages = cloneRequestMessages(domain.requestMessages)
		domain.procedures = cloneProcedures(domain.procedures)
		domain.projectorEvents = slices.Clone(domain.projectorEvents)
		domain.searchableColumns = slices.Clone(domain.searchableColumns)
		registry[domain.name] = domain
	}
	return &CRUDKernel{appender: appender, gate: gate, domains: registry}, nil
}

func (k *CRUDKernel) create(
	ctx context.Context,
	procedure string,
	domainName string,
	request proto.Message,
) (proto.Message, error) {
	domain, err := k.prepare(ctx, procedure, domainName, crudCreate, request)
	if err != nil {
		return nil, err
	}
	id, err := crudStringField(request, "id")
	if err != nil {
		return nil, invalidCRUDRequest()
	}
	// Creation is still an object write: a scoped caller may create only an ID
	// explicitly present in its direct reach; global reach may create any ID.
	authorized, scope, err := k.authorize(ctx, procedure, domain, id)
	if err != nil {
		return nil, err
	}
	event, err := domain.createEvent(request)
	if err != nil {
		return nil, unavailableCRUD()
	}
	if err := k.appender.AppendEvent(authorized, event); err != nil {
		return nil, mapCRUDStoreError(domain, err)
	}
	result, err := domain.get(authorized, id, scope)
	if err != nil {
		return nil, mapCRUDStoreError(domain, err)
	}
	if err := validateCRUDResult(result, domain.objectMessage); err != nil {
		return nil, unavailableCRUD()
	}
	return result, nil
}

func (k *CRUDKernel) get(
	ctx context.Context,
	procedure string,
	domainName string,
	request proto.Message,
) (proto.Message, error) {
	domain, err := k.prepare(ctx, procedure, domainName, crudGet, request)
	if err != nil {
		return nil, err
	}
	id, err := crudStringField(request, "id")
	if err != nil {
		return nil, invalidCRUDRequest()
	}
	authorized, scope, err := k.authorize(ctx, procedure, domain, id)
	if err != nil {
		return nil, err
	}
	result, err := domain.get(authorized, id, scope)
	if err != nil {
		return nil, mapCRUDStoreError(domain, err)
	}
	if err := validateCRUDResult(result, domain.objectMessage); err != nil {
		return nil, unavailableCRUD()
	}
	return result, nil
}

func (k *CRUDKernel) list(
	ctx context.Context,
	procedure string,
	domainName string,
	request proto.Message,
) ([]proto.Message, error) {
	domain, err := k.prepare(ctx, procedure, domainName, crudList, request)
	if err != nil {
		return nil, err
	}
	limit, err := crudUintField(request, "limit")
	if err != nil || limit > maxCRUDPageSize {
		return nil, invalidCRUDRequest()
	}
	authorized, scope, err := k.authorize(ctx, procedure, domain, "")
	if err != nil {
		return nil, err
	}
	results, err := domain.list(authorized, scope, int32(limit))
	if err != nil {
		return nil, mapCRUDStoreError(domain, err)
	}
	for _, result := range results {
		if err := validateCRUDResult(result, domain.objectMessage); err != nil {
			return nil, unavailableCRUD()
		}
	}
	return results, nil
}

func (k *CRUDKernel) update(
	ctx context.Context,
	procedure string,
	domainName string,
	request proto.Message,
) (proto.Message, error) {
	domain, err := k.prepare(ctx, procedure, domainName, crudUpdate, request)
	if err != nil {
		return nil, err
	}
	id, err := crudStringField(request, "id")
	if err != nil {
		return nil, invalidCRUDRequest()
	}
	expectedVersion, err := crudUintField(request, "expected_version")
	if err != nil || expectedVersion > math.MaxInt64 {
		return nil, invalidCRUDRequest()
	}
	authorized, scope, err := k.authorize(ctx, procedure, domain, id)
	if err != nil {
		return nil, err
	}
	event, err := domain.updateEvent(request)
	if err != nil {
		return nil, unavailableCRUD()
	}
	if err := k.appender.AppendEventWithVersion(
		authorized,
		event,
		int64(expectedVersion),
	); err != nil {
		return nil, mapCRUDStoreError(domain, err)
	}
	result, err := domain.get(authorized, id, scope)
	if err != nil {
		return nil, mapCRUDStoreError(domain, err)
	}
	if err := validateCRUDResult(result, domain.objectMessage); err != nil {
		return nil, unavailableCRUD()
	}
	return result, nil
}

func (k *CRUDKernel) delete(
	ctx context.Context,
	procedure string,
	domainName string,
	request proto.Message,
) (string, error) {
	domain, err := k.prepare(ctx, procedure, domainName, crudDelete, request)
	if err != nil {
		return "", err
	}
	id, err := crudStringField(request, "id")
	if err != nil {
		return "", invalidCRUDRequest()
	}
	expectedVersion, err := crudUintField(request, "expected_version")
	if err != nil || expectedVersion > math.MaxInt64 {
		return "", invalidCRUDRequest()
	}
	authorized, _, err := k.authorize(ctx, procedure, domain, id)
	if err != nil {
		return "", err
	}
	event, err := domain.deleteEvent(request)
	if err != nil {
		return "", unavailableCRUD()
	}
	if err := k.appender.AppendEventWithVersion(
		authorized,
		event,
		int64(expectedVersion),
	); err != nil {
		return "", mapCRUDStoreError(domain, err)
	}
	return id, nil
}

func (k *CRUDKernel) prepare(
	ctx context.Context,
	procedure string,
	domainName string,
	operation crudOperation,
	request proto.Message,
) (crudDomain, error) {
	if k == nil || nilcheck.Interface(k.appender) || k.gate == nil ||
		k.gate.ValidateWiring() != nil || nilcheck.Interface(ctx) {
		return crudDomain{}, unavailableCRUD()
	}
	domain, ok := k.domains[domainName]
	if !ok {
		return crudDomain{}, unavailableCRUD()
	}
	if domain.procedures[operation] != procedure {
		return crudDomain{}, unavailableCRUD()
	}
	if err := validateCRUDRequest(request, domain.requestMessages[operation]); err != nil {
		return crudDomain{}, invalidCRUDRequest()
	}
	return domain, nil
}

func (k *CRUDKernel) authorize(
	ctx context.Context,
	procedure string,
	domain crudDomain,
	objectID string,
) (context.Context, CRUDScope, error) {
	authorized, err := k.gate.AuthorizeContext(ctx, procedure)
	if err != nil {
		return nil, CRUDScope{}, err
	}
	decision, ok := auth.AuthorizationDecisionFromContext(authorized)
	if !ok || decision.RequiredPermission != domain.permission {
		return nil, CRUDScope{}, unavailableCRUD()
	}
	reach, ok := decision.EffectiveAccess.Permissions[domain.permission]
	if !ok {
		return nil, CRUDScope{}, unavailableCRUD()
	}
	scope, err := domain.scope(reach)
	if err != nil {
		return nil, CRUDScope{}, unavailableCRUD()
	}
	scope.DeviceGroupIDs = slices.Clone(scope.DeviceGroupIDs)
	if objectID != "" && !scope.allowsDeviceGroup(objectID) {
		return nil, CRUDScope{}, notFoundCRUD()
	}
	return authorized, scope, nil
}

func (s CRUDScope) allowsDeviceGroup(id string) bool {
	return s.Global || slices.Contains(s.DeviceGroupIDs, id)
}

func validateCRUDDomain(domain crudDomain) error {
	if strings.TrimSpace(domain.name) == "" ||
		domain.permission == "" ||
		domain.objectMessage == "" ||
		len(domain.requestMessages) != 5 ||
		len(domain.procedures) != 5 ||
		len(domain.projectorEvents) == 0 ||
		len(domain.searchableColumns) == 0 ||
		domain.alreadyExists == nil ||
		domain.scope == nil ||
		domain.createEvent == nil ||
		domain.updateEvent == nil ||
		domain.deleteEvent == nil ||
		domain.get == nil ||
		domain.list == nil {
		return fmt.Errorf("%w: %q", errCRUDDomainIncomplete, domain.name)
	}
	if _, ok := authz.Lookup(domain.permission); !ok {
		return fmt.Errorf(
			"%w: domain %q has unknown permission",
			errCRUDDomainAuthorization,
			domain.name,
		)
	}
	policies := auth.ProcedureAuthorizations()
	for operation := crudCreate; operation <= crudDelete; operation++ {
		if domain.requestMessages[operation] == "" {
			return fmt.Errorf(
				"%w: domain %q lacks operation %d request",
				errCRUDDomainIncomplete,
				domain.name,
				operation,
			)
		}
		procedure := domain.procedures[operation]
		policy, ok := policies[procedure]
		if !ok ||
			policy.Class != auth.ProcedurePermissionGated ||
			policy.Permission != domain.permission {
			return fmt.Errorf(
				"%w: domain %q operation %d",
				errCRUDDomainAuthorization,
				domain.name,
				operation,
			)
		}
	}
	if hasBlankOrDuplicate(domain.projectorEvents) ||
		hasBlankOrDuplicate(domain.searchableColumns) {
		return fmt.Errorf("%w: %q", errCRUDDomainMetadata, domain.name)
	}
	return nil
}

func cloneRequestMessages(
	messages map[crudOperation]protoreflect.FullName,
) map[crudOperation]protoreflect.FullName {
	clone := make(map[crudOperation]protoreflect.FullName, len(messages))
	for operation, message := range messages {
		clone[operation] = message
	}
	return clone
}

func cloneProcedures(procedures map[crudOperation]string) map[crudOperation]string {
	clone := make(map[crudOperation]string, len(procedures))
	for operation, procedure := range procedures {
		clone[operation] = procedure
	}
	return clone
}

func hasBlankOrDuplicate(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
		if _, duplicate := seen[value]; duplicate {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func validateCRUDRequest(message proto.Message, want protoreflect.FullName) error {
	if nilcheck.Interface(message) || !message.ProtoReflect().IsValid() ||
		message.ProtoReflect().Descriptor().FullName() != want {
		return errCRUDInvalid
	}
	return protovalidate.Validate(message)
}

func validateCRUDResult(message proto.Message, want protoreflect.FullName) error {
	if nilcheck.Interface(message) || !message.ProtoReflect().IsValid() ||
		message.ProtoReflect().Descriptor().FullName() != want {
		return errCRUDUnavailable
	}
	if err := protovalidate.Validate(message); err != nil {
		return errCRUDUnavailable
	}
	return nil
}

func crudStringField(message proto.Message, name protoreflect.Name) (string, error) {
	field := message.ProtoReflect().Descriptor().Fields().ByName(name)
	if field == nil || field.Kind() != protoreflect.StringKind {
		return "", errCRUDInvalid
	}
	return message.ProtoReflect().Get(field).String(), nil
}

func crudUintField(message proto.Message, name protoreflect.Name) (uint64, error) {
	field := message.ProtoReflect().Descriptor().Fields().ByName(name)
	if field == nil {
		return 0, errCRUDInvalid
	}
	switch field.Kind() {
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind:
		return message.ProtoReflect().Get(field).Uint(), nil
	default:
		return 0, errCRUDInvalid
	}
}

func mapCRUDStoreError(domain crudDomain, err error) error {
	switch {
	case store.IsNotFound(err):
		return notFoundCRUD()
	case store.IsVersionConflict(err):
		return connect.NewError(connect.CodeAborted, errCRUDConflict)
	case domain.alreadyExists(err):
		return connect.NewError(connect.CodeAlreadyExists, errCRUDExists)
	default:
		return unavailableCRUD()
	}
}

func invalidCRUDRequest() error {
	return connect.NewError(connect.CodeInvalidArgument, errCRUDInvalid)
}

func notFoundCRUD() error {
	return connect.NewError(connect.CodeNotFound, errCRUDNotFound)
}

func unavailableCRUD() error {
	return connect.NewError(connect.CodeUnavailable, errCRUDUnavailable)
}
