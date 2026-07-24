package auth

import (
	"context"
	"errors"
	"maps"
	"net/http"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/sdk/nilcheck"
	"github.com/manchtools/power-manage/server/internal/authz"
)

var (
	// ErrInterceptorChainNotWired classifies constructor and handler wiring failures.
	ErrInterceptorChainNotWired = errors.New("interceptor chain is not wired: auth")
	// ErrProcedureAuthorizationInvalid identifies an incomplete or contradictory
	// RPC policy registry.
	ErrProcedureAuthorizationInvalid = errors.New("procedure authorization is invalid: auth")
)

// ProcedureClass identifies the one authentication path an RPC uses.
type ProcedureClass uint8

const (
	ProcedurePublic ProcedureClass = iota + 1
	ProcedurePermissionGated
	ProcedureAltAuth
)

// ProcedureAuthorization is the complete authorization policy for one RPC.
type ProcedureAuthorization struct {
	Class      ProcedureClass
	Permission authz.Permission
}

var procedureAuthorizations = map[string]ProcedureAuthorization{
	powermanagev1connect.AgentServiceStreamProcedure:                    {Class: ProcedureAltAuth},
	powermanagev1connect.ControlServiceCompleteOidcSessionProcedure:     {Class: ProcedurePublic},
	powermanagev1connect.ControlServiceCreateActionProcedure:            {Class: ProcedurePermissionGated, Permission: "actions.manage"},
	powermanagev1connect.ControlServiceCreateActionSetProcedure:         {Class: ProcedurePermissionGated, Permission: "action_sets.manage"},
	powermanagev1connect.ControlServiceCreateApiTokenProcedure:          {Class: ProcedurePermissionGated, Permission: "users.manage"},
	powermanagev1connect.ControlServiceCreateAssignmentProcedure:        {Class: ProcedurePermissionGated, Permission: "actions.manage"},
	powermanagev1connect.ControlServiceCreateCompliancePolicyProcedure:  {Class: ProcedurePermissionGated, Permission: "actions.manage"},
	powermanagev1connect.ControlServiceCreateGrantProcedure:             {Class: ProcedurePermissionGated, Permission: "roles.manage"},
	powermanagev1connect.ControlServiceCreateIdentityProviderProcedure:  {Class: ProcedurePermissionGated, Permission: "identity_providers.manage"},
	powermanagev1connect.ControlServiceCreateRoleProcedure:              {Class: ProcedurePermissionGated, Permission: "roles.manage"},
	powermanagev1connect.ControlServiceCreateScimConfigurationProcedure: {Class: ProcedurePermissionGated, Permission: "scim_configuration.manage"},
	powermanagev1connect.ControlServiceCreateServerSettingProcedure:     {Class: ProcedurePermissionGated, Permission: "server_settings.manage"},
	powermanagev1connect.ControlServiceCreateRegistrationTokenProcedure: {Class: ProcedurePermissionGated, Permission: "pki.manage"},
	powermanagev1connect.ControlServiceCreateUserProcedure:              {Class: ProcedurePermissionGated, Permission: "users.manage"},
	powermanagev1connect.ControlServiceCreateUserGroupProcedure:         {Class: ProcedurePermissionGated, Permission: "user_groups.manage"},
	powermanagev1connect.ControlServiceCreateDeviceGroupProcedure:       {Class: ProcedurePermissionGated, Permission: "devices.manage"},
	powermanagev1connect.ControlServiceDeleteApiTokenProcedure:          {Class: ProcedurePermissionGated, Permission: "users.manage"},
	powermanagev1connect.ControlServiceDeleteActionProcedure:            {Class: ProcedurePermissionGated, Permission: "actions.manage"},
	powermanagev1connect.ControlServiceDeleteActionSetProcedure:         {Class: ProcedurePermissionGated, Permission: "action_sets.manage"},
	powermanagev1connect.ControlServiceDeleteAssignmentProcedure:        {Class: ProcedurePermissionGated, Permission: "actions.manage"},
	powermanagev1connect.ControlServiceDeleteCompliancePolicyProcedure:  {Class: ProcedurePermissionGated, Permission: "actions.manage"},
	powermanagev1connect.ControlServiceDeleteGrantProcedure:             {Class: ProcedurePermissionGated, Permission: "roles.manage"},
	powermanagev1connect.ControlServiceDeleteIdentityProviderProcedure:  {Class: ProcedurePermissionGated, Permission: "identity_providers.manage"},
	powermanagev1connect.ControlServiceDeleteRoleProcedure:              {Class: ProcedurePermissionGated, Permission: "roles.manage"},
	powermanagev1connect.ControlServiceDeleteScimConfigurationProcedure: {Class: ProcedurePermissionGated, Permission: "scim_configuration.manage"},
	powermanagev1connect.ControlServiceDeleteServerSettingProcedure:     {Class: ProcedurePermissionGated, Permission: "server_settings.manage"},
	powermanagev1connect.ControlServiceDeleteRegistrationTokenProcedure: {Class: ProcedurePermissionGated, Permission: "pki.manage"},
	powermanagev1connect.ControlServiceDeleteUserProcedure:              {Class: ProcedurePermissionGated, Permission: "users.manage"},
	powermanagev1connect.ControlServiceDeleteUserGroupProcedure:         {Class: ProcedurePermissionGated, Permission: "user_groups.manage"},
	powermanagev1connect.ControlServiceDeleteDeviceGroupProcedure:       {Class: ProcedurePermissionGated, Permission: "devices.manage"},
	powermanagev1connect.ControlServiceDeleteDeviceProcedure:            {Class: ProcedurePermissionGated, Permission: "devices.manage"},
	powermanagev1connect.ControlServiceGetApiTokenProcedure:             {Class: ProcedurePermissionGated, Permission: "users.manage"},
	powermanagev1connect.ControlServiceGetActionProcedure:               {Class: ProcedurePermissionGated, Permission: "actions.manage"},
	powermanagev1connect.ControlServiceGetActionSetProcedure:            {Class: ProcedurePermissionGated, Permission: "action_sets.manage"},
	powermanagev1connect.ControlServiceGetAssignmentProcedure:           {Class: ProcedurePermissionGated, Permission: "actions.manage"},
	powermanagev1connect.ControlServiceGetCompliancePolicyProcedure:     {Class: ProcedurePermissionGated, Permission: "actions.manage"},
	powermanagev1connect.ControlServiceGetGrantProcedure:                {Class: ProcedurePermissionGated, Permission: "roles.manage"},
	powermanagev1connect.ControlServiceGetIdentityProviderProcedure:     {Class: ProcedurePermissionGated, Permission: "identity_providers.manage"},
	powermanagev1connect.ControlServiceGetRoleProcedure:                 {Class: ProcedurePermissionGated, Permission: "roles.manage"},
	powermanagev1connect.ControlServiceGetScimConfigurationProcedure:    {Class: ProcedurePermissionGated, Permission: "scim_configuration.manage"},
	powermanagev1connect.ControlServiceGetServerSettingProcedure:        {Class: ProcedurePermissionGated, Permission: "server_settings.manage"},
	powermanagev1connect.ControlServiceGetRegistrationTokenProcedure:    {Class: ProcedurePermissionGated, Permission: "pki.manage"},
	powermanagev1connect.ControlServiceGetUserProcedure:                 {Class: ProcedurePermissionGated, Permission: "users.manage"},
	powermanagev1connect.ControlServiceGetUserGroupProcedure:            {Class: ProcedurePermissionGated, Permission: "user_groups.manage"},
	powermanagev1connect.ControlServiceGetDeviceGroupProcedure:          {Class: ProcedurePermissionGated, Permission: "devices.manage"},
	powermanagev1connect.ControlServiceGetDeviceProcedure:               {Class: ProcedurePermissionGated, Permission: "devices.manage"},
	powermanagev1connect.ControlServiceGetExecutionProcedure:            {Class: ProcedurePermissionGated, Permission: "executions.read"},
	powermanagev1connect.ControlServiceGetGatewayProcedure:              {Class: ProcedurePermissionGated, Permission: "pki.manage"},
	powermanagev1connect.ControlServiceGetInventorySnapshotProcedure:    {Class: ProcedurePermissionGated, Permission: "devices.manage"},
	powermanagev1connect.ControlServiceListApiTokensProcedure:           {Class: ProcedurePermissionGated, Permission: "users.manage"},
	powermanagev1connect.ControlServiceListActionsProcedure:             {Class: ProcedurePermissionGated, Permission: "actions.manage"},
	powermanagev1connect.ControlServiceListActionSetsProcedure:          {Class: ProcedurePermissionGated, Permission: "action_sets.manage"},
	powermanagev1connect.ControlServiceListAssignmentsProcedure:         {Class: ProcedurePermissionGated, Permission: "actions.manage"},
	powermanagev1connect.ControlServiceListCompliancePoliciesProcedure:  {Class: ProcedurePermissionGated, Permission: "actions.manage"},
	powermanagev1connect.ControlServiceListGrantsProcedure:              {Class: ProcedurePermissionGated, Permission: "roles.manage"},
	powermanagev1connect.ControlServiceListIdentityProvidersProcedure:   {Class: ProcedurePermissionGated, Permission: "identity_providers.manage"},
	powermanagev1connect.ControlServiceListRolesProcedure:               {Class: ProcedurePermissionGated, Permission: "roles.manage"},
	powermanagev1connect.ControlServiceListScimConfigurationsProcedure:  {Class: ProcedurePermissionGated, Permission: "scim_configuration.manage"},
	powermanagev1connect.ControlServiceListServerSettingsProcedure:      {Class: ProcedurePermissionGated, Permission: "server_settings.manage"},
	powermanagev1connect.ControlServiceListRegistrationTokensProcedure:  {Class: ProcedurePermissionGated, Permission: "pki.manage"},
	powermanagev1connect.ControlServiceListUsersProcedure:               {Class: ProcedurePermissionGated, Permission: "users.manage"},
	powermanagev1connect.ControlServiceListUserGroupsProcedure:          {Class: ProcedurePermissionGated, Permission: "user_groups.manage"},
	powermanagev1connect.ControlServiceListDeviceGroupsProcedure:        {Class: ProcedurePermissionGated, Permission: "devices.manage"},
	powermanagev1connect.ControlServiceListDevicesProcedure:             {Class: ProcedurePermissionGated, Permission: "devices.manage"},
	powermanagev1connect.ControlServiceListAuditEventsProcedure:         {Class: ProcedurePermissionGated, Permission: "audit.read"},
	powermanagev1connect.ControlServiceListExecutionsProcedure:          {Class: ProcedurePermissionGated, Permission: "executions.read"},
	powermanagev1connect.ControlServiceListGatewaysProcedure:            {Class: ProcedurePermissionGated, Permission: "pki.manage"},
	powermanagev1connect.ControlServiceListInventorySnapshotsProcedure:  {Class: ProcedurePermissionGated, Permission: "devices.manage"},
	powermanagev1connect.ControlServiceRefreshSessionProcedure:          {Class: ProcedurePublic},
	powermanagev1connect.ControlServiceStartOidcSessionProcedure:        {Class: ProcedurePublic},
	powermanagev1connect.ControlServiceUpdateApiTokenProcedure:          {Class: ProcedurePermissionGated, Permission: "users.manage"},
	powermanagev1connect.ControlServiceUpdateActionProcedure:            {Class: ProcedurePermissionGated, Permission: "actions.manage"},
	powermanagev1connect.ControlServiceUpdateActionSetProcedure:         {Class: ProcedurePermissionGated, Permission: "action_sets.manage"},
	powermanagev1connect.ControlServiceUpdateCompliancePolicyProcedure:  {Class: ProcedurePermissionGated, Permission: "actions.manage"},
	powermanagev1connect.ControlServiceUpdateGrantProcedure:             {Class: ProcedurePermissionGated, Permission: "roles.manage"},
	powermanagev1connect.ControlServiceUpdateIdentityProviderProcedure:  {Class: ProcedurePermissionGated, Permission: "identity_providers.manage"},
	powermanagev1connect.ControlServiceUpdateRoleProcedure:              {Class: ProcedurePermissionGated, Permission: "roles.manage"},
	powermanagev1connect.ControlServiceUpdateScimConfigurationProcedure: {Class: ProcedurePermissionGated, Permission: "scim_configuration.manage"},
	powermanagev1connect.ControlServiceUpdateServerSettingProcedure:     {Class: ProcedurePermissionGated, Permission: "server_settings.manage"},
	powermanagev1connect.ControlServiceUpdateRegistrationTokenProcedure: {Class: ProcedurePermissionGated, Permission: "pki.manage"},
	powermanagev1connect.ControlServiceUpdateUserProcedure:              {Class: ProcedurePermissionGated, Permission: "users.manage"},
	powermanagev1connect.ControlServiceUpdateUserGroupProcedure:         {Class: ProcedurePermissionGated, Permission: "user_groups.manage"},
	powermanagev1connect.ControlServiceUpdateDeviceGroupProcedure:       {Class: ProcedurePermissionGated, Permission: "devices.manage"},
	powermanagev1connect.ControlServiceUpdateDeviceProcedure:            {Class: ProcedurePermissionGated, Permission: "devices.manage"},
	powermanagev1connect.InternalServiceStreamProcedure:                 {Class: ProcedureAltAuth},
	powermanagev1connect.InternalServiceValidateTerminalTokenProcedure:  {Class: ProcedureAltAuth},
	powermanagev1connect.PkiServiceEnrollAgentProcedure:                 {Class: ProcedurePublic},
	powermanagev1connect.PkiServiceRenewAgentProcedure:                  {Class: ProcedurePublic},
	powermanagev1connect.PkiServiceRevokeAgentProcedure:                 {Class: ProcedurePublic},
	powermanagev1connect.PkiServiceForceRenewAgentProcedure:             {Class: ProcedurePublic},
	powermanagev1connect.PkiServiceEnrollGatewayProcedure:               {Class: ProcedurePublic},
	powermanagev1connect.PkiServiceRenewGatewayProcedure:                {Class: ProcedurePublic},
	powermanagev1connect.PkiServiceRevokeGatewayProcedure:               {Class: ProcedurePublic},
	powermanagev1connect.PkiServiceConfirmAgentTrustStateProcedure:      {Class: ProcedurePublic},
	powermanagev1connect.PkiServiceConfirmGatewayTrustStateProcedure:    {Class: ProcedurePublic},
}

// ProcedureAuthorizations returns a copy of the complete RPC policy registry.
func ProcedureAuthorizations() map[string]ProcedureAuthorization {
	return maps.Clone(procedureAuthorizations)
}

// ProcedureClassifications returns a class-only view derived from the complete
// RPC policy registry.
func ProcedureClassifications() map[string]ProcedureClass {
	classifications := make(map[string]ProcedureClass, len(procedureAuthorizations))
	for procedure, policy := range procedureAuthorizations {
		classifications[procedure] = policy.Class
	}
	return classifications
}

// ClassifyProcedure resolves one RPC without defaulting unknown procedures.
func ClassifyProcedure(procedure string) (ProcedureClass, bool) {
	policy, ok := procedureAuthorizations[procedure]
	return policy.Class, ok
}

func classifyProcedureAuthorization(procedure string) (ProcedureAuthorization, bool) {
	policy, ok := procedureAuthorizations[procedure]
	return policy, ok
}

// InterceptorChain is the immutable validate → authenticate → rate-limit →
// authorize server chain.
type InterceptorChain struct {
	stages [4]connect.Interceptor
}

// NewInterceptorChain fixes the security-stage order at construction time.
func NewInterceptorChain(
	validate connect.Interceptor,
	authenticate connect.Interceptor,
	rateLimit connect.Interceptor,
	authorize connect.Interceptor,
) (*InterceptorChain, error) {
	chain := &InterceptorChain{
		stages: [4]connect.Interceptor{validate, authenticate, rateLimit, authorize},
	}
	if err := chain.ValidateWiring(); err != nil {
		return nil, err
	}
	return chain, nil
}

// ValidateWiring rejects nil and zero-value chains before handler exposure.
func (c *InterceptorChain) ValidateWiring() error {
	if c == nil {
		return ErrInterceptorChainNotWired
	}
	for _, stage := range c.stages {
		if nilcheck.Interface(stage) {
			return ErrInterceptorChainNotWired
		}
	}
	gate, ok := c.stages[len(c.stages)-1].(*AuthorizationGate)
	if !ok || gate.ValidateWiring() != nil {
		return ErrInterceptorChainNotWired
	}
	return nil
}

// WrapUnary implements connect.Interceptor.
func (c *InterceptorChain) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	if c.ValidateWiring() != nil || next == nil {
		return func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
			return nil, boundaryNotWiredError()
		}
	}
	for index := len(c.stages) - 1; index >= 0; index-- {
		next = c.stages[index].WrapUnary(next)
	}
	return next
}

// WrapStreamingClient implements connect.Interceptor.
func (c *InterceptorChain) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	if c.ValidateWiring() != nil || next == nil {
		return func(_ context.Context, spec connect.Spec) connect.StreamingClientConn {
			return &rejectedStreamingClientConn{
				spec:          spec,
				requestHeader: make(http.Header),
			}
		}
	}
	for index := len(c.stages) - 1; index >= 0; index-- {
		next = c.stages[index].WrapStreamingClient(next)
	}
	return next
}

type rejectedStreamingClientConn struct {
	spec          connect.Spec
	requestHeader http.Header
}

func (c *rejectedStreamingClientConn) Spec() connect.Spec {
	return c.spec
}

func (*rejectedStreamingClientConn) Peer() connect.Peer {
	return connect.Peer{}
}

func (*rejectedStreamingClientConn) Send(any) error {
	return boundaryNotWiredError()
}

func (c *rejectedStreamingClientConn) RequestHeader() http.Header {
	return c.requestHeader
}

func (*rejectedStreamingClientConn) CloseRequest() error {
	return boundaryNotWiredError()
}

func (*rejectedStreamingClientConn) Receive(any) error {
	return boundaryNotWiredError()
}

func (*rejectedStreamingClientConn) ResponseHeader() http.Header {
	return make(http.Header)
}

func (*rejectedStreamingClientConn) ResponseTrailer() http.Header {
	return make(http.Header)
}

func (*rejectedStreamingClientConn) CloseResponse() error {
	return boundaryNotWiredError()
}

// WrapStreamingHandler implements connect.Interceptor.
func (c *InterceptorChain) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	if c.ValidateWiring() != nil || next == nil {
		return func(context.Context, connect.StreamingHandlerConn) error {
			return boundaryNotWiredError()
		}
	}
	for index := len(c.stages) - 1; index >= 0; index-- {
		next = c.stages[index].WrapStreamingHandler(next)
	}
	return next
}

func boundaryNotWiredError() error {
	return connect.NewError(connect.CodeInternal, errors.New("authentication boundary is not wired"))
}
