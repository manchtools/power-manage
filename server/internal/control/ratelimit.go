package control

import (
	"maps"
	"time"

	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
)

var publicRateLimitPolicies = map[string]auth.RateLimitPolicy{
	powermanagev1connect.ControlServiceCompleteOidcSessionProcedure:  oidcRateLimitPolicy(),
	powermanagev1connect.ControlServiceRefreshSessionProcedure:       refreshRateLimitPolicy(),
	powermanagev1connect.ControlServiceStartOidcSessionProcedure:     oidcRateLimitPolicy(),
	powermanagev1connect.PkiServiceEnrollAgentProcedure:              pkiAuthenticationRateLimitPolicy(),
	powermanagev1connect.PkiServiceRenewAgentProcedure:               pkiAuthenticationRateLimitPolicy(),
	powermanagev1connect.PkiServiceRevokeAgentProcedure:              pkiAuthenticationRateLimitPolicy(),
	powermanagev1connect.PkiServiceForceRenewAgentProcedure:          pkiAuthenticationRateLimitPolicy(),
	powermanagev1connect.PkiServiceEnrollGatewayProcedure:            pkiAuthenticationRateLimitPolicy(),
	powermanagev1connect.PkiServiceRenewGatewayProcedure:             pkiAuthenticationRateLimitPolicy(),
	powermanagev1connect.PkiServiceRevokeGatewayProcedure:            pkiAuthenticationRateLimitPolicy(),
	powermanagev1connect.PkiServiceConfirmAgentTrustStateProcedure:   pkiAuthenticationRateLimitPolicy(),
	powermanagev1connect.PkiServiceConfirmGatewayTrustStateProcedure: pkiAuthenticationRateLimitPolicy(),
}

func refreshRateLimitPolicy() auth.RateLimitPolicy {
	limit := auth.FailureLimit{Attempts: 5, Window: time.Minute}
	return auth.RateLimitPolicy{PerIP: limit, PerAccount: limit}
}

func oidcRateLimitPolicy() auth.RateLimitPolicy {
	limit := auth.FailureLimit{Attempts: 5, Window: time.Minute}
	return auth.RateLimitPolicy{PerIP: limit, PerAccount: limit}
}

func pkiAuthenticationRateLimitPolicy() auth.RateLimitPolicy {
	limit := auth.FailureLimit{Attempts: 5, Window: time.Minute}
	return auth.RateLimitPolicy{PerIP: limit, PerAccount: limit}
}

// PublicRateLimitPolicies returns the complete public authentication ladder
// registry with independent IP and account dimensions.
func PublicRateLimitPolicies() map[string]auth.RateLimitPolicy {
	return maps.Clone(publicRateLimitPolicies)
}
