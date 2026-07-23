package pki

import (
	"maps"
	"time"

	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
)

// PublicRateLimit is one procedure's public admission bound.
type PublicRateLimit struct {
	Attempts int
	Window   time.Duration
}

var publicProcedureLimits = map[string]PublicRateLimit{
	powermanagev1connect.PkiServiceEnrollAgentProcedure: {
		Attempts: registrationAttemptsPerMinute,
		Window:   time.Minute,
	},
	powermanagev1connect.PkiServiceRenewAgentProcedure: {
		Attempts: registrationAttemptsPerMinute,
		Window:   time.Minute,
	},
	powermanagev1connect.PkiServiceRevokeAgentProcedure: {
		Attempts: registrationAttemptsPerMinute,
		Window:   time.Minute,
	},
	powermanagev1connect.PkiServiceForceRenewAgentProcedure: {
		Attempts: registrationAttemptsPerMinute,
		Window:   time.Minute,
	},
	powermanagev1connect.PkiServiceEnrollGatewayProcedure: {
		Attempts: registrationAttemptsPerMinute,
		Window:   time.Minute,
	},
	powermanagev1connect.PkiServiceRenewGatewayProcedure: {
		Attempts: registrationAttemptsPerMinute,
		Window:   time.Minute,
	},
	powermanagev1connect.PkiServiceRevokeGatewayProcedure: {
		Attempts: registrationAttemptsPerMinute,
		Window:   time.Minute,
	},
	powermanagev1connect.PkiServiceConfirmAgentTrustStateProcedure: {
		Attempts: registrationAttemptsPerMinute,
		Window:   time.Minute,
	},
	powermanagev1connect.PkiServiceConfirmGatewayTrustStateProcedure: {
		Attempts: registrationAttemptsPerMinute,
		Window:   time.Minute,
	},
}

// PublicProcedureLimits returns the defensively copied PkiService public
// rate-limit registry consumed by the shared AUTH-4 ladder and GUARD-006-1.
func PublicProcedureLimits() map[string]PublicRateLimit {
	return maps.Clone(publicProcedureLimits)
}
