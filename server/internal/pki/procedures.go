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
}

// PublicProcedureLimits returns the defensively copied PkiService public
// rate-limit registry consumed by the shared AUTH-4 ladder and GUARD-006-1.
func PublicProcedureLimits() map[string]PublicRateLimit {
	return maps.Clone(publicProcedureLimits)
}
