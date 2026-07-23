package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
)

const maxRefreshRequestTokenBytes = 8 << 10

var (
	errSessionRequestRejected = errors.New("session refresh request rejected")
	errSessionAuthRejected    = errors.New("session refresh rejected")
	errSessionRateLimited     = errors.New("session refresh rate limited")
	errSessionUnavailable     = errors.New("session refresh unavailable")
)

// SessionService implements public refresh-token rotation for ControlService.
type SessionService struct {
	refresh          *auth.RefreshService
	oidc             *auth.OIDCService
	failureLadder    *auth.FailureLadder
	clientIPResolver *auth.ClientIPResolver
	now              func() time.Time
}

// NewSessionService validates the refresh handler and trusted-proxy boundary.
func NewSessionService(
	refresh *auth.RefreshService,
	trustedProxies []netip.Prefix,
	now func() time.Time,
) (*SessionService, error) {
	return newSessionService(refresh, nil, trustedProxies, now)
}

// NewSessionServiceWithOIDC validates both public session boundaries.
func NewSessionServiceWithOIDC(
	refresh *auth.RefreshService,
	oidc *auth.OIDCService,
	trustedProxies []netip.Prefix,
	now func() time.Time,
) (*SessionService, error) {
	if oidc == nil || oidc.ValidateWiring() != nil {
		return nil, errors.New("control: oidc service is not wired")
	}
	return newSessionService(refresh, oidc, trustedProxies, now)
}

func newSessionService(
	refresh *auth.RefreshService,
	oidc *auth.OIDCService,
	trustedProxies []netip.Prefix,
	now func() time.Time,
) (*SessionService, error) {
	if refresh == nil || refresh.ValidateWiring() != nil {
		return nil, errors.New("control: refresh service is not wired")
	}
	if now == nil {
		return nil, errors.New("control: session clock is not wired")
	}
	policies := map[string]auth.RateLimitPolicy{
		powermanagev1connect.ControlServiceRefreshSessionProcedure: refreshRateLimitPolicy(),
	}
	if oidc != nil {
		policies[powermanagev1connect.ControlServiceStartOidcSessionProcedure] = oidcRateLimitPolicy()
		policies[powermanagev1connect.ControlServiceCompleteOidcSessionProcedure] = oidcRateLimitPolicy()
	}
	failureLadder, err := auth.NewFailureLadder(policies)
	if err != nil {
		return nil, fmt.Errorf("control: create refresh failure ladder: %w", err)
	}
	clientIPResolver, err := auth.NewClientIPResolver(trustedProxies)
	if err != nil {
		return nil, fmt.Errorf("control: create client IP resolver: %w", err)
	}
	return &SessionService{
		refresh:          refresh,
		oidc:             oidc,
		failureLadder:    failureLadder,
		clientIPResolver: clientIPResolver,
		now:              now,
	}, nil
}

// RefreshSession rotates the presented token without exposing parser, replay,
// or persistence details.
func (s *SessionService) RefreshSession(
	ctx context.Context,
	request *connect.Request[powermanagev1.RefreshSessionRequest],
) (*connect.Response[powermanagev1.RefreshSessionResponse], error) {
	if err := s.validateWiring(); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errSessionUnavailable)
	}
	if ctx == nil || request == nil || request.Msg == nil ||
		len(request.Msg.GetRefreshToken()) == 0 ||
		len(request.Msg.GetRefreshToken()) > maxRefreshRequestTokenBytes {
		return nil, connect.NewError(connect.CodeInvalidArgument, errSessionRequestRejected)
	}
	clientIP, err := s.resolveClientIP(
		request.Peer().Addr,
		request.Header().Values("X-Forwarded-For"),
	)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errSessionUnavailable)
	}
	rawToken := strings.TrimSpace(request.Msg.GetRefreshToken())
	accountKey := refreshAccountKey(rawToken)
	tokens, rotateErr := s.refresh.Rotate(ctx, rawToken)
	switch {
	case rotateErr == nil:
		return connect.NewResponse(&powermanagev1.RefreshSessionResponse{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
		}), nil
	case errors.Is(rotateErr, auth.ErrRefreshRejected):
		if !s.failureLadder.Allow(auth.AuthenticationAttempt{
			Procedure:  powermanagev1connect.ControlServiceRefreshSessionProcedure,
			ClientIP:   clientIP,
			AccountKey: accountKey,
			Succeeded:  false,
		}, s.now()) {
			return nil, connect.NewError(connect.CodeResourceExhausted, errSessionRateLimited)
		}
		return nil, connect.NewError(connect.CodeUnauthenticated, errSessionAuthRejected)
	default:
		return nil, connect.NewError(connect.CodeUnavailable, errSessionUnavailable)
	}
}

func (s *SessionService) validateWiring() error {
	if s == nil ||
		s.refresh == nil ||
		s.refresh.ValidateWiring() != nil ||
		s.failureLadder == nil ||
		s.clientIPResolver == nil ||
		s.now == nil {
		return errSessionUnavailable
	}
	return nil
}

func (s *SessionService) resolveClientIP(
	peerAddress string,
	forwardedFor []string,
) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(peerAddress)
	if err != nil {
		return netip.Addr{}, errors.New("control: session peer address is invalid")
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, errors.New("control: session peer address is invalid")
	}
	return s.clientIPResolver.Resolve(peer, strings.Join(forwardedFor, ","))
}

func refreshAccountKey(rawToken string) string {
	digest := sha256.Sum256([]byte(rawToken))
	return "refresh-token:" + hex.EncodeToString(digest[:])
}
