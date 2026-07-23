package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
)

const (
	maxOIDCProviderSlugBytes = 64
	maxOIDCRedirectURIBytes  = 2048
	maxOIDCStateBytes        = 256
	maxOIDCCodeBytes         = 4096
)

var (
	errOIDCRequestRejected = errors.New("oidc sign-in request rejected")
	errOIDCAuthRejected    = errors.New("oidc sign-in rejected")
	errOIDCRateLimited     = errors.New("oidc sign-in rate limited")
	errOIDCUnavailable     = errors.New("oidc sign-in unavailable")
)

// StartOidcSession creates one server-bound authorization request.
func (s *SessionService) StartOidcSession(
	ctx context.Context,
	request *connect.Request[powermanagev1.StartOidcSessionRequest],
) (*connect.Response[powermanagev1.StartOidcSessionResponse], error) {
	if err := s.validateOIDCWiring(); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errOIDCUnavailable)
	}
	if ctx == nil || request == nil || request.Msg == nil ||
		len(request.Msg.GetProviderSlug()) == 0 ||
		len(request.Msg.GetProviderSlug()) > maxOIDCProviderSlugBytes ||
		len(request.Msg.GetRedirectUri()) == 0 ||
		len(request.Msg.GetRedirectUri()) > maxOIDCRedirectURIBytes {
		return nil, connect.NewError(connect.CodeInvalidArgument, errOIDCRequestRejected)
	}
	clientIP, err := s.resolveClientIP(
		request.Peer().Addr,
		request.Header().Values("X-Forwarded-For"),
	)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errOIDCUnavailable)
	}
	providerSlug := strings.TrimSpace(request.Msg.GetProviderSlug())
	authorizationURL, startErr := s.oidc.Start(ctx, providerSlug, request.Msg.GetRedirectUri())
	switch {
	case startErr == nil:
		return connect.NewResponse(&powermanagev1.StartOidcSessionResponse{
			AuthorizationUrl: authorizationURL,
		}), nil
	case errors.Is(startErr, auth.ErrOIDCRejected):
		if !s.failureLadder.Allow(auth.AuthenticationAttempt{
			Procedure:  powermanagev1connect.ControlServiceStartOidcSessionProcedure,
			ClientIP:   clientIP,
			AccountKey: "oidc-provider:" + providerSlug,
			Succeeded:  false,
		}, s.now()) {
			return nil, connect.NewError(connect.CodeResourceExhausted, errOIDCRateLimited)
		}
		return nil, connect.NewError(connect.CodeUnauthenticated, errOIDCAuthRejected)
	default:
		return nil, connect.NewError(connect.CodeUnavailable, errOIDCUnavailable)
	}
}

// CompleteOidcSession consumes one authorization request and returns a normal
// rotating session without exposing provider or claim validation details.
func (s *SessionService) CompleteOidcSession(
	ctx context.Context,
	request *connect.Request[powermanagev1.CompleteOidcSessionRequest],
) (*connect.Response[powermanagev1.CompleteOidcSessionResponse], error) {
	if err := s.validateOIDCWiring(); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errOIDCUnavailable)
	}
	if ctx == nil || request == nil || request.Msg == nil ||
		len(request.Msg.GetState()) == 0 ||
		len(request.Msg.GetState()) > maxOIDCStateBytes ||
		len(request.Msg.GetCode()) == 0 ||
		len(request.Msg.GetCode()) > maxOIDCCodeBytes {
		return nil, connect.NewError(connect.CodeInvalidArgument, errOIDCRequestRejected)
	}
	clientIP, err := s.resolveClientIP(
		request.Peer().Addr,
		request.Header().Values("X-Forwarded-For"),
	)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errOIDCUnavailable)
	}
	state := request.Msg.GetState()
	tokens, completeErr := s.oidc.Complete(ctx, state, request.Msg.GetCode())
	switch {
	case completeErr == nil:
		return connect.NewResponse(&powermanagev1.CompleteOidcSessionResponse{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
		}), nil
	case errors.Is(completeErr, auth.ErrOIDCRejected):
		if !s.failureLadder.Allow(auth.AuthenticationAttempt{
			Procedure:  powermanagev1connect.ControlServiceCompleteOidcSessionProcedure,
			ClientIP:   clientIP,
			AccountKey: oidcStateAccountKey(state),
			Succeeded:  false,
		}, s.now()) {
			return nil, connect.NewError(connect.CodeResourceExhausted, errOIDCRateLimited)
		}
		return nil, connect.NewError(connect.CodeUnauthenticated, errOIDCAuthRejected)
	default:
		return nil, connect.NewError(connect.CodeUnavailable, errOIDCUnavailable)
	}
}

func (s *SessionService) validateOIDCWiring() error {
	if err := s.validateWiring(); err != nil ||
		s.oidc == nil ||
		s.oidc.ValidateWiring() != nil {
		return errOIDCUnavailable
	}
	return nil
}

func oidcStateAccountKey(state string) string {
	digest := sha256.Sum256([]byte(state))
	return "oidc-state:" + hex.EncodeToString(digest[:])
}
