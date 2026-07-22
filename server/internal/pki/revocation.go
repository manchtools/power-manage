package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"strings"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/store"
)

const maxLifecycleAuthorizationBytes = 8192

var (
	errLifecycleRequestRejected   = errors.New("certificate lifecycle request rejected")
	errLifecycleAuthRejected      = errors.New("certificate lifecycle authorization rejected")
	errLifecycleRateLimited       = errors.New("certificate lifecycle rate limited")
	errLifecycleTemporarilyFailed = errors.New("certificate lifecycle temporarily unavailable")
)

// LifecycleAuthorizer validates the operator credential carried in transport
// metadata for the certificate-derived device resource. Implementations must
// not derive authority from caller-asserted request identity.
type LifecycleAuthorizer interface {
	AuthorizeCertificateLifecycle(context.Context, string, string, string) error
}

// RevokeAgent terminally revokes the exact currently stored certificate.
func (s *EnrollmentService) RevokeAgent(
	ctx context.Context,
	request *connect.Request[powermanagev1.RevokeAgentRequest],
) (*connect.Response[powermanagev1.RevokeAgentResponse], error) {
	if request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errLifecycleRequestRejected)
	}
	presented, deviceID, err := s.authorizeAgentCertificateLifecycle(
		ctx,
		request.Header().Values("Authorization"),
		request.Peer().Addr,
		request.Msg.GetCertificateDer(),
		powermanagev1connect.PkiServiceRevokeAgentProcedure,
	)
	if err != nil {
		return nil, err
	}
	err = s.eventStore.WithDeviceLifecycleLock(ctx, deviceID, func(lifecycle *store.DeviceLifecycle) error {
		return appendAgentLifecycleEvent(ctx, lifecycle, presented, deviceID, store.DeviceLifecycleRevoked)
	})
	if err := mapLifecycleError(err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&powermanagev1.RevokeAgentResponse{}), nil
}

// ForceRenewAgent revokes the exact current certificate while preserving one
// proof-of-possession renewal transition.
func (s *EnrollmentService) ForceRenewAgent(
	ctx context.Context,
	request *connect.Request[powermanagev1.ForceRenewAgentRequest],
) (*connect.Response[powermanagev1.ForceRenewAgentResponse], error) {
	if request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errLifecycleRequestRejected)
	}
	presented, deviceID, err := s.authorizeAgentCertificateLifecycle(
		ctx,
		request.Header().Values("Authorization"),
		request.Peer().Addr,
		request.Msg.GetCertificateDer(),
		powermanagev1connect.PkiServiceForceRenewAgentProcedure,
	)
	if err != nil {
		return nil, err
	}
	err = s.eventStore.WithDeviceLifecycleLock(ctx, deviceID, func(lifecycle *store.DeviceLifecycle) error {
		return appendAgentLifecycleEvent(ctx, lifecycle, presented, deviceID, store.DeviceLifecycleForceRenewal)
	})
	if err := mapLifecycleError(err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&powermanagev1.ForceRenewAgentResponse{}), nil
}

func (s *EnrollmentService) authorizeAgentCertificateLifecycle(
	ctx context.Context,
	authorizationHeaders []string,
	peerAddress string,
	certificateDER []byte,
	procedure string,
) (*x509.Certificate, string, error) {
	if err := s.validateWiring(); err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, errLifecycleTemporarilyFailed)
	}
	if ctx == nil || len(authorizationHeaders) != 1 || strings.TrimSpace(authorizationHeaders[0]) == "" ||
		len(authorizationHeaders[0]) > maxLifecycleAuthorizationBytes {
		return nil, "", connect.NewError(connect.CodeUnauthenticated, errLifecycleAuthRejected)
	}
	if err := ctx.Err(); err != nil {
		return nil, "", mapLifecycleError(err)
	}
	source, err := enrollmentSource(peerAddress)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, errLifecycleTemporarilyFailed)
	}
	if !s.lifecycleLimiter.Allow(source+"\x00"+procedure, s.now()) {
		return nil, "", connect.NewError(connect.CodeResourceExhausted, errLifecycleRateLimited)
	}
	presented, deviceID, err := parseRenewalCertificate(certificateDER)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInvalidArgument, errLifecycleRequestRejected)
	}
	if err := s.lifecycleAuthorizer.AuthorizeCertificateLifecycle(ctx, authorizationHeaders[0], procedure, deviceID); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, "", mapLifecycleError(contextErr)
		}
		return nil, "", connect.NewError(connect.CodeUnauthenticated, errLifecycleAuthRejected)
	}
	return presented, deviceID, nil
}

func appendAgentLifecycleEvent(
	ctx context.Context,
	lifecycle *store.DeviceLifecycle,
	presented *x509.Certificate,
	deviceID string,
	nextState store.DeviceLifecycleState,
) error {
	fingerprint := sha256.Sum256(presented.Raw)
	current, err := lifecycle.Device(ctx)
	if err != nil {
		if store.IsNotFound(err) {
			return errLifecycleAuthRejected
		}
		return err
	}
	allowedState := current.LifecycleState == store.DeviceLifecycleActive ||
		(nextState == store.DeviceLifecycleRevoked && current.LifecycleState == store.DeviceLifecycleForceRenewal)
	if subtle.ConstantTimeCompare(current.CertificateFingerprint[:], fingerprint[:]) != 1 ||
		!bytes.Equal(current.CertificateDER, presented.Raw) || !allowedState {
		return errLifecycleAuthRejected
	}
	var event store.Event
	switch nextState {
	case store.DeviceLifecycleRevoked:
		event, err = store.AgentCertificateRevokedEvent(deviceID, presented.Raw)
	case store.DeviceLifecycleForceRenewal:
		event, err = store.AgentCertificateForceRenewalRequiredEvent(deviceID, presented.Raw)
	default:
		return errors.New("pki: unsupported lifecycle transition")
	}
	if err != nil {
		return err
	}
	return lifecycle.AppendEvent(ctx, event, current.ProjectionVersion)
}

func mapLifecycleError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, errLifecycleAuthRejected):
		return connect.NewError(connect.CodeUnauthenticated, errLifecycleAuthRejected)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, context.DeadlineExceeded)
	default:
		return connect.NewError(connect.CodeInternal, errLifecycleTemporarilyFailed)
	}
}
