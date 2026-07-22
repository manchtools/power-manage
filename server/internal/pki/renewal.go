package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/contract/seal"
	"github.com/manchtools/power-manage/contract/sign"
	"github.com/manchtools/power-manage/server/internal/store"
)

var (
	errRenewalRequestRejected   = errors.New("renewal request rejected")
	errRenewalAuthRejected      = errors.New("renewal authorization rejected")
	errRenewalRateLimited       = errors.New("renewal rate limited")
	errRenewalTemporarilyFailed = errors.New("renewal temporarily unavailable")
)

// RenewAgent proves continuity from the stored certificate and enrolled key,
// then signs and persists one serialized supersession transaction.
func (s *EnrollmentService) RenewAgent(
	ctx context.Context,
	request *connect.Request[powermanagev1.RenewAgentRequest],
) (*connect.Response[powermanagev1.RenewAgentResponse], error) {
	if err := s.validateWiring(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errRenewalTemporarilyFailed)
	}
	if ctx == nil || request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errRenewalRequestRejected)
	}
	presented, deviceID, err := parseRenewalCertificate(request.Msg.GetCertificateDer())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errRenewalRequestRejected)
	}
	csr, err := parseEnrollmentCSR(request.Msg.GetCertificateSigningRequestDer())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errRenewalRequestRejected)
	}
	if err := seal.ValidateX25519PublicKey(request.Msg.GetSealingPublicKey()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errRenewalRequestRejected)
	}
	if !renewalPublicKeysEqual(presented.PublicKey, csr.PublicKey) {
		return nil, connect.NewError(connect.CodeUnauthenticated, errRenewalAuthRejected)
	}
	source, err := enrollmentSource(request.Peer().Addr)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errRenewalTemporarilyFailed)
	}
	if !s.renewalLimiter.Allow(source, s.now()) {
		return nil, connect.NewError(connect.CodeResourceExhausted, errRenewalRateLimited)
	}

	presentedFingerprint := sha256.Sum256(presented.Raw)
	var certificateDER, certificateAuthorityDER []byte
	err = s.eventStore.WithDeviceLifecycleLock(ctx, deviceID, func(lifecycle *store.DeviceLifecycle) error {
		current, readErr := lifecycle.Device(ctx)
		if readErr != nil {
			if store.IsNotFound(readErr) {
				return errRenewalAuthRejected
			}
			return readErr
		}
		if current.LifecycleState == store.DeviceLifecycleRevoked {
			return errRenewalAuthRejected
		}
		if subtle.ConstantTimeCompare(current.CertificateFingerprint[:], presentedFingerprint[:]) != 1 ||
			!bytes.Equal(current.CertificateDER, presented.Raw) {
			currentFingerprint := sha256.Sum256(current.CertificateDER)
			if current.LifecycleState != store.DeviceLifecycleActive ||
				subtle.ConstantTimeCompare(current.CertificateFingerprint[:], currentFingerprint[:]) != 1 ||
				!bytes.Equal(current.PreviousCertificateDER, presented.Raw) ||
				!bytes.Equal(current.SealingPublicKey, request.Msg.GetSealingPublicKey()) {
				return errRenewalAuthRejected
			}
			currentCertificate, currentDeviceID, parseErr := parseRenewalCertificate(current.CertificateDER)
			if parseErr != nil {
				return parseErr
			}
			if currentDeviceID != deviceID || !renewalPublicKeysEqual(currentCertificate.PublicKey, csr.PublicKey) {
				return errRenewalAuthRejected
			}
			certificateDER = bytes.Clone(current.CertificateDER)
			certificateAuthorityDER = bytes.Clone(s.authorities.agentCA.certificate.Raw)
			return nil
		}
		certificateDER, certificateAuthorityDER, readErr = s.authorities.issueAgentCertificate(
			csr.PublicKey,
			deviceID,
			s.now(),
			s.random,
		)
		if readErr != nil {
			return readErr
		}
		event, eventErr := store.AgentCertificateRenewedEvent(
			deviceID,
			certificateDER,
			request.Msg.GetSealingPublicKey(),
			presented.Raw,
		)
		if eventErr != nil {
			return eventErr
		}
		return lifecycle.AppendEvent(ctx, event, current.ProjectionVersion)
	})
	if err != nil {
		switch {
		case errors.Is(err, errRenewalAuthRejected):
			return nil, connect.NewError(connect.CodeUnauthenticated, errRenewalAuthRejected)
		case errors.Is(err, context.Canceled):
			return nil, connect.NewError(connect.CodeCanceled, context.Canceled)
		case errors.Is(err, context.DeadlineExceeded):
			return nil, connect.NewError(connect.CodeDeadlineExceeded, context.DeadlineExceeded)
		default:
			return nil, connect.NewError(connect.CodeInternal, errRenewalTemporarilyFailed)
		}
	}
	return connect.NewResponse(&powermanagev1.RenewAgentResponse{
		CertificateDer:                 certificateDER,
		CertificateAuthorityDer:        certificateAuthorityDER,
		GatewayCertificateAuthorityDer: bytes.Clone(s.authorities.gatewayCA.certificate.Raw),
	}), nil
}

func parseRenewalCertificate(der []byte) (*x509.Certificate, string, error) {
	certificate, err := parseExactCertificate(der)
	if err != nil {
		return nil, "", fmt.Errorf("pki: parse renewal certificate: %w", err)
	}
	class, deviceID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil {
		return nil, "", fmt.Errorf("pki: parse renewal certificate identity: %w", err)
	}
	if class != identity.AgentClass {
		return nil, "", fmt.Errorf("pki: renewal certificate class %q is not agent", class)
	}
	if certificate.IsCA || !certificate.BasicConstraintsValid ||
		certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		!certificate.NotAfter.After(certificate.NotBefore) {
		return nil, "", errors.New("pki: renewal certificate has an invalid agent profile")
	}
	if err := sign.ValidateSigningKey(certificate.PublicKey); err != nil {
		return nil, "", fmt.Errorf("pki: validate renewal certificate key: %w", err)
	}
	return certificate, deviceID, nil
}

func renewalPublicKeysEqual(first, second crypto.PublicKey) bool {
	firstDER, err := x509.MarshalPKIXPublicKey(first)
	if err != nil {
		return false
	}
	secondDER, err := x509.MarshalPKIXPublicKey(second)
	return err == nil && bytes.Equal(firstDER, secondDER)
}
