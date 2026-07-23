package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/contract/sign"
	"github.com/manchtools/power-manage/server/internal/store"
)

const gatewayCertificateLifetime = 45 * 24 * time.Hour

// EnrollGateway authorizes a gateway-purpose token and persists one fresh,
// control-addressed per-boot gateway identity.
func (s *EnrollmentService) EnrollGateway(
	ctx context.Context,
	request *connect.Request[powermanagev1.EnrollGatewayRequest],
) (*connect.Response[powermanagev1.EnrollGatewayResponse], error) {
	if err := s.validateWiring(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errEnrollmentTemporarilyFailed)
	}
	if ctx == nil || request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errEnrollmentRequestRejected)
	}
	csr, err := parseEnrollmentCSR(request.Msg.GetCertificateSigningRequestDer())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errEnrollmentRequestRejected)
	}
	source, err := enrollmentSource(request.Peer().Addr)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errEnrollmentTemporarilyFailed)
	}
	grant, err := s.tokens.Consume(ctx, source, request.Msg.GetRegistrationToken(), RegistrationTokenPurposeGateway)
	if err != nil {
		return nil, mapEnrollmentTokenError(err)
	}
	gatewayID, err := newEnrollmentDeviceID(s.now(), s.random)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errEnrollmentTemporarilyFailed)
	}
	var certificateDER, certificateAuthorityDER []byte
	err = s.eventStore.WithDeviceLifecycleLock(ctx, gatewayID, func(lifecycle *store.DeviceLifecycle) error {
		var issueErr error
		certificateDER, certificateAuthorityDER, issueErr = s.authorities.issueGatewayCertificate(
			csr.PublicKey,
			gatewayID,
			grant.DNSNames,
			s.now(),
			s.random,
		)
		if issueErr != nil {
			return issueErr
		}
		event, eventErr := store.GatewayEnrolledEvent(
			gatewayID,
			certificateDER,
			grant.TokenID,
			grant.Owner,
			grant.DNSNames,
		)
		if eventErr != nil {
			return eventErr
		}
		return lifecycle.AppendGatewayEvent(ctx, event, 0)
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errEnrollmentTemporarilyFailed)
	}
	return connect.NewResponse(&powermanagev1.EnrollGatewayResponse{
		CertificateDer: certificateDER, CertificateAuthorityDer: certificateAuthorityDER,
	}), nil
}

// RenewGateway requires the exact stored fingerprint and proof of possession,
// serializing the successor and predecessor revocation in one transaction.
func (s *EnrollmentService) RenewGateway(
	ctx context.Context,
	request *connect.Request[powermanagev1.RenewGatewayRequest],
) (*connect.Response[powermanagev1.RenewGatewayResponse], error) {
	if err := s.validateWiring(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errRenewalTemporarilyFailed)
	}
	if ctx == nil || request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errRenewalRequestRejected)
	}
	presented, gatewayID, err := parseGatewayRenewalCertificate(request.Msg.GetCertificateDer())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errRenewalRequestRejected)
	}
	csr, err := parseEnrollmentCSR(request.Msg.GetCertificateSigningRequestDer())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errRenewalRequestRejected)
	}
	if !renewalPublicKeysEqual(presented.PublicKey, csr.PublicKey) {
		return nil, connect.NewError(connect.CodeUnauthenticated, errRenewalAuthRejected)
	}
	source, err := enrollmentSource(request.Peer().Addr)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errRenewalTemporarilyFailed)
	}
	if !s.renewalLimiter.Allow(source+"\x00gateway", s.now()) {
		return nil, connect.NewError(connect.CodeResourceExhausted, errRenewalRateLimited)
	}
	presentedFingerprint := sha256.Sum256(presented.Raw)
	var certificateDER, certificateAuthorityDER []byte
	err = s.eventStore.WithDeviceLifecycleLock(ctx, gatewayID, func(lifecycle *store.DeviceLifecycle) error {
		current, readErr := lifecycle.Gateway(ctx)
		if readErr != nil {
			if store.IsNotFound(readErr) {
				return errRenewalAuthRejected
			}
			return readErr
		}
		if current.LifecycleState != store.GatewayLifecycleActive {
			return errRenewalAuthRejected
		}
		if subtle.ConstantTimeCompare(current.CertificateFingerprint[:], presentedFingerprint[:]) != 1 ||
			!bytes.Equal(current.CertificateDER, presented.Raw) {
			currentFingerprint := sha256.Sum256(current.CertificateDER)
			if subtle.ConstantTimeCompare(current.CertificateFingerprint[:], currentFingerprint[:]) != 1 ||
				!bytes.Equal(current.PreviousCertificateDER, presented.Raw) {
				return errRenewalAuthRejected
			}
			currentCertificate, currentID, parseErr := parseGatewayRenewalCertificate(current.CertificateDER)
			if parseErr != nil || currentID != gatewayID || !renewalPublicKeysEqual(currentCertificate.PublicKey, csr.PublicKey) {
				return errRenewalAuthRejected
			}
			certificateDER = bytes.Clone(current.CertificateDER)
			certificateAuthorityDER = bytes.Clone(s.authorities.gatewayCA.certificate.Raw)
			return nil
		}
		certificateDER, certificateAuthorityDER, readErr = s.authorities.issueGatewayCertificate(
			csr.PublicKey,
			gatewayID,
			current.DNSNames,
			s.now(),
			s.random,
		)
		if readErr != nil {
			return readErr
		}
		event, eventErr := store.GatewayCertificateRenewedEvent(gatewayID, certificateDER, presented.Raw)
		if eventErr != nil {
			return eventErr
		}
		return lifecycle.AppendGatewayEvent(ctx, event, current.ProjectionVersion)
	})
	if err != nil {
		return nil, mapRenewalError(err)
	}
	return connect.NewResponse(&powermanagev1.RenewGatewayResponse{
		CertificateDer: certificateDER, CertificateAuthorityDer: certificateAuthorityDER,
	}), nil
}

// RevokeGateway terminally revokes the exact currently stored gateway cert.
func (s *EnrollmentService) RevokeGateway(
	ctx context.Context,
	request *connect.Request[powermanagev1.RevokeGatewayRequest],
) (*connect.Response[powermanagev1.RevokeGatewayResponse], error) {
	if request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errLifecycleRequestRejected)
	}
	presented, gatewayID, err := s.authorizeGatewayLifecycle(
		ctx,
		request.Header().Values("Authorization"),
		request.Peer().Addr,
		request.Msg.GetCertificateDer(),
	)
	if err != nil {
		return nil, err
	}
	err = s.eventStore.WithDeviceLifecycleLock(ctx, gatewayID, func(lifecycle *store.DeviceLifecycle) error {
		current, readErr := lifecycle.Gateway(ctx)
		if readErr != nil {
			if store.IsNotFound(readErr) {
				return errLifecycleAuthRejected
			}
			return readErr
		}
		fingerprint := sha256.Sum256(presented.Raw)
		if current.LifecycleState != store.GatewayLifecycleActive ||
			subtle.ConstantTimeCompare(current.CertificateFingerprint[:], fingerprint[:]) != 1 ||
			!bytes.Equal(current.CertificateDER, presented.Raw) {
			return errLifecycleAuthRejected
		}
		event, eventErr := store.GatewayCertificateRevokedEvent(gatewayID, presented.Raw)
		if eventErr != nil {
			return eventErr
		}
		return lifecycle.AppendGatewayEvent(ctx, event, current.ProjectionVersion)
	})
	if err := mapLifecycleError(err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&powermanagev1.RevokeGatewayResponse{}), nil
}

func (s *EnrollmentService) authorizeGatewayLifecycle(
	ctx context.Context,
	authorizationHeaders []string,
	peerAddress string,
	certificateDER []byte,
) (*x509.Certificate, string, error) {
	if err := s.validateWiring(); err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, errLifecycleTemporarilyFailed)
	}
	if ctx == nil || len(authorizationHeaders) != 1 || strings.TrimSpace(authorizationHeaders[0]) == "" || len(authorizationHeaders[0]) > maxLifecycleAuthorizationBytes {
		return nil, "", connect.NewError(connect.CodeUnauthenticated, errLifecycleAuthRejected)
	}
	if err := ctx.Err(); err != nil {
		return nil, "", mapLifecycleError(err)
	}
	source, err := enrollmentSource(peerAddress)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, errLifecycleTemporarilyFailed)
	}
	procedure := powermanagev1connect.PkiServiceRevokeGatewayProcedure
	if !s.lifecycleLimiter.Allow(source+"\x00"+procedure, s.now()) {
		return nil, "", connect.NewError(connect.CodeResourceExhausted, errLifecycleRateLimited)
	}
	presented, gatewayID, err := parseGatewayRenewalCertificate(certificateDER)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInvalidArgument, errLifecycleRequestRejected)
	}
	if err := s.lifecycleAuthorizer.AuthorizeCertificateLifecycle(ctx, authorizationHeaders[0], procedure, gatewayID); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, "", mapLifecycleError(contextErr)
		}
		return nil, "", connect.NewError(connect.CodeUnauthenticated, errLifecycleAuthRejected)
	}
	return presented, gatewayID, nil
}

func mapEnrollmentTokenError(err error) error {
	switch {
	case errors.Is(err, ErrRegistrationRateLimited):
		return connect.NewError(connect.CodeResourceExhausted, errEnrollmentRateLimited)
	case errors.Is(err, ErrInvalidRegistrationToken):
		return connect.NewError(connect.CodeUnauthenticated, errEnrollmentAuthRejected)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, context.DeadlineExceeded)
	default:
		return connect.NewError(connect.CodeInternal, errEnrollmentTemporarilyFailed)
	}
}

func mapRenewalError(err error) error {
	switch {
	case errors.Is(err, errRenewalAuthRejected):
		return connect.NewError(connect.CodeUnauthenticated, errRenewalAuthRejected)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, context.DeadlineExceeded)
	default:
		return connect.NewError(connect.CodeInternal, errRenewalTemporarilyFailed)
	}
}

func parseGatewayRenewalCertificate(der []byte) (*x509.Certificate, string, error) {
	certificate, err := parseExactCertificate(der)
	if err != nil {
		return nil, "", fmt.Errorf("pki: parse gateway renewal certificate: %w", err)
	}
	class, gatewayID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil || class != identity.GatewayClass {
		return nil, "", errors.New("pki: gateway renewal certificate identity is invalid")
	}
	if certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		certificate.NotAfter.Sub(certificate.NotBefore) != gatewayCertificateLifetime ||
		!exactGatewayEKUs(certificate.ExtKeyUsage) || len(certificate.UnknownExtKeyUsage) != 0 ||
		len(certificate.DNSNames) == 0 || len(certificate.EmailAddresses) != 0 || len(certificate.IPAddresses) != 0 {
		return nil, "", errors.New("pki: gateway renewal certificate profile is invalid")
	}
	if err := identity.RequireDNSAndURISANs(certificate); err != nil {
		return nil, "", fmt.Errorf("pki: gateway renewal certificate profile is invalid: %w", err)
	}
	if err := sign.ValidateSigningKey(certificate.PublicKey); err != nil {
		return nil, "", fmt.Errorf("pki: validate gateway renewal certificate key: %w", err)
	}
	return certificate, gatewayID, nil
}

func (a *Authorities) issueGatewayCertificate(
	publicKey crypto.PublicKey,
	gatewayID string,
	dnsNames []string,
	now time.Time,
	random io.Reader,
) ([]byte, []byte, error) {
	if a == nil || a.gatewayCA.certificate == nil || a.gatewayCA.signer == nil {
		return nil, nil, errors.New("pki: gateway certificate authority is not wired")
	}
	if err := sign.ValidateSigningKey(publicKey); err != nil {
		return nil, nil, fmt.Errorf("pki: validate gateway certificate public key: %w", err)
	}
	if !identity.IsCanonicalULID(gatewayID) || len(dnsNames) == 0 || random == nil {
		return nil, nil, errors.New("pki: gateway certificate input is invalid")
	}
	serialBytes := make([]byte, certificateSerialBytes)
	if _, err := io.ReadFull(random, serialBytes); err != nil {
		return nil, nil, fmt.Errorf("pki: generate gateway certificate serial: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	notBefore := now.UTC().Truncate(time.Second).Add(-certificateClockSkew)
	notAfter := notBefore.Add(gatewayCertificateLifetime)
	if notBefore.Before(a.gatewayCA.certificate.NotBefore) || notAfter.After(a.gatewayCA.certificate.NotAfter) {
		return nil, nil, errors.New("pki: gateway CA validity does not cover the certificate lifetime")
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: marshal gateway certificate public key: %w", err)
	}
	keyID := sha256.Sum256(publicKeyDER)
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, SubjectKeyId: bytes.Clone(keyID[:20]), DNSNames: slices.Clone(dnsNames),
	}
	if err := identity.StampCertificateIdentity(template, identity.GatewayClass, gatewayID); err != nil {
		return nil, nil, fmt.Errorf("pki: stamp gateway certificate identity: %w", err)
	}
	certificateDER, err := x509.CreateCertificate(random, template, a.gatewayCA.certificate, publicKey, a.gatewayCA.signer)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: issue gateway certificate: %w", err)
	}
	return certificateDER, bytes.Clone(a.gatewayCA.certificate.Raw), nil
}

func exactGatewayEKUs(usages []x509.ExtKeyUsage) bool {
	return len(usages) == 2 && slices.Contains(usages, x509.ExtKeyUsageServerAuth) && slices.Contains(usages, x509.ExtKeyUsageClientAuth)
}
