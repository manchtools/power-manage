package pki

import (
	"bytes"
	"context"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"slices"
	"time"

	"connectrpc.com/connect"
	connectvalidate "connectrpc.com/validate"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/contract/seal"
	"github.com/manchtools/power-manage/contract/sign"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	agentCertificateLifetime  = 365 * 24 * time.Hour
	certificateClockSkew      = 5 * time.Minute
	certificateSerialBytes    = 16
	maxEnrollmentMessageBytes = 128 << 10
)

var (
	subjectAlternativeNameOID      = asn1.ObjectIdentifier{2, 5, 29, 17}
	errEnrollmentRequestRejected   = errors.New("enrollment request rejected")
	errEnrollmentAuthRejected      = errors.New("enrollment authorization rejected")
	errEnrollmentRateLimited       = errors.New("enrollment rate limited")
	errEnrollmentTemporarilyFailed = errors.New("enrollment temporarily unavailable")
)

// EnrollmentService implements the public certificate-lifecycle service.
type EnrollmentService struct {
	tokens              *RegistrationTokens
	eventStore          *store.Store
	authorities         *Authorities
	renewalLimiter      *registrationRateLimiter
	lifecycleAuthorizer LifecycleAuthorizer
	lifecycleLimiter    *registrationRateLimiter
	rotationManager     *RotationManager
	random              io.Reader
	now                 func() time.Time
}

// NewEnrollmentService validates every enrollment and lifecycle dependency.
func NewEnrollmentService(
	tokens *RegistrationTokens,
	eventStore *store.Store,
	authorities *Authorities,
	lifecycleAuthorizer LifecycleAuthorizer,
) (*EnrollmentService, error) {
	if tokens == nil {
		return nil, errors.New("pki: nil enrollment token service")
	}
	if eventStore == nil {
		return nil, errors.New("pki: nil enrollment event store")
	}
	if tokens.eventStore != eventStore {
		return nil, errors.New("pki: enrollment token service and event store differ")
	}
	if authorities == nil || authorities.agentCA.certificate == nil || authorities.agentCA.signer == nil ||
		authorities.gatewayCA.certificate == nil || authorities.gatewayCA.signer == nil {
		return nil, errors.New("pki: enrollment certificate authorities are not wired")
	}
	if interfaceNil(lifecycleAuthorizer) {
		return nil, errors.New("pki: lifecycle authorizer is not wired")
	}
	return &EnrollmentService{
		tokens:              tokens,
		eventStore:          eventStore,
		authorities:         authorities,
		renewalLimiter:      newRegistrationRateLimiter(),
		lifecycleAuthorizer: lifecycleAuthorizer,
		lifecycleLimiter:    newRegistrationRateLimiter(),
		random:              cryptorand.Reader,
		now:                 time.Now,
	}, nil
}

// NewEnrollmentHTTPHandler installs request and response Protovalidate on the
// generated Connect handler. A nil service remains a fail-closed handler whose
// method returns an internal error instead of panicking.
func NewEnrollmentHTTPHandler(service *EnrollmentService) (string, http.Handler) {
	interceptor := connectvalidate.NewInterceptor(connectvalidate.WithValidateResponses())
	return powermanagev1connect.NewPkiServiceHandler(
		service,
		connect.WithInterceptors(interceptor),
		connect.WithReadMaxBytes(maxEnrollmentMessageBytes),
	)
}

func (s *EnrollmentService) validateWiring() error {
	if s == nil || s.tokens == nil || s.eventStore == nil || s.authorities == nil || s.renewalLimiter == nil ||
		interfaceNil(s.lifecycleAuthorizer) || s.lifecycleLimiter == nil || s.random == nil || s.now == nil {
		return errors.New("pki: enrollment service is not wired")
	}
	if s.tokens.eventStore != s.eventStore || s.authorities.agentCA.certificate == nil || s.authorities.agentCA.signer == nil ||
		s.authorities.gatewayCA.certificate == nil || s.authorities.gatewayCA.signer == nil {
		return errors.New("pki: enrollment service dependencies are inconsistent")
	}
	return nil
}

func interfaceNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// EnrollAgent validates device-generated proof, authorizes the registration
// token, then invokes the agent CA and persists the issued identity.
func (s *EnrollmentService) EnrollAgent(
	ctx context.Context,
	request *connect.Request[powermanagev1.EnrollAgentRequest],
) (*connect.Response[powermanagev1.EnrollAgentResponse], error) {
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
	if err := seal.ValidateX25519PublicKey(request.Msg.GetSealingPublicKey()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errEnrollmentRequestRejected)
	}
	source, err := enrollmentSource(request.Peer().Addr)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errEnrollmentTemporarilyFailed)
	}
	var grant RegistrationTokenGrant
	var deviceID string
	var certificateDER, certificateAuthorityDER []byte
	var agentTrust, gatewayTrust AuthoritySnapshot
	err = s.withIssuanceFences(ctx, func(agent, gateway AuthoritySnapshot) error {
		agentTrust, gatewayTrust = agent, gateway
		var consumeErr error
		grant, consumeErr = s.tokens.Consume(ctx, source, request.Msg.GetRegistrationToken(), RegistrationTokenPurposeAgent)
		if consumeErr != nil {
			return consumeErr
		}
		deviceID, consumeErr = newEnrollmentDeviceID(s.now(), s.random)
		if consumeErr != nil {
			return consumeErr
		}
		return s.eventStore.WithDeviceLifecycleLock(ctx, deviceID, func(lifecycle *store.DeviceLifecycle) error {
			var issueErr error
			certificateDER, certificateAuthorityDER, issueErr = s.authorities.issueAgentCertificate(
				csr.PublicKey,
				deviceID,
				s.now(),
				s.random,
			)
			if issueErr != nil {
				return issueErr
			}
			event, eventErr := store.AgentEnrolledEvent(
				deviceID,
				certificateDER,
				request.Msg.GetSealingPublicKey(),
				grant.TokenID,
				grant.Owner,
			)
			if eventErr != nil {
				return eventErr
			}
			return lifecycle.AppendEvent(ctx, event, 0)
		})
	})
	if err != nil {
		return nil, mapEnrollmentTokenError(err)
	}
	return connect.NewResponse(&powermanagev1.EnrollAgentResponse{
		CertificateDer:                 certificateDER,
		CertificateAuthorityDer:        certificateAuthorityDER,
		GatewayCertificateAuthorityDer: slices.Clone(gatewayTrust.IssuingRootDER),
		AgentTrustBundle:               trustBundleFromSnapshot(agentTrust),
		GatewayTrustBundle:             trustBundleFromSnapshot(gatewayTrust),
	}), nil
}

func parseEnrollmentCSR(der []byte) (*x509.CertificateRequest, error) {
	ownedDER := slices.Clone(der)
	request, err := x509.ParseCertificateRequest(ownedDER)
	if err != nil {
		return nil, fmt.Errorf("pki: parse enrollment CSR: %w", err)
	}
	if !bytes.Equal(request.Raw, ownedDER) {
		return nil, errors.New("pki: enrollment CSR contains trailing data")
	}
	if err := request.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: verify enrollment CSR signature: %w", err)
	}
	if enrollmentCSRHasSAN(request) {
		return nil, errors.New("pki: enrollment CSR contains a subject alternative name")
	}
	if err := sign.ValidateSigningKey(request.PublicKey); err != nil {
		return nil, fmt.Errorf("pki: validate enrollment CSR public key: %w", err)
	}
	return request, nil
}

func enrollmentCSRHasSAN(request *x509.CertificateRequest) bool {
	if request == nil || len(request.DNSNames) != 0 || len(request.EmailAddresses) != 0 || len(request.IPAddresses) != 0 || len(request.URIs) != 0 {
		return true
	}
	for _, extension := range request.Extensions {
		if extension.Id.Equal(subjectAlternativeNameOID) {
			return true
		}
	}
	return false
}

func enrollmentSource(address string) (string, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("pki: parse enrollment peer address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", errors.New("pki: enrollment peer address is not an IP")
	}
	return ip.String(), nil
}

func newEnrollmentDeviceID(now time.Time, random io.Reader) (string, error) {
	if random == nil {
		return "", errors.New("pki: nil enrollment random source")
	}
	entropy := make([]byte, registrationTokenEntropyBytes)
	if _, err := io.ReadFull(random, entropy); err != nil {
		return "", fmt.Errorf("pki: generate enrollment device ID: %w", err)
	}
	return newRegistrationTokenID(now, entropy)
}

func (a *Authorities) issueAgentCertificate(
	publicKey crypto.PublicKey,
	deviceID string,
	now time.Time,
	random io.Reader,
) ([]byte, []byte, error) {
	authority, ok := a.currentAuthority(store.CertificateClassAgent)
	if !ok {
		return nil, nil, errors.New("pki: agent certificate authority is not wired")
	}
	if err := sign.ValidateSigningKey(publicKey); err != nil {
		return nil, nil, fmt.Errorf("pki: validate agent certificate public key: %w", err)
	}
	if !identity.IsCanonicalULID(deviceID) {
		return nil, nil, errors.New("pki: agent certificate device ID is not a canonical ULID")
	}
	if random == nil {
		return nil, nil, errors.New("pki: nil certificate random source")
	}
	serialBytes := make([]byte, certificateSerialBytes)
	if _, err := io.ReadFull(random, serialBytes); err != nil {
		return nil, nil, fmt.Errorf("pki: generate agent certificate serial: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	notBefore := now.UTC().Truncate(time.Second).Add(-certificateClockSkew)
	notAfter := notBefore.Add(agentCertificateLifetime)
	if notBefore.Before(authority.certificate.NotBefore) || notAfter.After(authority.certificate.NotAfter) {
		return nil, nil, errors.New("pki: agent CA validity does not cover the certificate lifetime")
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: marshal agent certificate public key: %w", err)
	}
	keyID := sha256.Sum256(publicKeyDER)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          append([]byte(nil), keyID[:20]...),
	}
	if err := identity.StampCertificateIdentity(template, identity.AgentClass, deviceID); err != nil {
		return nil, nil, fmt.Errorf("pki: stamp agent certificate identity: %w", err)
	}
	certificateDER, err := x509.CreateCertificate(random, template, authority.certificate, publicKey, authority.signer)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: issue agent certificate: %w", err)
	}
	return certificateDER, slices.Clone(authority.certificate.Raw), nil
}
