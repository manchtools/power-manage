package pki

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

func newPublicFailureLadder() (*auth.FailureLadder, error) {
	limits := PublicProcedureLimits()
	policies := make(map[string]auth.RateLimitPolicy, len(limits))
	for procedure, limit := range limits {
		failureLimit := auth.FailureLimit{
			Attempts: limit.Attempts,
			Window:   limit.Window,
		}
		policies[procedure] = auth.RateLimitPolicy{
			PerIP:      failureLimit,
			PerAccount: failureLimit,
		}
	}
	return auth.NewFailureLadder(policies)
}

func (s *EnrollmentService) resolvePublicClientIP(peerAddress string, forwardedFor []string) (netip.Addr, error) {
	if s == nil || s.clientIPResolver == nil {
		return netip.Addr{}, errors.New("pki: client IP resolver is not wired")
	}
	host, _, err := net.SplitHostPort(peerAddress)
	if err != nil {
		return netip.Addr{}, errors.New("pki: enrollment peer address is invalid")
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, errors.New("pki: enrollment peer address is invalid")
	}
	return s.clientIPResolver.Resolve(peer, strings.Join(forwardedFor, ","))
}

func (s *EnrollmentService) applyPublicAuthenticationLimit(
	procedure string,
	clientIP netip.Addr,
	accountKey string,
	resultErr error,
	rateLimited error,
) error {
	if resultErr != nil && connect.CodeOf(resultErr) != connect.CodeUnauthenticated {
		return resultErr
	}
	if s == nil || s.failureLadder == nil || s.now == nil || rateLimited == nil {
		return connect.NewError(connect.CodeInternal, errors.New("public authentication limiter is not wired"))
	}
	if s.failureLadder.Allow(auth.AuthenticationAttempt{
		Procedure:  procedure,
		ClientIP:   clientIP,
		AccountKey: accountKey,
		Succeeded:  resultErr == nil,
	}, s.now()) {
		return resultErr
	}
	return connect.NewError(connect.CodeResourceExhausted, rateLimited)
}

func registrationTokenAccountKey(rawToken string) string {
	tokenID, _, wellFormed := parseRegistrationToken(rawToken)
	if wellFormed == 1 {
		return "registration-token:" + tokenID
	}
	return hashedAuthenticationAccountKey("registration-token", []byte(rawToken))
}

func certificateAccountKey(class store.CertificateClass, certificateDER []byte) string {
	switch class {
	case store.CertificateClassAgent:
		if _, deviceID, err := parseRenewalCertificate(certificateDER); err == nil {
			return string(class) + ":" + deviceID
		}
	case store.CertificateClassGateway:
		if _, gatewayID, err := parseGatewayRenewalCertificate(certificateDER); err == nil {
			return string(class) + ":" + gatewayID
		}
	}
	return hashedAuthenticationAccountKey(string(class)+"-certificate", certificateDER)
}

func hashedAuthenticationAccountKey(namespace string, material []byte) string {
	digest := sha256.Sum256(material)
	return namespace + ":" + hex.EncodeToString(digest[:])
}
