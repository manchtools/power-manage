package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509/pkix"
	"net/netip"
	"testing"
	"time"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/server/internal/store"
)

func TestRevocationHandlers_RequireOperatorAuthorizationAndExactCertificate(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	_, certificateDER, deviceID := enrollRenewalFixture(t, fixture)
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()
	response, err := fixture.service.RevokeAgent(canceledContext, authorizedRevokeRequest(certificateDER))
	if response != nil || connect.CodeOf(err) != connect.CodeCanceled || err.Error() != "canceled: context canceled" {
		t.Fatalf("RevokeAgent with canceled context = (%v, %v); want exact cancellation", response, err)
	}
	if len(fixture.authorizer.credentials) != 0 {
		t.Fatalf("canceled request reached authorizer; credentials = %v", fixture.authorizer.credentials)
	}

	missing := connect.NewRequest(&powermanagev1.RevokeAgentRequest{CertificateDer: certificateDER})
	if _, err := fixture.client.RevokeAgent(context.Background(), missing); connect.CodeOf(err) != connect.CodeUnauthenticated || err.Error() != "unauthenticated: certificate lifecycle authorization rejected" {
		t.Fatalf("RevokeAgent without authorization = %v; want exact unauthenticated rejection", err)
	}
	assertLifecycleState(t, fixture, deviceID, store.DeviceLifecycleActive, 1)
	duplicate := authorizedRevokeRequest(certificateDER)
	duplicate.Header().Add("Authorization", "Bearer second-proof")
	if _, err := fixture.client.RevokeAgent(context.Background(), duplicate); connect.CodeOf(err) != connect.CodeUnauthenticated || err.Error() != "unauthenticated: certificate lifecycle authorization rejected" {
		t.Fatalf("RevokeAgent with duplicate authorization = %v; want exact unauthenticated rejection", err)
	}
	assertLifecycleState(t, fixture, deviceID, store.DeviceLifecycleActive, 1)

	fixture.authorizer.allow = false
	denied := authorizedRevokeRequest(certificateDER)
	if _, err := fixture.client.RevokeAgent(context.Background(), denied); connect.CodeOf(err) != connect.CodeUnauthenticated || err.Error() != "unauthenticated: certificate lifecycle authorization rejected" {
		t.Fatalf("RevokeAgent denied by authorizer = %v; want exact unauthenticated rejection", err)
	}
	assertLifecycleState(t, fixture, deviceID, store.DeviceLifecycleActive, 1)

	fixture.authorizer.allow = true
	malformed := authorizedRevokeRequest([]byte("not a certificate"))
	credentialsBeforeMalformed := len(fixture.authorizer.credentials)
	if _, err := fixture.client.RevokeAgent(context.Background(), malformed); connect.CodeOf(err) != connect.CodeInvalidArgument || err.Error() != "invalid_argument: certificate lifecycle request rejected" {
		t.Fatalf("RevokeAgent with malformed certificate = %v; want exact request rejection", err)
	}
	if len(fixture.authorizer.credentials) != credentialsBeforeMalformed {
		t.Fatalf("malformed certificate reached authorizer; credentials = %v", fixture.authorizer.credentials)
	}
	assertLifecycleState(t, fixture, deviceID, store.DeviceLifecycleActive, 1)

	substituted := newPresentedRenewalCertificate(
		t,
		certificateDER,
		newEnrollmentSigningKey(t),
		identity.AgentClass,
		deviceID,
		82,
	)
	if _, err := fixture.client.RevokeAgent(context.Background(), authorizedRevokeRequest(substituted)); connect.CodeOf(err) != connect.CodeUnauthenticated || err.Error() != "unauthenticated: certificate lifecycle authorization rejected" {
		t.Fatalf("RevokeAgent with substituted certificate = %v; want exact unauthenticated rejection", err)
	}
	assertLifecycleState(t, fixture, deviceID, store.DeviceLifecycleActive, 1)

	if _, err := fixture.client.RevokeAgent(context.Background(), authorizedRevokeRequest(certificateDER)); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}
	assertLifecycleState(t, fixture, deviceID, store.DeviceLifecycleRevoked, 2)
	if len(fixture.authorizer.credentials) != 3 || fixture.authorizer.credentials[0] != "Bearer operator-proof" {
		t.Fatalf("authorizer credentials = %v; want only three exact bearer credentials", fixture.authorizer.credentials)
	}
	if len(fixture.authorizer.deviceIDs) != 3 {
		t.Fatalf("authorizer device IDs = %v; want three certificate-derived resources", fixture.authorizer.deviceIDs)
	}
	for _, authorizedDeviceID := range fixture.authorizer.deviceIDs {
		if authorizedDeviceID != deviceID {
			t.Fatalf("authorizer device ID = %q; want certificate-derived %q", authorizedDeviceID, deviceID)
		}
	}
}

func TestNewEnrollmentService_RequiresLifecycleAuthorizer(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	var typedNil *testLifecycleAuthorizer
	for _, authorizer := range []LifecycleAuthorizer{nil, typedNil} {
		service, err := NewEnrollmentService(
			fixture.service.tokens,
			fixture.eventStore,
			fixture.service.authorities,
			authorizer,
		)
		if service != nil || err == nil || err.Error() != "pki: lifecycle authorizer is not wired" {
			t.Fatalf("NewEnrollmentService with authorizer %v = (%v, %v); want exact unwired rejection", authorizer, service, err)
		}
	}
}

func TestForceRenew_AllowsOneReplacementWhileStandaloneRevokeIsTerminal(t *testing.T) {
	t.Run("force renewal", func(t *testing.T) {
		fixture := newEnrollmentHandlerFixture(t, 1)
		key, certificateDER, deviceID := enrollRenewalFixture(t, fixture)
		request := connect.NewRequest(&powermanagev1.ForceRenewAgentRequest{CertificateDer: certificateDER})
		request.Header().Set("Authorization", "Bearer operator-proof")
		if _, err := fixture.client.ForceRenewAgent(context.Background(), request); err != nil {
			t.Fatalf("ForceRenewAgent: %v", err)
		}
		assertLifecycleState(t, fixture, deviceID, store.DeviceLifecycleForceRenewal, 2)

		response, err := fixture.client.RenewAgent(context.Background(), connect.NewRequest(&powermanagev1.RenewAgentRequest{
			CertificateDer:               certificateDER,
			CertificateSigningRequestDer: newEnrollmentCSR(t, key, pkix.Name{}, nil),
			SealingPublicKey:             newEnrollmentSealingKey(t),
		}))
		if err != nil {
			t.Fatalf("renew force-renewed certificate: %v", err)
		}
		if bytes.Equal(response.Msg.GetCertificateDer(), certificateDER) {
			t.Fatal("force renewal returned the revoked certificate")
		}
		assertLifecycleState(t, fixture, deviceID, store.DeviceLifecycleActive, 3)
	})

	t.Run("force renewal escalates to terminal revoke", func(t *testing.T) {
		fixture := newEnrollmentHandlerFixture(t, 1)
		key, certificateDER, deviceID := enrollRenewalFixture(t, fixture)
		request := connect.NewRequest(&powermanagev1.ForceRenewAgentRequest{CertificateDer: certificateDER})
		request.Header().Set("Authorization", "Bearer operator-proof")
		if _, err := fixture.client.ForceRenewAgent(context.Background(), request); err != nil {
			t.Fatalf("ForceRenewAgent: %v", err)
		}
		if _, err := fixture.client.RevokeAgent(context.Background(), authorizedRevokeRequest(certificateDER)); err != nil {
			t.Fatalf("RevokeAgent after force renewal: %v", err)
		}
		response, err := fixture.client.RenewAgent(context.Background(), connect.NewRequest(&powermanagev1.RenewAgentRequest{
			CertificateDer:               certificateDER,
			CertificateSigningRequestDer: newEnrollmentCSR(t, key, pkix.Name{}, nil),
			SealingPublicKey:             newEnrollmentSealingKey(t),
		}))
		if response != nil || connect.CodeOf(err) != connect.CodeUnauthenticated || err.Error() != "unauthenticated: renewal authorization rejected" {
			t.Fatalf("renew terminally escalated certificate = (%v, %v); want exact unauthenticated rejection", response, err)
		}
		assertLifecycleState(t, fixture, deviceID, store.DeviceLifecycleRevoked, 3)
	})

	t.Run("terminal revoke", func(t *testing.T) {
		fixture := newEnrollmentHandlerFixture(t, 1)
		key, certificateDER, deviceID := enrollRenewalFixture(t, fixture)
		if _, err := fixture.client.RevokeAgent(context.Background(), authorizedRevokeRequest(certificateDER)); err != nil {
			t.Fatalf("RevokeAgent: %v", err)
		}
		response, err := fixture.client.RenewAgent(context.Background(), connect.NewRequest(&powermanagev1.RenewAgentRequest{
			CertificateDer:               certificateDER,
			CertificateSigningRequestDer: newEnrollmentCSR(t, key, pkix.Name{}, nil),
			SealingPublicKey:             newEnrollmentSealingKey(t),
		}))
		if response != nil || connect.CodeOf(err) != connect.CodeUnauthenticated || err.Error() != "unauthenticated: renewal authorization rejected" {
			t.Fatalf("renew terminally revoked certificate = (%v, %v); want exact unauthenticated rejection", response, err)
		}
		assertLifecycleState(t, fixture, deviceID, store.DeviceLifecycleRevoked, 2)
	})
}

func TestRenewalHandler_RevokedSuccessorRejectsPredecessorRetry(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	key, predecessorDER, deviceID := enrollRenewalFixture(t, fixture)
	csrDER := newEnrollmentCSR(t, key, pkix.Name{}, nil)
	sealingPublicKey := newEnrollmentSealingKey(t)
	renew := func() (*connect.Response[powermanagev1.RenewAgentResponse], error) {
		return fixture.client.RenewAgent(context.Background(), connect.NewRequest(&powermanagev1.RenewAgentRequest{
			CertificateDer:               bytes.Clone(predecessorDER),
			CertificateSigningRequestDer: bytes.Clone(csrDER),
			SealingPublicKey:             bytes.Clone(sealingPublicKey),
		}))
	}

	issued, err := renew()
	if err != nil {
		t.Fatalf("renew predecessor: %v", err)
	}
	if _, err := fixture.client.RevokeAgent(
		context.Background(),
		authorizedRevokeRequest(issued.Msg.GetCertificateDer()),
	); err != nil {
		t.Fatalf("revoke renewal successor: %v", err)
	}

	retried, err := renew()
	if retried != nil || connect.CodeOf(err) != connect.CodeUnauthenticated || err.Error() != "unauthenticated: renewal authorization rejected" {
		t.Fatalf("retry revoked successor from predecessor = (%v, %v); want exact unauthenticated rejection", retried, err)
	}
	assertLifecycleState(t, fixture, deviceID, store.DeviceLifecycleRevoked, 3)
}

func TestRevocationHandler_ProjectionVersionDriftIsTemporaryFailure(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	_, certificateDER, deviceID := enrollRenewalFixture(t, fixture)
	result, err := fixture.pool.Exec(
		context.Background(),
		`UPDATE devices SET projection_version = 2 WHERE device_id = $1`,
		deviceID,
	)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf("drift device projection version = (%d, %v); want one row", result.RowsAffected(), err)
	}

	response, err := fixture.client.RevokeAgent(context.Background(), authorizedRevokeRequest(certificateDER))
	if response != nil || connect.CodeOf(err) != connect.CodeInternal || err.Error() != "internal: certificate lifecycle temporarily unavailable" {
		t.Fatalf("revoke with projection drift = (%v, %v); want exact temporary failure", response, err)
	}
	assertLifecycleState(t, fixture, deviceID, store.DeviceLifecycleActive, 2)
}

func TestRevocationHandlers_ConcurrentLifecycleOperationsSerialize(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	_, certificateDER, deviceID := enrollRenewalFixture(t, fixture)
	start := make(chan struct{})
	results := make(chan error, 2)
	run := func(operation func() error) {
		go func() {
			select {
			case <-start:
			case <-time.After(5 * time.Second):
				results <- context.DeadlineExceeded
				return
			}
			results <- operation()
		}()
	}
	run(func() error {
		_, err := fixture.client.RevokeAgent(context.Background(), authorizedRevokeRequest(certificateDER))
		return err
	})
	run(func() error {
		request := connect.NewRequest(&powermanagev1.ForceRenewAgentRequest{CertificateDer: bytes.Clone(certificateDER)})
		request.Header().Set("Authorization", "Bearer operator-proof")
		_, err := fixture.client.ForceRenewAgent(context.Background(), request)
		return err
	})
	close(start)
	successes := 0
	for range 2 {
		var err error
		select {
		case err = <-results:
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent lifecycle operations did not complete")
		}
		if err == nil {
			successes++
			continue
		}
		if connect.CodeOf(err) != connect.CodeUnauthenticated || err.Error() != "unauthenticated: certificate lifecycle authorization rejected" {
			t.Fatalf("losing lifecycle operation = %v; want exact unauthenticated rejection", err)
		}
	}
	device, err := fixture.eventStore.Device(context.Background(), deviceID)
	if err != nil {
		t.Fatalf("read serialized lifecycle result: %v", err)
	}
	if device.LifecycleState != store.DeviceLifecycleRevoked ||
		(successes == 1 && device.ProjectionVersion != 2) ||
		(successes == 2 && device.ProjectionVersion != 3) ||
		(successes != 1 && successes != 2) {
		t.Fatalf("serialized lifecycle result = %+v after %d successes; want terminal revocation", device, successes)
	}
}

func TestRevocationHandlers_RateLimitNetworkSource(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	_, certificateDER, _ := enrollRenewalFixture(t, fixture)
	for attempt := 1; attempt <= 7; attempt++ {
		_, err := fixture.client.RevokeAgent(context.Background(), authorizedRevokeRequest(certificateDER))
		switch attempt {
		case 1:
			if err != nil {
				t.Fatalf("first revoke: %v", err)
			}
		case 7:
			if connect.CodeOf(err) != connect.CodeResourceExhausted || err.Error() != "resource_exhausted: certificate lifecycle rate limited" {
				t.Fatalf("sixth failed revoke = %v; want exact rate limit", err)
			}
		default:
			if connect.CodeOf(err) != connect.CodeUnauthenticated || err.Error() != "unauthenticated: certificate lifecycle authorization rejected" {
				t.Fatalf("repeated revoke %d = %v; want exact authorization rejection", attempt, err)
			}
		}
	}
}

func TestRevocationHandler_SameIdentityCertificatesShareAccountFailureBucket(t *testing.T) {
	fixture := newEnrollmentHandlerFixtureWithTrustedProxies(t, 1, []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	})
	key, enrolledDER, deviceID := enrollRenewalFixture(t, fixture)
	alternateDER := newPresentedRenewalCertificate(
		t,
		enrolledDER,
		key,
		identity.AgentClass,
		deviceID,
		91,
	)
	if bytes.Equal(enrolledDER, alternateDER) {
		t.Fatal("same-identity certificate fixtures have identical DER")
	}
	for index, certificateDER := range [][]byte{enrolledDER, alternateDER} {
		_, parsedID, err := parseRenewalCertificate(certificateDER)
		if err != nil {
			t.Fatalf("parse same-identity certificate %d: %v", index, err)
		}
		if parsedID != deviceID {
			t.Fatalf("same-identity certificate %d device ID = %q; want %q", index, parsedID, deviceID)
		}
	}

	fixture.authorizer.allow = false
	for attempt := 1; attempt <= 6; attempt++ {
		certificateDER := enrolledDER
		if attempt%2 == 0 {
			certificateDER = alternateDER
		}
		request := authorizedRevokeRequest(certificateDER)
		request.Header().Set(
			"X-Forwarded-For",
			netip.AddrFrom4([4]byte{198, 51, 100, byte(attempt)}).String(),
		)
		_, err := fixture.client.RevokeAgent(context.Background(), request)
		if attempt < 6 {
			wantError := connect.CodeUnauthenticated.String() + ": " + errLifecycleAuthRejected.Error()
			if connect.CodeOf(err) != connect.CodeUnauthenticated || err.Error() != wantError {
				t.Fatalf("same-identity failure %d error = %v; want %q", attempt, err, wantError)
			}
			continue
		}
		wantError := connect.CodeResourceExhausted.String() + ": " + errLifecycleRateLimited.Error()
		if connect.CodeOf(err) != connect.CodeResourceExhausted || err.Error() != wantError {
			t.Fatalf("sixth same-identity failure error = %v; want %q", err, wantError)
		}
	}
	assertLifecycleState(t, fixture, deviceID, store.DeviceLifecycleActive, 1)
}

func authorizedRevokeRequest(certificateDER []byte) *connect.Request[powermanagev1.RevokeAgentRequest] {
	request := connect.NewRequest(&powermanagev1.RevokeAgentRequest{CertificateDer: bytes.Clone(certificateDER)})
	request.Header().Set("Authorization", "Bearer operator-proof")
	return request
}

func assertLifecycleState(
	t *testing.T,
	fixture enrollmentHandlerFixture,
	deviceID string,
	want store.DeviceLifecycleState,
	wantVersion int64,
) {
	t.Helper()
	device, err := fixture.eventStore.Device(context.Background(), deviceID)
	if err != nil {
		t.Fatalf("read device lifecycle: %v", err)
	}
	wantFingerprint := sha256.Sum256(device.CertificateDER)
	if device.LifecycleState != want || device.ProjectionVersion != wantVersion || device.CertificateFingerprint != wantFingerprint {
		t.Fatalf("device lifecycle = %+v; want state %q version %d with DER-derived fingerprint", device, want, wantVersion)
	}
}

var _ LifecycleAuthorizer = (*testLifecycleAuthorizer)(nil)
