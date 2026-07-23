package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/contract/sign"
	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	gatewayStreamType                  = "gateway"
	gatewayEnrolledEventType           = "GatewayEnrolled"
	gatewayCertificateRenewedEventType = "GatewayCertificateRenewed"
	gatewayCertificateRevokedEventType = "GatewayCertificateRevoked"
	gatewayPayloadVersion              = 1
	gatewayCertificateLifetime         = 45 * 24 * time.Hour
)

// GatewayRebuildTarget is the CLI-only gateway projection recovery target.
const GatewayRebuildTarget = "gateways"

// PublishGatewayCRLWorkKind is durable gateway-CRL publication work.
const PublishGatewayCRLWorkKind = "publish-gateway-crl"

// GatewayLifecycleState is the terminal lifecycle projected for one gateway.
type GatewayLifecycleState string

const (
	GatewayLifecycleActive  GatewayLifecycleState = "active"
	GatewayLifecycleRevoked GatewayLifecycleState = "revoked"
)

// Gateway is the DER-authoritative control view of one enrolled gateway.
type Gateway struct {
	GatewayID              string
	CertificateDER         []byte
	CertificateFingerprint [sha256.Size]byte
	PreviousCertificateDER []byte
	RegistrationTokenID    string
	Owner                  string
	DNSNames               []string
	LifecycleState         GatewayLifecycleState
	ProjectionVersion      int64
}

type gatewayEnrolledPayload struct {
	CertificateDER      []byte   `json:"certificate_der"`
	RegistrationTokenID string   `json:"registration_token_id"`
	Owner               string   `json:"owner"`
	DNSNames            []string `json:"dns_names"`
}

type gatewayCertificateRenewedPayload struct {
	CertificateDER           []byte `json:"certificate_der"`
	SupersededCertificateDER []byte `json:"superseded_certificate_der"`
}

type gatewayCertificateRevokedPayload struct {
	CertificateDER []byte `json:"certificate_der"`
}

// GatewayEnrolledEvent binds a control-issued certificate to token-owned DNS.
func GatewayEnrolledEvent(
	gatewayID string,
	certificateDER []byte,
	registrationTokenID string,
	owner string,
	dnsNames []string,
) (Event, error) {
	gatewayID, payload, err := validateGatewayEnrollment(gatewayID, gatewayEnrolledPayload{
		CertificateDER:      certificateDER,
		RegistrationTokenID: registrationTokenID,
		Owner:               owner,
		DNSNames:            dnsNames,
	})
	if err != nil {
		return Event{}, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Event{}, fmt.Errorf("store: encode gateway enrollment: %w", err)
	}
	return gatewayEvent(gatewayID, gatewayEnrolledEventType, encoded), nil
}

// GatewayCertificateRenewedEvent replaces one exact predecessor certificate.
func GatewayCertificateRenewedEvent(gatewayID string, certificateDER, supersededDER []byte) (Event, error) {
	gatewayID, payload, err := validateGatewayRenewal(gatewayID, gatewayCertificateRenewedPayload{
		CertificateDER:           certificateDER,
		SupersededCertificateDER: supersededDER,
	})
	if err != nil {
		return Event{}, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Event{}, fmt.Errorf("store: encode gateway certificate renewal: %w", err)
	}
	return gatewayEvent(gatewayID, gatewayCertificateRenewedEventType, encoded), nil
}

// GatewayCertificateRevokedEvent terminally revokes the exact current cert.
func GatewayCertificateRevokedEvent(gatewayID string, certificateDER []byte) (Event, error) {
	gatewayID, certificateDER, _, err := validateGatewayCertificate(gatewayID, certificateDER)
	if err != nil {
		return Event{}, err
	}
	encoded, err := json.Marshal(gatewayCertificateRevokedPayload{CertificateDER: certificateDER})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode gateway certificate revocation: %w", err)
	}
	return gatewayEvent(gatewayID, gatewayCertificateRevokedEventType, encoded), nil
}

// Gateway returns one fully validated gateway projection.
func (s *Store) Gateway(ctx context.Context, gatewayID string) (Gateway, error) {
	if s == nil || s.pool == nil {
		return Gateway{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return Gateway{}, errors.New("store: nil gateway context")
	}
	gatewayID, err := canonicalGatewayID(gatewayID)
	if err != nil {
		return Gateway{}, err
	}
	row, err := generated.New(s.pool).GetGateway(ctx, gatewayID)
	if err != nil {
		return Gateway{}, fmt.Errorf("store: read gateway: %w", err)
	}
	return gatewayFromRow(gatewayID, row, true)
}

func gatewayFromRow(gatewayID string, row generated.Gateway, requireDerivedFingerprint bool) (Gateway, error) {
	if row.ProjectionVersion <= 0 {
		return Gateway{}, errors.New("store: gateway projection has an invalid version")
	}
	canonicalID, payload, err := validateGatewayEnrollment(row.GatewayID, gatewayEnrolledPayload{
		CertificateDER:      row.CertificateDer,
		RegistrationTokenID: row.RegistrationTokenID,
		Owner:               row.Owner,
		DNSNames:            row.DnsNames,
	})
	if err != nil {
		return Gateway{}, fmt.Errorf("store: invalid gateway projection: %w", err)
	}
	if canonicalID != gatewayID || len(row.CertificateFingerprint) != sha256.Size {
		return Gateway{}, errors.New("store: gateway projection identity or fingerprint is invalid")
	}
	var fingerprint [sha256.Size]byte
	copy(fingerprint[:], row.CertificateFingerprint)
	if requireDerivedFingerprint && fingerprint != sha256.Sum256(payload.CertificateDER) {
		return Gateway{}, errors.New("store: gateway projection has a mismatched certificate fingerprint")
	}
	state := GatewayLifecycleState(row.LifecycleState)
	if state != GatewayLifecycleActive && state != GatewayLifecycleRevoked {
		return Gateway{}, errors.New("store: gateway projection has an invalid lifecycle state")
	}
	var previous []byte
	if len(row.PreviousCertificateDer) != 0 {
		_, renewal, err := validateGatewayRenewal(canonicalID, gatewayCertificateRenewedPayload{
			CertificateDER:           payload.CertificateDER,
			SupersededCertificateDER: row.PreviousCertificateDer,
		})
		if err != nil {
			return Gateway{}, fmt.Errorf("store: invalid previous gateway certificate: %w", err)
		}
		previous = renewal.SupersededCertificateDER
	}
	return Gateway{
		GatewayID: canonicalID, CertificateDER: payload.CertificateDER,
		CertificateFingerprint: fingerprint, PreviousCertificateDER: previous,
		RegistrationTokenID: payload.RegistrationTokenID, Owner: payload.Owner,
		DNSNames: payload.DNSNames, LifecycleState: state,
		ProjectionVersion: row.ProjectionVersion,
	}, nil
}

func gatewayEvent(gatewayID, eventType string, payload []byte) Event {
	return Event{StreamType: gatewayStreamType, StreamID: gatewayID, EventType: eventType, PayloadVersion: gatewayPayloadVersion, Payload: payload}
}

func gatewayEventDefinitions() map[string]eventDefinition {
	return map[string]eventDefinition{
		gatewayEnrolledEventType: {
			PayloadVersion: gatewayPayloadVersion,
			PayloadType:    gatewayEnrolledPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(gatewayEnrolledPayload{CertificateDER: []byte{1, 2, 3}, RegistrationTokenID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", Owner: "gateway-owner@example.com", DNSNames: []string{"gateway.internal.example"}})
			},
			Projector: projectGatewayEnrollment,
		},
		gatewayCertificateRenewedEventType: {
			PayloadVersion: gatewayPayloadVersion,
			PayloadType:    gatewayCertificateRenewedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(gatewayCertificateRenewedPayload{CertificateDER: []byte{1, 2, 3}, SupersededCertificateDER: []byte{4, 5, 6}})
			},
			Projector: projectGatewayRenewal,
		},
		gatewayCertificateRevokedEventType: {
			PayloadVersion: gatewayPayloadVersion,
			PayloadType:    gatewayCertificateRevokedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(gatewayCertificateRevokedPayload{CertificateDER: []byte{1, 2, 3}})
			},
			Projector: projectGatewayRevocation,
		},
	}
}

func gatewayGoldenCorpus() map[string]goldenEvent {
	return map[string]goldenEvent{
		gatewayEnrolledEventType:           {PayloadVersion: 1, Payload: []byte(`{"certificate_der":"AQID","registration_token_id":"01ARZ3NDEKTSV4RRFFQ69G5FAW","owner":"gateway-owner@example.com","dns_names":["gateway.internal.example"]}`)},
		gatewayCertificateRenewedEventType: {PayloadVersion: 1, Payload: []byte(`{"certificate_der":"AQID","superseded_certificate_der":"BAUG"}`)},
		gatewayCertificateRevokedEventType: {PayloadVersion: 1, Payload: []byte(`{"certificate_der":"AQID"}`)},
	}
}

func projectGatewayEnrollment(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion != 1 {
		return fmt.Errorf("store: gateway enrollment must be stream version 1, got %d", event.StreamVersion)
	}
	payload, err := decodeEventPayload[gatewayEnrolledPayload](event, gatewayPayloadVersion)
	if err != nil {
		return err
	}
	gatewayID, payload, err := validateGatewayEnrollment(event.StreamID, payload)
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(payload.CertificateDER)
	affected, err := generated.New(tx).UpsertGatewayEnrollment(ctx, generated.UpsertGatewayEnrollmentParams{
		GatewayID: gatewayID, ProjectionVersion: event.StreamVersion,
		CertificateDer: payload.CertificateDER, CertificateFingerprint: fingerprint[:],
		RegistrationTokenID: payload.RegistrationTokenID, Owner: payload.Owner,
		DnsNames: payload.DNSNames, UpdatedAt: event.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("store: project gateway enrollment: %w", err)
	}
	if affected == 1 {
		return nil
	}
	if affected != 0 {
		return fmt.Errorf("store: gateway enrollment affected %d rows; want one", affected)
	}
	row, err := generated.New(tx).GetGateway(ctx, gatewayID)
	if err != nil {
		return fmt.Errorf("store: inspect gateway enrollment projection: %w", err)
	}
	current, validationErr := gatewayFromRow(gatewayID, row, true)
	if validationErr == nil && current.ProjectionVersion == event.StreamVersion &&
		bytes.Equal(current.CertificateDER, payload.CertificateDER) && current.CertificateFingerprint == fingerprint &&
		len(current.PreviousCertificateDER) == 0 && current.RegistrationTokenID == payload.RegistrationTokenID &&
		current.Owner == payload.Owner && slices.Equal(current.DNSNames, payload.DNSNames) &&
		current.LifecycleState == GatewayLifecycleActive && row.UpdatedAt.Equal(event.CreatedAt) {
		return nil
	}
	return errors.New("store: gateway enrollment conflicts with the current projection")
}

func projectGatewayRenewal(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: gateway renewal requires prior enrollment")
	}
	payload, err := decodeEventPayload[gatewayCertificateRenewedPayload](event, gatewayPayloadVersion)
	if err != nil {
		return err
	}
	gatewayID, payload, err := validateGatewayRenewal(event.StreamID, payload)
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(payload.CertificateDER)
	affected, err := generated.New(tx).UpdateGatewayRenewal(ctx, generated.UpdateGatewayRenewalParams{
		ProjectionVersion: event.StreamVersion, CertificateDer: payload.CertificateDER,
		CertificateFingerprint: fingerprint[:], SupersededCertificateDer: payload.SupersededCertificateDER,
		UpdatedAt: event.CreatedAt, GatewayID: gatewayID, PreviousProjectionVersion: event.StreamVersion - 1,
	})
	if err != nil {
		return fmt.Errorf("store: project gateway renewal: %w", err)
	}
	if affected == 0 {
		row, readErr := generated.New(tx).GetGateway(ctx, gatewayID)
		current, validationErr := gatewayFromRow(gatewayID, row, true)
		if readErr != nil || validationErr != nil || current.ProjectionVersion != event.StreamVersion ||
			!bytes.Equal(current.CertificateDER, payload.CertificateDER) ||
			current.CertificateFingerprint != fingerprint ||
			!bytes.Equal(current.PreviousCertificateDER, payload.SupersededCertificateDER) ||
			current.LifecycleState != GatewayLifecycleActive || !row.UpdatedAt.Equal(event.CreatedAt) {
			return errors.New("store: gateway renewal conflicts with the current projection")
		}
	} else if affected != 1 {
		return fmt.Errorf("store: gateway renewal affected %d rows; want one", affected)
	}
	return projectCertificateRevocation(ctx, tx, event, payload.SupersededCertificateDER, reasonCodeSuperseded, CertificateClassGateway, PublishGatewayCRLWorkKind)
}

func projectGatewayRevocation(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: gateway revocation requires prior enrollment")
	}
	payload, err := decodeEventPayload[gatewayCertificateRevokedPayload](event, gatewayPayloadVersion)
	if err != nil {
		return err
	}
	gatewayID, certificateDER, _, err := validateGatewayCertificate(event.StreamID, payload.CertificateDER)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).UpdateGatewayLifecycleState(ctx, generated.UpdateGatewayLifecycleStateParams{
		ProjectionVersion: event.StreamVersion, UpdatedAt: event.CreatedAt, GatewayID: gatewayID,
		PreviousProjectionVersion: event.StreamVersion - 1, CertificateDer: certificateDER,
	})
	if err != nil {
		return fmt.Errorf("store: project gateway revocation: %w", err)
	}
	if affected == 0 {
		row, readErr := generated.New(tx).GetGateway(ctx, gatewayID)
		current, validationErr := gatewayFromRow(gatewayID, row, true)
		expectedFingerprint := sha256.Sum256(certificateDER)
		if readErr != nil || validationErr != nil || current.ProjectionVersion != event.StreamVersion ||
			current.LifecycleState != GatewayLifecycleRevoked ||
			!bytes.Equal(current.CertificateDER, certificateDER) ||
			current.CertificateFingerprint != expectedFingerprint || !row.UpdatedAt.Equal(event.CreatedAt) {
			return errors.New("store: gateway revocation conflicts with the current projection")
		}
	} else if affected != 1 {
		return fmt.Errorf("store: gateway revocation affected %d rows; want one", affected)
	}
	return projectCertificateRevocation(ctx, tx, event, certificateDER, reasonCodeUnspecified, CertificateClassGateway, PublishGatewayCRLWorkKind)
}

func resetGateways(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetGatewayCertificateRevocations(ctx); err != nil {
		return fmt.Errorf("store: reset gateway certificate revocations: %w", err)
	}
	if err := generated.New(tx).ResetGateways(ctx); err != nil {
		return fmt.Errorf("store: reset gateways: %w", err)
	}
	return nil
}

func validateGatewayEnrollment(gatewayID string, payload gatewayEnrolledPayload) (string, gatewayEnrolledPayload, error) {
	gatewayID, certificateDER, certificate, err := validateGatewayCertificate(gatewayID, payload.CertificateDER)
	if err != nil {
		return "", gatewayEnrolledPayload{}, err
	}
	dnsNames, err := validateRegistrationTokenPurpose(RegistrationTokenPurposeGateway, payload.DNSNames)
	if err != nil {
		return "", gatewayEnrolledPayload{}, err
	}
	if !slices.Equal(certificate.DNSNames, dnsNames) {
		return "", gatewayEnrolledPayload{}, errors.New("store: gateway certificate DNS names differ from token metadata")
	}
	tokenID, err := canonicalRegistrationTokenID(payload.RegistrationTokenID)
	if err != nil {
		return "", gatewayEnrolledPayload{}, err
	}
	if err := validateRegistrationTokenMetadata(1, certificate.NotAfter, payload.Owner); err != nil {
		return "", gatewayEnrolledPayload{}, err
	}
	return gatewayID, gatewayEnrolledPayload{CertificateDER: certificateDER, RegistrationTokenID: tokenID, Owner: payload.Owner, DNSNames: dnsNames}, nil
}

func validateGatewayRenewal(gatewayID string, payload gatewayCertificateRenewedPayload) (string, gatewayCertificateRenewedPayload, error) {
	gatewayID, certificateDER, certificate, err := validateGatewayCertificate(gatewayID, payload.CertificateDER)
	if err != nil {
		return "", gatewayCertificateRenewedPayload{}, err
	}
	_, supersededDER, superseded, err := validateGatewayCertificate(gatewayID, payload.SupersededCertificateDER)
	if err != nil {
		return "", gatewayCertificateRenewedPayload{}, fmt.Errorf("store: invalid superseded gateway certificate: %w", err)
	}
	if bytes.Equal(certificateDER, supersededDER) || !slices.Equal(certificate.DNSNames, superseded.DNSNames) {
		return "", gatewayCertificateRenewedPayload{}, errors.New("store: gateway renewal certificate continuity is invalid")
	}
	currentKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return "", gatewayCertificateRenewedPayload{}, err
	}
	previousKey, err := x509.MarshalPKIXPublicKey(superseded.PublicKey)
	if err != nil || !bytes.Equal(currentKey, previousKey) {
		return "", gatewayCertificateRenewedPayload{}, errors.New("store: renewed gateway public key differs from predecessor")
	}
	return gatewayID, gatewayCertificateRenewedPayload{CertificateDER: certificateDER, SupersededCertificateDER: supersededDER}, nil
}

func validateGatewayCertificate(gatewayID string, der []byte) (string, []byte, *x509.Certificate, error) {
	gatewayID, err := canonicalGatewayID(gatewayID)
	if err != nil {
		return "", nil, nil, err
	}
	if len(der) == 0 || len(der) > maxCertificateDERBytes {
		return "", nil, nil, errors.New("store: gateway certificate DER size is invalid")
	}
	owned := slices.Clone(der)
	certificate, err := x509.ParseCertificate(owned)
	if err != nil || !bytes.Equal(certificate.Raw, owned) {
		return "", nil, nil, errors.New("store: gateway certificate DER is invalid")
	}
	class, certificateID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil || class != identity.GatewayClass || certificateID != gatewayID {
		return "", nil, nil, errors.New("store: gateway certificate identity is invalid")
	}
	if certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		certificate.NotAfter.Sub(certificate.NotBefore) != gatewayCertificateLifetime ||
		!exactGatewayExtendedKeyUsage(certificate.ExtKeyUsage) || len(certificate.UnknownExtKeyUsage) != 0 ||
		len(certificate.EmailAddresses) != 0 || len(certificate.IPAddresses) != 0 {
		return "", nil, nil, errors.New("store: gateway certificate profile is invalid")
	}
	if err := identity.RequireDNSAndURISANs(certificate); err != nil {
		return "", nil, nil, fmt.Errorf("store: gateway certificate profile is invalid: %w", err)
	}
	if _, err := validateRegistrationTokenPurpose(RegistrationTokenPurposeGateway, certificate.DNSNames); err != nil {
		return "", nil, nil, err
	}
	if err := sign.ValidateSigningKey(certificate.PublicKey); err != nil {
		return "", nil, nil, fmt.Errorf("store: validate gateway certificate key: %w", err)
	}
	return gatewayID, owned, certificate, nil
}

func exactGatewayExtendedKeyUsage(usages []x509.ExtKeyUsage) bool {
	return len(usages) == 2 && slices.Contains(usages, x509.ExtKeyUsageServerAuth) && slices.Contains(usages, x509.ExtKeyUsageClientAuth)
}

func canonicalGatewayID(gatewayID string) (string, error) {
	if err := validate.ULIDPathID(gatewayID); err != nil {
		return "", fmt.Errorf("store: invalid gateway ID: %w", err)
	}
	return strings.ToUpper(gatewayID), nil
}
