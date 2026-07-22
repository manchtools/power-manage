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

	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/contract/seal"
	"github.com/manchtools/power-manage/contract/sign"
	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	deviceStreamType                 = "device"
	agentEnrolledEventType           = "AgentEnrolled"
	agentCertificateRenewedEventType = "AgentCertificateRenewed"
	devicePayloadVersion             = 1
	maxCertificateDERBytes           = 65536
)

// DeviceRebuildTarget is the CLI-only device projection recovery target.
const DeviceRebuildTarget = "devices"

// Device is the DER-authoritative enrolled agent state. Public key material is
// always re-derived from CertificateDER by its consumers.
type Device struct {
	DeviceID               string
	CertificateDER         []byte
	CertificateFingerprint [sha256.Size]byte
	SealingPublicKey       []byte
	PreviousCertificateDER []byte
	RegistrationTokenID    string
	Owner                  string
	ProjectionVersion      int64
}

type agentEnrolledPayload struct {
	CertificateDER      []byte `json:"certificate_der"`
	SealingPublicKey    []byte `json:"sealing_public_key"`
	RegistrationTokenID string `json:"registration_token_id"`
	Owner               string `json:"owner"`
}

type agentCertificateRenewedPayload struct {
	CertificateDER           []byte `json:"certificate_der"`
	SealingPublicKey         []byte `json:"sealing_public_key"`
	SupersededCertificateDER []byte `json:"superseded_certificate_der"`
}

// AgentEnrolledEvent binds issued certificate DER and an X25519 sealing key to
// one control-authored device identity.
func AgentEnrolledEvent(
	deviceID string,
	certificateDER []byte,
	sealingPublicKey []byte,
	registrationTokenID string,
	owner string,
) (Event, error) {
	deviceID, payload, err := validateAgentEnrollment(
		deviceID,
		agentEnrolledPayload{
			CertificateDER:      certificateDER,
			SealingPublicKey:    sealingPublicKey,
			RegistrationTokenID: registrationTokenID,
			Owner:               owner,
		},
	)
	if err != nil {
		return Event{}, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Event{}, fmt.Errorf("store: encode agent enrollment: %w", err)
	}
	return Event{
		StreamType:     deviceStreamType,
		StreamID:       deviceID,
		EventType:      agentEnrolledEventType,
		PayloadVersion: devicePayloadVersion,
		Payload:        encoded,
	}, nil
}

// AgentCertificateRenewedEvent atomically replaces an agent certificate and
// sealing key while retaining the exact superseded DER as durable revocation
// input for CRL materialization.
func AgentCertificateRenewedEvent(
	deviceID string,
	certificateDER []byte,
	sealingPublicKey []byte,
	supersededCertificateDER []byte,
) (Event, error) {
	deviceID, payload, err := validateAgentCertificateRenewal(deviceID, agentCertificateRenewedPayload{
		CertificateDER:           certificateDER,
		SealingPublicKey:         sealingPublicKey,
		SupersededCertificateDER: supersededCertificateDER,
	})
	if err != nil {
		return Event{}, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Event{}, fmt.Errorf("store: encode agent certificate renewal: %w", err)
	}
	return Event{
		StreamType:     deviceStreamType,
		StreamID:       deviceID,
		EventType:      agentCertificateRenewedEventType,
		PayloadVersion: devicePayloadVersion,
		Payload:        encoded,
	}, nil
}

// Device reads one enrolled agent projection and validates every trust-bearing
// field before returning it.
func (s *Store) Device(ctx context.Context, deviceID string) (Device, error) {
	if s == nil || s.pool == nil {
		return Device{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return Device{}, errors.New("store: nil device context")
	}
	deviceID, err := canonicalDeviceID(deviceID)
	if err != nil {
		return Device{}, err
	}
	row, err := generated.New(s.pool).GetDevice(ctx, deviceID)
	if err != nil {
		return Device{}, fmt.Errorf("store: read device: %w", err)
	}
	return deviceFromRow(deviceID, row)
}

func deviceFromRow(deviceID string, row generated.Device) (Device, error) {
	return deviceFromRowWithFingerprintPolicy(deviceID, row, true)
}

func deviceFromRowWithFingerprintPolicy(deviceID string, row generated.Device, requireDerivedFingerprint bool) (Device, error) {
	if row.ProjectionVersion <= 0 {
		return Device{}, errors.New("store: device projection has an invalid version")
	}
	canonicalID, payload, err := validateAgentEnrollment(row.DeviceID, agentEnrolledPayload{
		CertificateDER:      row.CertificateDer,
		SealingPublicKey:    row.SealingPublicKey,
		RegistrationTokenID: row.RegistrationTokenID,
		Owner:               row.Owner,
	})
	if err != nil {
		return Device{}, fmt.Errorf("store: invalid device projection: %w", err)
	}
	if canonicalID != deviceID {
		return Device{}, errors.New("store: device projection returned a mismatched ID")
	}
	if len(row.CertificateFingerprint) != sha256.Size {
		return Device{}, errors.New("store: device projection has an invalid certificate fingerprint")
	}
	var storedFingerprint [sha256.Size]byte
	copy(storedFingerprint[:], row.CertificateFingerprint)
	derivedFingerprint := sha256.Sum256(payload.CertificateDER)
	if requireDerivedFingerprint && storedFingerprint != derivedFingerprint {
		return Device{}, errors.New("store: device projection has a mismatched certificate fingerprint")
	}
	var previousCertificateDER []byte
	if len(row.PreviousCertificateDer) > 0 {
		_, renewal, err := validateAgentCertificateRenewal(canonicalID, agentCertificateRenewedPayload{
			CertificateDER:           payload.CertificateDER,
			SealingPublicKey:         payload.SealingPublicKey,
			SupersededCertificateDER: row.PreviousCertificateDer,
		})
		if err != nil {
			return Device{}, fmt.Errorf("store: invalid previous certificate projection: %w", err)
		}
		previousCertificateDER = renewal.SupersededCertificateDER
	}
	return Device{
		DeviceID:               canonicalID,
		CertificateDER:         payload.CertificateDER,
		CertificateFingerprint: storedFingerprint,
		SealingPublicKey:       payload.SealingPublicKey,
		PreviousCertificateDER: previousCertificateDER,
		RegistrationTokenID:    payload.RegistrationTokenID,
		Owner:                  payload.Owner,
		ProjectionVersion:      row.ProjectionVersion,
	}, nil
}

func deviceEventDefinitions() map[string]eventDefinition {
	return map[string]eventDefinition{
		agentEnrolledEventType: {
			PayloadVersion: devicePayloadVersion,
			PayloadType:    agentEnrolledPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(agentEnrolledPayload{
					CertificateDER:      []byte{1, 2, 3},
					SealingPublicKey:    make([]byte, seal.X25519PublicKeySize),
					RegistrationTokenID: "01ARZ3NDEKTSV4RRFFQ69G5FAW",
					Owner:               "owner@example.com",
				})
			},
			Projector: projectAgentEnrollment,
		},
		agentCertificateRenewedEventType: {
			PayloadVersion: devicePayloadVersion,
			PayloadType:    agentCertificateRenewedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(agentCertificateRenewedPayload{
					CertificateDER:           []byte{1, 2, 3},
					SealingPublicKey:         make([]byte, seal.X25519PublicKeySize),
					SupersededCertificateDER: []byte{4, 5, 6},
				})
			},
			Projector: projectAgentCertificateRenewal,
		},
	}
}

func deviceGoldenCorpus() map[string]goldenEvent {
	return map[string]goldenEvent{
		agentEnrolledEventType: {
			PayloadVersion: devicePayloadVersion,
			Payload: []byte(
				`{"certificate_der":"AQID","sealing_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","registration_token_id":"01ARZ3NDEKTSV4RRFFQ69G5FAW","owner":"owner@example.com"}`,
			),
		},
		agentCertificateRenewedEventType: {
			PayloadVersion: devicePayloadVersion,
			Payload: []byte(
				`{"certificate_der":"AQID","sealing_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","superseded_certificate_der":"BAUG"}`,
			),
		},
	}
}

func projectAgentEnrollment(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion != 1 {
		return fmt.Errorf("store: agent enrollment must be stream version 1, got %d", event.StreamVersion)
	}
	payload, err := decodeEventPayload[agentEnrolledPayload](event, devicePayloadVersion)
	if err != nil {
		return err
	}
	deviceID, payload, err := validateAgentEnrollment(event.StreamID, payload)
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(payload.CertificateDER)
	affected, err := generated.New(tx).UpsertDeviceEnrollment(ctx, generated.UpsertDeviceEnrollmentParams{
		DeviceID:               deviceID,
		ProjectionVersion:      event.StreamVersion,
		CertificateDer:         payload.CertificateDER,
		CertificateFingerprint: fingerprint[:],
		SealingPublicKey:       payload.SealingPublicKey,
		RegistrationTokenID:    payload.RegistrationTokenID,
		Owner:                  payload.Owner,
		UpdatedAt:              event.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("store: project agent enrollment: %w", err)
	}
	if affected == 1 {
		return nil
	}
	if affected != 0 {
		return fmt.Errorf("store: agent enrollment affected %d rows; want one", affected)
	}
	row, err := generated.New(tx).GetDevice(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("store: inspect agent enrollment projection: %w", err)
	}
	if row.ProjectionVersion == event.StreamVersion &&
		bytes.Equal(row.CertificateDer, payload.CertificateDER) &&
		bytes.Equal(row.CertificateFingerprint, fingerprint[:]) &&
		bytes.Equal(row.SealingPublicKey, payload.SealingPublicKey) &&
		len(row.PreviousCertificateDer) == 0 &&
		row.RegistrationTokenID == payload.RegistrationTokenID &&
		row.Owner == payload.Owner {
		return nil
	}
	return errors.New("store: agent enrollment conflicts with the current device projection")
}

func projectAgentCertificateRenewal(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return fmt.Errorf("store: agent certificate renewal must follow enrollment, got stream version %d", event.StreamVersion)
	}
	payload, err := decodeEventPayload[agentCertificateRenewedPayload](event, devicePayloadVersion)
	if err != nil {
		return err
	}
	deviceID, payload, err := validateAgentCertificateRenewal(event.StreamID, payload)
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(payload.CertificateDER)
	affected, err := generated.New(tx).UpdateDeviceRenewal(ctx, generated.UpdateDeviceRenewalParams{
		DeviceID:                  deviceID,
		ProjectionVersion:         event.StreamVersion,
		PreviousProjectionVersion: event.StreamVersion - 1,
		CertificateDer:            payload.CertificateDER,
		CertificateFingerprint:    fingerprint[:],
		SealingPublicKey:          payload.SealingPublicKey,
		SupersededCertificateDer:  payload.SupersededCertificateDER,
		UpdatedAt:                 event.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("store: project agent certificate renewal: %w", err)
	}
	if affected == 1 {
		return nil
	}
	if affected != 0 {
		return fmt.Errorf("store: agent certificate renewal affected %d rows; want one", affected)
	}
	row, err := generated.New(tx).GetDevice(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("store: inspect agent certificate renewal projection: %w", err)
	}
	if row.ProjectionVersion == event.StreamVersion &&
		bytes.Equal(row.CertificateDer, payload.CertificateDER) &&
		bytes.Equal(row.CertificateFingerprint, fingerprint[:]) &&
		bytes.Equal(row.SealingPublicKey, payload.SealingPublicKey) &&
		bytes.Equal(row.PreviousCertificateDer, payload.SupersededCertificateDER) {
		return nil
	}
	return errors.New("store: agent certificate renewal conflicts with the current device projection")
}

func resetDevices(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetDevices(ctx); err != nil {
		return fmt.Errorf("store: reset devices: %w", err)
	}
	return nil
}

func validateAgentEnrollment(deviceID string, payload agentEnrolledPayload) (string, agentEnrolledPayload, error) {
	deviceID, certificateDER, certificate, err := validateAgentCertificate(deviceID, payload.CertificateDER)
	if err != nil {
		return "", agentEnrolledPayload{}, err
	}
	if err := seal.ValidateX25519PublicKey(payload.SealingPublicKey); err != nil {
		return "", agentEnrolledPayload{}, err
	}
	tokenID, err := canonicalRegistrationTokenID(payload.RegistrationTokenID)
	if err != nil {
		return "", agentEnrolledPayload{}, fmt.Errorf("store: invalid registration token ID: %w", err)
	}
	if err := validateRegistrationTokenMetadata(1, certificate.NotAfter, payload.Owner); err != nil {
		return "", agentEnrolledPayload{}, fmt.Errorf("store: invalid device owner: %w", err)
	}
	return deviceID, agentEnrolledPayload{
		CertificateDER:      certificateDER,
		SealingPublicKey:    slices.Clone(payload.SealingPublicKey),
		RegistrationTokenID: tokenID,
		Owner:               payload.Owner,
	}, nil
}

func validateAgentCertificateRenewal(
	deviceID string,
	payload agentCertificateRenewedPayload,
) (string, agentCertificateRenewedPayload, error) {
	deviceID, certificateDER, certificate, err := validateAgentCertificate(deviceID, payload.CertificateDER)
	if err != nil {
		return "", agentCertificateRenewedPayload{}, err
	}
	_, supersededDER, superseded, err := validateAgentCertificate(deviceID, payload.SupersededCertificateDER)
	if err != nil {
		return "", agentCertificateRenewedPayload{}, fmt.Errorf("store: invalid superseded certificate: %w", err)
	}
	if bytes.Equal(certificateDER, supersededDER) {
		return "", agentCertificateRenewedPayload{}, errors.New("store: renewed certificate equals the superseded certificate")
	}
	certificateKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return "", agentCertificateRenewedPayload{}, fmt.Errorf("store: marshal renewed certificate public key: %w", err)
	}
	supersededKey, err := x509.MarshalPKIXPublicKey(superseded.PublicKey)
	if err != nil {
		return "", agentCertificateRenewedPayload{}, fmt.Errorf("store: marshal superseded certificate public key: %w", err)
	}
	if !bytes.Equal(certificateKey, supersededKey) {
		return "", agentCertificateRenewedPayload{}, errors.New("store: renewed certificate public key differs from superseded certificate")
	}
	if err := seal.ValidateX25519PublicKey(payload.SealingPublicKey); err != nil {
		return "", agentCertificateRenewedPayload{}, err
	}
	return deviceID, agentCertificateRenewedPayload{
		CertificateDER:           certificateDER,
		SealingPublicKey:         slices.Clone(payload.SealingPublicKey),
		SupersededCertificateDER: supersededDER,
	}, nil
}

func validateAgentCertificate(deviceID string, der []byte) (string, []byte, *x509.Certificate, error) {
	deviceID, err := canonicalDeviceID(deviceID)
	if err != nil {
		return "", nil, nil, err
	}
	if len(der) == 0 || len(der) > maxCertificateDERBytes {
		return "", nil, nil, fmt.Errorf("store: certificate DER must contain 1..%d bytes", maxCertificateDERBytes)
	}
	certificateDER := slices.Clone(der)
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return "", nil, nil, fmt.Errorf("store: parse certificate DER: %w", err)
	}
	if !bytes.Equal(certificate.Raw, certificateDER) {
		return "", nil, nil, errors.New("store: certificate DER contains trailing data")
	}
	class, certificateID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil {
		return "", nil, nil, fmt.Errorf("store: parse certificate identity: %w", err)
	}
	if class != identity.AgentClass {
		return "", nil, nil, fmt.Errorf("store: certificate class %q is not agent", class)
	}
	if certificateID != deviceID {
		return "", nil, nil, errors.New("store: certificate identity is mismatched with device ID")
	}
	if certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		!certificate.NotAfter.After(certificate.NotBefore) {
		return "", nil, nil, errors.New("store: certificate DER has an invalid agent profile")
	}
	if err := sign.ValidateSigningKey(certificate.PublicKey); err != nil {
		return "", nil, nil, fmt.Errorf("store: validate certificate public key: %w", err)
	}
	return deviceID, certificateDER, certificate, nil
}

func canonicalDeviceID(deviceID string) (string, error) {
	if err := validate.ULIDPathID(deviceID); err != nil {
		return "", fmt.Errorf("store: invalid device ID: %w", err)
	}
	return strings.ToUpper(deviceID), nil
}
