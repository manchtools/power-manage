package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// CertificateClass separates revocation state by issuing CA.
type CertificateClass string

const (
	CertificateClassAgent   CertificateClass = "agent"
	CertificateClassGateway CertificateClass = "gateway"
)

// CertificateRevocation is the event-derived input to one signed CRL.
type CertificateRevocation struct {
	Class               CertificateClass
	CertificateDER      []byte
	Fingerprint         [sha256.Size]byte
	SerialNumber        []byte
	RevokedAt           time.Time
	ReasonCode          int
	SourceStreamType    string
	SourceStreamID      string
	SourceStreamVersion int64
}

// SignedCRL is the latest durable publication for one certificate class.
type SignedCRL struct {
	Class    CertificateClass
	Sequence int64
	DER      []byte
	IssuedAt time.Time
	Source   CRLSource
}

// CRLSource is the event tuple whose work produced a signed CRL. The zero
// value identifies an initial empty publication.
type CRLSource struct {
	StreamType    string
	StreamID      string
	StreamVersion int64
}

// CertificateRevocations returns validated, defensively copied CRL inputs.
func (s *Store) CertificateRevocations(ctx context.Context, class CertificateClass) ([]CertificateRevocation, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("store: nil store")
	}
	if ctx == nil {
		return nil, errors.New("store: nil certificate-revocations context")
	}
	if !validCertificateClass(class) {
		return nil, errors.New("store: invalid certificate class")
	}
	rows, err := generated.New(s.pool).ListCertificateRevocations(ctx, string(class))
	if err != nil {
		return nil, fmt.Errorf("store: list certificate revocations: %w", err)
	}
	result := make([]CertificateRevocation, 0, len(rows))
	for _, row := range rows {
		revocation, err := certificateRevocation(row)
		if err != nil {
			return nil, err
		}
		result = append(result, revocation)
	}
	return result, nil
}

func certificateRevocation(row generated.CertificateRevocation) (CertificateRevocation, error) {
	class := CertificateClass(row.CertificateClass)
	if !validCertificateClass(class) || len(row.CertificateFingerprint) != sha256.Size ||
		row.RevokedAt.IsZero() || row.SourceStreamVersion <= 0 ||
		row.SourceStreamType == "" || row.SourceStreamID == "" || !validReasonCode(int(row.ReasonCode)) {
		return CertificateRevocation{}, errors.New("store: invalid certificate revocation projection")
	}
	certificate, err := x509.ParseCertificate(row.CertificateDer)
	if err != nil || !bytes.Equal(certificate.Raw, row.CertificateDer) || certificate.SerialNumber == nil ||
		certificate.SerialNumber.Sign() <= 0 || !bytes.Equal(certificate.SerialNumber.Bytes(), row.SerialNumber) {
		return CertificateRevocation{}, errors.New("store: certificate revocation contains invalid certificate material")
	}
	identityClass, _, err := identity.ParseCertificateIdentity(certificate)
	if err != nil || (class == CertificateClassAgent && identityClass != identity.AgentClass) ||
		(class == CertificateClassGateway && identityClass != identity.GatewayClass) {
		return CertificateRevocation{}, errors.New("store: certificate revocation class does not match certificate identity")
	}
	fingerprint := sha256.Sum256(row.CertificateDer)
	if !bytes.Equal(fingerprint[:], row.CertificateFingerprint) {
		return CertificateRevocation{}, errors.New("store: certificate revocation fingerprint is mismatched")
	}
	return CertificateRevocation{
		Class:               class,
		CertificateDER:      slices.Clone(row.CertificateDer),
		Fingerprint:         fingerprint,
		SerialNumber:        slices.Clone(row.SerialNumber),
		RevokedAt:           row.RevokedAt,
		ReasonCode:          int(row.ReasonCode),
		SourceStreamType:    row.SourceStreamType,
		SourceStreamID:      row.SourceStreamID,
		SourceStreamVersion: row.SourceStreamVersion,
	}, nil
}

// LatestCRL returns the durable signed publication, or sequence zero before
// the first CRL has been issued.
func (s *Store) LatestCRL(ctx context.Context, class CertificateClass) (SignedCRL, error) {
	if s == nil || s.pool == nil {
		return SignedCRL{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return SignedCRL{}, errors.New("store: nil CRL-state context")
	}
	if !validCertificateClass(class) {
		return SignedCRL{}, errors.New("store: invalid certificate class")
	}
	row, err := generated.New(s.pool).GetCRLState(ctx, string(class))
	if err != nil {
		return SignedCRL{}, fmt.Errorf("store: read CRL state: %w", err)
	}
	state := SignedCRL{Class: class, Sequence: row.Sequence}
	if row.Sequence == 0 {
		if len(row.CrlDer) != 0 || row.IssuedAt.Valid {
			return SignedCRL{}, errors.New("store: empty CRL state contains publication material")
		}
		return state, nil
	}
	if row.Sequence < 0 || len(row.CrlDer) == 0 || !row.IssuedAt.Valid || row.IssuedAt.Time.IsZero() {
		return SignedCRL{}, errors.New("store: invalid CRL state projection")
	}
	if err := validateCRLMaterial(row.CrlDer, row.Sequence, row.IssuedAt.Time); err != nil {
		return SignedCRL{}, fmt.Errorf("store: invalid CRL state projection: %w", err)
	}
	state.DER = slices.Clone(row.CrlDer)
	state.IssuedAt = row.IssuedAt.Time
	if row.SourceStreamType.Valid || row.SourceStreamID.Valid || row.SourceStreamVersion.Valid {
		state.Source = CRLSource{
			StreamType:    row.SourceStreamType.String,
			StreamID:      row.SourceStreamID.String,
			StreamVersion: row.SourceStreamVersion.Int64,
		}
		if !validCRLSource(state.Source) {
			return SignedCRL{}, errors.New("store: invalid CRL source event")
		}
	}
	return state, nil
}

// CRLWorkReceipt returns the publication sequence produced by one durable
// source event. Missing receipts are reported without an error.
func (s *Store) CRLWorkReceipt(
	ctx context.Context,
	class CertificateClass,
	source CRLSource,
) (int64, bool, error) {
	if s == nil || s.pool == nil {
		return 0, false, errors.New("store: nil store")
	}
	if ctx == nil {
		return 0, false, errors.New("store: nil CRL-work-receipt context")
	}
	if !validCertificateClass(class) || !validCRLSource(source) {
		return 0, false, errors.New("store: invalid CRL-work-receipt input")
	}
	sequence, err := generated.New(s.pool).GetCRLWorkReceipt(ctx, generated.GetCRLWorkReceiptParams{
		CertificateClass:    string(class),
		SourceStreamType:    source.StreamType,
		SourceStreamID:      source.StreamID,
		SourceStreamVersion: source.StreamVersion,
	})
	if IsNotFound(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("store: read CRL work receipt: %w", err)
	}
	if sequence <= 0 {
		return 0, false, errors.New("store: invalid CRL work receipt")
	}
	return sequence, true, nil
}

// CompareAndSwapCRL stores exactly the next signed sequence.
func (s *Store) CompareAndSwapCRL(
	ctx context.Context,
	class CertificateClass,
	expectedSequence int64,
	der []byte,
	issuedAt time.Time,
	source CRLSource,
) (bool, error) {
	if s == nil || s.pool == nil {
		return false, errors.New("store: nil store")
	}
	if ctx == nil {
		return false, errors.New("store: nil CRL compare-and-swap context")
	}
	if !validCertificateClass(class) || expectedSequence < 0 || len(der) == 0 || issuedAt.IsZero() ||
		(source.isZero() && expectedSequence != 0) || (!source.isZero() && !validCRLSource(source)) {
		return false, errors.New("store: invalid CRL compare-and-swap input")
	}
	if err := validateCRLMaterial(der, expectedSequence+1, issuedAt); err != nil {
		return false, fmt.Errorf("store: invalid CRL compare-and-swap input: %w", err)
	}
	queries := generated.New(s.pool)
	var (
		affected int64
		err      error
	)
	if source.isZero() {
		affected, err = queries.CompareAndSwapCRLState(ctx, generated.CompareAndSwapCRLStateParams{
			NextSequence:     expectedSequence + 1,
			CrlDer:           slices.Clone(der),
			IssuedAt:         pgtype.Timestamptz{Time: issuedAt, Valid: true},
			CertificateClass: string(class),
			ExpectedSequence: expectedSequence,
		})
	} else {
		affected, err = queries.CompareAndSwapCRLStateForWork(ctx, generated.CompareAndSwapCRLStateForWorkParams{
			NextSequence:        expectedSequence + 1,
			CrlDer:              slices.Clone(der),
			IssuedAt:            pgtype.Timestamptz{Time: issuedAt, Valid: true},
			SourceStreamType:    source.StreamType,
			SourceStreamID:      source.StreamID,
			SourceStreamVersion: source.StreamVersion,
			CertificateClass:    string(class),
			ExpectedSequence:    expectedSequence,
		})
	}
	if err != nil {
		return false, fmt.Errorf("store: compare and swap CRL state: %w", err)
	}
	if affected != 0 && affected != 1 {
		return false, fmt.Errorf("store: compare and swap CRL state affected %d rows", affected)
	}
	return affected == 1, nil
}

func validateCRLMaterial(der []byte, sequence int64, issuedAt time.Time) error {
	list, err := x509.ParseRevocationList(der)
	if err != nil || !bytes.Equal(list.Raw, der) {
		return errors.New("revocation-list DER is invalid")
	}
	if list.Number == nil || !list.Number.IsInt64() || list.Number.Int64() != sequence {
		return errors.New("revocation-list number does not match sequence")
	}
	if !list.ThisUpdate.Equal(issuedAt) || !list.NextUpdate.After(list.ThisUpdate) {
		return errors.New("revocation-list validity does not match issued-at")
	}
	return nil
}

func (source CRLSource) isZero() bool {
	return source.StreamType == "" && source.StreamID == "" && source.StreamVersion == 0
}

func validCRLSource(source CRLSource) bool {
	return source.StreamType != "" && source.StreamID != "" && source.StreamVersion > 0
}

func validCertificateClass(class CertificateClass) bool {
	return class == CertificateClassAgent || class == CertificateClassGateway
}

func validReasonCode(code int) bool {
	switch code {
	case 0, 1, 2, 3, 4, 5, 6, 8, 9, 10:
		return true
	default:
		return false
	}
}
