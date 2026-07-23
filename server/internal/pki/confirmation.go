package pki

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/sign"
	"github.com/manchtools/power-manage/server/internal/store"
)

// ConfirmAgentTrustState accepts signed receipts only from an active agent certificate.
func (s *EnrollmentService) ConfirmAgentTrustState(
	ctx context.Context,
	request *connect.Request[powermanagev1.ConfirmTrustStateRequest],
) (*connect.Response[powermanagev1.ConfirmTrustStateResponse], error) {
	if s == nil || s.rotationManager == nil || s.eventStore == nil || ctx == nil || request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("trust confirmation unavailable"))
	}
	confirmation := trustStateConfirmationFromRequest(store.CertificateClassAgent, request.Msg)
	claimedClass := store.CertificateClass(request.Msg.GetClaimedClass())
	err := s.rotationManager.withTrustStateFences(ctx, store.CertificateClassAgent, claimedClass, func() error {
		leaf, consumer, reporterClass, validatedClass, err := s.rotationManager.validateTrustStateConfirmation(ctx, confirmation)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return ErrTrustStateRejected
		}
		if reporterClass != store.CertificateClassAgent || validatedClass != claimedClass {
			return ErrTrustStateRejected
		}
		if leaf != nil {
			if err := s.eventStore.RecordLeafTrustConfirmation(ctx, *leaf); err != nil {
				return err
			}
			return s.eventStore.AppendEvents(ctx, nil)
		}
		if err := s.eventStore.RecordConsumerTrustConfirmation(ctx, *consumer); err != nil {
			return err
		}
		return s.eventStore.AppendEvents(ctx, nil)
	})
	if err != nil {
		return nil, mapTrustConfirmationError(err)
	}
	return connect.NewResponse(&powermanagev1.ConfirmTrustStateResponse{}), nil
}

// ConfirmGatewayTrustState accepts signed receipts only from an active gateway certificate.
func (s *EnrollmentService) ConfirmGatewayTrustState(
	ctx context.Context,
	request *connect.Request[powermanagev1.ConfirmTrustStateRequest],
) (*connect.Response[powermanagev1.ConfirmTrustStateResponse], error) {
	if s == nil || s.rotationManager == nil || s.eventStore == nil || ctx == nil || request == nil || request.Msg == nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("trust confirmation unavailable"))
	}
	confirmation := trustStateConfirmationFromRequest(store.CertificateClassGateway, request.Msg)
	claimedClass := store.CertificateClass(request.Msg.GetClaimedClass())
	err := s.rotationManager.withTrustStateFences(ctx, store.CertificateClassGateway, claimedClass, func() error {
		leaf, consumer, reporterClass, validatedClass, err := s.rotationManager.validateTrustStateConfirmation(ctx, confirmation)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return ErrTrustStateRejected
		}
		if reporterClass != store.CertificateClassGateway || validatedClass != claimedClass {
			return ErrTrustStateRejected
		}
		if leaf != nil {
			if err := s.eventStore.RecordLeafTrustConfirmation(ctx, *leaf); err != nil {
				return err
			}
			return s.eventStore.AppendEvents(ctx, nil)
		}
		if err := s.eventStore.RecordConsumerTrustConfirmation(ctx, *consumer); err != nil {
			return err
		}
		return s.eventStore.AppendEvents(ctx, nil)
	})
	if err != nil {
		return nil, mapTrustConfirmationError(err)
	}
	return connect.NewResponse(&powermanagev1.ConfirmTrustStateResponse{}), nil
}

func trustStateConfirmationFromRequest(
	reporterClass store.CertificateClass,
	request *powermanagev1.ConfirmTrustStateRequest,
) TrustStateConfirmation {
	fingerprint := sha256.Sum256(request.GetCertificateDer())
	return TrustStateConfirmation{
		ReporterCertificateDER: slices.Clone(request.GetCertificateDer()),
		Claim: sign.TrustStateClaim{
			ReporterClass: string(reporterClass), ClaimedClass: request.GetClaimedClass(),
			Generation: request.GetGeneration(), Revision: request.GetRevision(),
			ReporterCertificateFingerprint: slices.Clone(fingerprint[:]),
			RootFingerprints:               cloneDERList(request.GetRootFingerprints()),
			CRLIssuerFingerprint:           slices.Clone(request.GetCrlIssuerFingerprint()),
			CRLSequence:                    request.GetCrlSequence(),
		},
		Signature: slices.Clone(request.GetSignature()),
	}
}

func mapTrustConfirmationError(err error) error {
	if errors.Is(err, ErrTrustStateRejected) {
		return connect.NewError(connect.CodeUnauthenticated, ErrTrustStateRejected)
	}
	if errors.Is(err, context.Canceled) {
		return connect.NewError(connect.CodeCanceled, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return connect.NewError(connect.CodeDeadlineExceeded, context.DeadlineExceeded)
	}
	return connect.NewError(connect.CodeInternal, errors.New("trust confirmation unavailable"))
}
