package control

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
)

func TestManagementNumericInputs_RejectInt32Overflow(t *testing.T) {
	if _, err := compliancePolicyInput(
		"01J00000000000000000000190",
		"overflow",
		[]string{"01J00000000000000000000191"},
		math.MaxUint32,
	); !errors.Is(err, errCRUDInvalid) {
		t.Fatalf("compliance-policy overflow error = %v; want errCRUDInvalid", err)
	}

	domain := registrationTokenDomain(nil)
	_, _, err := domain.createEvent(
		context.Background(),
		&powermanagev1.CreateRegistrationTokenRequest{
			Id:        "01J00000000000000000000192",
			Purpose:   powermanagev1.RegistrationTokenPurpose_REGISTRATION_TOKEN_PURPOSE_AGENT,
			MaxUses:   math.MaxUint32,
			ExpiresAt: timestamppb.New(time.Now().UTC().Add(time.Hour)),
		},
	)
	if !errors.Is(err, errCRUDInvalid) {
		t.Fatalf("registration-token overflow error = %v; want errCRUDInvalid", err)
	}
}
