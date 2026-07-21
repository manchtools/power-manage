package store

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestIsNotFound_RecognizesDriverSentinels(t *testing.T) {
	for _, err := range []error{
		pgx.ErrNoRows,
		sql.ErrNoRows,
		fmt.Errorf("wrapped: %w", pgx.ErrNoRows),
		fmt.Errorf("wrapped: %w", sql.ErrNoRows),
	} {
		if !IsNotFound(err) {
			t.Errorf("IsNotFound(%v) = false; want true", err)
		}
	}
	if IsNotFound(nil) || IsNotFound(errors.New("other")) {
		t.Fatal("IsNotFound recognized a non-not-found error")
	}
}
