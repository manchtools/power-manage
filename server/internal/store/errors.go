package store

import (
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5"
)

// IsNotFound recognizes every backend no-row shape exposed by the store.
func IsNotFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows)
}
