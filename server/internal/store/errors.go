package store

import (
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ErrNotFound is the backend-independent no-row sentinel for scope predicates
// that reject before issuing a query.
var ErrNotFound = errors.New("store: resource not found")

// IsNotFound recognizes every backend no-row shape exposed by the store.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound) ||
		errors.Is(err, pgx.ErrNoRows) ||
		errors.Is(err, sql.ErrNoRows)
}
