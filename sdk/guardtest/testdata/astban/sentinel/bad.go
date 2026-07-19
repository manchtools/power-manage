package sentinel

import (
	"database/sql"
	"errors"
)

// Planted violations: raw sentinel recognition outside the recognizer
// package (INV-13) — errors.Is against the driver sentinel and direct
// equality comparisons.
func isMissing(err error) bool { return errors.Is(err, sql.ErrNoRows) }

func isMissingEq(err error) bool { return err == sql.ErrNoRows }

func isPresent(err error) bool { return err != sql.ErrNoRows }

func isMissingParen(err error) bool { return err == (sql.ErrNoRows) }

func isMissingIsParen(err error) bool { return errors.Is(err, (sql.ErrNoRows)) }
