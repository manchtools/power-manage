package sentinel

import (
	"errors"

	"github.com/jackc/pgx/v5"
)

func rawNotFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
