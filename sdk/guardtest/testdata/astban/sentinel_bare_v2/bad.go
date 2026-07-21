package sentinelbarev2

import (
	"errors"

	"v2"
)

func rawNotFound(err error) bool {
	return errors.Is(err, v2.ErrNoRows)
}
