package sentinelv0

import (
	"errors"

	"example.com/driver/v0"
)

func rawNotFound(err error) bool {
	return errors.Is(err, v0.ErrNoRows)
}
