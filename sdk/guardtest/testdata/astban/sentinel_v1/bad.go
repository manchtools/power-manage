package sentinelv1

import (
	"errors"

	"example.com/driver/v1"
)

func rawNotFound(err error) bool {
	return errors.Is(err, v1.ErrNoRows)
}
