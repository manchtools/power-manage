package sentinelv01

import (
	"errors"

	"example.com/driver/v01"
)

func rawNotFound(err error) bool {
	return errors.Is(err, v01.ErrNoRows)
}
