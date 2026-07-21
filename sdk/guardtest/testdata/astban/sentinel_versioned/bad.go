package sentinelversioned

import (
	"errors"

	"example.com/driver/v5"
)

func rawNotFound(err error) bool {
	return errors.Is(err, driver.ErrNoRows)
}
