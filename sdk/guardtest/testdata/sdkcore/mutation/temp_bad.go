package mutation

import (
	"os"
	"time"
)

// Planted violations: temp-file/dir creation and timestamp mutation are
// filesystem mutations too — the chokepoint owns them (review finding,
// PR #20).
func tempBad(dir string) error {
	if _, err := os.CreateTemp(dir, "x*"); err != nil {
		return err
	}
	if _, err := os.MkdirTemp(dir, "y*"); err != nil {
		return err
	}
	return os.Chtimes(dir, time.Time{}, time.Time{})
}
