package mutation

import "os"

// Clean: OpenFile is the fd-anchored primitive itself (recorded ceiling:
// clobber-flag inspection arrives with the helpers at M3).
func decoy(path string) (*os.File, error) { return os.OpenFile(path, os.O_RDONLY, 0) }
