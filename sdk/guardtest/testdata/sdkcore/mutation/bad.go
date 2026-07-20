package mutation

import "os"

// Planted violations: path-based chmod and rename outside the fd-anchored
// helpers package.
func bad(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return os.Rename(path, path+".new")
}
