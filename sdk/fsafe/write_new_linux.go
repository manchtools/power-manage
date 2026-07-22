//go:build linux

package fsafe

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileNew atomically publishes a new regular file and refuses to replace
// any existing directory entry, including a symlink. The parent is resolved
// and required to be root-owned and non-writable by group/other before the
// random sibling temp is created.
func WriteFileNew(path string, data []byte, mode os.FileMode) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: path %q is not absolute", ErrInvalidPath, path)
	}
	if err := validateMode(mode); err != nil {
		return err
	}
	clean := filepath.Clean(path)
	parent, err := filepath.EvalSymlinks(filepath.Dir(clean))
	if err != nil {
		return fmt.Errorf("resolve parent of %s: %w", path, err)
	}
	if err := parentDirSafe(parent); err != nil {
		return err
	}
	resolved := filepath.Join(parent, filepath.Base(clean))
	if err := replaceFileFrom(resolved, bytes.NewReader(data), mode, false); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	return nil
}
