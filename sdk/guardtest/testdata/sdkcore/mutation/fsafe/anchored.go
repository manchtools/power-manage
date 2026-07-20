package fsafe

import "os"

// The helpers package is the sanctioned mutation site — allowed by prefix.
func Anchored(path string) error { return os.Chmod(path, 0o600) }
