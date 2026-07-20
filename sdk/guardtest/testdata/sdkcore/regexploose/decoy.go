package regexploose

// MustCompile is a local same-named helper — the scan resolves through the
// real regexp import and must keep it clean.
func MustCompile(p string) string { return p }

var decoy = MustCompile(`x`)
