// Fixture: knobs read below stay clean; UnreadKnob (inline section),
// Retries (named section type), and TTL (embedded section) have no read
// site and must be flagged. Ext's cross-package section type cannot be
// enumerated from the AST — the scan must fail closed on it, not skip.
package fixture

import "example.com/extern"

type reportConfig struct {
	Tuning struct {
		UnreadKnob int `doc:"never read"`
		UsedKnob   int `doc:"read in use()"`
	}
	Store diskSection
	CacheSection
	Ext extern.PoolSection
}

type diskSection struct {
	Path    string `doc:"read in use()"`
	Retries int    `doc:"never read"`
}

type CacheSection struct {
	TTL     int `doc:"never read"`
	Refresh int `doc:"read in use()"`
}

func use(c reportConfig) (int, string, int) {
	return c.Tuning.UsedKnob, c.Store.Path, c.CacheSection.Refresh
}
