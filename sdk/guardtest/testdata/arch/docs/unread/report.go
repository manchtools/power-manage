// Fixture: knobs read below stay clean; UnreadKnob (inline section),
// Retries (named section type), and TTL (embedded section) have no read
// site and must be flagged. Cross-package section types — named (Ext)
// AND embedded (RemoteSection) — cannot be enumerated from the AST; the
// scan must fail closed on each, never skip.
package fixture

import "example.com/extern"

type reportConfig struct {
	Tuning struct {
		UnreadKnob int `doc:"never read"`
		UsedKnob   int `doc:"read in use()"`
	}
	Store diskSection
	CacheSection
	extern.RemoteSection
	winSection[int]
	Ext extern.PoolSection
}

type winSection[T any] struct {
	Limit T `doc:"generic sections resolve to no plain struct decl"`
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
