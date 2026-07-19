// Fixture: knobs read below stay clean; UnreadKnob (inline section) and
// Retries (named section type) have no read site and must be flagged.
package fixture

type reportConfig struct {
	Tuning struct {
		UnreadKnob int `doc:"never read"`
		UsedKnob   int `doc:"read in use()"`
	}
	Store diskSection
}

type diskSection struct {
	Path    string `doc:"read in use()"`
	Retries int    `doc:"never read"`
}

func use(c reportConfig) (int, string) {
	return c.Tuning.UsedKnob, c.Store.Path
}
