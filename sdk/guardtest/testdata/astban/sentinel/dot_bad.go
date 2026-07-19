package sentinel

import (
	. "database/sql"
	. "errors"
)

// Planted violation: dot-imports of both the sentinel package and errors —
// the unqualified Is(err, ErrNoRows) must still be flagged.
func isMissingDot(err error) bool { return Is(err, ErrNoRows) }
