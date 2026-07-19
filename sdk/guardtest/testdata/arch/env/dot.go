// Fixture: a dot import resolves unqualified Getenv to package os —
// still a read.
package fixture

import . "os"

func dotted() string {
	return Getenv("PM_FAKE")
}
