// Fixture: a plain read in a function body and a read in a var
// initializer (attributed to the var's decl unit).
package fixture

import "os"

func plain() string {
	return os.Getenv("PM_FAKE")
}

var home = os.ExpandEnv("$HOME/x")
