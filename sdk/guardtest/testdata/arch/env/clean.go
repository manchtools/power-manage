// Fixture: a same-named helper from an unrelated package and env
// WRITES — neither is an environment read.
package fixture

import (
	settings "example.com/settings"
	"os"
)

func cleanRead() string {
	return settings.Getenv("PM_FAKE")
}

func cleanWrite() error {
	return os.Setenv("PM_FAKE", "x")
}
