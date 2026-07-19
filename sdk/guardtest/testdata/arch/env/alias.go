// Fixture: an aliased import and a parenthesized callee — neither
// hides the read.
package fixture

import osx "os"

func aliased() (string, bool) {
	return osx.LookupEnv("PM_FAKE")
}

func wrapped() []string {
	return (osx.Environ)()
}
