// Fixture: a read inside a closure still belongs to the enclosing
// declaration — descent into function literals must not be skipped.
package fixture

import "os"

func viaClosure() string {
	f := func() string {
		return os.Getenv("PM_FAKE")
	}
	return f()
}
