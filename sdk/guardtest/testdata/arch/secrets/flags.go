// Fixture: secret-named flags on argv (flagged) and their -file forms
// (clean).
package fixture

import "flag"

var (
	tok     = flag.String("auth-token", "", "secret on argv")
	tokFile = flag.String("auth-token-file", "", "path indirection")
)

func register(dst *string) {
	flag.StringVar(dst, "client-secret", "", "secret on argv")
	flag.StringVar(dst, "client-secret-file", "", "path indirection")
}
