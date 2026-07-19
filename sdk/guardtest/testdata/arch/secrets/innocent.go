// Fixture: qualified-key look-alikes in a Config struct, a secret field
// in a type NOT named *Config (naming-convention ceiling, recorded), and
// an innocent flag.
package fixture

import "flag"

type helperConfig struct {
	SortKey   string
	KeyPrefix string
	Keyboard  string
}

type creds struct {
	Token string
}

var listen = flag.String("listen-addr", "", "bind address")
