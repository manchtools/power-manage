// G-7 deny-list liveness fixture (import family): the clean sibling. A Postgres
// or stdlib dependency is the sanctioned replacement for the banned middle tier
// ([WIRE-30]); the scan must leave it untouched. Under testdata — never
// compiled.
package clean

import (
	_ "database/sql"

	_ "github.com/jackc/pgx/v5"
)
