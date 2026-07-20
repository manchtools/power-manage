// G-7 deny-list liveness fixture (import family). This file lives under
// testdata, so the Go toolchain never compiles it and the banned module is
// never a real dependency — the deny-list scan parses it as data and must
// flag the import. A blank import keeps it parseable without a use site.
package dispatch

import _ "github.com/hibiken/asynq"
