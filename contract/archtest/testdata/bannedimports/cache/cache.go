// G-7 deny-list liveness fixture (import family): a second banned dependency
// family (a Valkey/Redis client) in a separate package, proving the scan
// spans the whole tree, not one file. Under testdata — never compiled.
package cache

import _ "github.com/valkey-io/valkey-go"
