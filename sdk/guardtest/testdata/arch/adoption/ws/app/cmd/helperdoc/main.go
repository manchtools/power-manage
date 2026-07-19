// Fixture: a binary that adopts the loader but whose test file calls Doc
// only from a non-Test helper — the :docs demand must still fire.
package main

import (
	"fmt"

	_ "example.com/pm/sdk/config"
)

func main() { fmt.Println("helperdoc") }
