// Fixture: a binary adopting the shared loader.
package main

import (
	"fmt"

	_ "example.com/pm/sdk/config"
)

func main() { fmt.Println("configured") }
