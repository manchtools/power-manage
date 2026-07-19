// Fixture: the per-binary docs test the adoption guard demands — a test
// in the binary's package calling the loader's Doc.
package main

import (
	"testing"

	"example.com/pm/sdk/config"
)

func TestConfigDocs(t *testing.T) {
	_, _ = config.Doc(nil)
}
