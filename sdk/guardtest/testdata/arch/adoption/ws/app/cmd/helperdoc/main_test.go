// Fixture: Doc is called only from a helper, never inside a Test
// function body — file-level presence must not satisfy the :docs demand.
package main

import (
	"testing"

	"example.com/pm/sdk/config"
)

func renderReference() {
	_, _ = config.Doc(nil)
}

func TestUnrelated(t *testing.T) {
	_ = t
}
