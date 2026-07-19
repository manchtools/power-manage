package liveness

import "testing"

// Deliberate G-000-3 violation: a guard that never calls the harness. This
// file is the standing red proof that the conformance scan still detects
// non-conforming guards — it must stay non-conforming.
func TestGuard_Fixture(t *testing.T) {}
