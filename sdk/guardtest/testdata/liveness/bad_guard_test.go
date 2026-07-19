package liveness

import "testing"

// Deliberate G-000-3 violation: a guard that never calls the harness. This
// file is the standing red proof that the conformance scan still detects
// non-conforming guards — it must stay non-conforming. Its registration
// line below must NOT count as coverage for G-000-1.
//
// Guards: INV-12.
func TestGuard_Fixture(t *testing.T) {}
