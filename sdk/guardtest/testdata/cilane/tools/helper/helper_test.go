package helper

import "testing"

// Planted violation: a test-bearing package in a depth-2 module — invisible
// to verify.sh's depth-1 `*/go.mod` walk, so CI would never run this test.
func TestHelper(t *testing.T) {}
