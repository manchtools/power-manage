package generic

import g "example.com/registry"

// Planted violations: explicitly instantiated generic calls arrive as
// IndexExpr (one type arg) / IndexListExpr (several) — the ban must not
// be bypassable by instantiation.
func one() { g.Make[int]() }

func two() { g.Make[int, string]() }
