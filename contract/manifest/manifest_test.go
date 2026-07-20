package manifest_test

// SPEC-003 M4 sync-manifest monotonicity tests (AC-9, [WIRE-26], choice 9).
// manifest.Newer(epoch, generation, lastEpoch, lastGeneration) is the strict
// lexicographic "(epoch, generation) is strictly after the last accepted pair"
// predicate: a pair <= the last accepted pair is rejected (Newer == false), a
// strictly-later pair is accepted (Newer == true). The manifest travels as the
// `sync-manifest` SignedCommand; its <=15-min validity window is the M3 helper's
// concern (choice 10), so this package holds NO clock and NO freshness logic.

import (
	"math"
	"testing"

	"github.com/manchtools/power-manage/contract/manifest"
)

// pair is a candidate/last (epoch, generation) tuple for the table rows.
type pair struct{ epoch, generation uint64 }

// TestNewer_Rows pins the AC-9 acceptance/rejection boundary across the
// lexicographic edges: equality, a same-epoch generation bump, an epoch bump
// that RESETS generation lower (epoch dominates), a lower epoch that a higher
// generation must not rescue, the zero pair, and the max-uint64 corners.
func TestNewer_Rows(t *testing.T) {
	const maxU = uint64(math.MaxUint64)
	cases := []struct {
		name       string
		cand, last pair
		want       bool
		why        string
	}{
		{
			name: "equal pair is not newer",
			cand: pair{5, 5}, last: pair{5, 5}, want: false,
			why: "AC-9: a pair == the last accepted pair is rejected (<= is rejected)",
		},
		{
			name: "generation bump same epoch is newer",
			cand: pair{5, 6}, last: pair{5, 5}, want: true,
			why: "same epoch, higher generation advances the pair",
		},
		{
			name: "epoch bump with lower generation is newer",
			cand: pair{6, 0}, last: pair{5, 9}, want: true,
			why: "epoch dominates lexicographically: a higher epoch is newer even after a generation reset to 0",
		},
		{
			name: "lower epoch higher generation is not newer",
			cand: pair{4, 100}, last: pair{5, 1}, want: false,
			why: "a lower epoch is stale regardless of a higher generation (no rescue)",
		},
		{
			name: "same epoch lower generation is not newer",
			cand: pair{5, 4}, last: pair{5, 5}, want: false,
			why: "AC-9: a strictly-lower pair is rejected",
		},
		{
			name: "zero vs zero is not newer",
			cand: pair{0, 0}, last: pair{0, 0}, want: false,
			why: "the first-ever pair equals the zero last-accepted and must not re-accept",
		},
		{
			name: "max epoch max generation vs itself is not newer",
			cand: pair{maxU, maxU}, last: pair{maxU, maxU}, want: false,
			why: "equality holds at the uint64 ceiling",
		},
		{
			name: "max epoch generation bump at the ceiling is newer",
			cand: pair{maxU, maxU}, last: pair{maxU, maxU - 1}, want: true,
			why: "generation advances by one at the ceiling",
		},
		{
			name: "epoch bump to ceiling from zero generation is newer",
			cand: pair{maxU, 0}, last: pair{maxU - 1, maxU}, want: true,
			why: "epoch to the ceiling dominates a max generation at a lower epoch",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := manifestNewer(c.cand, c.last)
			if got != c.want {
				t.Errorf("Newer(%d,%d, %d,%d) = %v, want %v — %s (AC-9, [WIRE-26])",
					c.cand.epoch, c.cand.generation, c.last.epoch, c.last.generation, got, c.want, c.why)
			}
		})
	}
}

// TestNewer_StrictOrderProperties drives Newer over a deterministic pseudo-
// random stream of (epoch, generation) pairs (a hand-rolled LCG — fully
// reproducible, no global RNG state) and asserts the three defining properties
// of a strict total order, which AC-9's "<= is rejected, strictly-later is
// accepted" requires:
//   - irreflexivity: Newer(p, p) is never true (equality is not newer),
//   - antisymmetry:  Newer(p, q) and Newer(q, p) are never both true,
//   - trichotomy:    for distinct pairs exactly one of Newer(p,q)/Newer(q,p)
//     holds (the order is total, never leaving two pairs incomparable).
func TestNewer_StrictOrderProperties(t *testing.T) {
	// LCG (Numerical Recipes constants) seeded fixed at 1 for determinism.
	var state uint64 = 1
	next := func() uint64 {
		state = state*6364136223846793005 + 1442695040888963407
		return state
	}
	// Draw from a deliberately small domain so collisions (equal pairs) occur
	// often and exercise the irreflexivity / equality branch.
	drawPair := func() pair {
		return pair{epoch: next() % 4, generation: next() % 4}
	}

	const iterations = 20000
	for i := 0; i < iterations; i++ {
		p, q := drawPair(), drawPair()

		if manifestNewer(p, p) {
			t.Fatalf("irreflexivity broken: Newer(%v, %v) = true — an equal pair must never be newer (AC-9)", p, p)
		}

		pq := manifestNewer(p, q)
		qp := manifestNewer(q, p)
		if pq && qp {
			t.Fatalf("antisymmetry broken: Newer(%v,%v) and Newer(%v,%v) are both true (AC-9)", p, q, q, p)
		}
		if p == q {
			if pq || qp {
				t.Fatalf("equal pairs %v compared as newer in some direction: Newer=%v/%v (AC-9)", p, pq, qp)
			}
			continue
		}
		// Distinct pairs: the order is total, so exactly one direction is newer.
		if pq == qp {
			t.Fatalf("trichotomy broken for distinct pairs %v vs %v: Newer=%v/%v, want exactly one true ([WIRE-26] strict lexicographic order)", p, q, pq, qp)
		}
	}
}

// manifestNewer adapts the pair table to the flat manifest.Newer signature
// (choice 9): Newer(epoch, generation, lastEpoch, lastGeneration).
func manifestNewer(cand, last pair) bool {
	return manifest.Newer(cand.epoch, cand.generation, last.epoch, last.generation)
}
