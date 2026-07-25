package store

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/guardtest"
)

func TestGuard_LastAdminSensitiveEventsAreTotallyClassified(t *testing.T) {
	definitions, err := lastAdminSensitiveEventDefinitions(
		productionEventDefinitions(),
		productionRebuildTargets(),
	)
	if err != nil {
		t.Fatalf("discover last-admin-sensitive events: %v", err)
	}
	guardtest.Discover(
		t,
		"last-admin-sensitive production events",
		1,
		func() ([]string, error) {
			return slices.Sorted(maps.Keys(definitions)), nil
		},
	)
	if err := validateLastAdminEffects(definitions); err != nil {
		t.Fatalf("validate last-admin event effects: %v", err)
	}
	reductions := lastAdminReductionEventTypes(definitions)
	guardtest.Discover(
		t,
		"last-admin-reducing production events",
		1,
		func() ([]string, error) {
			return reductions, nil
		},
	)
}

func TestLastAdminEffectGuard_RejectsMissingUnknownAndZeroReducing(t *testing.T) {
	allDefinitions := productionEventDefinitions()
	targets := productionRebuildTargets()
	definitions, err := lastAdminSensitiveEventDefinitions(allDefinitions, targets)
	if err != nil {
		t.Fatalf("discover last-admin-sensitive events: %v", err)
	}
	first := slices.Min(slices.Collect(maps.Keys(definitions)))

	fixtureTargets := maps.Clone(targets)
	fixtureTargets["fixture"] = RebuildTarget{
		Tables:     []string{"users"},
		EventTypes: []string{"FixtureAdminMutation"},
	}
	if _, err := lastAdminSensitiveEventDefinitions(
		allDefinitions,
		fixtureTargets,
	); !errors.Is(err, errInvalidLastAdminPolicy) ||
		!strings.Contains(err.Error(), "FixtureAdminMutation") {
		t.Fatalf("undiscovered-event error = %v; want fixture event name", err)
	}

	missing := maps.Clone(definitions)
	entry := missing[first]
	entry.LastAdminEffect = lastAdminEffectUnknown
	missing[first] = entry
	if err := validateLastAdminEffects(missing); !errors.Is(err, errInvalidLastAdminPolicy) ||
		!strings.Contains(err.Error(), first) {
		t.Fatalf("missing-effect error = %v; want event name", err)
	}

	unknown := maps.Clone(definitions)
	entry = unknown[first]
	entry.LastAdminEffect = lastAdminEffect(255)
	unknown[first] = entry
	if err := validateLastAdminEffects(unknown); !errors.Is(err, errInvalidLastAdminPolicy) ||
		!strings.Contains(err.Error(), first) {
		t.Fatalf("unknown-effect error = %v; want event name", err)
	}

	noReductions := maps.Clone(definitions)
	for eventType, definition := range noReductions {
		definition.LastAdminEffect = lastAdminUnaffected
		noReductions[eventType] = definition
	}
	if err := validateLastAdminEffects(noReductions); !errors.Is(err, errInvalidLastAdminPolicy) ||
		!strings.Contains(err.Error(), "no reducing events") {
		t.Fatalf("zero-reducing error = %v; want non-vacuous failure", err)
	}

	if err := validateLastAdminEffects(nil); !errors.Is(err, errInvalidLastAdminPolicy) ||
		!strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty-definitions error = %v; want empty failure", err)
	}
}
