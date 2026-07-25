package store

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/manchtools/power-manage/server/internal/authz"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const lastAdminPermission authz.Permission = "roles.manage"

var (
	// ErrLastAdmin identifies a mutation rolled back to preserve an enabled administrator.
	ErrLastAdmin = errors.New("store: at least one enabled administrator is required")

	errInvalidLastAdminPolicy = errors.New("store: invalid last-admin policy")
)

type lastAdminEffect uint8

const (
	lastAdminEffectUnknown lastAdminEffect = iota
	lastAdminUnaffected
	lastAdminMayReduce
)

func lastAdminSensitiveEventDefinitions(
	definitions map[string]eventDefinition,
	targets map[string]RebuildTarget,
) (map[string]eventDefinition, error) {
	result := make(map[string]eventDefinition)
	for targetName, target := range targets {
		touchesAdminState := slices.ContainsFunc(
			append(slices.Clone(target.Tables), target.SharedTables...),
			lastAdminProjectionTable,
		)
		if !touchesAdminState {
			continue
		}
		for _, eventType := range target.EventTypes {
			definition, ok := definitions[eventType]
			if !ok {
				return nil, fmt.Errorf(
					"%w: target %q references unknown event %q",
					errInvalidLastAdminPolicy,
					targetName,
					eventType,
				)
			}
			result[eventType] = definition
		}
	}
	return result, nil
}

func lastAdminProjectionTable(table string) bool {
	switch table {
	case "authorization_grants",
		"authorization_roles",
		"managed_user_group_members",
		"managed_user_groups",
		"scim_group_members",
		"scim_groups",
		"users":
		return true
	default:
		return false
	}
}

func validateLastAdminEffects(definitions map[string]eventDefinition) error {
	if len(definitions) == 0 {
		return fmt.Errorf("%w: event definitions are empty", errInvalidLastAdminPolicy)
	}
	entry, ok := authz.Lookup(lastAdminPermission)
	if !ok || entry.Class != authz.GlobalOnly {
		return fmt.Errorf(
			"%w: permission is not cataloged as global-only",
			errInvalidLastAdminPolicy,
		)
	}
	reducing := 0
	for _, eventType := range slices.Sorted(maps.Keys(definitions)) {
		switch definitions[eventType].LastAdminEffect {
		case lastAdminUnaffected:
		case lastAdminMayReduce:
			reducing++
		default:
			return fmt.Errorf(
				"%w: event %q has no valid effect classification",
				errInvalidLastAdminPolicy,
				eventType,
			)
		}
	}
	if reducing == 0 {
		return fmt.Errorf("%w: no reducing events", errInvalidLastAdminPolicy)
	}
	return nil
}

func lastAdminReductionEventTypes(
	definitions map[string]eventDefinition,
) []string {
	eventTypes := make([]string, 0, len(definitions))
	for eventType, definition := range definitions {
		if definition.LastAdminEffect == lastAdminMayReduce {
			eventTypes = append(eventTypes, eventType)
		}
	}
	slices.Sort(eventTypes)
	return eventTypes
}

func lastAdminReductionEventSet(
	definitions map[string]eventDefinition,
) map[string]struct{} {
	eventTypes := lastAdminReductionEventTypes(definitions)
	result := make(map[string]struct{}, len(eventTypes))
	for _, eventType := range eventTypes {
		result[eventType] = struct{}{}
	}
	return result
}

// protectLastAdminMutation runs its lock, counts, and mutation on one
// caller-owned transaction. The caller commits only after this function
// returns successfully.
func protectLastAdminMutation(
	ctx context.Context,
	tx pgx.Tx,
	protect bool,
	mutate func(*generated.Queries) error,
) error {
	if tx == nil || mutate == nil {
		return errors.New("store: invalid last-admin mutation")
	}
	queries := generated.New(tx)
	if !protect {
		return mutate(queries)
	}
	if err := queries.AcquireLastAdminMutationLock(ctx); err != nil {
		return fmt.Errorf("store: acquire last-admin mutation lock: %w", err)
	}
	before, err := queries.CountEnabledAdmins(ctx, string(lastAdminPermission))
	if err != nil {
		return fmt.Errorf("store: count enabled administrators before mutation: %w", err)
	}
	if err := mutate(queries); err != nil {
		return err
	}
	if before == 0 {
		return nil
	}
	after, err := queries.CountEnabledAdmins(ctx, string(lastAdminPermission))
	if err != nil {
		return fmt.Errorf("store: count enabled administrators after mutation: %w", err)
	}
	if after == 0 {
		return ErrLastAdmin
	}
	return nil
}

// IsLastAdmin recognizes the stable last-enabled-administrator rejection.
func IsLastAdmin(err error) bool {
	return errors.Is(err, ErrLastAdmin)
}
