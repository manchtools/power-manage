package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// TableClassification enumerates the single storage class of every public table.
type TableClassification struct {
	Events      []string
	Projections []string
	Work        []string
	Operational []string
	Artifacts   []string
	Migrations  []string
	Exceptions  []string
}

// ProductionTableClassification returns the exact production table registry.
func ProductionTableClassification() TableClassification {
	return TableClassification{
		Events: []string{"events"},
		Projections: []string{
			"authorization_grants",
			"authorization_roles",
			"assignments",
			"bootstrap_logins",
			"ca_rotation_state",
			"certificate_revocations",
			"device_groups",
			"devices",
			"gateways",
			"inventory_snapshots",
			"managed_user_group_members",
			"managed_user_groups",
			"managed_action_sets",
			"managed_actions",
			"oidc_providers",
			"personal_access_tokens",
			"refresh_families",
			"refresh_tokens",
			"registration_tokens",
			"scim_group_members",
			"scim_groups",
			"scim_identities",
			"scim_providers",
			"server_settings",
			"compliance_policies",
			"oidc_identities",
			"users",
		},
		Work:        []string{"work_items"},
		Operational: []string{"crl_state", "crl_work_receipts", "execution_output_chunks", "execution_outputs", "oidc_login_states"},
		Migrations:  []string{"goose_db_version"},
		Exceptions:  []string{"user_encryption_keys"},
	}
}

// CheckTableClassification validates the live public schema.
func CheckTableClassification(
	ctx context.Context,
	pool *pgxpool.Pool,
	classification TableClassification,
) error {
	if ctx == nil {
		return errors.New("store: nil table-classification context")
	}
	if pool == nil {
		return errors.New("store: nil Postgres pool")
	}
	tables, err := generated.New(pool).ListPublicTables(ctx)
	if err != nil {
		return fmt.Errorf("store: list public tables: %w", err)
	}
	if err := validateTableClassification(tables, classification); err != nil {
		return fmt.Errorf("store: classify public tables: %w", err)
	}
	return nil
}

func validateTableClassification(discovered []string, classification TableClassification) error {
	if len(discovered) == 0 {
		return errors.New("zero public tables discovered")
	}
	type tableClass struct {
		name     string
		tables   []string
		required bool
	}
	classes := []tableClass{
		{name: "events", tables: classification.Events, required: true},
		{name: "projection", tables: classification.Projections, required: true},
		{name: "work", tables: classification.Work, required: true},
		{name: "operational telemetry", tables: classification.Operational, required: true},
		{name: "artifact", tables: classification.Artifacts, required: true},
		{name: "migration", tables: classification.Migrations, required: true},
		{name: "exception", tables: classification.Exceptions},
	}
	owners := make(map[string]string)
	required := make(map[string]struct{})
	for _, class := range classes {
		for _, table := range class.tables {
			if strings.TrimSpace(table) == "" {
				return fmt.Errorf("%s class contains an empty table name", class.name)
			}
			if owner, ok := owners[table]; ok {
				return fmt.Errorf("table %q belongs to both %s and %s classes", table, owner, class.name)
			}
			owners[table] = class.name
			if class.required {
				required[table] = struct{}{}
			}
		}
	}
	if len(owners) == 0 {
		return errors.New("table classification registry is empty")
	}
	live := make(map[string]struct{}, len(discovered))
	var unclassified []string
	for _, table := range discovered {
		live[table] = struct{}{}
		if _, ok := owners[table]; !ok {
			unclassified = append(unclassified, table)
		}
	}
	if len(unclassified) > 0 {
		slices.Sort(unclassified)
		return fmt.Errorf("unclassified public tables: %s", strings.Join(unclassified, ", "))
	}
	var missing []string
	for table := range required {
		if _, ok := live[table]; !ok {
			missing = append(missing, table)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf("classified tables missing from public schema: %s", strings.Join(missing, ", "))
	}
	return nil
}
