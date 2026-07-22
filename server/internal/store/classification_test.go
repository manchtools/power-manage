package store

import (
	"context"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/guardtest"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Guards: INV-12.
func TestGuard_TableClassification(t *testing.T) {
	pool := testPostgres(t)
	tables := guardtest.Discover(t, "public Postgres tables", 7, func() ([]string, error) {
		return generated.New(pool).ListPublicTables(context.Background())
	})
	if err := validateTableClassification(tables, ProductionTableClassification()); err != nil {
		t.Fatalf("validate production table classification: %v", err)
	}
	if err := CheckTableClassification(
		context.Background(),
		pool,
		ProductionTableClassification(),
	); err != nil {
		t.Fatalf("check production table classification: %v", err)
	}
}

func TestTableClassificationGuard_RejectsUnclassifiedTable(t *testing.T) {
	pool := testPostgres(t)
	if _, err := pool.Exec(context.Background(), `CREATE TABLE rogue_table (id bigint PRIMARY KEY)`); err != nil {
		t.Fatalf("create unclassified table: %v", err)
	}
	err := CheckTableClassification(
		context.Background(),
		pool,
		ProductionTableClassification(),
	)
	if err == nil || !strings.Contains(err.Error(), "rogue_table") {
		t.Fatalf("classification error = %v; want unclassified table name", err)
	}
}

func TestTableClassificationGuard_MatchesZero(t *testing.T) {
	err := validateTableClassification(nil, ProductionTableClassification())
	if err == nil || !strings.Contains(err.Error(), "zero") {
		t.Fatalf("zero-table classification error = %v; want matches-zero failure", err)
	}
}

func TestTableClassificationGuard_RejectsDuplicateClass(t *testing.T) {
	classification := ProductionTableClassification()
	classification.Projections = append(classification.Projections, "events")
	err := validateTableClassification(productionTableNames(), classification)
	if err == nil || !strings.Contains(err.Error(), "events") {
		t.Fatalf("duplicate-classification error = %v; want duplicate table name", err)
	}
}

func productionTableNames() []string {
	return []string{
		"events",
		"execution_output_chunks",
		"execution_outputs",
		"goose_db_version",
		"inventory_snapshots",
		"registration_tokens",
		"work_items",
	}
}
