package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestGatewayTokenChecks_UseDeferredValidationMigration(t *testing.T) {
	const gatewayIdentityVersion = 11
	constraintNames := []string{
		"registration_tokens_purpose_check",
		"registration_tokens_dns_names_check",
	}
	migrations := discoverSQLMigrations(t, "migrations")
	var gatewayIdentity []sqlMigration
	for _, migration := range migrations {
		if migration.version == gatewayIdentityVersion {
			gatewayIdentity = append(gatewayIdentity, migration)
		}
	}
	if len(gatewayIdentity) != 1 {
		t.Fatalf("gateway identity migration matches = %d; want exactly one version 011 migration", len(gatewayIdentity))
	}
	up := migrationUpSQL(t, gatewayIdentity[0].path)
	for _, constraintName := range constraintNames {
		pattern := regexp.MustCompile(
			`(?is)\bALTER\s+TABLE\s+` + registrationTokensTablePattern() +
				`\s+ADD\s+CONSTRAINT\s+"?` + regexp.QuoteMeta(constraintName) + `"?\s+CHECK\s*\([^;]*\)\s+NOT\s+VALID\s*;`,
		)
		if !pattern.MatchString(up) {
			t.Errorf("migration 011 must add CHECK constraint %q as NOT VALID in its forward section", constraintName)
		}
	}

	var later []sqlMigration
	for _, migration := range migrations {
		if migration.version > gatewayIdentityVersion {
			later = append(later, migration)
		}
	}
	if len(later) == 0 {
		t.Fatal("no migration later than 011 discovered to validate gateway token CHECK constraints")
	}
	for _, migration := range later {
		up := migrationUpSQL(t, migration.path)
		validatesAll := true
		for _, constraintName := range constraintNames {
			if !validateConstraintPattern(constraintName).MatchString(up) {
				validatesAll = false
				break
			}
		}
		if validatesAll {
			return
		}
	}
	t.Fatalf("no forward migration later than 011 validates both exact constraints %v", constraintNames)
}

func TestCARotationMigration_BackfillsGlobalPositionDeterministically(t *testing.T) {
	const caRotationVersion = 13
	migrations := discoverSQLMigrations(t, "migrations")
	var migrationPath string
	for _, migration := range migrations {
		if migration.version == caRotationVersion {
			migrationPath = migration.path
			break
		}
	}
	if migrationPath == "" {
		t.Fatal("CA rotation migration 013 is absent")
	}

	database := testPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := database.Exec(ctx, migrationDownSQL(t, migrationPath), pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatalf("roll back migration 013 fixture: %v", err)
	}
	earlier := time.Date(2026, time.July, 23, 8, 0, 0, 0, time.UTC)
	later := earlier.Add(time.Minute)
	if _, err := database.Exec(ctx, `
		INSERT INTO events (
			stream_type, stream_id, stream_version, event_type,
			payload_version, payload, created_at
		) VALUES
			('zeta', '01J00000000000000000000002', 1, 'fourth', 1, '{}', $2),
			('zeta', '01J00000000000000000000001', 2, 'second', 1, '{}', $1),
			('alpha', '01J00000000000000000000002', 1, 'third', 1, '{}', $2),
			('zeta', '01J00000000000000000000001', 1, 'first', 1, '{}', $1)`,
		earlier, later,
	); err != nil {
		t.Fatalf("seed pre-migration events: %v", err)
	}
	if _, err := database.Exec(ctx, migrationUpSQL(t, migrationPath), pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatalf("apply migration 013 fixture: %v", err)
	}

	rows, err := database.Query(ctx, `SELECT event_type, global_position FROM events ORDER BY global_position`)
	if err != nil {
		t.Fatalf("query backfilled global positions: %v", err)
	}
	defer rows.Close()
	var eventTypes []string
	var positions []int64
	for rows.Next() {
		var eventType string
		var position int64
		if err := rows.Scan(&eventType, &position); err != nil {
			t.Fatalf("scan backfilled global position: %v", err)
		}
		eventTypes = append(eventTypes, eventType)
		positions = append(positions, position)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate backfilled global positions: %v", err)
	}
	if !slices.Equal(eventTypes, []string{"first", "second", "third", "fourth"}) ||
		!slices.Equal(positions, []int64{1, 2, 3, 4}) {
		t.Fatalf("backfilled events = (%v, %v); want deterministic semantic order and positions 1..4", eventTypes, positions)
	}

	var nextPosition int64
	if err := database.QueryRow(ctx, `
		INSERT INTO events (
			stream_type, stream_id, stream_version, event_type,
			payload_version, payload, created_at
		) VALUES ('omega', '01J00000000000000000000003', 1, 'next', 1, '{}', $1)
		RETURNING global_position`, later.Add(time.Minute)).Scan(&nextPosition); err != nil {
		t.Fatalf("insert first post-migration event: %v", err)
	}
	if nextPosition != 5 {
		t.Fatalf("first post-migration global position = %d; want 5", nextPosition)
	}
}

func TestCARotationMigration_RejectsLegacyRevocationsWithoutIssuerIdentity(t *testing.T) {
	const caRotationVersion = 13
	var migrationPath string
	for _, migration := range discoverSQLMigrations(t, "migrations") {
		if migration.version == caRotationVersion {
			migrationPath = migration.path
			break
		}
	}
	if migrationPath == "" {
		t.Fatal("CA rotation migration 013 is absent")
	}

	database := testPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := database.Exec(ctx, migrationDownSQL(t, migrationPath), pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatalf("roll back migration 013 fixture: %v", err)
	}
	const streamID = "01J00000000000000000000004"
	if _, err := database.Exec(ctx, `
		INSERT INTO events (
			stream_type, stream_id, stream_version, event_type,
			payload_version, payload
		) VALUES ('device', $1, 1, 'AgentCertificateRevoked', 1, '{}')`, streamID); err != nil {
		t.Fatalf("seed legacy revocation source event: %v", err)
	}
	if _, err := database.Exec(ctx, `
		INSERT INTO certificate_revocations (
			certificate_class, certificate_fingerprint, certificate_der,
			serial_number, revoked_at, reason_code,
			source_stream_type, source_stream_id, source_stream_version
		) VALUES ('agent', $1, $2, $3, now(), 0, 'device', $4, 1)`,
		make([]byte, 32), []byte{1}, []byte{1}, streamID,
	); err != nil {
		t.Fatalf("seed legacy certificate revocation: %v", err)
	}

	_, err := database.Exec(ctx, migrationUpSQL(t, migrationPath), pgx.QueryExecModeSimpleProtocol)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "issuer") {
		t.Fatalf("migration 013 with legacy revocation error = %v; want explicit issuer-identity refusal", err)
	}
}

type sqlMigration struct {
	version int
	path    string
}

func discoverSQLMigrations(t *testing.T, directory string) []sqlMigration {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read migration directory: %v", err)
	}
	namePattern := regexp.MustCompile(`^(\d{3})_.+\.sql$`)
	migrations := make([]sqlMigration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		matches := namePattern.FindStringSubmatch(entry.Name())
		if matches == nil {
			continue
		}
		version, err := strconv.Atoi(matches[1])
		if err != nil {
			t.Fatalf("parse migration version from %q: %v", entry.Name(), err)
		}
		migrations = append(migrations, sqlMigration{version: version, path: filepath.Join(directory, entry.Name())})
	}
	if len(migrations) == 0 {
		t.Fatal("no numbered SQL migrations discovered")
	}
	sort.Slice(migrations, func(i, j int) bool {
		if migrations[i].version == migrations[j].version {
			return migrations[i].path < migrations[j].path
		}
		return migrations[i].version < migrations[j].version
	})
	return migrations
}

func migrationUpSQL(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration %s: %v", path, err)
	}
	parts := strings.SplitN(string(contents), "-- +goose Down", 2)
	if len(parts) != 2 {
		t.Fatalf("migration %s has no exact goose Down boundary", path)
	}
	withoutBlockComments := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(parts[0], " ")
	return regexp.MustCompile(`(?m)--.*$`).ReplaceAllString(withoutBlockComments, " ")
}

func migrationDownSQL(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration %s: %v", path, err)
	}
	parts := strings.SplitN(string(contents), "-- +goose Down", 2)
	if len(parts) != 2 {
		t.Fatalf("migration %s has no exact goose Down boundary", path)
	}
	withoutBlockComments := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(parts[1], " ")
	return regexp.MustCompile(`(?m)--.*$`).ReplaceAllString(withoutBlockComments, " ")
}

func validateConstraintPattern(constraintName string) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(
		`(?is)\bALTER\s+TABLE\s+%s\s+VALIDATE\s+CONSTRAINT\s+"?%s"?\s*;`,
		registrationTokensTablePattern(),
		regexp.QuoteMeta(constraintName),
	))
}

func registrationTokensTablePattern() string {
	return `(?:"?public"?\s*\.\s*)?"?registration_tokens"?`
}
