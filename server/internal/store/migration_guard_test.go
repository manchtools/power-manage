package store

import (
	"context"
	"errors"
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
	"github.com/jackc/pgx/v5/pgconn"
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

func TestUserSessionVersionCheck_UsesDeferredValidationMigration(t *testing.T) {
	const sessionInvalidationVersion = 19
	const sessionValidationVersion = 20
	const constraintName = "users_session_version_check"
	const usersTablePattern = `(?:"?public"?\s*\.\s*)?"?users"?`

	migrationPath := migrationPathByVersion(t, sessionInvalidationVersion)
	up := migrationUpSQL(t, migrationPath)
	addsNotValid := regexp.MustCompile(
		`(?is)\bALTER\s+TABLE\s+(?:ONLY\s+)?` + usersTablePattern +
			`[^;]*\bADD\s+CONSTRAINT\s+"?` +
			regexp.QuoteMeta(constraintName) +
			`"?\s+CHECK\s*\(\s*session_version\s*>\s*0\s*\)\s+NOT\s+VALID\s*;`,
	)
	if !addsNotValid.MatchString(up) {
		t.Fatalf("migration 019 must add CHECK constraint %q as NOT VALID", constraintName)
	}
	separateAlterFixture := `
		ALTER TABLE ONLY public.users
		ADD CONSTRAINT users_session_version_check
		CHECK (session_version > 0) NOT VALID;
	`
	if !addsNotValid.MatchString(separateAlterFixture) {
		t.Fatal("session-version constraint guard rejected a separate ALTER TABLE ONLY statement")
	}

	validatesLater := regexp.MustCompile(
		`(?is)\bALTER\s+TABLE\s+(?:ONLY\s+)?` + usersTablePattern +
			`\s+VALIDATE\s+CONSTRAINT\s+"?` + regexp.QuoteMeta(constraintName) + `"?\s*;`,
	)
	validationUp := migrationUpSQL(t, migrationPathByVersion(t, sessionValidationVersion))
	if !validatesLater.MatchString(validationUp) {
		t.Fatalf("migration 020 must validate constraint %q", constraintName)
	}
}

func TestCARotationMigration_BackfillsGlobalPositionDeterministically(t *testing.T) {
	migrationPath := migrationPathByVersion(t, 13)

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

func TestCARotationMigration_AppliesToEmptyPreUpgradeState(t *testing.T) {
	migrationPath := migrationPathByVersion(t, 13)
	database := testPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := database.Exec(ctx, migrationDownSQL(t, migrationPath), pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatalf("roll back migration 013 empty-state fixture: %v", err)
	}

	var events, revocations int
	if err := database.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM events),
		(SELECT count(*) FROM certificate_revocations)`).Scan(&events, &revocations); err != nil {
		t.Fatalf("read empty pre-migration state: %v", err)
	}
	if events != 0 || revocations != 0 {
		t.Fatalf("empty pre-migration state = (%d events, %d revocations); want both zero", events, revocations)
	}
	if _, err := database.Exec(ctx, migrationUpSQL(t, migrationPath), pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatalf("apply migration 013 to empty state: %v", err)
	}

	var nextPosition int64
	if err := database.QueryRow(ctx, `
		INSERT INTO events (
			stream_type, stream_id, stream_version, event_type,
			payload_version, payload
		) VALUES ('device', '01J00000000000000000000005', 1, 'first', 1, '{}')
		RETURNING global_position`).Scan(&nextPosition); err != nil {
		t.Fatalf("insert first event after empty migration: %v", err)
	}
	if nextPosition != 1 {
		t.Fatalf("first empty-state global position = %d; want 1", nextPosition)
	}
}

func TestCARotationMigration_RejectsLegacyRevocationsWithoutIssuerIdentity(t *testing.T) {
	migrationPath := migrationPathByVersion(t, 13)

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

	const wantMigrationError = "issuer-scoped revocation migration requires empty legacy certificate_revocations"
	_, err := database.Exec(ctx, migrationUpSQL(t, migrationPath), pgx.QueryExecModeSimpleProtocol)
	if err == nil || !strings.Contains(err.Error(), wantMigrationError) {
		t.Fatalf("migration 013 with legacy revocation error = %v; want explicit issuer-identity refusal", err)
	}
}

func TestExecutionTargetMigration_AppliesToEmptyPreUpgradeState(t *testing.T) {
	migrationPath := migrationPathByVersion(t, 28)
	database := testPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := database.Exec(
		ctx,
		migrationDownSQL(t, migrationPath),
		pgx.QueryExecModeSimpleProtocol,
	); err != nil {
		t.Fatalf("roll back migration 028 empty-state fixture: %v", err)
	}
	if _, err := database.Exec(
		ctx,
		migrationUpSQL(t, migrationPath),
		pgx.QueryExecModeSimpleProtocol,
	); err != nil {
		t.Fatalf("apply migration 028 to empty state: %v", err)
	}
	var nullable string
	if err := database.QueryRow(ctx, `
		SELECT is_nullable
		FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND table_name = 'execution_outputs'
		  AND column_name = 'device_id'`).Scan(&nullable); err != nil {
		t.Fatalf("inspect execution target nullability: %v", err)
	}
	if nullable != "NO" {
		t.Fatalf("execution target nullability = %q; want NO", nullable)
	}
}

func TestExecutionTargetMigration_RejectsUnattributablePreUpgradeRows(t *testing.T) {
	migrationPath := migrationPathByVersion(t, 28)
	database := testPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := database.Exec(
		ctx,
		migrationDownSQL(t, migrationPath),
		pgx.QueryExecModeSimpleProtocol,
	); err != nil {
		t.Fatalf("roll back migration 028 populated-state fixture: %v", err)
	}
	if _, err := database.Exec(ctx, `
		INSERT INTO execution_outputs (
			execution_id, output_bytes, output_chunks, truncated, updated_at
		) VALUES ('01J00000000000000000000185', 0, 0, false, now())`); err != nil {
		t.Fatalf("seed pre-migration execution output: %v", err)
	}
	const wantMigrationError = "execution target migration requires empty execution_outputs; existing rows cannot be assigned exact device identities"
	_, err := database.Exec(
		ctx,
		migrationUpSQL(t, migrationPath),
		pgx.QueryExecModeSimpleProtocol,
	)
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Message != wantMigrationError {
		t.Fatalf("migration 028 populated-state error = %v; want explicit attribution refusal", err)
	}
	var deviceColumnCount int
	if err := database.QueryRow(ctx, `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND table_name = 'execution_outputs'
		  AND column_name = 'device_id'`).Scan(&deviceColumnCount); err != nil {
		t.Fatalf("inspect failed execution-target migration: %v", err)
	}
	if deviceColumnCount != 0 {
		t.Fatalf("device_id columns after rejected migration = %d; want zero", deviceColumnCount)
	}
}

func TestProjectionIdentifierArraysRejectMalformedULIDs(t *testing.T) {
	database := testPostgres(t)
	tests := []struct {
		name       string
		query      string
		constraint string
	}{
		{
			name: "static device IDs",
			query: `INSERT INTO device_groups (
				device_group_id, name, dynamic_query, static_device_ids,
				projection_version, updated_at
			) VALUES (
				'01J00000000000000000000186', 'devices', '',
				ARRAY['not-a-ulid'], 1, now()
			)`,
			constraint: "device_groups_static_device_ids_ulid_check",
		},
		{
			name: "compliance rule action IDs",
			query: `INSERT INTO compliance_policies (
				policy_id, name, rule_action_ids, grace_hours,
				projection_version, updated_at
			) VALUES (
				'01J00000000000000000000187', 'baseline',
				ARRAY['not-a-ulid'], 24, 1, now()
			)`,
			constraint: "compliance_policies_rule_action_ids_ulid_check",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := database.Exec(t.Context(), test.query)
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) ||
				postgresError.Code != "23514" ||
				postgresError.ConstraintName != test.constraint {
				t.Fatalf(
					"malformed ID array error = %v; want SQLSTATE 23514 constraint %q",
					err,
					test.constraint,
				)
			}
		})
	}
}

type sqlMigration struct {
	version int
	path    string
}

func migrationPathByVersion(t *testing.T, version int) string {
	t.Helper()
	for _, migration := range discoverSQLMigrations(t, "migrations") {
		if migration.version == version {
			return migration.path
		}
	}
	t.Fatalf("migration %03d is absent", version)
	return ""
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
