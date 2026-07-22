package store

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
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
