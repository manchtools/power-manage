package authz

import (
	"slices"
	"testing"

	"github.com/manchtools/power-manage/sdk/guardtest"
)

func TestGuard_PermissionCatalogClassification(t *testing.T) {
	entries := Catalog()
	names := guardtest.Discover(t, "authorization permission catalog", 1, func() ([]string, error) {
		discovered := make([]string, 0, len(entries))
		for _, entry := range entries {
			discovered = append(discovered, string(entry.Name))
		}
		return discovered, nil
	})
	if err := validateCatalog(entries); err != nil {
		t.Fatalf("validate production permission catalog: %v", err)
	}
	if !slices.IsSorted(names) {
		t.Fatalf("permission catalog names are not deterministic: %v", names)
	}
}

func TestValidateCatalog_RejectsIncompleteEntries(t *testing.T) {
	valid := []CatalogEntry{
		{Name: "devices.manage", Class: Confinable},
		{
			Name:      "roles.manage",
			Class:     GlobalOnly,
			Rationale: "role and grant definitions alter global authorization",
		},
	}
	tests := map[string][]CatalogEntry{
		"empty": nil,
		"unclassified": append(slices.Clone(valid), CatalogEntry{
			Name: "users.manage",
		}),
		"unknown classification": append(slices.Clone(valid), CatalogEntry{
			Name:  "users.manage",
			Class: ScopeClass("unknown"),
		}),
		"global rationale missing": {
			{Name: "roles.manage", Class: GlobalOnly},
		},
		"duplicate": append(slices.Clone(valid), valid[0]),
		"uppercase": append(slices.Clone(valid), CatalogEntry{
			Name:  "Users.manage",
			Class: Confinable,
		}),
		"scope suffix": append(slices.Clone(valid), CatalogEntry{
			Name:  "users.manage:self",
			Class: Confinable,
		}),
		"dotted scope suffix": append(slices.Clone(valid), CatalogEntry{
			Name:  "users.manage.self",
			Class: Confinable,
		}),
		"unsorted": {valid[1], valid[0]},
	}
	for name, entries := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateCatalog(entries); err == nil {
				t.Fatal("validateCatalog accepted an incomplete catalog")
			}
		})
	}
}

func TestCatalog_DefensivelyCopiedAndLookupFailsClosed(t *testing.T) {
	first := Catalog()
	if len(first) == 0 {
		t.Fatal("production permission catalog is empty")
	}
	original := first[0]
	first[0] = CatalogEntry{Name: "mutated.manage", Class: GlobalOnly}

	second := Catalog()
	if len(second) == 0 || second[0] != original {
		t.Fatalf("mutating a returned catalog changed production data: %+v", second)
	}
	for _, entry := range second {
		got, ok := Lookup(entry.Name)
		if !ok || got != entry {
			t.Fatalf("Lookup(%q) = (%+v, %t); want (%+v, true)", entry.Name, got, ok, entry)
		}
	}
	for _, unknown := range []Permission{
		"",
		"Users.manage",
		"users.manage:self",
		"users.manage.self",
		"unknown.manage",
	} {
		if entry, ok := Lookup(unknown); ok {
			t.Fatalf("Lookup(%q) = (%+v, true); want fail-closed miss", unknown, entry)
		}
	}
}
