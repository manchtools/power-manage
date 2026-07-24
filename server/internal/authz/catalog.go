// Package authz owns control-plane authorization policy and enforcement.
package authz

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

const maxPermissionNameBytes = 128

// Permission is one atomic authorization capability.
type Permission string

// ScopeClass determines whether a grant may narrow a permission.
type ScopeClass string

const (
	// Confinable permits grant-level scope restriction.
	Confinable ScopeClass = "confinable"
	// GlobalOnly activates only through a global grant.
	GlobalOnly ScopeClass = "global-only"
)

// CatalogEntry is the complete policy metadata for one permission.
type CatalogEntry struct {
	Name      Permission
	Class     ScopeClass
	Rationale string
}

var permissionCatalog = [...]CatalogEntry{
	{Name: "action_sets.manage", Class: Confinable},
	{Name: "actions.manage", Class: Confinable},
	{Name: "audit.read", Class: Confinable},
	{
		Name:      "audit_retention.manage",
		Class:     GlobalOnly,
		Rationale: "audit and retention policy changes affect the whole control plane",
	},
	{Name: "devices.manage", Class: Confinable},
	{Name: "executions.read", Class: Confinable},
	{
		Name:      "identity_providers.manage",
		Class:     GlobalOnly,
		Rationale: "identity-provider trust configuration controls global sign-in",
	},
	{Name: "logs.read", Class: Confinable},
	{
		Name:      "pki.manage",
		Class:     GlobalOnly,
		Rationale: "certificate-authority operations alter global machine trust",
	},
	{
		Name:      "roles.manage",
		Class:     GlobalOnly,
		Rationale: "role and grant definitions alter global authorization",
	},
	{
		Name:      "scim_configuration.manage",
		Class:     GlobalOnly,
		Rationale: "SCIM provisioning configuration controls global identity state",
	},
	{
		Name:      "server_settings.manage",
		Class:     GlobalOnly,
		Rationale: "server settings alter control-plane-wide behavior",
	},
	{
		Name:      "user_group_memberships.manage",
		Class:     GlobalOnly,
		Rationale: "membership changes can alter authorization reach across scopes",
	},
	{Name: "user_groups.manage", Class: Confinable},
	{Name: "users.manage", Class: Confinable},
}

// Catalog returns the deterministic permission catalog as an independent copy.
func Catalog() []CatalogEntry {
	return slices.Clone(permissionCatalog[:])
}

// Lookup returns one exact catalog entry without defaulting unknown names.
func Lookup(name Permission) (CatalogEntry, bool) {
	if !validPermissionName(name) {
		return CatalogEntry{}, false
	}
	for _, entry := range permissionCatalog {
		if entry.Name == name {
			return entry, true
		}
	}
	return CatalogEntry{}, false
}

func validateCatalog(entries []CatalogEntry) error {
	if len(entries) == 0 {
		return errors.New("authz: permission catalog is empty")
	}
	var previous Permission
	for index, entry := range entries {
		if !validPermissionName(entry.Name) {
			return fmt.Errorf("authz: permission %q is invalid", entry.Name)
		}
		if index > 0 && entry.Name <= previous {
			return errors.New("authz: permission catalog is not strictly sorted and unique")
		}
		switch entry.Class {
		case Confinable:
		case GlobalOnly:
			if strings.TrimSpace(entry.Rationale) == "" {
				return fmt.Errorf("authz: global-only permission %q lacks a rationale", entry.Name)
			}
		default:
			return fmt.Errorf("authz: permission %q has no classification", entry.Name)
		}
		previous = entry.Name
	}
	return nil
}

func validPermissionName(name Permission) bool {
	value := string(name)
	if len(value) == 0 || len(value) > maxPermissionNameBytes {
		return false
	}
	segments := strings.Split(value, ".")
	if len(segments) < 2 {
		return false
	}
	last := segments[len(segments)-1]
	if last == "self" || last == "assigned" {
		return false
	}
	for _, segment := range segments {
		if len(segment) == 0 || segment[0] < 'a' || segment[0] > 'z' {
			return false
		}
		for _, character := range []byte(segment[1:]) {
			if character >= 'a' && character <= 'z' ||
				character >= '0' && character <= '9' ||
				character == '_' {
				continue
			}
			return false
		}
	}
	return true
}
