//go:build integration

package integrationfirewall

import (
	"errors"
	"slices"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/firewall"
)

// Aliases are only created with names starting with namePrefix() (a8fw_<8 hex>) and a testDescription, always
// disabled, and are never applied (no reconfigure), so pf never sees them. The live pf tables are only read:
// alias_util add/delete/flush and the bogons update are covered by the unit tests only

func aliasFirewallApi(t *testing.T) *firewall.FirewallApi {
	t.Helper()
	return &firewall.FirewallApi{OPNsense: coreApi(t)}
}

func aliasTestName(suffix string) string {
	return namePrefix() + "_" + suffix
}

// aliasCleanup removes the alias uuid when the test ends (with the raw API) and checks it is gone
func aliasCleanup(t *testing.T, uuid string) {
	t.Helper()
	var core = coreApi(t)
	t.Cleanup(func() {
		if _, err := core.Mutate(core.EndpointForModule("firewall/alias/del_item/"+uuid), nil); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of alias %s failed: %v", uuid, err)
		}
		if rows, err := rawSearch(core, "firewall/alias/search_item", ""); err == nil {
			for _, row := range rows {
				if row.Uuid == uuid {
					t.Errorf("alias %s still exists after the cleanup", uuid)
				}
			}
		}
	})
}

// aliasRawNames returns the names of this run's aliases, read with the raw API
func aliasRawNames(t *testing.T) []string {
	t.Helper()
	var rows, err = rawSearch(coreApi(t), "firewall/alias/search_item", "")
	if err != nil {
		t.Fatalf("raw search: %v", err)
	}
	var names []string
	for _, row := range rows {
		if ownedByRun(row.Name) || ownedByRun(row.Description) {
			names = append(names, row.Name)
		}
	}
	return names
}

func TestAliasLibraryLifecycle(t *testing.T) {
	var fw = aliasFirewallApi(t)
	var name = aliasTestName("hosts")
	var description = testDescription("alias-lib")

	var uuid, err = fw.AliasCreate(firewall.AliasFields{
		"name": name, "type": "host", "content": "10.250.0.1\n10.250.0.2", "enabled": "0", "description": description,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	aliasCleanup(t, uuid)
	if names := aliasRawNames(t); !slices.Contains(names, name) {
		t.Fatalf("created alias not found by the raw search: %v", names)
	}

	alias, err := fw.AliasGetByName(name)
	if err != nil || alias.Uuid != uuid || alias.BuiltIn() || alias.Enabled != "0" ||
		!slices.Equal(alias.ContentList(), []string{"10.250.0.1", "10.250.0.2"}) {
		t.Fatalf("get by name: %+v %v", alias, err)
	}

	t.Run("a second alias with the name is rejected", func(t *testing.T) {
		var _, err = fw.AliasCreate(firewall.AliasFields{"name": name, "type": "host", "enabled": "0", "description": description})
		var validation *api.ValidationError
		if !errors.As(err, &validation) || validation.Validations["name"] == "" {
			t.Errorf("want a name validation error, got %v", err)
		}
	})
	t.Run("invalid content is rejected", func(t *testing.T) {
		var _, err = fw.AliasCreate(firewall.AliasFields{"name": aliasTestName("bad"), "type": "network", "content": "10.0.0.0/33",
			"enabled": "0", "description": description})
		var validation *api.ValidationError
		if !errors.As(err, &validation) || validation.Validations["content"] == "" {
			t.Errorf("want a content validation error, got %v", err)
		}
	})
	t.Run("update keeps the other fields", func(t *testing.T) {
		if err := fw.AliasUpdate(uuid, firewall.AliasFields{"content": "10.250.0.3", "counters": "1"}); err != nil {
			t.Fatal(err)
		}
		var alias, err = fw.AliasGet(uuid)
		if err != nil || alias.Content != "10.250.0.3" || alias.Counters != "1" || alias.Description != description || alias.Enabled != "0" {
			t.Errorf("after update: %+v %v", alias, err)
		}
	})
	t.Run("enable and disable change only the flag", func(t *testing.T) {
		// the alias is never applied, the flag only changes the configuration
		if changed, err := fw.AliasSetEnabled(uuid, false); err != nil || changed {
			t.Errorf("disable a disabled alias: %v %v", changed, err)
		}
		if changed, err := fw.AliasSetEnabled(uuid, true); err != nil || !changed {
			t.Errorf("enable: %v %v", changed, err)
		}
		if changed, err := fw.AliasSetEnabled(uuid, false); err != nil || !changed {
			t.Errorf("disable: %v %v", changed, err)
		}
	})
	t.Run("an alias in use can not be removed, a rename follows", func(t *testing.T) {
		var groupUuid, err = fw.AliasCreate(firewall.AliasFields{"name": aliasTestName("group"), "type": "networkgroup",
			"content": name, "enabled": "0", "description": description})
		if err != nil {
			t.Fatal(err)
		}
		aliasCleanup(t, groupUuid)

		err = fw.AliasRemove(uuid)
		var httpErr *api.HttpError
		if !errors.As(err, &httpErr) || !strings.Contains(err.Error(), "in use") {
			t.Errorf("want an in use error, got %v", err)
		}

		var renamed = aliasTestName("renamed")
		if err := fw.AliasUpdate(uuid, firewall.AliasFields{"name": renamed}); err != nil {
			t.Fatal(err)
		}
		group, err := fw.AliasGet(groupUuid)
		if err != nil || group.Content != renamed {
			t.Errorf("OPNsense renames references: %+v %v", group, err)
		}
		if err := fw.AliasRemove(groupUuid); err != nil {
			t.Errorf("remove group: %v", err)
		}
	})

	if err := fw.AliasRemove(uuid); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := fw.AliasGet(uuid); !api.IsNotFound(err) {
		t.Errorf("want not found after remove, got %v", err)
	}
	if err := fw.AliasRemove(uuid); !api.IsNotFound(err) {
		t.Errorf("second remove: want not found, got %v", err)
	}
	if names := aliasRawNames(t); len(names) != 0 {
		t.Errorf("aliases left: %v", names)
	}
}

func TestAliasBuiltInIsRefused(t *testing.T) {
	var fw = aliasFirewallApi(t)
	var aliases, err = fw.AliasList("")
	if err != nil {
		t.Fatal(err)
	}
	var builtIn *firewall.Alias
	for i, alias := range aliases {
		if alias.BuiltIn() {
			builtIn = &aliases[i]
			break
		}
	}
	if builtIn == nil {
		t.Skip("no built-in alias")
	}
	// refused by the library before anything is sent (OPNsense answers set_item with "saved" for them)
	if err := fw.AliasUpdate(builtIn.Uuid, firewall.AliasFields{"description": "x"}); err == nil || !strings.Contains(err.Error(), "built-in") {
		t.Errorf("update: %v", err)
	}
	if err := fw.AliasRemove(builtIn.Uuid); err == nil || !strings.Contains(err.Error(), "built-in") {
		t.Errorf("remove: %v", err)
	}
	if _, err := fw.AliasSetEnabled(builtIn.Uuid, false); err == nil || !strings.Contains(err.Error(), "built-in") {
		t.Errorf("disable: %v", err)
	}
}

func TestAliasExportImport(t *testing.T) {
	var fw = aliasFirewallApi(t)
	var name = aliasTestName("export")
	var description = testDescription("alias-transfer")
	var uuid, err = fw.AliasCreate(firewall.AliasFields{"name": name, "type": "port", "content": "8080\n8443", "enabled": "0",
		"description": description})
	if err != nil {
		t.Fatal(err)
	}
	aliasCleanup(t, uuid)

	raw, err := fw.AliasExport([]string{uuid})
	if err != nil {
		t.Fatal(err)
	}
	exported, err := firewall.AliasParseExport(raw)
	if err != nil || len(exported) != 1 || exported[uuid]["name"] != name || exported[uuid]["content"] != "8080\n8443" {
		t.Fatalf("export: %v %v\n%s", exported, err, raw)
	}

	// a copy under another name is new, the original with another description is changed
	var copyName = aliasTestName("imported")
	var copied = firewall.AliasFields{}
	for field, value := range exported[uuid] {
		copied[field] = value
	}
	copied["name"] = copyName
	exported[uuid]["description"] = description + " changed"
	result, err := fw.AliasImport(map[string]firewall.AliasFields{"copy": copied, uuid: exported[uuid]})
	if copy, getErr := fw.AliasGetByName(copyName); getErr == nil {
		aliasCleanup(t, copy.Uuid)
	}
	if err != nil || result != (firewall.AliasImportResult{New: 1, Existing: 1}) {
		t.Fatalf("import: %+v %v", result, err)
	}
	copy, err := fw.AliasGetByName(copyName)
	if err != nil || copy.Content != "8080\n8443" || copy.Enabled != "0" {
		t.Errorf("imported copy: %+v %v", copy, err)
	}
	if original, err := fw.AliasGet(uuid); err != nil || original.Description != description+" changed" {
		t.Errorf("changed original: %+v %v", original, err)
	}

	t.Run("invalid aliases are not saved", func(t *testing.T) {
		var _, err = fw.AliasImport(map[string]firewall.AliasFields{
			"ok":  {"name": aliasTestName("valid"), "type": "host", "content": "10.250.0.9", "enabled": "0", "description": description},
			"bad": {"name": aliasTestName("invalid"), "type": "port", "content": "nope!", "enabled": "0", "description": description},
		})
		var validation *api.ValidationError
		if !errors.As(err, &validation) || validation.Validations["bad.content"] == "" {
			t.Errorf("want a validation error keyed bad.content, got %v", err)
		}
		for _, leftover := range []string{aliasTestName("valid"), aliasTestName("invalid")} {
			if alias, err := fw.AliasGetByName(leftover); err == nil {
				aliasCleanup(t, alias.Uuid)
				t.Errorf("%s was saved although the import failed", leftover)
			}
		}
	})
}

func TestAliasLookups(t *testing.T) {
	var fw = aliasFirewallApi(t)
	if _, err := fw.AliasCategories(); err != nil {
		t.Errorf("categories: %v", err)
	}
	countries, err := fw.AliasCountries()
	if err != nil || !slices.ContainsFunc(countries, func(c firewall.AliasCountry) bool { return c.Code == "NL" && c.Region == "Europe" }) {
		t.Errorf("countries: %d %v", len(countries), err)
	}
	if _, err := fw.AliasUserGroups(); err != nil {
		t.Errorf("user groups: %v", err)
	}
	interfaces, err := fw.AliasFieldOptions(firewall.AliasFieldInterface)
	if err != nil || len(interfaces) == 0 {
		t.Errorf("interfaces: %v %v", interfaces, err)
	}
	sizes, err := fw.AliasTableSize()
	if err != nil || sizes.Size == 0 {
		t.Errorf("table size: %+v %v", sizes, err)
	}
}

// TestAliasTablesReadOnly reads the live pf tables
func TestAliasTablesReadOnly(t *testing.T) {
	var fw = aliasFirewallApi(t)
	var tables, err = fw.AliasTables()
	if err != nil || !slices.Contains(tables, "bogons") {
		t.Fatalf("tables: %v %v", tables, err)
	}
	if entries, err := fw.AliasTableEntries("bogons"); err != nil || len(entries) == 0 {
		t.Errorf("bogons entries: %v %v", entries, err)
	}
	if _, err := fw.AliasTableEntries(aliasTestName("missing")); !api.IsNotFound(err) {
		t.Errorf("want not found for a missing table, got %v", err)
	}
	if matches, err := fw.AliasFindReferences("10.250.255.254"); err != nil {
		t.Errorf("find: %v %v", matches, err)
	}
	if _, err := fw.AliasFindReferences("nope!"); err == nil {
		t.Error("want an error for an invalid address")
	}
}
