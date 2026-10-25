//go:build integration

package integrationfirewall

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/firewall"
)

// Categories are only created with names starting with namePrefix(). The in use check uses a disabled filter rule
// created with the raw API (description with the run prefix), which is never applied

// categoryCleanup removes the category uuid when the test ends
func categoryCleanup(t *testing.T, fw *firewall.FirewallApi, uuid string) {
	t.Helper()
	t.Cleanup(func() {
		if err := fw.CategoryRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of category %s failed: %v", uuid, err)
		}
	})
}

// categoryRawNames returns the names of this run's categories, read with the raw API
func categoryRawNames(t *testing.T) []string {
	t.Helper()
	var core = coreApi(t)
	var rows, err = rawSearch(core, "firewall/category/search_item", "")
	if err != nil {
		t.Fatalf("raw search: %v", err)
	}
	var names []string
	for _, row := range rows {
		if ownedByRun(row.Name) {
			names = append(names, row.Name)
		}
	}
	return names
}

// categoryUsingRule creates a disabled filter rule with the category and removes it when the test ends (before the
// category, whose cleanup must be registered earlier). Returns the rule uuid
func categoryUsingRule(t *testing.T, categoryUuid string, label string) string {
	t.Helper()
	var core = coreApi(t)
	var uuid, err = core.Mutate(core.EndpointForModule("firewall/filter/add_rule"), map[string]map[string]string{"rule": {
		"enabled": "0", "action": "pass", "interface": "lan", "direction": "in", "ipprotocol": "inet",
		"source_net": "any", "destination_net": "any", "categories": categoryUuid, "description": testDescription(label),
	}})
	if err != nil {
		t.Fatalf("creating the disabled test rule: %v", err)
	}
	t.Cleanup(func() {
		if _, err := core.Mutate(core.EndpointForModule("firewall/filter/del_rule/"+uuid), nil); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of the test rule %s failed: %v", uuid, err)
		}
	})
	return uuid
}

func TestCategoryLibraryLifecycle(t *testing.T) {
	var fw = groupFirewallApi(t)
	var name = namePrefix() + " lib"

	var uuid, err = fw.CategoryCreate(firewall.Category{Name: name, Color: "ff8800"})
	if err != nil {
		t.Fatalf("CategoryCreate: %v", err)
	}
	categoryCleanup(t, fw, uuid)

	t.Run("get", func(t *testing.T) {
		var category, err = fw.CategoryGet(uuid)
		if err != nil || !reflect.DeepEqual(category, firewall.Category{Uuid: uuid, Name: name, Color: "ff8800"}) {
			t.Errorf("CategoryGet: %+v / %v", category, err)
		}
		if byName, err := fw.CategoryGetByName(name); err != nil || byName.Uuid != uuid {
			t.Errorf("CategoryGetByName: %+v / %v", byName, err)
		}
		if _, err := fw.CategoryGetByName(strings.ToUpper(name)); !api.IsNotFound(err) {
			t.Errorf("names are case-sensitive: %v", err)
		}
	})

	t.Run("update", func(t *testing.T) {
		var color = ""
		if err := fw.CategoryUpdate(uuid, firewall.CategoryPatch{Color: &color}); err != nil {
			t.Fatalf("CategoryUpdate: %v", err)
		}
		if category, _ := fw.CategoryGet(uuid); category.Name != name || category.Color != "" {
			t.Errorf("unexpected category after the partial update %+v", category)
		}
		var renamed = name + "2"
		if err := fw.CategoryUpdate(uuid, firewall.CategoryPatch{Name: &renamed}); err != nil {
			t.Fatalf("rename: %v", err)
		}
		if category, err := fw.CategoryGetByName(renamed); err != nil || category.Uuid != uuid {
			t.Errorf("after the rename: %+v / %v", category, err)
		}
		name = renamed

		if err := fw.CategoryUpdate("00000000-0000-4000-8000-0000000a8f01", firewall.CategoryPatch{Color: &color}); !api.IsNotFound(err) {
			t.Errorf("unknown uuid: want NotFoundError, got %v", err)
		}
		var validationErr *api.ValidationError
		if _, err := fw.CategoryCreate(firewall.Category{Name: name}); !errors.As(err, &validationErr) {
			t.Errorf("duplicate name: want a validation error, got %v", err)
		}
		if got := categoryRawNames(t); !reflect.DeepEqual(got, []string{name}) {
			t.Errorf("only the test category must exist, got %v", got)
		}
	})

	t.Run("in use", func(t *testing.T) {
		var ruleUuid = categoryUsingRule(t, uuid, "category-lib rule")
		var err = fw.CategoryRemove(uuid)
		if err == nil || !strings.Contains(err.Error(), "in use by") || !strings.Contains(err.Error(), ruleUuid) {
			t.Errorf("want the in use error naming the rule, got %v", err)
		}
		if _, getErr := fw.CategoryGet(uuid); getErr != nil {
			t.Errorf("the category must still exist: %v", getErr)
		}
	})

	t.Run("remove", func(t *testing.T) {
		// the rule of "in use" was removed by its subtest's cleanup
		if err := fw.CategoryRemove(uuid); err != nil {
			t.Fatalf("CategoryRemove: %v", err)
		}
		if err := fw.CategoryRemove(uuid); !api.IsNotFound(err) {
			t.Errorf("second remove: want NotFoundError, got %v", err)
		}
		if got := categoryRawNames(t); len(got) != 0 {
			t.Errorf("no test category must be left, got %v", got)
		}
	})
}
