//go:build integration

package integrationfirewall

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// TestCliCategory drives /firewall/category through the opn binary
func TestCliCategory(t *testing.T) {
	var fw = groupFirewallApi(t)
	var name = namePrefix() + " cli"
	const menu = "/firewall/category"

	var added = mustOpn(t, menu, "add", "name="+name, "color=#00FF88")
	var uuid = uuidFrom(t, added)
	categoryCleanup(t, fw, uuid)
	if strings.TrimSpace(added.stdout) != uuid {
		t.Errorf("add must print only the uuid:\n%s", added)
	}

	t.Run("print and show", func(t *testing.T) {
		var printed = mustOpn(t, menu, "print", "search="+name)
		requireContains(t, printed, printed.stdout, "NAME", "COLOR", "AUTO", name, "00FF88")

		var asJSON = mustOpn(t, menu, "print", "json", "search="+name)
		var row map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(asJSON.stdout)), &row); err != nil {
			t.Fatalf("json output: %v\n%s", err, asJSON)
		}
		if row["uuid"] != uuid || row["name"] != name || row["color"] != "00FF88" || row["auto"] != "0" {
			t.Errorf("unexpected raw row %v", row)
		}

		for _, selector := range []string{uuid, name} {
			var shown = mustOpn(t, menu, "show", selector)
			requireContains(t, shown, shown.stdout, "uuid:", uuid, "name:", name, "color:", "00FF88", "auto:", "no")
		}
		mustFailOpn(t, menu, "show", name+"x")
	})

	t.Run("set", func(t *testing.T) {
		requireNoStdout(t, mustOpn(t, menu, "set", name, "color="))
		if category, err := fw.CategoryGet(uuid); err != nil || category.Name != name || category.Color != "" {
			t.Errorf("after set color=: %+v / %v", category, err)
		}
		var renamed = name + "2"
		requireNoStdout(t, mustOpn(t, menu, "set", name, "name="+renamed, "color=abcdef"))
		if category, err := fw.CategoryGet(uuid); err != nil || category.Name != renamed || category.Color != "abcdef" {
			t.Errorf("after the rename: %+v / %v", category, err)
		}
		name = renamed

		mustFailOpn(t, menu, "set", name, "color=red")
		mustFailOpn(t, menu, "set", name, "name=a,b")
		mustFailOpn(t, menu, "set", name)
	})

	t.Run("add", func(t *testing.T) {
		var refused = mustFailOpn(t, menu, "add", "name="+name)
		requireContains(t, refused, refused.stderr, "exists already")
		var replaced = mustOpn(t, menu, "add", "name="+name, "replace")
		if uuidFrom(t, replaced) != uuid {
			t.Errorf("replace must keep the uuid:\n%s", replaced)
		}
		if category, _ := fw.CategoryGet(uuid); category.Color != "" {
			t.Errorf("replace must clear the color: %+v", category)
		}
		if got := categoryRawNames(t); !reflect.DeepEqual(got, []string{name}) {
			t.Errorf("only the test category must exist, got %v", got)
		}
	})

	t.Run("in use", func(t *testing.T) {
		var ruleUuid = categoryUsingRule(t, uuid, "category-cli rule")
		var refused = mustFailOpn(t, menu, "remove", name)
		requireContains(t, refused, refused.stderr, "in use by", ruleUuid)
	})

	t.Run("remove", func(t *testing.T) {
		requireNoStdout(t, mustOpn(t, menu, "remove", name))
		mustFailOpn(t, menu, "show", uuid)
		if got := categoryRawNames(t); len(got) != 0 {
			t.Errorf("no test category must be left, got %v", got)
		}
	})
}
