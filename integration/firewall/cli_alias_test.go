//go:build integration

package integrationfirewall

import (
	"opnsense-cli/opnsense/api/firewall"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// opn /firewall/alias against the live box: aliases are created disabled with this run's prefix and never applied;
// apply, the table changes (add, remove, flush) and update-bogons only run against the fakes of the unit tests

func TestCliAliasLifecycle(t *testing.T) {
	var name = aliasTestName("cli")
	var description = testDescription("alias-cli")

	var result = mustOpn(t, "/firewall/alias", "add", "name="+name, "type=network", "content=10.251.0.0/24,10.251.1.0/24",
		"disabled", "description="+description)
	var uuid = uuidFrom(t, result)
	aliasCleanup(t, uuid)

	result = mustOpn(t, "/firewall/alias", "print", "search="+name)
	requireContains(t, result, result.stdout, name, "network", "10.251.0.0/24,10.251.1.0/24", description)

	result = mustOpn(t, "/firewall/alias", "show", name)
	requireContains(t, result, result.stdout, "uuid:             "+uuid, "disabled:         yes", "built-in:         no")

	result = mustFailOpn(t, "/firewall/alias", "add", "name="+name, "type=host", "content=10.251.0.1", "disabled", "description="+description)
	requireContains(t, result, result.stderr, "exists already")

	requireNoStdout(t, mustOpn(t, "/firewall/alias", "set", name, "content=10.251.2.0/24", "counters"))
	result = mustOpn(t, "/firewall/alias", "show", uuid)
	requireContains(t, result, result.stdout, "content:          10.251.2.0/24\n", "counters:         yes")

	result = mustFailOpn(t, "/firewall/alias", "set", name, "content=10.251.0.0/33")
	requireContains(t, result, result.stderr, "content:")

	requireNoStdout(t, mustOpn(t, "/firewall/alias", "enable", name))
	requireNoStdout(t, mustOpn(t, "/firewall/alias", "disable", name))
	result = mustOpn(t, "/firewall/alias", "disable", name)
	requireContains(t, result, result.stderr, "already disabled")

	t.Run("export and import", func(t *testing.T) {
		var dir = t.TempDir()
		var file = filepath.Join(dir, "aliases.json")
		var exported = mustOpn(t, "/firewall/alias", "export", "items="+name, "file="+file)
		requireNoStdout(t, exported)
		var data, err = os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var aliases, parseErr = firewall.AliasParseExport(data)
		if parseErr != nil || len(aliases) != 1 || aliases[uuid]["content"] != "10.251.2.0/24" {
			t.Fatalf("export file: %v %s", parseErr, data)
		}

		var refused = mustFailOpn(t, "/firewall/alias", "import", "file="+file)
		requireContains(t, refused, refused.stderr, name, "replace")

		// OPNsense escapes the slash: "10.251.2.0\/24"
		var changed = strings.ReplaceAll(string(data), `10.251.2.0\/24`, "10.251.3.0/24")
		if err := os.WriteFile(file, []byte(changed), 0o600); err != nil {
			t.Fatal(err)
		}
		var imported = mustOpn(t, "/firewall/alias", "import", "file="+file, "replace")
		requireContains(t, imported, imported.stderr, "0 new and 1 changed")
		var shown = mustOpn(t, "/firewall/alias", "show", name)
		requireContains(t, shown, shown.stdout, "content:          10.251.3.0/24\n", "disabled:         yes")
	})

	result = mustFailOpn(t, "/firewall/alias", "remove", "bogons")
	requireContains(t, result, result.stderr, "built-in")
	requireNoStdout(t, mustOpn(t, "/firewall/alias", "remove", name))
	result = mustFailOpn(t, "/firewall/alias", "show", uuid)
	requireContains(t, result, result.stderr, "not found")
}

func TestCliAliasLookups(t *testing.T) {
	var result = mustOpn(t, "/firewall/alias", "countries", "search=netherlands")
	requireContains(t, result, result.stdout, "NL", "Europe")
	result = mustOpn(t, "/firewall/alias", "categories")
	requireContains(t, result, result.stdout, "NAME", "COLOR", "ALIASES")
	result = mustOpn(t, "/firewall/alias", "print", "type=external")
	requireContains(t, result, result.stdout, "bogons")
}

func TestCliAliasTableReadOnly(t *testing.T) {
	var result = mustOpn(t, "/firewall/alias/table", "print")
	requireContains(t, result, result.stdout, "NAME", "ENTRIES", "bogons")
	requireContains(t, result, result.stderr, "table entries in use")

	result = mustOpn(t, "/firewall/alias/table", "print", "bogons")
	requireContains(t, result, result.stdout, "ADDRESS", "/")

	result = mustFailOpn(t, "/firewall/alias/table", "print", aliasTestName("missing"))
	requireContains(t, result, result.stderr, "not found")

	mustOpn(t, "/firewall/alias/table", "find", "10.250.255.254")

	// refused before anything is sent: no confirmation non-interactively
	result = mustFailOpn(t, "/firewall/alias/table", "flush", "bogons")
	requireContains(t, result, result.stderr, "confirm=yes")
}
