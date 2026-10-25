//go:build integration

package integrationfirewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/firewall"
)

// TestCliNat runs the /firewall/nat menus against the live instance: disabled rules with documentation addresses,
// never applied, the outbound NAT mode only printed, nothing imported (see nat_test.go)
func TestCliNat(t *testing.T) {
	var fw = natFirewallApi(t)
	natRequireNothingLeft(t, fw)

	for _, tc := range []struct {
		menu    string
		rules   *firewall.NatRules
		add     []string
		set     string
		want    func(rule firewall.NatRule) bool
		printed []string
	}{
		{"/firewall/nat/source", fw.SourceNat(),
			[]string{"interface=wan", "source=198.51.100.0/24", "destination=203.0.113.0/24", "target=203.0.113.10", "protocol=tcp", "destination-port=443"},
			"target-port=8443", func(rule firewall.NatRule) bool {
				return rule.Fields["target_port"] == "8443" && rule.Fields["protocol"] == "TCP"
			},
			[]string{"198.51.100.0/24", "203.0.113.0/24 port 443", "203.0.113.10"}},
		{"/firewall/nat/destination", fw.DestinationNat(),
			[]string{"interface=wan", "protocol=tcp", "destination=203.0.113.5", "destination-port=8080", "target=198.51.100.5", "target-port=80"},
			"source=198.51.100.128/25", func(rule firewall.NatRule) bool {
				return rule.Fields["source.network"] == "198.51.100.128/25" && rule.Fields["destination.port"] == "8080" && rule.Fields["pass"] == ""
			},
			[]string{"203.0.113.5 port 8080", "198.51.100.5 port 80"}},
		{"/firewall/nat/one-to-one", fw.OneToOne(),
			[]string{"interface=wan", "source=198.51.100.0/28", "external=203.0.113.0/28"},
			"nat-reflection=disable", func(rule firewall.NatRule) bool { return rule.Fields["natreflection"] == "disable" },
			[]string{"binat", "198.51.100.0/28", "203.0.113.0/28"}},
		{"/firewall/nat/npt", fw.Npt(),
			[]string{"interface=wan", "internal-prefix=2001:db8:1::/48", "external-prefix=2001:db8:2::/48"},
			"external-prefix=2001:db8:3::/48", func(rule firewall.NatRule) bool { return rule.Fields["destination_net"] == "2001:db8:3::/48" },
			[]string{"2001:db8:1::/48", "2001:db8:2::/48"}},
	} {
		t.Run(tc.menu, func(t *testing.T) {
			var rules = tc.rules
			var description = testDescription("cli-nat" + strings.ReplaceAll(tc.menu, "/", "-"))

			var created = mustOpn(t, append(append([]string{tc.menu, "add"}, tc.add...), "description="+description, "disabled")...)
			var uuid = uuidFrom(t, created)
			natCleanup(t, rules, uuid)
			if strings.TrimSpace(created.stdout) != uuid {
				t.Errorf("add should print only the uuid:\n%s", created)
			}
			if rule, err := rules.Get(uuid); err != nil || !rules.Disabled(rule) {
				t.Fatalf("the rule is not disabled: %+v, %v", rule, err)
			}

			var printed = mustOpn(t, tc.menu, "print", "search="+description)
			requireContains(t, printed, printed.stdout, append([]string{"DISABLED", "AUTO", description, "yes"}, tc.printed...)...)
			var detail = mustOpn(t, tc.menu, "print", "search="+description, "detail")
			requireContains(t, detail, detail.stdout, uuid, "automatic:")
			var asJSON = mustOpn(t, tc.menu, "print", "search="+description, "json")
			requireContains(t, asJSON, asJSON.stdout, `"uuid":"`+uuid+`"`)

			var show = mustOpn(t, tc.menu, "show", description)
			requireContains(t, show, show.stdout, uuid, "disabled:", "yes")

			requireNoStdout(t, mustOpn(t, tc.menu, "set", description, tc.set))
			if rule, err := rules.Get(uuid); err != nil || !tc.want(rule) || !rules.Disabled(rule) {
				t.Errorf("after set %s: %+v, %v", tc.set, rule.Fields, err)
			}
			var disable = mustOpn(t, tc.menu, "disable", uuid)
			requireContains(t, disable, disable.stderr, "already disabled")

			// the description names the rule
			var duplicate = mustFailOpn(t, append(append([]string{tc.menu, "add"}, tc.add...), "description="+description, "disabled")...)
			requireContains(t, duplicate, duplicate.stderr, "exists already", uuid)
			var replaced = mustOpn(t, append(append([]string{tc.menu, "add"}, tc.add...), "description="+description, "disabled", "replace")...)
			if replacedUuid := uuidFrom(t, replaced); replacedUuid != uuid {
				natCleanup(t, rules, replacedUuid)
				t.Errorf("add replace created %s instead of replacing %s", replacedUuid, uuid)
			}

			// a second rule, placed before the first, then moved to the end
			var second = uuidFrom(t, mustOpn(t, append(append([]string{tc.menu, "add"}, tc.add...),
				"description="+description+" 2", "disabled", "place-before="+description)...))
			natCleanup(t, rules, second)
			var order = func() string {
				var out = mustOpn(t, tc.menu, "print", "search="+description, "json").stdout
				return strings.Join(uuidPattern.FindAllString(out, -1), ",")
			}
			if got := order(); got != second+","+uuid {
				t.Errorf("after place-before: %s", got)
			}
			requireNoStdout(t, mustOpn(t, tc.menu, "move", second))
			if got := order(); got != uuid+","+second {
				t.Errorf("after move to the end: %s", got)
			}

			var file = filepath.Join(t.TempDir(), "nat.csv")
			mustOpn(t, tc.menu, "export", file)
			if content, err := os.ReadFile(file); err != nil || !strings.Contains(string(content), uuid) {
				t.Errorf("export lacks %s: %v\n%s", uuid, err, content)
			}
			// import is never run live: without confirm=yes it is refused before anything is sent
			var refused = mustFailOpn(t, tc.menu, "import", file)
			requireContains(t, refused, refused.stderr, "confirm=yes")

			requireNoStdout(t, mustOpn(t, tc.menu, "remove", description+" 2"))
			requireNoStdout(t, mustOpn(t, tc.menu, "remove", description))
			if _, err := rules.Get(uuid); !api.IsNotFound(err) {
				t.Errorf("the rule exists after remove: %v", err)
			}
			mustFailOpn(t, tc.menu, "show", description)
		})
	}

	t.Run("local checks send nothing", func(t *testing.T) {
		for _, args := range [][]string{
			{"/firewall/nat/destination", "add", "interface=wan", "destination-port=80", "description=" + testDescription("never")},
			{"/firewall/nat/source", "add", "interface=wan", "source=2001:db8::/32", "description=" + testDescription("never")},
			{"/firewall/nat/one-to-one", "add", "interface=wan", "source=198.51.100.0/24", "external=203.0.113.0/25"},
			{"/firewall/nat/npt", "add", "interface=wan", "internal-prefix=2001:db8:1::/48", "external-prefix=2001:db8:2::/56"},
			{"/firewall/nat/destination", "add", "interface=wan,nope0", "target=198.51.100.9", "description=" + testDescription("never")},
		} {
			mustFailOpn(t, args...)
		}
	})

	t.Run("generated rules can not be changed", func(t *testing.T) {
		var list, err = fw.DestinationNat().List()
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range list {
			if rule.Automatic {
				var refused = mustFailOpn(t, "/firewall/nat/destination", "set", rule.Uuid, "log")
				requireContains(t, refused, refused.stderr, "generated by OPNsense")
				return
			}
		}
		t.Skip("no generated destination NAT rule on this instance")
	})

	t.Run("mode print", func(t *testing.T) {
		var mode = mustOpn(t, "/firewall/nat/source/mode", "print")
		requireContains(t, mode, mode.stdout, "mode:")
	})
}
