//go:build integration

package integrationfirewall

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// TestCliGroup drives /firewall/group through the opn binary. apply is never run live, built-in groups and names of
// interfaces are only tested with fakes
func TestCliGroup(t *testing.T) {
	var fw = groupFirewallApi(t)
	var name = groupTestName("c")
	var description = testDescription("group-cli")
	const menu = "/firewall/group"

	var added = mustOpn(t, menu, "add", "name="+name, "members=lan", "sequence=7", "description="+description)
	var uuid = uuidFrom(t, added)
	groupCleanup(t, fw, uuid)
	if strings.TrimSpace(added.stdout) != uuid {
		t.Errorf("add must print only the uuid:\n%s", added)
	}

	t.Run("print and show", func(t *testing.T) {
		var printed = mustOpn(t, menu, "print", "search="+name)
		requireContains(t, printed, printed.stdout, "NAME", "MEMBERS", "BUILT-IN", name, "lan", description)

		var all = mustOpn(t, menu, "print")
		requireContains(t, all, all.stdout, "openvpn", "enc0", "wireguard", name)

		var asJSON = mustOpn(t, menu, "print", "json", "search="+name)
		var row map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(asJSON.stdout)), &row); err != nil {
			t.Fatalf("json output: %v\n%s", err, asJSON)
		}
		if row["uuid"] != uuid || row["ifname"] != name || row["members"] != "lan" || row["sequence"] != "7" {
			t.Errorf("unexpected raw row %v", row)
		}

		for _, selector := range []string{uuid, name, strings.ToUpper(name)} {
			var shown = mustOpn(t, menu, "show", selector)
			requireContains(t, shown, shown.stdout, "uuid:", uuid, "members:", "lan", "member-names:", "LAN", "sequence:", "7",
				"no-group:", "built-in:", "description:", description)
		}
		mustFailOpn(t, menu, "show", name+"x")
	})

	t.Run("set", func(t *testing.T) {
		requireNoStdout(t, mustOpn(t, menu, "set", name, "members=lan,wan", "no-group", "description="+description+" set"))
		var group, err = fw.GroupGet(uuid)
		if err != nil {
			t.Fatal(err)
		}
		if group.Name != name || !reflect.DeepEqual(group.Members, []string{"lan", "wan"}) || !group.NoGroup || group.Sequence != 7 ||
			group.Description != description+" set" {
			t.Errorf("unexpected group after set %+v", group)
		}

		var refused = mustFailOpn(t, menu, "set", name, "members=a8nonexistent")
		requireContains(t, refused, refused.stderr, "unknown interface")
		mustFailOpn(t, menu, "set", name, "members=")
		mustFailOpn(t, menu, "set", name)
		if after, _ := fw.GroupGet(uuid); !reflect.DeepEqual(after, group) {
			t.Errorf("refused sets changed the group:\n%+v\n%+v", group, after)
		}

		var renamed = groupTestName("d")
		requireNoStdout(t, mustOpn(t, menu, "set", name, "name="+renamed))
		if group, err := fw.GroupGet(uuid); err != nil || group.Name != renamed {
			t.Errorf("after the rename: %+v / %v", group, err)
		}
		name = renamed
	})

	t.Run("add", func(t *testing.T) {
		var refused = mustFailOpn(t, menu, "add", "name="+name, "members=lan")
		requireContains(t, refused, refused.stderr, "exists already")
		refused = mustFailOpn(t, menu, "add", "name="+groupTestName("e"), "members=a8nonexistent", "description="+description)
		requireContains(t, refused, refused.stderr, "unknown interface")
		mustFailOpn(t, menu, "add", "name="+namePrefix()+"1", "members=lan", "description="+description)
		if got := groupRawNames(t); !reflect.DeepEqual(got, []string{name}) {
			t.Errorf("only the test group must exist, got %v", got)
		}

		var replaced = mustOpn(t, menu, "add", "name="+name, "members=wan", "replace", "description="+description)
		if uuidFrom(t, replaced) != uuid {
			t.Errorf("replace must keep the uuid:\n%s", replaced)
		}
		var group, err = fw.GroupGet(uuid)
		if err != nil || !reflect.DeepEqual(group.Members, []string{"wan"}) || group.NoGroup || group.Sequence != 0 || group.Description != description {
			t.Errorf("unexpected group after replace %+v / %v", group, err)
		}
	})

	t.Run("remove", func(t *testing.T) {
		requireNoStdout(t, mustOpn(t, menu, "remove", name))
		mustFailOpn(t, menu, "show", uuid)
		mustFailOpn(t, menu, "remove", uuid)
		if got := groupRawNames(t); len(got) != 0 {
			t.Errorf("no test group must be left, got %v", got)
		}
	})
}
