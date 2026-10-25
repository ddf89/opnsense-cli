//go:build integration

package integrationsystem

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// TestCliGatewayGroup drives /system/gateway/group through the opn binary. apply is never run live
func TestCliGatewayGroup(t *testing.T) {
	var sys = systemApi(t)
	var members = gatewayGroupMembers(t, "gateway-group-cli member", "192.168.1.252", "192.168.1.253")
	var gwC, gwD = members[0], members[1]
	var name = gatewayGroupRandomName(t)
	var description = testDescription("gateway-group-cli")
	const menu = "/system/gateway/group"

	var added = mustOpn(t, menu, "add", "name="+name, "tier1="+gwC, "tier2="+gwD, "trigger=packet-loss",
		"pool=round-robin-sticky", "description="+description)
	var uuid = uuidFrom(t, added)
	gatewayGroupCleanup(t, sys, uuid)
	if strings.TrimSpace(added.stdout) != uuid {
		t.Errorf("add must print only the uuid:\n%s", added)
	}

	t.Run("print", func(t *testing.T) {
		var printed = mustOpn(t, menu, "print", "search="+name)
		requireContains(t, printed, printed.stdout, "NAME", "TIERS", "STATUS", name, "1: "+gwC+"  2: "+gwD, "packet-loss",
			"round-robin-sticky", description)

		var asJSON = mustOpn(t, menu, "print", "json", "search="+name)
		var row map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(asJSON.stdout)), &row); err != nil {
			t.Fatalf("json output: %v\n%s", err, asJSON)
		}
		if row["uuid"] != uuid || row["item"] != gwC || row["item2"] != gwD || row["trigger"] != "downloss" ||
			row["poolopts"] != "round-robin sticky-address" || row["gateways"] == nil {
			t.Errorf("unexpected raw row %v", row)
		}

		var detail = mustOpn(t, menu, "print", "detail", "search="+name)
		requireContains(t, detail, detail.stdout, "uuid:", uuid, "tier1:", "member "+gwC+":", "member "+gwD+":")
	})

	t.Run("show", func(t *testing.T) {
		for _, selector := range []string{uuid, name, strings.ToUpper(name)} {
			var shown = mustOpn(t, menu, "show", selector)
			requireContains(t, shown, shown.stdout, "uuid:", uuid, "tier1:", gwC, "tier2:", gwD, "trigger:", "packet-loss",
				"pool:", "round-robin-sticky", "description:", description)
		}
		mustFailOpn(t, menu, "show", name+"x")
	})

	t.Run("set", func(t *testing.T) {
		requireNoStdout(t, mustOpn(t, menu, "set", name, "tier3="+gwD+","+gwC, "tier2=", "trigger=member-down", "description="+description+" set"))
		var group, err = sys.GatewayGroupGet(uuid)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(group.Tiers[0], []string{gwC}) || len(group.Tiers[1]) != 0 || !reflect.DeepEqual(group.Tiers[2], []string{gwD, gwC}) ||
			group.Trigger != "down" || group.PoolOptions != "round-robin sticky-address" || group.Description != description+" set" {
			t.Errorf("unexpected group after set %+v", group)
		}

		var refused = mustFailOpn(t, menu, "set", name, "tier1=")
		requireContains(t, refused, refused.stderr, "tier 1")
		refused = mustFailOpn(t, menu, "set", name, "name="+name+"x")
		requireContains(t, refused, refused.stderr, "can not be renamed")
		refused = mustFailOpn(t, menu, "set", name, "tier4=a8gg_nonexistent")
		requireContains(t, refused, refused.stderr, "unknown gateway")
		if after, _ := sys.GatewayGroupGet(uuid); !reflect.DeepEqual(after, group) {
			t.Errorf("refused sets changed the group:\n%+v\n%+v", group, after)
		}
	})

	t.Run("add", func(t *testing.T) {
		var refused = mustFailOpn(t, menu, "add", "name="+name, "tier1="+gwD)
		requireContains(t, refused, refused.stderr, "exists already")
		refused = mustFailOpn(t, menu, "add", "name="+gwC, "tier1="+gwD, "description="+description)
		requireContains(t, refused, refused.stderr, "name of a gateway")
		refused = mustFailOpn(t, menu, "add", "name="+gatewayGroupRandomName(t), "tier1=a8gg_nonexistent", "description="+description)
		requireContains(t, refused, refused.stderr, "unknown gateway")
		mustFailOpn(t, menu, "add", "name="+gatewayGroupRandomName(t), "description="+description)
		if got := gatewayGroupRawNames(t); !reflect.DeepEqual(got, []string{name}) {
			t.Errorf("only the test group must exist, got %v", got)
		}

		var replaced = mustOpn(t, menu, "add", "name="+name, "tier1="+gwD, "replace", "description="+description)
		if uuidFrom(t, replaced) != uuid {
			t.Errorf("replace must keep the uuid:\n%s", replaced)
		}
		var group, err = sys.GatewayGroupGet(uuid)
		if err != nil {
			t.Fatal(err)
		}
		var wantTiers = [5][]string{{gwD}}
		if !reflect.DeepEqual(group.Tiers, wantTiers) || group.Trigger != "down" || group.PoolOptions != "" || group.Description != description {
			t.Errorf("unexpected group after replace %+v", group)
		}
	})

	t.Run("remove", func(t *testing.T) {
		requireNoStdout(t, mustOpn(t, menu, "remove", name))
		mustFailOpn(t, menu, "show", uuid)
		mustFailOpn(t, menu, "remove", uuid)
		if got := gatewayGroupRawNames(t); len(got) != 0 {
			t.Errorf("no test group must be left, got %v", got)
		}
	})
}
