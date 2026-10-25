//go:build integration

package integrationvpn

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCliClientOverride drives /vpn/openvpn/client-override through the binary. Every add carries disabled, so no
// override is ever active on the shared box
func TestCliClientOverride(t *testing.T) {
	var core = coreApi(t)
	var serverDescription = testDescription("cso-cli-server")
	var server = csoCreateServerInstance(t, core, "cso-cli-server")
	var commonName = strings.ReplaceAll(runPrefix, "-", "_") + "_cli"
	const menu = "/vpn/openvpn/client-override"

	// client side validation sends nothing
	mustFailOpn(t, menu, "add", "common-name="+commonName, "tunnel-network=10.213.0.8", "disabled")
	mustFailOpn(t, menu, "add", "common-name="+commonName, "servers="+runPrefix+" no such server", "disabled")

	var added = mustOpn(t, menu, "add", "common-name="+commonName, "servers="+serverDescription, "tunnel-network=10.213.0.12/30",
		"tunnel-network6=FD00:213:0::c/64", "local-networks=192.168.213.0/24", "redirect-gateway=def1,!ipv4",
		"dns-servers=10.213.0.53", "description="+testDescription("cso-cli"), "disabled")
	var uuid = uuidFrom(t, added)
	csoCleanup(t, core, uuid)
	if strings.TrimSpace(added.stdout) != uuid {
		t.Errorf("add must print only the uuid:\n%s", added)
	}

	var rows = csoRawFind(t, core, uuid)
	if len(rows) != 1 || rows[0]["enabled"] != "0" || rows[0]["servers"] != server || rows[0]["tunnel_networkv6"] != "fd00:213::c/64" ||
		rows[0]["redirect_gateway"] != "def1,!ipv4" || rows[0]["common_name"] != commonName {
		t.Fatalf("unexpected row after add: %v", rows)
	}

	// the same common name and servers again
	var duplicate = mustFailOpn(t, menu, "add", "common-name="+commonName, "servers="+server, "disabled")
	requireContains(t, duplicate, duplicate.stderr, "exists", uuid)

	var printed = mustOpn(t, menu, "print", "search="+commonName)
	requireContains(t, printed, printed.stdout, "DISABLED", "COMMON-NAME", commonName, serverDescription, "10.213.0.12/30", "yes")

	var asJSON = mustOpn(t, menu, "print", "json", "search="+commonName)
	var row map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(asJSON.stdout)), &row); err != nil || row["uuid"] != uuid {
		t.Errorf("want one raw JSON row: %v\n%s", err, asJSON)
	}

	var shown = mustOpn(t, menu, "show", commonName)
	requireContains(t, shown, shown.stdout, "uuid:", uuid, "disabled:", "tunnel-network6:", "fd00:213::c/64", "redirect-gateway:", "def1,!ipv4")

	requireNoStdout(t, mustOpn(t, menu, "set", commonName, "block", "description="+testDescription("cso-cli changed")))
	if rows = csoRawFind(t, core, uuid); rows[0]["block"] != "1" || rows[0]["tunnel_network"] != "10.213.0.12/30" ||
		rows[0]["description"] != testDescription("cso-cli changed") || rows[0]["enabled"] != "0" {
		t.Errorf("unexpected row after set: %v", rows[0])
	}

	// the instance can not be removed while the override refers to it (OPNsense would leave a dangling reference)
	var inUse = mustFailOpn(t, "/vpn/openvpn/instance", "remove", server)
	requireContains(t, inUse, inUse.stderr, "client specific overrides", commonName, uuid)

	// invalid values are refused by OPNsense or the CLI, nothing changes
	mustFailOpn(t, menu, "set", uuid, "route-gateway=10.213.0.1/24")
	mustFailOpn(t, menu, "set", "0f0f0f0f-1111-4222-8333-a8a8a8a8a8a8", "description=x")

	// replace overwrites completely and keeps it disabled
	var replaced = mustOpn(t, menu, "add", "common-name="+commonName, "servers="+server, "remote-networks=192.168.216.0/24",
		"description="+testDescription("cso-cli replaced"), "disabled", "replace")
	if uuidFrom(t, replaced) != uuid {
		t.Errorf("replace must reuse %s:\n%s", uuid, replaced)
	}
	requireContains(t, replaced, replaced.stderr, "replaced")
	if rows = csoRawFind(t, core, uuid); rows[0]["block"] != "0" || rows[0]["tunnel_network"] != "" ||
		rows[0]["remote_networks"] != "192.168.216.0/24" || rows[0]["enabled"] != "0" {
		t.Errorf("unexpected row after replace: %v", rows[0])
	}

	// disabling a disabled override changes nothing (enable is never run live)
	var disabled = mustOpn(t, menu, "disable", uuid)
	requireNoStdout(t, disabled)
	requireContains(t, disabled, disabled.stderr, "already disabled")

	requireNoStdout(t, mustOpn(t, menu, "remove", commonName))
	if rows = csoRawFind(t, core, uuid); len(rows) != 0 {
		t.Errorf("still there after remove: %v", rows)
	}
	mustFailOpn(t, menu, "remove", commonName)
}
