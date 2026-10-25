//go:build integration

package integrationinterfaces

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"opnsense-cli/opnsense/api/interfaces"
)

var uuidPattern = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

type opnResult struct {
	args     []string
	stdout   string
	stderr   string
	exitCode int
}

func (r opnResult) String() string {
	return fmt.Sprintf("opn %s\nexit code %d\nstdout:\n%s\nstderr:\n%s", strings.Join(r.args, " "), r.exitCode, r.stdout, r.stderr)
}

// runOpn runs the CLI in an empty temp dir with the current environment
func runOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	requireLive(t)
	if opnBuildErr != nil {
		t.Fatalf("the opn binary could not be built: %v", opnBuildErr)
	}
	var ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var command = exec.CommandContext(ctx, opnBinary, args...)
	command.Dir = t.TempDir()
	command.Env = os.Environ()
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	var err = command.Run()
	var result = opnResult{args: args, stdout: stdout.String(), stderr: stderr.String()}
	if exitErr, ok := err.(*exec.ExitError); ok {
		result.exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running opn %v: %v", args, err)
	}
	return result
}

func mustOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	var result = runOpn(t, args...)
	if result.exitCode != 0 {
		t.Fatalf("want exit code 0, got:\n%s", result)
	}
	return result
}

func mustFailOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	var result = runOpn(t, args...)
	if result.exitCode != 1 || !strings.HasPrefix(result.stderr, "error: ") {
		t.Errorf("want exit code 1 and an \"error: \" message, got:\n%s", result)
	}
	return result
}

func requireContains(t *testing.T, result opnResult, output string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(output, w) {
			t.Errorf("output lacks %q:\n%s", w, result)
		}
	}
}

func uuidFrom(t *testing.T, result opnResult) string {
	t.Helper()
	var uuid = uuidPattern.FindString(result.stdout)
	if uuid == "" || strings.TrimSpace(result.stdout) != uuid {
		t.Fatalf("add must print only the uuid:\n%s", result)
	}
	return uuid
}

// TestCliVlan drives /interface/vlan through the opn binary, with apply when only this run has VLANs
func TestCliVlan(t *testing.T) {
	var ifs = ifApi(t)
	var tag = freeVlanTag(t, ifs, 1)
	var description = testDescription("cli-vlan")
	const menu = "/interface/vlan"

	var added = mustOpn(t, menu, "add", "parent=vtnet0", "tag="+tag, "description="+description)
	var uuid = uuidFrom(t, added)
	removeCleanup(t, ifs, interfaces.Vlans, uuid)
	requireContains(t, added, added.stderr, "device vlan0")

	var printed = mustOpn(t, menu, "print", "search="+description)
	requireContains(t, printed, printed.stdout, "DEVICE", "PARENT", "vtnet0", tag, description)
	var shown = mustOpn(t, menu, "show", description)
	requireContains(t, shown, shown.stdout, "uuid:", uuid, "parent:", "vtnet0", "proto:", "auto", "assigned:")

	var refused = mustFailOpn(t, menu, "add", "parent=vtnet0", "tag="+tag)
	requireContains(t, refused, refused.stderr, "exists already", uuid)
	if result := mustOpn(t, menu, "set", uuid, "pcp=5", "proto=802.1q"); result.stdout != "" {
		t.Errorf("set must be silent:\n%s", result)
	}
	if item, _ := ifs.Get(interfaces.Vlans, uuid); item.Get("pcp") != "5" || item.Get("proto") != "802.1q" || item.Get("descr") != description {
		t.Errorf("after set: %+v", item.Fields)
	}
	var invalid = mustFailOpn(t, menu, "set", uuid, "parent=a5nosuch0")
	requireContains(t, invalid, invalid.stderr, "parent:")
	if replaced := mustOpn(t, menu, "add", "parent=vtnet0", "tag="+tag, "description="+description, "replace"); uuidFrom(t, replaced) != uuid {
		t.Errorf("replace must keep the uuid:\n%s", replaced)
	}
	if item, _ := ifs.Get(interfaces.Vlans, uuid); item.Get("pcp") != "0" || item.Get("proto") != "" {
		t.Errorf("replace must reset pcp and proto: %+v", item.Fields)
	}

	var applied = onlyOwnItems(t, ifs, interfaces.Vlans)
	var device = interfaces.Vlans.Device(func() interfaces.Item { var item, _ = ifs.Get(interfaces.Vlans, uuid); return item }())
	if applied {
		mustOpn(t, menu, "apply")
		var overview = mustOpn(t, "/interface/overview", "print", "search="+device)
		requireContains(t, overview, overview.stdout, device)
		var detail = mustOpn(t, "/interface/overview", "show", device)
		requireContains(t, detail, detail.stdout, "device:", device, "vlan:", "parent=vtnet0", "tag="+tag)
	}
	mustOpn(t, menu, "remove", description)
	mustFailOpn(t, menu, "show", uuid)
	if applied {
		mustOpn(t, menu, "reconfigure")
		if _, found := overviewDevice(t, ifs, device); found {
			t.Errorf("%s must be gone after remove and apply", device)
		}
	}
}

// TestCliItems drives the other item menus: loopback, vip (lo0), neighbor, vxlan, gif, gre; LAGG and bridge print only
func TestCliItems(t *testing.T) {
	var ifs = ifApi(t)
	var description = testDescription("cli")

	var loopback = uuidFrom(t, mustOpn(t, "/interface/loopback", "add", "description="+description+" lo"))
	removeCleanup(t, ifs, interfaces.Loopbacks, loopback)
	mustOpn(t, "/interface/loopback", "set", loopback, "description="+description+" lo2")
	var loPrint = mustOpn(t, "/interface/loopback", "print")
	requireContains(t, loPrint, loPrint.stdout, description+" lo2")
	mustOpn(t, "/interface/loopback", "remove", description+" lo2")

	var vip = uuidFrom(t, mustOpn(t, "/interface/vip", "add", "interface=lo0", "address=192.0.2.210", "description="+description+" vip"))
	removeCleanup(t, ifs, interfaces.Vips, vip)
	mustFailOpn(t, "/interface/vip", "add", "interface=lo0", "address=192.0.2.210/32")
	mustOpn(t, "/interface/vip", "set", "192.0.2.210", "no-expand")
	var vipShow = mustOpn(t, "/interface/vip", "show", "192.0.2.210/32")
	requireContains(t, vipShow, vipShow.stdout, "interface:", "lo0", "address:", "192.0.2.210/32", "no-expand:", "yes")
	var vipJSON = mustOpn(t, "/interface/vip", "print", "json", "search="+description)
	var row map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(vipJSON.stdout)), &row); err != nil || row["uuid"] != vip {
		t.Errorf("vip json: %v\n%s", err, vipJSON)
	}
	mustOpn(t, "/interface/vip", "remove", vip)

	var neighbor = uuidFrom(t, mustOpn(t, "/interface/neighbor", "add", "address=192.0.2.211", "mac-address=02:00:00:00:a5:11",
		"description="+description+" neighbor"))
	removeCleanup(t, ifs, interfaces.Neighbors, neighbor)
	var nPrint = mustOpn(t, "/interface/neighbor", "print", "search="+description)
	requireContains(t, nPrint, nPrint.stdout, "192.0.2.211", "02:00:00:00:a5:11", "manual")
	mustOpn(t, "/interface/neighbor", "remove", "192.0.2.211")

	var vni = fmt.Sprint(runVni + 2)
	var vxlan = uuidFrom(t, mustOpn(t, "/interface/vxlan", "add", "vni="+vni, "local-address=192.0.2.212", "remote-address=198.51.100.212"))
	removeCleanup(t, ifs, interfaces.Vxlans, vxlan)
	mustFailOpn(t, "/interface/vxlan", "set", vxlan, "group=239.1.1.1", "remote-address=198.51.100.1")
	mustOpn(t, "/interface/vxlan", "set", vxlan, "remote-port=4790")
	var vxShow = mustOpn(t, "/interface/vxlan", "show", vxlan)
	requireContains(t, vxShow, vxShow.stdout, "vni:", vni, "remote-port:", "4790")
	mustOpn(t, "/interface/vxlan", "remove", vxlan)

	for _, name := range []string{"gif", "gre"} {
		var menu = "/interface/" + name
		var uuid = uuidFrom(t, mustOpn(t, menu, "add", "local-address=192.0.2.213", "remote-address=198.51.100.213",
			"tunnel-local-address=192.0.2.214", "tunnel-remote-address=192.0.2.215", "tunnel-prefix=31", "description="+description+" "+name))
		var kind = map[string]interfaces.Kind{"gif": interfaces.Gifs, "gre": interfaces.Gres}[name]
		removeCleanup(t, ifs, kind, uuid)
		var printed = mustOpn(t, menu, "print", "search="+description)
		requireContains(t, printed, printed.stdout, "192.0.2.213", "198.51.100.213", "192.0.2.214 -> 192.0.2.215/31")
		mustOpn(t, menu, "remove", uuid)
	}

	for _, menu := range []string{"/interface/lagg", "/interface/bridge"} {
		var printed = mustOpn(t, menu, "print")
		requireContains(t, printed, printed.stdout, "DEVICE", "MEMBERS")
		// apply is never run live: without confirm=yes it must refuse
		mustFailOpn(t, menu, "apply")
	}
}

// TestCliReadOnly runs the overview, assignment and settings menus (settings: set and restore, never applied)
func TestCliReadOnly(t *testing.T) {
	var ifs = ifApi(t)
	var overview = mustOpn(t, "/interface/overview", "print")
	requireContains(t, overview, overview.stdout, "vtnet0", "lan", "vtnet1", "wan")
	var lan = mustOpn(t, "/interface/overview", "show", "lan")
	requireContains(t, lan, lan.stdout, "device:", "vtnet0", "packets-received:")
	mustFailOpn(t, "/interface/overview", "show", "a5nosuch0")
	mustFailOpn(t, "/interface/overview", "reload", "wan") // no confirm: refused, never run live

	var assignments = mustOpn(t, "/interface/assignment", "print")
	requireContains(t, assignments, assignments.stdout, "IDENTIFIER", "lan", "vtnet0", "wan", "vtnet1")

	var settings = mustOpn(t, "/interface/settings", "print", "detail")
	requireContains(t, settings, settings.stdout, "vlan-hw-filter:", "dhcp6-ra-timeout:", "duid-current:")
	var before, err = ifs.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var restore = before.Dhcp6RaTimeout
		if err := ifs.SettingsSet(interfaces.SettingsFields{Dhcp6RaTimeout: &restore}); err != nil {
			t.Errorf("restore: %v", err)
		}
	})
	mustOpn(t, "/interface/settings", "set", "dhcp6-ra-timeout=41")
	if after, _ := ifs.SettingsGet(); after.Dhcp6RaTimeout != "41" || after.DisableIpv6 != before.DisableIpv6 {
		t.Errorf("after set: %+v", after)
	}
	mustFailOpn(t, "/interface/settings", "apply") // no confirm: refused, never run live
}
