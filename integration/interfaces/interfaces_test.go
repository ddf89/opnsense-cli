//go:build integration

package integrationinterfaces

import (
	"strconv"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/interfaces"
)

// TestVlanLifecycle creates a VLAN on vtnet0 with a high tag, applies it (the VLAN apply only touches VLAN
// devices), checks the device in the overview, removes it and applies again
func TestVlanLifecycle(t *testing.T) {
	var ifs = ifApi(t)
	var tag = freeVlanTag(t, ifs, 0)
	var description = testDescription("vlan")
	var uuid, err = ifs.Create(interfaces.Vlans, map[string]string{"if": "vtnet0", "tag": tag, "pcp": "3", "descr": description})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	removeCleanup(t, ifs, interfaces.Vlans, uuid)

	var item, getErr = ifs.Get(interfaces.Vlans, uuid)
	if getErr != nil || item.Get("tag") != tag || item.Get("pcp") != "3" || item.Get("descr") != description {
		t.Fatalf("Get: %+v / %v", item, getErr)
	}
	var device = interfaces.Vlans.Device(item)
	if !strings.HasPrefix(device, "vlan0") {
		t.Errorf("unexpected device name %q", device)
	}

	// a partial update keeps parent, tag and device name
	if err := ifs.Update(interfaces.Vlans, uuid, map[string]string{"descr": description + " x"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if item, _ = ifs.Get(interfaces.Vlans, uuid); item.Get("if") != "vtnet0" || item.Get("tag") != tag ||
		interfaces.Vlans.Device(item) != device || item.Get("descr") != description+" x" {
		t.Errorf("after Update: %+v", item.Fields)
	}

	// the unique constraint of parent and tag
	if _, err := ifs.Create(interfaces.Vlans, map[string]string{"if": "vtnet0", "tag": tag, "descr": description + " dup"}); err == nil {
		t.Error("a second VLAN with the same parent and tag must be refused")
	}
	// unknown uuids are not created by Update
	if err := ifs.Update(interfaces.Vlans, "00000000-0000-4000-8000-0000000000a5", map[string]string{"descr": description}); !api.IsNotFound(err) {
		t.Errorf("Update of an unknown uuid: want NotFoundError, got %v", err)
	}

	if !onlyOwnItems(t, ifs, interfaces.Vlans) {
		return
	}
	if err := ifs.Reconfigure(interfaces.Vlans); err != nil {
		t.Fatalf("Reconfigure: %v", err)
	}
	if entry, found := overviewDevice(t, ifs, device); !found || string(entry.VlanTag) != tag {
		t.Errorf("after apply the overview must show %s with tag %s: tag %q found %v", device, tag, entry.VlanTag, found)
	}
	if detail, err := ifs.OverviewGet(device); err != nil || detail.Get("device") != device {
		t.Errorf("OverviewGet(%s): %+v / %v", device, detail, err)
	}

	if err := ifs.Remove(interfaces.Vlans, uuid); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := ifs.Reconfigure(interfaces.Vlans); err != nil {
		t.Fatalf("Reconfigure after remove: %v", err)
	}
	if _, found := overviewDevice(t, ifs, device); found {
		t.Errorf("after remove and apply %s must be gone", device)
	}
}

// TestLoopbackLifecycle creates a loopback device, applies it and removes it again
func TestLoopbackLifecycle(t *testing.T) {
	var ifs = ifApi(t)
	var uuid, err = ifs.Create(interfaces.Loopbacks, map[string]string{"description": testDescription("loopback")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	removeCleanup(t, ifs, interfaces.Loopbacks, uuid)
	var item, _ = ifs.Get(interfaces.Loopbacks, uuid)
	var device = interfaces.Loopbacks.Device(item)
	if !strings.HasPrefix(device, "lo") || device == "lo0" {
		t.Fatalf("unexpected device %q", device)
	}
	if !onlyOwnItems(t, ifs, interfaces.Loopbacks) {
		return
	}
	if err := ifs.Reconfigure(interfaces.Loopbacks); err != nil {
		t.Fatalf("Reconfigure: %v", err)
	}
	if _, found := overviewDevice(t, ifs, device); !found {
		t.Errorf("after apply the overview must show %s", device)
	}
	if err := ifs.Remove(interfaces.Loopbacks, uuid); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := ifs.Reconfigure(interfaces.Loopbacks); err != nil {
		t.Fatalf("Reconfigure after remove: %v", err)
	}
	if _, found := overviewDevice(t, ifs, device); found {
		t.Errorf("after remove and apply %s must be gone", device)
	}
	if _, found := overviewDevice(t, ifs, "lo0"); !found {
		t.Error("lo0 must stay")
	}
}

// TestVipLifecycle adds an IP alias with a documentation address on lo0, applies it and removes it again
func TestVipLifecycle(t *testing.T) {
	var ifs = ifApi(t)
	var address = "192.0.2." + strconv.Itoa(100+runVni%50)
	var description = testDescription("vip")
	var uuid, err = ifs.Create(interfaces.Vips, map[string]string{"interface": "lo0", "mode": "ipalias", "network": address + "/32",
		"descr": description})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	removeCleanup(t, ifs, interfaces.Vips, uuid)
	if err := ifs.Update(interfaces.Vips, uuid, map[string]string{"nobind": "1"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	var item, _ = ifs.Get(interfaces.Vips, uuid)
	if interfaces.VipNetwork(item) != address+"/32" || item.Get("interface") != "lo0" || item.Get("nobind") != "1" {
		t.Errorf("after Update: %+v", item.Fields)
	}
	// CARP is not possible on a loopback
	if _, err := ifs.Create(interfaces.Vips, map[string]string{"interface": "lo0", "mode": "carp", "network": "192.0.2.249/32",
		"vhid": "250", "password": "x", "descr": description + " carp"}); err == nil {
		t.Error("CARP on lo0 must be refused")
	}

	if !onlyOwnItems(t, ifs, interfaces.Vips) {
		return
	}
	var hasAddress = func() bool {
		var entry, _ = overviewDevice(t, ifs, "lo0")
		for _, ip := range entry.IPv4 {
			if ip.Address == address+"/32" {
				return true
			}
		}
		return false
	}
	if err := ifs.Reconfigure(interfaces.Vips); err != nil {
		t.Fatalf("Reconfigure: %v", err)
	}
	if !hasAddress() {
		t.Errorf("after apply lo0 must have %s", address)
	}
	if err := ifs.Remove(interfaces.Vips, uuid); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := ifs.Reconfigure(interfaces.Vips); err != nil {
		t.Fatalf("Reconfigure after remove: %v", err)
	}
	if hasAddress() {
		t.Errorf("after remove and apply lo0 must not have %s", address)
	}
}

// TestNeighborAndVxlan create a static ARP entry and a VXLAN with documentation addresses (the VXLAN is skipped by
// apply: its local address does not exist), apply both and remove them
func TestNeighborAndVxlan(t *testing.T) {
	var ifs = ifApi(t)
	var neighbor, err = ifs.Create(interfaces.Neighbors, map[string]string{"ipaddress": "192.0.2.201", "etheraddr": "02:00:00:00:a5:01",
		"descr": testDescription("neighbor")})
	if err != nil {
		t.Fatalf("Create neighbor: %v", err)
	}
	removeCleanup(t, ifs, interfaces.Neighbors, neighbor)
	if item, _ := ifs.Get(interfaces.Neighbors, neighbor); item.Get("origin") != interfaces.NeighborManual {
		t.Errorf("unexpected neighbor %+v", item.Fields)
	}
	var vxlan, vxErr = ifs.Create(interfaces.Vxlans, map[string]string{"vxlanid": strconv.Itoa(runVni), "vxlanlocal": "192.0.2.202",
		"vxlanremote": "198.51.100.202"})
	if vxErr != nil {
		t.Fatalf("Create VXLAN: %v", vxErr)
	}
	removeCleanup(t, ifs, interfaces.Vxlans, vxlan)
	if _, err := ifs.Create(interfaces.Vxlans, map[string]string{"vxlanid": strconv.Itoa(runVni + 1), "vxlanlocal": "192.0.2.202"}); err == nil {
		t.Error("a VXLAN without remote address or group must be refused")
	}

	for _, kind := range []interfaces.Kind{interfaces.Neighbors, interfaces.Vxlans} {
		if onlyOwnItems(t, ifs, kind) {
			if err := ifs.Reconfigure(kind); err != nil {
				t.Errorf("Reconfigure %s: %v", kind.Name, err)
			}
		}
	}
	if err := ifs.Remove(interfaces.Neighbors, neighbor); err != nil {
		t.Errorf("Remove neighbor: %v", err)
	}
	if err := ifs.Remove(interfaces.Vxlans, vxlan); err != nil {
		t.Errorf("Remove VXLAN: %v", err)
	}
	for _, kind := range []interfaces.Kind{interfaces.Neighbors, interfaces.Vxlans} {
		if onlyOwnItems(t, ifs, kind) {
			if err := ifs.Reconfigure(kind); err != nil {
				t.Errorf("Reconfigure %s after remove: %v", kind.Name, err)
			}
		}
	}
}

// TestTunnelsSaveOnly creates GIF and GRE tunnels with documentation addresses, never applied
func TestTunnelsSaveOnly(t *testing.T) {
	var ifs = ifApi(t)
	for _, kind := range []interfaces.Kind{interfaces.Gifs, interfaces.Gres} {
		var uuid, err = ifs.Create(kind, map[string]string{"local-addr": "192.0.2.203", "remote-addr": "198.51.100.203",
			"tunnel-local-addr": "192.0.2.204", "tunnel-remote-addr": "192.0.2.205", "descr": testDescription(kind.Name)})
		if err != nil {
			t.Fatalf("Create %s: %v", kind.Name, err)
		}
		removeCleanup(t, ifs, kind, uuid)
		if err := ifs.Update(kind, uuid, map[string]string{"tunnel-remote-net": "30"}); err != nil {
			t.Fatalf("Update %s: %v", kind.Name, err)
		}
		var item, _ = ifs.Get(kind, uuid)
		if item.Get("local-addr") != "192.0.2.203" || item.Get("ipaddr") != "192.0.2.203" || item.Get("if") != "" ||
			item.Get("tunnel-remote-net") != "30" || kind.Device(item) == "" {
			t.Errorf("%s after Update: %+v", kind.Name, item.Fields)
		}
		if err := ifs.Remove(kind, uuid); err != nil {
			t.Errorf("Remove %s: %v", kind.Name, err)
		}
		if err := ifs.Remove(kind, uuid); !api.IsNotFound(err) {
			t.Errorf("second Remove %s: want NotFoundError, got %v", kind.Name, err)
		}
	}
}

// TestReadOnly reads LAGGs, bridges, the forms, the overview, the assignments and the settings
func TestReadOnly(t *testing.T) {
	var ifs = ifApi(t)
	for _, kind := range interfaces.Kinds {
		if _, err := ifs.List(kind); err != nil {
			t.Errorf("List %s: %v", kind.Name, err)
		}
		if _, err := ifs.Form(kind); err != nil {
			t.Errorf("Form %s: %v", kind.Name, err)
		}
	}
	if form, _ := ifs.Form(interfaces.Vlans); len(form.Options["if"]) == 0 || form.Defaults["pcp"] != "0" {
		t.Errorf("VLAN form %+v", form)
	}
	if lan, found := overviewDevice(t, ifs, "vtnet0"); !found || lan.Identifier != "lan" || lan.Addr4 == "" {
		t.Errorf("overview vtnet0: %+v / %v", lan, found)
	}
	if list, err := ifs.Overview("vtnet1"); err != nil || len(list) != 1 || list[0].Identifier != "wan" {
		t.Errorf("Overview search: %+v / %v", list, err)
	}
	if _, err := ifs.OverviewGet("nosuch99"); !api.IsNotFound(err) {
		t.Errorf("OverviewGet of an unknown device: %v", err)
	}
	if settings, err := ifs.SettingsGet(); err != nil || settings.DisableVlanHwFilter == "" || settings.Dhcp6RaTimeout == "" {
		t.Errorf("SettingsGet: %+v / %v", settings, err)
	}
	if vhid, err := ifs.UnusedVhid(); err != nil || vhid < 1 {
		t.Errorf("UnusedVhid: %d / %v", vhid, err)
	}
}

// TestSettingsSetRestore changes the router advertisement timeout and restores it, never applied (the settings
// controller only saves)
func TestSettingsSetRestore(t *testing.T) {
	var ifs = ifApi(t)
	var before, err = ifs.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var restore = before.Dhcp6RaTimeout
		if err := ifs.SettingsSet(interfaces.SettingsFields{Dhcp6RaTimeout: &restore}); err != nil {
			t.Errorf("restore: %v", err)
		}
		if after, _ := ifs.SettingsGet(); after.Dhcp6RaTimeout != before.Dhcp6RaTimeout {
			t.Errorf("not restored: %q, want %q", after.Dhcp6RaTimeout, before.Dhcp6RaTimeout)
		}
	})
	var changed = "37"
	if before.Dhcp6RaTimeout == changed {
		changed = "38"
	}
	if err := ifs.SettingsSet(interfaces.SettingsFields{Dhcp6RaTimeout: &changed}); err != nil {
		t.Fatal(err)
	}
	var after, _ = ifs.SettingsGet()
	if after.Dhcp6RaTimeout != changed || after.DisableChecksumOffloading != before.DisableChecksumOffloading ||
		after.DisableVlanHwFilter != before.DisableVlanHwFilter {
		t.Errorf("after set: %+v (before %+v)", after, before)
	}
	var invalid = "abc"
	if err := ifs.SettingsSet(interfaces.SettingsFields{Dhcp6RaTimeout: &invalid}); err == nil {
		t.Error("an invalid timeout must be refused")
	}
}
