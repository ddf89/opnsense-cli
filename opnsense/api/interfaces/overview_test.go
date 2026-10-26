package interfaces

import (
	"reflect"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

// testOverview is interfaces/overview/interfaces_info of OPNsense 26.7 (shortened): an assigned device with a
// CARP address and an unassigned one
const testOverview = `{"total":2,"rowCount":2,"current":1,"rows":[` +
	`{"flags":["up","running"],"macaddr":"52:54:00:12:34:56","is_physical":true,"device":"vtnet0","mtu":"1500",` +
	`"media":"10Gbase-T <full-duplex>","status":"up","routes":["192.168.1.0/24"],"config":{"if":"vtnet0"},` +
	`"identifier":"lan","description":"LAN","enabled":true,"link_type":"static","link_typev6":"track6",` +
	`"addr4":"192.168.1.1/24","addr6":"","ipv4":[{"ipaddr":"192.168.1.1/24"},{"ipaddr":"192.168.1.10/24","vhid":"3",` +
	`"status":"MASTER","advbase":"1","advskew":"0"}],"ipv6":[{"ipaddr":"fe80::1/64"}],"vlan_tag":null,"gateways":["192.168.1.254"]},` +
	`{"flags":[],"macaddr":"00:00:00:00:00:00","ipv4":[],"ipv6":[],"is_physical":false,"device":"vlan01","mtu":"1500",` +
	`"vlan":{"tag":"4091","parent":"vtnet0","pcp":"0","proto":"802.1q"},"status":"down","identifier":"","description":"Unassigned Interface"}]}`

func TestOverview(t *testing.T) {
	var api, requests = newTestApi(t, func(r testRequest) (int, string) { return 200, testOverview })
	var list, err = api.Overview("")
	if err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Method != "GET" || got.Path != "/api/interfaces/overview/interfaces_info" {
		t.Errorf("unexpected request %+v", got)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 devices, got %+v", list)
	}
	var lan = list[0]
	if lan.Device != "vtnet0" || lan.Identifier != "lan" || !lan.Enabled || !lan.IsPhysical || lan.Mtu != "1500" ||
		lan.LinkTypeV6 != "track6" || lan.VlanTag != "" || !reflect.DeepEqual(lan.Gateways, []string{"192.168.1.254"}) {
		t.Errorf("unexpected lan %+v", lan)
	}
	var carp = OverviewAddress{Address: "192.168.1.10/24", Vhid: "3", Status: "MASTER", Advbase: "1", Advskew: "0"}
	if len(lan.IPv4) != 2 || lan.IPv4[1] != carp || len(lan.IPv6) != 1 {
		t.Errorf("addresses %+v / %+v", lan.IPv4, lan.IPv6)
	}
	if list[1].VlanTag != "4091" || list[1].Identifier != "" || list[1].Vlan["parent"] != "vtnet0" || !strings.Contains(string(list[1].Raw), `"parent":"vtnet0"`) {
		t.Errorf("unexpected vlan %+v", list[1])
	}

	// a search is POSTed, interfaces_info ignores searchPhrase on GET
	if _, err := api.Overview("vtnet"); err != nil {
		t.Fatal(err)
	}
	var want = map[string]any{"current": float64(1), "rowCount": float64(-1), "searchPhrase": "vtnet"}
	if got := (*requests)[1]; got.Method != "POST" || !reflect.DeepEqual(got.Body, want) {
		t.Errorf("unexpected search request %+v", got)
	}
}

func TestOverviewGet(t *testing.T) {
	var answer = `{"message":{"flags":{"value":["up","running"],"translation":"Flags"},"mtu":{"value":"1500","translation":"mtu"},` +
		`"is_physical":{"value":true,"translation":"Physical"},"vlan_tag":{"value":null,"translation":"VLAN Tag"},` +
		`"packets received":{"value":"1973","translation":"Packets Received"}}}`
	var api, requests = newTestApi(t, func(r testRequest) (int, string) { return 200, answer })
	var detail, err = api.OverviewGet("vtnet0")
	if err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Path != "/api/interfaces/overview/get_interface/vtnet0" {
		t.Errorf("unexpected request %+v", got)
	}
	var keys []string
	for _, entry := range detail.Entries {
		keys = append(keys, entry.Key)
	}
	if !reflect.DeepEqual(keys, []string{"flags", "mtu", "is_physical", "vlan_tag", "packets received"}) {
		t.Errorf("keys %q", keys)
	}
	if detail.Entries[4].Label != "Packets Received" || detail.Get("flags") != "up,running" || detail.Get("is_physical") != "1" ||
		detail.Get("vlan_tag") != "" || detail.Get("missing") != "" {
		t.Errorf("unexpected detail %+v", detail)
	}

	answer = `{"message":"failed"}`
	if _, err := api.OverviewGet("nosuch0"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	for _, device := range []string{"", "a/b", "a b"} {
		if _, err := api.OverviewGet(device); err == nil {
			t.Errorf("OverviewGet(%q): want an error", device)
		}
	}
}

func TestOverviewReload(t *testing.T) {
	var answer = `{"message":"OK\n\n"}`
	var api, requests = newTestApi(t, func(r testRequest) (int, string) { return 200, answer })
	if output, err := api.OverviewReload("opt1"); err != nil || output != "OK" {
		t.Errorf("OverviewReload: %q / %v", output, err)
	}
	if got := (*requests)[0]; got.Method != "POST" || got.Path != "/api/interfaces/overview/reload_interface/opt1" || got.Body == nil {
		t.Errorf("unexpected request %+v", got)
	}
	answer = `{"message":"failed"}`
	if _, err := api.OverviewReload("opt1"); err == nil {
		t.Error("want an error")
	}
	if _, err := api.OverviewReload(""); err == nil || len(*requests) != 2 {
		t.Errorf("an empty identifier must fail before any call: %v", err)
	}
}
