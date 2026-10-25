package cli

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const (
	interfaceOverviewPath = "/api/interfaces/overview/interfaces_info"
	interfaceOverviewInfo = `{"total":3,"rowCount":3,"current":1,"rows":[` +
		`{"flags":["up","running"],"macaddr":"52:54:00:12:34:56","is_physical":true,"device":"vtnet0","mtu":"1500","status":"up",` +
		`"routes":["192.168.1.0/24"],"identifier":"lan","description":"LAN","enabled":true,"link_type":"static","link_typev6":"track6",` +
		`"addr4":"192.168.1.1/24","ipv4":[{"ipaddr":"192.168.1.1/24"},{"ipaddr":"192.168.1.10/24","vhid":"3","status":"MASTER"}],` +
		`"ipv6":[{"ipaddr":"fe80::1/64"},{"ipaddr":"2001:db8::1/64"}],"vlan_tag":null,"gateways":[]},` +
		`{"flags":["up"],"macaddr":"52:54:00:12:34:57","is_physical":true,"device":"vtnet1","mtu":"1500","status":"up",` +
		`"identifier":"wan","description":"WAN","enabled":true,"link_type":"dhcp","ipv4":[{"ipaddr":"10.0.2.15/24"}],"ipv6":[],` +
		`"gateways":["10.0.2.2"]},` +
		`{"flags":[],"macaddr":"00:00:00:00:00:00","ipv4":[],"ipv6":[],"is_physical":false,"device":"vlan01","mtu":"1500",` +
		`"vlan_tag":4091,"status":"down","identifier":"","description":"Unassigned Interface"}]}`
)

func interfaceOverviewFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", interfaceOverviewPath, 200, interfaceOverviewInfo)
	f.on("GET", "/api/interfaces/overview/get_interface/vtnet0", 200, `{"message":{"flags":{"value":["up","running"],"translation":"Flags"},`+
		`"device":{"value":"vtnet0","translation":"Device"},"ipv4":{"value":[{"ipaddr":"192.168.1.10/24","vhid":"3","status":"MASTER"}],"translation":"IPv4"},`+
		`"nd6":{"value":{"flags":["performnud"]},"translation":"nd6"},"is_physical":{"value":true,"translation":"Physical"},`+
		`"vlan_tag":{"value":null,"translation":"VLAN Tag"},"packets received":{"value":"1973","translation":"Packets Received"}}}`)
	return f
}

func TestInterfaceOverviewPrint(t *testing.T) {
	t.Parallel()
	var f = interfaceOverviewFake(t)
	var r = f.run("/interface/overview", "print")
	wantExit(t, r, 0)
	var want = []string{"#|DEVICE|IDENTIFIER|DESCRIPTION|STATUS|IPV4|IPV6|MAC-ADDRESS",
		"0|vtnet0|lan|LAN|up|192.168.1.1/24, 192.168.1.10/24 (vhid 3 MASTER)|2001:db8::1/64|52:54:00:12:34:56",
		"1|vtnet1|wan|WAN|up|10.0.2.15/24|-|52:54:00:12:34:57",
		"2|vlan01|-|Unassigned Interface|down|-|-|00:00:00:00:00:00"}
	if got := interfaceLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	var detail = f.run("/interface/overview", "print", "detail")
	wantContains(t, "stdout", detail.stdout, "link-type-v6:", "track6", "fe80::1/64", "vlan-tag:", "4091", "gateways:", "10.0.2.2")
	var asJSON = f.run("/interface/overview", "print", "json")
	var lines = strings.Split(strings.TrimSpace(asJSON.stdout), "\n")
	var row map[string]any
	if len(lines) != 3 || json.Unmarshal([]byte(lines[2]), &row) != nil || row["vlan_tag"] != float64(4091) {
		t.Errorf("want the raw rows, got %q", asJSON.stdout)
	}

	// a search is POSTed (interfaces_info ignores searchPhrase on GET), that is not a change
	var search = newFakeOPN(t)
	search.on("POST", interfaceOverviewPath, 200, `{"rows":[]}`)
	wantExit(t, search.run("/interface/overview", "print", "search=vtnet1"), 0)
	var calls = search.calls()
	if len(calls) != 1 || calls[0].Method != "POST" || !strings.Contains(calls[0].Body, `"searchPhrase":"vtnet1"`) {
		t.Errorf("unexpected calls %v", calls)
	}
	wantNoMutations(t, f)
}

func TestInterfaceOverviewShow(t *testing.T) {
	t.Parallel()
	var f = interfaceOverviewFake(t)
	for _, selector := range []string{"vtnet0", "lan", "LAN", "0"} {
		var r = f.run("/interface/overview", "show", selector)
		wantExit(t, r, 0)
		var want = []string{"flags:|up, running", "device:|vtnet0", "ipv4:|192.168.1.10/24 status=MASTER vhid=3", "nd6:|flags=performnud",
			"is-physical:|yes", "vlan-tag:", "packets-received:|1973"}
		if got := interfaceLines(r.stdout); !reflect.DeepEqual(got, want) {
			t.Errorf("show %s:\n got  %q\n want %q", selector, got, want)
		}
	}
	var asJSON = f.run("/interface/overview", "show", "lan", "json")
	wantExit(t, asJSON, 0)
	if !strings.HasPrefix(asJSON.stdout, `{"flags":["up","running"],"device":"vtnet0",`) || !strings.Contains(asJSON.stdout, `"vlan_tag":null`) {
		t.Errorf("want one object in API order, got %q", asJSON.stdout)
	}
	wantFailure(t, f.run("/interface/overview", "show", "opt9"), "not found")
	wantNoMutations(t, f)
}

func TestInterfaceOverviewReload(t *testing.T) {
	t.Parallel()
	var f = interfaceOverviewFake(t)
	f.on("POST", "/api/interfaces/overview/reload_interface/wan", 200, `{"message":"OK\n\n"}`)
	// a reload can cut off the access: confirmation needed, nothing is sent without it
	wantFailure(t, f.run("/interface/overview", "reload", "wan"), "access through it can be lost", "confirm=yes")
	wantNoCalls(t, f)
	var r = f.run("/interface/overview", "reload", "vtnet1", "confirm=yes")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("reload must be silent: %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", "/api/interfaces/overview/reload_interface/wan")

	var unassigned = interfaceOverviewFake(t)
	wantFailure(t, unassigned.run("/interface/overview", "reload", "vlan01", "confirm=yes"), "not assigned")
	wantNoMutations(t, unassigned)

	var failing = interfaceOverviewFake(t)
	failing.on("POST", "/api/interfaces/overview/reload_interface/lan", 200, `{"message":"failed"}`)
	wantFailure(t, failing.run("/interface/overview", "reload", "lan", "confirm=yes"), "reload of lan")
}

func TestInterfaceAssignmentPrint(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search(interfaceAssignmentPath,
		map[string]any{"uuid": "wan", "descr": "", "%descr": "WAN", "identifier": "wan", "optgroup": "hardware", "if": "vtnet1",
			"%if": "vtnet1 (52:54:00:12:34:57)", "lock": "0"},
		map[string]any{"uuid": "opt1", "descr": "guests", "identifier": "opt1", "optgroup": "vlan", "if": "vlan01", "lock": "1"})
	var r = f.run("/interface/assignment", "print")
	wantExit(t, r, 0)
	var want = []string{"#|IDENTIFIER|DESCRIPTION|DEVICE|LOCKED", "0|wan|WAN|vtnet1|no", "1|opt1|guests|vlan01|yes"}
	if got := interfaceLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	wantContains(t, "stdout", f.run("/interface/assignment", "print", "detail").stdout, "device-info:", "vtnet1 (52:54:00:12:34:57)", "group:", "vlan")
	wantContains(t, "stdout", f.run("/interface/assignment", "print", "json").stdout, `"identifier":"opt1"`)
	// read only: no add, set or remove
	var help = f.run("/interface/assignment", "?")
	wantNotContains(t, "stdout", help.stdout, "add", "remove", "set ")
	wantNoMutations(t, f)
}

func TestInterfaceTrafficMenuKept(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var r = f.run("/interface", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "print", "monitor-traffic", "vlan", "lagg", "bridge", "gif", "gre", "loopback", "vxlan",
		"vip", "neighbor", "settings", "overview", "assignment")
	wantNoCalls(t, f)
}
