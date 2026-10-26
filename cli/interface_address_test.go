package cli

import (
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const (
	interfaceAddressApi = "/api/interfaces/assignment/"
	// interfaceAddressForm is assignment/get_item/<identifier> of OPNsense 26.7 (shortened to the option fields of
	// the address configuration): one configured IPv4 gateway, no IPv6 gateway, wan as track6 parent
	interfaceAddressForm = `{"interface":{"type4":{"":{"value":"None","selected":1},"staticv4":{"value":"Static IPv4","selected":0},` +
		`"dhcp":{"value":"DHCP","selected":0}},"type6":{"":{"value":"None","selected":1},"staticv6":{"value":"Static IPv6","selected":0}},` +
		`"gateway":{"":{"value":"None","selected":1},"GW_OPT1":{"value":"GW_OPT1","selected":0}},` +
		`"gatewayv6":{"":{"value":"None","selected":1}},"track6-interface":{"":{"value":"None","selected":1},"wan":{"value":"WAN","selected":0}}}}`
	// interfaceAddressOverview is overview/interfaces_info: opt2 holds 127.0.0.1, the address of the fake server the
	// CLI talks to (the access interface)
	interfaceAddressOverview = `{"rows":[` +
		`{"device":"vtnet0","identifier":"lan","description":"LAN","ipv4":[{"ipaddr":"192.168.1.1/24"}],"ipv6":[]},` +
		`{"device":"vtnet1","identifier":"wan","description":"WAN","ipv4":[{"ipaddr":"10.0.2.15/24"}],"ipv6":[]},` +
		`{"device":"vlan01","identifier":"opt1","description":"guests","ipv4":[],"ipv6":[]},` +
		`{"device":"lo1","identifier":"opt2","description":"mgmt","addr4":"127.0.0.1/8","ipv4":[{"ipaddr":"127.0.0.1/8"}],"ipv6":[]}]}`
)

// interfaceAddressRow is an assignment/search_item row of OPNsense 26.7 (shortened to the address fields)
func interfaceAddressRow(identifier string, description string, device string, overrides map[string]any) map[string]any {
	var row = map[string]any{"uuid": identifier, "identifier": identifier, "descr": description, "if": device, "pending_action": "",
		"lock": "0", "enable": "1", "type4": "", "type6": "", "ipaddr": "", "ipaddrv6": "", "gateway": "", "gatewayv6": "",
		"track6-interface": "", "track6-prefix-id": "", "mtu": "", "mss": "", "spoofmac": "", "blockpriv": "0", "blockbogons": "0",
		"dhcphostname": "", "dhcprejectfrom": ""}
	if description == "" {
		row["%descr"] = strings.ToUpper(identifier)
	}
	maps.Copy(row, overrides)
	return row
}

// interfaceAddressFake is a fake OPNsense whose set_item changes the rows search_item returns and stages them
type interfaceAddressFake struct {
	*fakeOPN
	mu      sync.Mutex
	rows    []map[string]any
	pending bool
}

func newInterfaceAddressFake(t *testing.T) *interfaceAddressFake {
	t.Helper()
	var f = &interfaceAddressFake{fakeOPN: newFakeOPN(t), rows: []map[string]any{
		interfaceAddressRow("wan", "", "vtnet1", map[string]any{"type4": "dhcp", "type6": "dhcp6", "blockpriv": "1", "blockbogons": "1"}),
		interfaceAddressRow("lan", "", "vtnet0", map[string]any{"type4": "staticv4", "ipaddr": "192.168.1.1/24", "type6": "idassoc6",
			"track6-interface": "wan", "track6-prefix-id": "0x0"}),
		interfaceAddressRow("opt1", "guests", "vlan01", nil),
		interfaceAddressRow("opt2", "mgmt", "lo1", map[string]any{"type4": "staticv4", "ipaddr": "127.0.0.1/8", "gateway": "GW_OPT1",
			"mtu": "1400", "type6": "6rd"}),
	}}
	f.on("GET", interfaceAddressApi+"get_item", 200, interfaceAddressForm)
	f.on("GET", interfaceOverviewPath, 200, interfaceAddressOverview)
	f.onFunc("GET", interfaceAddressApi+"search_item", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": f.rows, "rowCount": len(f.rows), "total": len(f.rows), "current": 1})
	})
	f.onFunc("GET", interfaceAddressApi+"pending", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var status = "ok"
		if f.pending {
			status = "pending"
		}
		_, _ = io.WriteString(w, `{"status":"`+status+`"}`)
	})
	for _, row := range f.rows {
		var identifier = row["identifier"].(string)
		f.on("GET", interfaceAddressApi+"get_item/"+identifier, 200, interfaceAddressForm)
		f.onFunc("POST", interfaceAddressApi+"set_item/"+identifier, func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Interface map[string]any `json:"interface"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, current := range f.rows {
				if current["identifier"] == identifier {
					maps.Copy(current, body.Interface)
					current["pending_action"] = "update"
					f.pending = true
				}
			}
			_, _ = io.WriteString(w, `{"result":"saved"}`)
		})
	}
	return f
}

func TestInterfaceAddressPrint(t *testing.T) {
	t.Parallel()
	var f = newInterfaceAddressFake(t)
	f.rows[2]["pending_action"] = "update"
	f.pending = true
	var r = f.run("/interface/address", "print")
	wantExit(t, r, 0)
	var want = []string{"#|IDENTIFIER|DESCRIPTION|IPV4-TYPE|IPV4|GATEWAY|IPV6-TYPE|IPV6|MTU|PENDING",
		"0|wan|WAN|dhcp|-|-|dhcp6|-|-|-", "1|lan|LAN|static|192.168.1.1/24|-|idassoc6|-|-|-", "2|opt1|guests|none|-|-|none|-|-|update",
		"3|opt2|mgmt|static|127.0.0.1/8|GW_OPT1|6rd|-|1400|-"}
	if got := interfaceLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	wantContains(t, "stderr", r.stderr, "staged", `"/interface/assignment apply"`)

	var detail = f.run("/interface/address", "print", "detail")
	wantContains(t, "stdout", detail.stdout, "track6-interface:", "wan", "track6-prefix-id:", "0x0", "block-bogons:", "yes", "gateway4:", "GW_OPT1")
	var asJSON = f.run("/interface/address", "print", "json")
	if lines := strings.Split(strings.TrimSpace(asJSON.stdout), "\n"); len(lines) != 4 || !strings.Contains(lines[3], `"ipaddr":"127.0.0.1/8"`) {
		t.Errorf("want the raw rows, got %q", asJSON.stdout)
	}
	// nothing staged: no hint
	f.pending = false
	wantNotContains(t, "stderr", f.run("/interface/address", "print").stderr, "staged")
	wantNoMutations(t, f.fakeOPN)
}

func TestInterfaceAddressShow(t *testing.T) {
	t.Parallel()
	var f = newInterfaceAddressFake(t)
	for _, selector := range []string{"opt2", "mgmt", "lo1", "3"} {
		var r = f.run("/interface/address", "show", selector)
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "identifier:", "opt2", "ipv4-type:", "static", "ipv4:", "127.0.0.1/8", "mtu:", "1400",
			"protected:", "yes, the API connection goes to its address 127.0.0.1")
	}
	wantContains(t, "stdout", f.run("/interface/address", "show", "guests").stdout, "ipv4-type:", "none", "protected:", "no")
	wantContains(t, "stdout", f.run("/interface/address", "show", "lan").stdout, "protected:", "LAN interface")
	wantFailure(t, f.run("/interface/address", "show", "opt9"), "not found")
	wantNoMutations(t, f.fakeOPN)
}

func TestInterfaceAddressSet(t *testing.T) {
	t.Parallel()
	var f = newInterfaceAddressFake(t)
	var r = f.run("/interface/address", "set", "guests", "ipv4-type=Static", "ipv4=192.0.2.1/24", "gateway4=GW_OPT1", "ipv6-type=track6",
		"track6-interface=wan", "track6-prefix-id=0x1", "mtu=1400", "mss=1360", "mac=02:00:5e:10:00:01", "block-private", "block-bogons=no")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("set must be silent: %q", r.stdout)
	}
	wantJSON(t, wantOneMutation(t, f.fakeOPN, "POST", interfaceAddressApi+"set_item/opt1"), map[string]any{"interface": map[string]any{
		"type4": "staticv4", "ipaddr": "192.0.2.1/24", "gateway": "GW_OPT1", "type6": "track6", "ipaddrv6": "", "gatewayv6": "", "track6-interface": "wan",
		"track6-prefix-id": "0x1", "mtu": "1400", "mss": "1360", "spoofmac": "02:00:5e:10:00:01", "blockpriv": "1", "blockbogons": "0"}})

	// IPv6 static; the configured type is enough for a new address
	var static6 = newInterfaceAddressFake(t)
	wantExit(t, static6.run("/interface/address", "set", "2", "ipv6-type=static", "ipv6=2001:db8::1/64"), 0)
	wantExit(t, static6.run("/interface/address", "set", "opt1", "ipv6=2001:db8::2/64", "mtu="), 0)
	var calls = static6.mutations()
	if len(calls) != 2 {
		t.Fatalf("want two set_item calls, got %v", calls)
	}
	wantJSON(t, calls[0], map[string]any{"interface": map[string]any{"type6": "staticv6", "ipaddrv6": "2001:db8::1/64"}})
	wantJSON(t, calls[1], map[string]any{"interface": map[string]any{"ipaddrv6": "2001:db8::2/64", "mtu": ""}})

	// a type other than static clears the address and the gateway (opt2 is not the access interface here)
	var dhcp = newInterfaceAddressFake(t)
	dhcp.rows[3] = interfaceAddressRow("opt2", "spare", "lo2", map[string]any{"type4": "staticv4", "ipaddr": "192.0.2.1/24", "gateway": "GW_OPT1"})
	dhcp.on("GET", interfaceOverviewPath, 200, `{"rows":[]}`)
	wantExit(t, dhcp.run("/interface/address", "set", "spare", "ipv4-type=dhcp", "dhcp-hostname=fw1", "dhcp-reject-from=192.0.2.9,192.0.2.10"), 0)
	wantJSON(t, wantOneMutation(t, dhcp.fakeOPN, "POST", interfaceAddressApi+"set_item/opt2"), map[string]any{"interface": map[string]any{
		"type4": "dhcp", "ipaddr": "", "gateway": "", "dhcphostname": "fw1", "dhcprejectfrom": "192.0.2.9,192.0.2.10"}})

	// refused before anything is changed
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"wan", "mtu=1400"}, "Changing the address settings of wan can cut off the access to the firewall (it is the WAN interface), there is no rollback. Not run: add confirm=yes"},
		{[]string{"lan", "block-bogons"}, "Changing the address settings of lan can cut off the access to the firewall (it is the LAN interface)"},
		{[]string{"1", "ipv4-type=none"}, "Changing the address settings of lan can cut off"},
		{[]string{"mgmt", "mtu=1500"}, "Changing the address settings of opt2 can cut off the access to the firewall (the API connection goes to its address 127.0.0.1)"},
		{[]string{"opt1"}, "nothing to change"},
		{[]string{"opt9", "mtu=1400"}, "not found"},
		{[]string{"opt1", "ipv4-type=dhcp", "ipv4=192.0.2.1/24"}, "ipv4= needs ipv4-type=static (the type is dhcp)"},
		{[]string{"opt1", "ipv4=192.0.2.1/24"}, "ipv4= needs ipv4-type=static (the type is none)"},
		{[]string{"opt1", "gateway4=GW_OPT1"}, "gateway4= needs ipv4-type=static"},
		{[]string{"opt1", "ipv4-type=static"}, "ipv4-type=static needs an address, give ipv4=address/bits"},
		{[]string{"opt1", "ipv4-type=static", "ipv4="}, "ipv4-type=static needs an address, ipv4= can not be empty"},
		{[]string{"opt1", "ipv6-type=static"}, "ipv6-type=static needs an address"},
		{[]string{"opt1", "ipv6-type=static", "ipv6="}, "ipv6= can not be empty"},
		{[]string{"opt1", "ipv6-type=track6"}, "ipv6-type=track6 needs a parent interface, give track6-interface="},
		{[]string{"opt1", "ipv6-type=static", "ipv6=2001:db8::1/64", "track6-interface=wan"}, "track6-interface= needs ipv6-type=track6 or idassoc6"},
		{[]string{"opt1", "track6-prefix-id=0x1"}, "track6-prefix-id= needs ipv6-type=track6 or idassoc6 (the type is none)"},
		{[]string{"opt1", "dhcp-hostname=fw1"}, "dhcp-hostname= needs ipv4-type=dhcp"},
		{[]string{"opt1", "ipv4-type=static", "dhcp-reject-from=192.0.2.9"}, "dhcp-reject-from= needs ipv4-type=dhcp"},
		{[]string{"opt1", "ipv4-type=static", "ipv4=192.0.2.1/24", "gateway4=GW_X"}, `gateway4: "GW_X" is not offered, OPNsense offers: GW_OPT1`},
		{[]string{"opt1", "ipv6-type=static", "ipv6=2001:db8::1/64", "gateway6=GW6"}, "gateway6: OPNsense offers no IPv6 gateways"},
		{[]string{"opt1", "ipv6-type=track6", "track6-interface=lan"}, `track6-interface: "lan" is not offered, OPNsense offers: wan`},
		{[]string{"opt1", "ipv6-type=6rd"}, "ipv6-type"},
		{[]string{"opt1", "ipv4-type=static", "ipv4=192.0.2.1"}, "must be an IPv4 address with prefix length"},
		{[]string{"opt1", "ipv4-type=static", "ipv4=2001:db8::1/64"}, "must be an IPv4 address with prefix length"},
		{[]string{"opt1", "ipv4-type=static", "ipv4=::ffff:192.0.2.1/120"}, "must be an IPv4 address with prefix length"},
		{[]string{"opt1", "ipv4-type=static", "ipv4=192.0.2.1/0"}, "the prefix length must be 1-32"},
		{[]string{"opt1", "ipv4-type=static", "ipv4=192.0.2.1/33"}, "must be an IPv4 address with prefix length"},
		{[]string{"opt1", "ipv6-type=static", "ipv6=192.0.2.1/24"}, "must be an IPv6 address with prefix length"},
		{[]string{"opt1", "mtu=500"}, "must be a number from 576 to 65535"},
		{[]string{"opt1", "mss=70000"}, "must be a number from 576 to 65535"},
		{[]string{"opt1", "mac=02:00:5e:10:00"}, "must be a MAC address"},
		{[]string{"opt1", "track6-prefix-id=1"}, "must be a hex number like 0x1"},
		{[]string{"opt1", "gateway4=a/b"}, "must be a gateway name"},
		{[]string{"opt1", "dhcp-hostname=-x"}, "must be a host name"},
		{[]string{"opt1", "dhcp-reject-from=2001:db8::1"}, "must be IPv4 addresses"},
	} {
		var refused = newInterfaceAddressFake(t)
		var r = refused.run(append([]string{"/interface/address", "set"}, tc.args...)...)
		wantFailure(t, r, tc.want)
		wantNoMutations(t, refused.fakeOPN)
	}

	// confirm=yes changes a protected interface
	var confirmed = newInterfaceAddressFake(t)
	wantExit(t, confirmed.run("/interface/address", "set", "lan", "mtu=1400", "confirm=yes"), 0)
	wantJSON(t, wantOneMutation(t, confirmed.fakeOPN, "POST", interfaceAddressApi+"set_item/lan"), map[string]any{"interface": map[string]any{"mtu": "1400"}})

	// OPNsense ignored the change (a change back to the applied value while another one is staged)
	var ignored = newInterfaceAddressFake(t)
	ignored.on("POST", interfaceAddressApi+"set_item/opt1", 200, `{"result":"saved"}`)
	wantFailure(t, ignored.run("/interface/address", "set", "opt1", "mtu=1400"), "kept the staged mtu of opt1", "apply")

	// OPNsense's validation messages name the arguments
	var invalid = newInterfaceAddressFake(t)
	invalid.on("POST", interfaceAddressApi+"set_item/opt1", 200,
		`{"result":"failed","validations":{"interface.spoofmac":"Cannot assign a MAC address to this type of interface."}}`)
	var failed = invalid.run("/interface/address", "set", "opt1", "mac=02:00:5e:10:00:01")
	wantFailure(t, failed, "mac", "Cannot assign a MAC address")
	wantNotContains(t, "output", failed.stderr, "spoofmac")
}

func TestInterfaceAddressHelp(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var r = f.run("/interface/address", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "print", "show", "set")
	var set = f.run("/interface/address", "set", "?")
	wantExit(t, set, 0)
	wantContains(t, "stdout", set.stdout, "/interface/assignment apply", "ipv4-type", "track6-interface", "lan, wan")
	wantNoCalls(t, f)
}
