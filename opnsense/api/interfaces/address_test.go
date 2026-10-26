package interfaces

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

// testAddressRows are assignment/search_item rows of OPNsense 26.7 (shortened to the address fields): lan static
// with track6, opt1 with a staged static IPv4 address, gateway, MTU and DHCP fields
const testAddressRows = `{"uuid":"lan","descr":"","%descr":"LAN","identifier":"lan","pending_action":"","if":"vtnet0","lock":"0",` +
	`"enable":"1","blockpriv":"0","blockbogons":"0","spoofmac":"","mtu":"","mss":"","type4":"staticv4","%type4":"Static IPv4",` +
	`"type6":"idassoc6","%type6":"Identity association","ipaddr":"192.168.1.1/24","ipaddrv6":"","dhcphostname":"",` +
	`"dhcprejectfrom":"","track6-interface":"wan","%track6-interface":"WAN","track6-prefix-id":"0x0","gateway":"","gatewayv6":""},` +
	`{"uuid":"opt1","descr":"guests","identifier":"opt1","pending_action":"update","if":"lo1","lock":"1","enable":"1",` +
	`"blockpriv":"1","blockbogons":"1","spoofmac":"02:00:00:00:00:01","mtu":"1400","mss":"1360","type4":"staticv4",` +
	`"type6":"staticv6","ipaddr":"192.0.2.1/24","ipaddrv6":"2001:db8::1/64","dhcphostname":"fw1",` +
	`"dhcprejectfrom":"192.0.2.9,192.0.2.10","track6-interface":"","track6-prefix-id":"","gateway":"GW4","gatewayv6":"GW6"}`

func TestAddresses(t *testing.T) {
	var api, requests = newTestApi(t, func(r testRequest) (int, string) {
		return 200, `{"rows":[` + testAddressRows + `]}`
	})
	var addresses, err = api.Addresses()
	if err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Method != "GET" || got.Path != "/api/interfaces/assignment/search_item" {
		t.Errorf("unexpected request %+v", got)
	}
	if len(addresses) != 2 {
		t.Fatalf("got %+v", addresses)
	}
	var lan = addresses[0]
	if lan.Identifier != "lan" || lan.Description != "LAN" || lan.Type4 != AddressType4Static || lan.IPv4 != "192.168.1.1/24" ||
		lan.Type6 != AddressType6IDAssoc || lan.Track6Interface != "wan" || lan.Track6PrefixID != "0x0" || lan.BlockPrivate ||
		lan.DHCPRejectFrom != nil {
		t.Errorf("unexpected lan %+v", lan)
	}
	var opt1 = addresses[1]
	var want = Address{Assignment: opt1.Assignment, Type4: AddressType4Static, Type6: AddressType6Static, Gateway4: "GW4", Gateway6: "GW6",
		MTU: "1400", MSS: "1360", SpoofMAC: "02:00:00:00:00:01", BlockPrivate: true, BlockBogons: true, DHCPHostname: "fw1",
		DHCPRejectFrom: []string{"192.0.2.9", "192.0.2.10"}}
	if !reflect.DeepEqual(opt1, want) || opt1.IPv4 != "192.0.2.1/24" || opt1.IPv6 != "2001:db8::1/64" || opt1.PendingAction != "update" {
		t.Errorf("unexpected opt1 %+v", opt1)
	}

	if _, err := api.AddressGet("opt1"); err != nil {
		t.Errorf("AddressGet: %v", err)
	}
	if _, err := api.AddressGet("opt9"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	var before = len(*requests)
	if _, err := api.AddressGet("../x"); err == nil || len(*requests) != before {
		t.Errorf("an invalid identifier must fail before any call: %v", err)
	}
}

// testAddressForm is assignment/get_item/opt1 of OPNsense 26.7 (shortened to the option fields)
const testAddressForm = `{"interface":{"identifier":"opt1","type4":{"":{"value":"None","selected":0},"staticv4":{"value":"Static IPv4","selected":1},` +
	`"dhcp":{"value":"DHCP","selected":0}},"type6":{"":{"value":"None","selected":1},"staticv6":{"value":"Static IPv6","selected":0}},` +
	`"gateway":{"":{"value":"None","selected":1},"GW4":{"value":"GW4","selected":0}},"gatewayv6":{"":{"value":"None","selected":1}},` +
	`"track6-interface":{"":{"value":"None","selected":1},"wan":{"value":"WAN","selected":0}}}}`

func TestAddressChoices(t *testing.T) {
	var api, requests = newTestApi(t, func(r testRequest) (int, string) {
		if strings.HasSuffix(r.Path, "/opt9") {
			return 200, `[]`
		}
		return 200, testAddressForm
	})
	var choices, err = api.AddressChoices("opt1")
	if err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Method != "GET" || got.Path != "/api/interfaces/assignment/get_item/opt1" {
		t.Errorf("unexpected request %+v", got)
	}
	if len(choices.Type4) != 3 || !choices.Type4[1].Selected || len(choices.Gateway4) != 2 || choices.Gateway4[1].Key != "GW4" ||
		len(choices.Gateway6) != 1 || choices.Track6Interface[1].Key != "wan" {
		t.Errorf("unexpected choices %+v", choices)
	}
	if _, err := api.AddressChoices(""); err != nil || (*requests)[1].Path != "/api/interfaces/assignment/get_item" {
		t.Errorf("without identifier the choices of a new interface: %v %+v", err, (*requests)[1])
	}
	if _, err := api.AddressChoices("opt9"); !coreapi.IsNotFound(err) {
		t.Errorf("get_item answers [] for an unknown interface, want not found: %v", err)
	}
	var before = len(*requests)
	if _, err := api.AddressChoices("x/y"); err == nil || len(*requests) != before {
		t.Errorf("an invalid identifier must fail before any call: %v", err)
	}
}

func TestAddressUpdate(t *testing.T) {
	var rows = testAddressRows
	var api, requests = newTestApi(t, func(r testRequest) (int, string) {
		if r.Method == "POST" {
			return 200, `{"result":"saved"}`
		}
		return 200, `{"rows":[` + rows + `]}`
	})
	// the values the read back shows (opt1 of testAddressRows)
	var static4, ipv4, gateway, mtu, prefix = AddressType4Static, "192.0.2.1/24", "GW4", "1400", "0x00"
	var private = true
	var servers = []string{"192.0.2.9", "192.0.2.10"}
	var mac = "02:00:00:00:00:01"
	if err := api.AddressUpdate("opt1", AddressChange{Type4: &static4, IPv4: &ipv4, Gateway4: &gateway, MTU: &mtu,
		BlockPrivate: &private, DHCPRejectFrom: &servers, SpoofMAC: &mac}); err != nil {
		t.Fatal(err)
	}
	var post = (*requests)[1]
	if post.Method != "POST" || post.Path != "/api/interfaces/assignment/set_item/opt1" {
		t.Fatalf("unexpected request %+v", post)
	}
	var want = map[string]any{"interface": map[string]any{"type4": "staticv4", "ipaddr": "192.0.2.1/24", "gateway": "GW4", "mtu": "1400",
		"blockpriv": "1", "dhcprejectfrom": "192.0.2.9,192.0.2.10", "spoofmac": "02:00:00:00:00:01"}}
	if !reflect.DeepEqual(post.Body, want) {
		t.Errorf("body %v, want %v", post.Body, want)
	}

	// a type other than static clears the address and the gateway; the read back shows the old values: ignored
	var none4 = AddressType4None
	var err = api.AddressUpdate("opt1", AddressChange{Type4: &none4})
	post = (*requests)[len(*requests)-2]
	if !reflect.DeepEqual(post.Body, map[string]any{"interface": map[string]any{"type4": "", "ipaddr": "", "gateway": ""}}) {
		t.Errorf("body %v", post.Body)
	}
	if err == nil || !strings.Contains(err.Error(), "kept the staged type4, ipaddr, gateway of opt1") {
		t.Errorf("want the ignored change reported, got %v", err)
	}

	// hex prefix IDs compare by number, MAC addresses case-insensitive
	rows = strings.Replace(strings.Replace(testAddressRows, `"track6-prefix-id":""`, `"track6-prefix-id":"0x0"`, 1),
		`"spoofmac":"02:00:00:00:00:01"`, `"spoofmac":"02:00:00:00:00:ab"`, 1)
	var upperMac = "02:00:00:00:00:AB"
	if err := api.AddressUpdate("opt1", AddressChange{Track6PrefixID: &prefix, SpoofMAC: &upperMac}); err != nil {
		t.Errorf("0x00 is 0x0: %v", err)
	}

	if err := api.AddressUpdate("opt1", AddressChange{}); err == nil || !strings.Contains(err.Error(), "nothing to change") {
		t.Errorf("want nothing to change, got %v", err)
	}
	var before = len(*requests)
	if err := api.AddressUpdate("opt9", AddressChange{MTU: &mtu}); !coreapi.IsNotFound(err) || len(*requests) != before+1 {
		t.Errorf("want not found without a change, got %v", err)
	}

	var invalid, _ = newTestApi(t, func(r testRequest) (int, string) {
		if r.Method == "POST" {
			return 200, `{"result":"failed","validations":{"interface.gateway":"This gateway belongs to a different interface."}}`
		}
		return 200, `{"rows":[` + testAddressRows + `]}`
	})
	var validation *coreapi.ValidationError
	if err := invalid.AddressUpdate("opt1", AddressChange{Gateway4: &gateway}); !errors.As(err, &validation) {
		t.Errorf("want the validation error, got %v", err)
	}
}
