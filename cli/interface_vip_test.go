package cli

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Tests of /interface/vip and /interface/neighbor

const interfaceVipPath = "/api/interfaces/vip_settings/"

func interfaceVipRows() []map[string]any {
	return []map[string]any{
		{"uuid": "vip-alias", "interface": "lan", "%interface": "LAN", "mode": "ipalias", "%mode": "IP Alias", "subnet": "192.168.1.10",
			"subnet_bits": "24", "gateway": "", "noexpand": "0", "nobind": "0", "password": "", "vhid": "", "advbase": "1", "advskew": "0",
			"peer": "", "peer6": "", "nosync": "0", "address": "192.168.1.10/24", "vhid_txt": "", "descr": "service"},
		{"uuid": "vip-carp", "interface": "wan", "%interface": "WAN", "mode": "carp", "%mode": "CARP", "subnet": "203.0.113.10",
			"subnet_bits": "24", "gateway": "", "noexpand": "0", "nobind": "0", "password": "s3cret", "vhid": "10", "advbase": "1",
			"advskew": "100", "peer": "", "peer6": "", "nosync": "1", "address": "203.0.113.10/24", "vhid_txt": "10 (freq. 1/100)", "descr": ""},
	}
}

func interfaceVipFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(interfaceVipPath+"search_item", rows...)
	f.on("GET", interfaceVipPath+"get_item", 200, `{"vip":{"interface":{"wan":{"value":"WAN","selected":0},"lan":{"value":"LAN","selected":0},`+
		`"lo0":{"value":"Loopback","selected":0}},"mode":{"ipalias":{"value":"IP Alias","selected":1},"carp":{"value":"CARP","selected":0},`+
		`"proxyarp":{"value":"Proxy ARP","selected":0}},"gateway":"","noexpand":"0","nobind":"0","password":"","vhid":"","advbase":"1",`+
		`"advskew":"0","peer":"","peer6":"","nosync":"0","address":"","vhid_txt":"","descr":"","network":""}}`)
	return f
}

func TestInterfaceVipPrint(t *testing.T) {
	t.Parallel()
	var f = interfaceVipFake(t, interfaceVipRows()...)
	var r = f.run("/interface/vip", "print")
	wantExit(t, r, 0)
	var want = []string{"#|INTERFACE|MODE|ADDRESS|VHID|DESCRIPTION", "0|lan|ipalias|192.168.1.10/24|-|service", "1|wan|carp|203.0.113.10/24|10|-"}
	if got := interfaceLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	// the CARP password is never shown
	for _, args := range [][]string{{"print", "json"}, {"print", "detail"}, {"show", "203.0.113.10"}} {
		var out = f.run(append([]string{"/interface/vip"}, args...)...)
		wantExit(t, out, 0)
		wantNotContains(t, "output", out.stdout, "s3cret")
		wantContains(t, "output", out.stdout, "********")
	}
	var asJSON = f.run("/interface/vip", "print", "json")
	var row map[string]any
	if err := json.Unmarshal([]byte(strings.Split(asJSON.stdout, "\n")[1]), &row); err != nil || row["vhid_txt"] != "10 (freq. 1/100)" {
		t.Errorf("want the raw row, got %q", asJSON.stdout)
	}
	var shown = f.run("/interface/vip", "show", "203.0.113.10/24")
	wantContains(t, "stdout", shown.stdout, "address:      203.0.113.10/24", "adv-skew:     100", "no-sync:      yes")
	wantExit(t, f.run("/interface/vip", "show", "service"), 0)
	wantNoMutations(t, f)
}

func TestInterfaceVipAdd(t *testing.T) {
	t.Parallel()
	var f = interfaceVipFake(t, interfaceVipRows()...)
	f.on("POST", interfaceVipPath+"add_item", 200, answerAdded("vip-new"))
	var r = f.run("/interface/vip", "add", "interface=lan", "address=192.168.1.11", "no-bind", "description=dns")
	wantExit(t, r, 0)
	if r.stdout != "vip-new\n" {
		t.Errorf("want the uuid, got %q", r.stdout)
	}
	// a bare address is a /32, sent as network
	wantJSON(t, wantOneMutation(t, f, "POST", interfaceVipPath+"add_item"), map[string]any{"vip": map[string]any{
		"interface": "lan", "network": "192.168.1.11/32", "nobind": "1", "descr": "dns"}})

	t.Run("carp", func(t *testing.T) {
		t.Parallel()
		var f = interfaceVipFake(t)
		f.on("POST", interfaceVipPath+"add_item", 200, answerAdded("vip-new"))
		wantExit(t, f.run("/interface/vip", "add", "interface=opt1", "mode=CARP", "address=2001:db8::10", "vhid=20", "password=pw",
			"adv-base=2", "adv-skew=50", "peer6=2001:db8::2"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", interfaceVipPath+"add_item"), map[string]any{"vip": map[string]any{
			"interface": "opt1", "mode": "carp", "network": "2001:db8::10/128", "vhid": "20", "password": "pw", "advbase": "2",
			"advskew": "50", "peer6": "2001:db8::2"}})
	})

	t.Run("refused before any call", func(t *testing.T) {
		t.Parallel()
		for _, args := range [][]string{{"interface=lan"}, {"address=192.168.1.12"}, {"interface=lan", "address=192.168.1.300"},
			{"interface=lan", "address=192.168.1.12/33"}, {"interface=lan", "address=192.168.1.12", "mode=vrrp"},
			{"interface=lan", "address=192.168.1.12", "mode=carp"}, {"interface=lan", "address=192.168.1.12", "mode=carp", "vhid=1"},
			{"interface=lan", "address=192.168.1.12", "vhid=256"}, {"interface=lan", "address=192.168.1.12", "peer=2001:db8::1"},
			{"interface=lan", "address=192.168.1.12", "peer6=192.0.2.1"}, {"interface=lan", "address=192.168.1.12", "adv-skew=255"}} {
			var f = interfaceVipFake(t)
			wantFailure(t, f.run(append([]string{"/interface/vip", "add"}, args...)...))
			wantNoCalls(t, f)
		}
	})

	t.Run("exists and replace", func(t *testing.T) {
		t.Parallel()
		var f = interfaceVipFake(t, interfaceVipRows()...)
		f.on("POST", interfaceVipPath+"set_item/vip-alias", 200, answerSaved)
		wantFailure(t, f.run("/interface/vip", "add", "interface=opt1", "address=192.168.1.10/32"), "exists already", "vip-alias")
		wantNoMutations(t, f)
		wantExit(t, f.run("/interface/vip", "add", "interface=opt1", "address=192.168.1.10/32", "replace"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", interfaceVipPath+"set_item/vip-alias"), map[string]any{"vip": map[string]any{
			"interface": "opt1", "mode": "ipalias", "network": "192.168.1.10/32", "gateway": "", "noexpand": "0", "nobind": "0",
			"vhid": "", "password": "", "advbase": "1", "advskew": "0", "peer": "", "peer6": "", "nosync": "0", "descr": ""}})
	})

	t.Run("validation of the network", func(t *testing.T) {
		t.Parallel()
		var f = interfaceVipFake(t)
		f.on("POST", interfaceVipPath+"add_item", 200, `{"result":"failed","validations":{"vip.network":["You cannot use the network address."]}}`)
		wantFailure(t, f.run("/interface/vip", "add", "interface=lan", "address=192.168.1.0/24"), "address: You cannot use the network address.")
	})
}

func TestInterfaceVipSetRemoveApply(t *testing.T) {
	t.Parallel()
	var f = interfaceVipFake(t, interfaceVipRows()...)
	f.on("POST", interfaceVipPath+"set_item/vip-carp", 200, answerSaved)
	wantExit(t, f.run("/interface/vip", "set", "203.0.113.10", "adv-skew=0", "password=new"), 0)
	// interface and network are always sent, set_item would queue the address for removal otherwise
	wantJSON(t, wantOneMutation(t, f, "POST", interfaceVipPath+"set_item/vip-carp"), map[string]any{"vip": map[string]any{
		"interface": "wan", "network": "203.0.113.10/24", "advskew": "0", "password": "new"}})

	var remove = interfaceVipFake(t, interfaceVipRows()...)
	remove.on("POST", interfaceVipPath+"del_item/vip-alias", 500, `{"errorMessage":"Address 192.168.1.10 referenced by port forward \"web\"","errorTitle":"Item in use by"}`)
	wantFailure(t, remove.run("/interface/vip", "remove", "192.168.1.10"), "referenced by port forward")

	var apply = interfaceVipFake(t)
	apply.on("POST", interfaceVipPath+"reconfigure", 200, `{"status":"ok"}`)
	wantExit(t, apply.run("/interface/vip", "apply"), 0)
	wantOneMutation(t, apply, "POST", interfaceVipPath+"reconfigure")
}

func TestInterfaceNeighbor(t *testing.T) {
	t.Parallel()
	const path = "/api/interfaces/neighbor_settings/"
	var rows = []map[string]any{
		{"uuid": "n1", "etheraddr": "00:11:22:33:44:55", "ipaddress": "192.168.1.20", "descr": "printer", "origin": "manual"},
		{"uuid": "dhcpd-1", "etheraddr": "00:11:22:33:44:66", "ipaddress": "192.168.1.21", "descr": "", "origin": "dhcpd"},
	}
	var f = newFakeOPN(t)
	f.search(path+"search_item", rows...)
	f.on("GET", path+"get_item", 200, `{"neighbor":{"etheraddr":"","ipaddress":"","descr":"","origin":""}}`)
	f.on("POST", path+"add_item", 200, answerAdded("n2"))
	f.on("POST", path+"set_item/n1", 200, answerSaved)
	f.on("POST", path+"del_item/n1", 200, answerDeleted)

	var printed = f.run("/interface/neighbor", "print")
	wantExit(t, printed, 0)
	var want = []string{"#|ADDRESS|MAC-ADDRESS|ORIGIN|DESCRIPTION", "0|192.168.1.20|00:11:22:33:44:55|manual|printer", "1|192.168.1.21|00:11:22:33:44:66|dhcpd|-"}
	if got := interfaceLines(printed.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	var shown = f.run("/interface/neighbor", "show", "00:11:22:33:44:66")
	wantContains(t, "stdout", shown.stdout, "origin:", "dhcpd")

	wantExit(t, f.run("/interface/neighbor", "add", "address=2001:db8::20", "mac-address=02:00:00:00:00:20"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", path+"add_item"), map[string]any{"neighbor": map[string]any{
		"ipaddress": "2001:db8::20", "etheraddr": "02:00:00:00:00:20"}})
	wantFailure(t, f.run("/interface/neighbor", "add", "address=192.168.1.20", "mac-address=02:00:00:00:00:20"), "exists already", "n1")
	for _, args := range [][]string{{"address=192.168.1.30"}, {"mac-address=02:00:00:00:00:20"}, {"address=x", "mac-address=02:00:00:00:00:20"},
		{"address=192.168.1.30", "mac-address=02:00:00:00:00:20:01:02"}} {
		var refused = newFakeOPN(t)
		wantFailure(t, refused.run(append([]string{"/interface/neighbor", "add"}, args...)...))
		wantNoCalls(t, refused)
	}

	// generated entries can not be changed, nothing is sent
	var before = len(f.mutations())
	wantFailure(t, f.run("/interface/neighbor", "set", "192.168.1.21", "description=x"), "generated by dhcpd")
	wantFailure(t, f.run("/interface/neighbor", "remove", "1"), "generated by dhcpd")
	if len(f.mutations()) != before {
		t.Errorf("unexpected mutations %v", f.mutations()[before:])
	}
	wantExit(t, f.run("/interface/neighbor", "set", "printer", "mac-address=00:11:22:33:44:56"), 0)
	wantExit(t, f.run("/interface/neighbor", "remove", "192.168.1.20"), 0)
	var mutations = f.mutations()[before:]
	if len(mutations) != 2 || mutations[0].Path != path+"set_item/n1" || mutations[1].Path != path+"del_item/n1" {
		t.Errorf("unexpected mutations %v", mutations)
	}
	wantJSON(t, mutations[0], map[string]any{"neighbor": map[string]any{"etheraddr": "00:11:22:33:44:56"}})
}
