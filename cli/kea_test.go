package cli

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const (
	keaSubnet4Path      = "/api/kea/dhcpv4/search_subnet"
	keaReservation4Path = "/api/kea/dhcpv4/search_reservation"
	keaOption4Path      = "/api/kea/dhcpv4/search_option"
	keaSubnetUuid       = "7bbdb6e0-fa69-42b5-91ad-21af3c1ffd54"
	keaSubnet2Uuid      = "8ccdb6e0-fa69-42b5-91ad-21af3c1ffd55"
	keaOptionUuid       = "57db66ef-d177-4a1f-a644-cd1eec79a779"
	keaReservationUuid  = "fd7ffa2d-3cea-4080-9486-4e4cd680df1a"
)

var keaColumnSeparator = regexp.MustCompile(`\s{2,}`)

// keaTestLines splits table / field output into lines with the columns joined by "|"
func keaTestLines(output string) []string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, strings.Join(keaColumnSeparator.Split(line, -1), "|"))
		}
	}
	return lines
}

// keaSubnet4Row is a search_subnet row of 26.7
func keaSubnet4Row(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": keaSubnetUuid, "subnet": "198.51.100.0/24", "valid_lifetime": "", "next_server": "", "option_data_autocollect": "0",
		"option_data.domain_name_servers": "198.51.100.2,198.51.100.3", "option_data.domain_search": "", "option_data.routers": "198.51.100.1",
		"option_data.static_routes": "", "option_data.classless_static_route": "", "option_data.domain_name": "office.example",
		"option_data.ntp_servers": "", "option_data.time_servers": "", "option_data.tftp_server_name": "", "option_data.boot_file_name": "",
		"option_data.v6_only_preferred": "", "option_data.v4_dnr": "", "option": keaOptionUuid, "%option": "wpad", "match-client-id": "1",
		"allocator": "random", "%allocator": "Random", "pools": "198.51.100.10-198.51.100.20\n198.51.100.32/28",
		"ddns_forward_zone": "", "ddns_reverse_zone": "", "ddns_qualifying_suffix": "", "ddns_dns_server": "", "ddns_dns_port": "",
		"ddns_domain_key_name": "k", "ddns_domain_key_secret": "c2VjcmV0", "ddns_domain_key_algorithm": "hmac-sha256",
		"ddns_override_no_update": "0", "ddns_override_client_update": "0", "ddns_update_on_renew": "0", "ddns_conflict_resolution_mode": "",
		"description": "office",
	}, overrides)
}

func keaReservation4Row(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": keaReservationUuid, "subnet": keaSubnetUuid, "%subnet": "198.51.100.0/24", "ip_address": "198.51.100.50",
		"hw_address": "02:00:5e:10:00:01", "client_id": "", "hostname": "printer", "description": "", "next_server": "",
		"option_data.domain_name_servers": "", "option_data.domain_search": "", "option_data.routers": "", "option_data.static_routes": "",
		"option_data.classless_static_route": "", "option_data.domain_name": "", "option_data.ntp_servers": "", "option_data.time_servers": "",
		"option_data.tftp_server_name": "", "option_data.boot_file_name": "", "option": "",
	}, overrides)
}

func keaOption4Row() map[string]any {
	return map[string]any{"uuid": keaOptionUuid, "code": "252", "%code": "wpad [252]", "encoding": "hex", "data": "0a0b", "force": "0",
		"match_code": "", "match_encoding": "", "match_data": "", "description": "wpad"}
}

func keaFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(keaSubnet4Path, keaSubnet4Row(nil), keaSubnet4Row(map[string]any{"uuid": keaSubnet2Uuid, "subnet": "203.0.113.0/24",
		"description": "lab", "option": "", "%option": "", "pools": "", "ddns_domain_key_secret": ""}))
	f.search(keaReservation4Path, keaReservation4Row(nil))
	f.search(keaOption4Path, keaOption4Row())
	return f
}

func TestKeaSubnetPrint(t *testing.T) {
	t.Parallel()
	var f = keaFake(t)
	var r = f.run("/kea/dhcp4/subnet", "print")
	wantExit(t, r, 0)
	var want = []string{
		"#|SUBNET|POOLS|ROUTERS|DNS-SERVERS|DESCRIPTION",
		"0|198.51.100.0/24|198.51.100.10-198.51.100.20,198.51.100.32/28|198.51.100.1|198.51.100.2,198.51.100.3|office",
		"1|203.0.113.0/24|-|198.51.100.1|198.51.100.2,198.51.100.3|lab",
	}
	if got := keaTestLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}

	// json: the raw rows with the TSIG secret masked
	var asJSON = f.run("/kea/dhcp4/subnet", "print", "json", "search=office")
	wantExit(t, asJSON, 0)
	var first map[string]any
	if err := json.Unmarshal([]byte(strings.Split(asJSON.stdout, "\n")[0]), &first); err != nil ||
		first["ddns_domain_key_secret"] != "********" || first["option_data.routers"] != "198.51.100.1" || first["%allocator"] != "Random" {
		t.Errorf("json: %v %q", err, asJSON.stdout)
	}
	wantNotContains(t, "json", asJSON.stdout, "c2VjcmV0")

	var detail = f.run("/kea/dhcp4/subnet", "print", "detail")
	wantExit(t, detail, 0)
	wantContains(t, "detail", detail.stdout, "auto-options:", "ddns-key-secret:", "********", "options:", "wpad", "allocator:", "random")
	wantNotContains(t, "detail", detail.stdout, "c2VjcmV0")
	wantSearchPhrases(t, f, keaSubnet4Path, "", "office", "")
	wantNoMutations(t, f)
}

func TestKeaSubnetShow(t *testing.T) {
	t.Parallel()
	var f = keaFake(t)
	for _, selector := range []string{"0", keaSubnetUuid, "198.51.100.0/24", "OFFICE"} {
		var r = f.run("/kea/dhcp4/subnet", "show", selector)
		wantExit(t, r, 0)
		var lines = keaTestLines(r.stdout)
		if lines[0] != "uuid:|"+keaSubnetUuid || !slicesContain(lines, "pools:|198.51.100.10-198.51.100.20,198.51.100.32/28") ||
			!slicesContain(lines, "options:|wpad") || !slicesContain(lines, "match-client-id:|yes") || !slicesContain(lines, "ddns-key-secret:|********") {
			t.Errorf("show %s: %q", selector, lines)
		}
	}
	wantFailure(t, f.run("/kea/dhcp4/subnet", "show", "198.51.100.0"), "not found")
	wantNoMutations(t, f)
}

func slicesContain(lines []string, want string) bool {
	for _, line := range lines {
		if line == want {
			return true
		}
	}
	return false
}

func TestKeaSubnetAdd(t *testing.T) {
	t.Parallel()
	var f = keaFake(t)
	f.on("POST", "/api/kea/dhcpv4/add_subnet", 200, answerAdded("new-subnet"))
	var r = f.run("/kea/dhcp4/subnet", "add", "subnet=192.0.2.0/24", "pools=192.0.2.10-192.0.2.20,192.0.2.64/26", "auto-options=no",
		"routers=192.0.2.1", "dns-servers=192.0.2.2,192.0.2.3", "options=WPAD", "allocator=FLQ", "description=new", "ddns-key-secret=c2VjcmV0")
	wantExit(t, r, 0)
	if r.stdout != "new-subnet\n" {
		t.Errorf("want the uuid on stdout, got %q", r.stdout)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/kea/dhcpv4/add_subnet"), map[string]any{"subnet4": map[string]any{
		"subnet": "192.0.2.0/24", "pools": "192.0.2.10-192.0.2.20\n192.0.2.64/26", "option_data_autocollect": "0",
		"option_data": map[string]any{"routers": "192.0.2.1", "domain_name_servers": "192.0.2.2,192.0.2.3"},
		"option":      keaOptionUuid, "allocator": "flq", "description": "new", "ddns_domain_key_secret": "c2VjcmV0",
	}})

	t.Run("refused before any call", func(t *testing.T) {
		t.Parallel()
		for _, args := range [][]string{
			{}, {"subnet=192.0.2.0"}, {"subnet=2001:db8::/64"}, {"subnet=192.0.2.0/24", "pools=192.0.2.20-192.0.2.10"},
			{"subnet=192.0.2.0/24", "pools=2001:db8::1-2001:db8::2"}, {"subnet=192.0.2.0/24", "routers=x"},
			{"subnet=192.0.2.0/24", "static-routes=10.0.0.1"}, {"subnet=192.0.2.0/24", "classless-routes=10.0.0.0/8"},
			{"subnet=192.0.2.0/24", "allocator=best"}, {"subnet=192.0.2.0/24", "v6-only-preferred=10"}, {"subnet=192.0.2.0/24", "description=a\nb"},
			{"subnet=192.0.2.0/24", "domain-search=a b"},
		} {
			var f = keaFake(t)
			wantFailure(t, f.run(append([]string{"/kea/dhcp4/subnet", "add"}, args...)...))
			wantNoCalls(t, f)
		}
	})

	t.Run("unknown option reference", func(t *testing.T) {
		t.Parallel()
		var f = keaFake(t)
		wantFailure(t, f.run("/kea/dhcp4/subnet", "add", "subnet=192.0.2.0/24", "options=nope"), "options", "nope", `"wpad"`)
		wantNoMutations(t, f)
	})

	t.Run("exists", func(t *testing.T) {
		t.Parallel()
		var f = keaFake(t)
		// the same network in another spelling
		wantFailure(t, f.run("/kea/dhcp4/subnet", "add", "subnet=198.51.100.7/24"), "exists already", keaSubnetUuid, "replace")
		wantNoMutations(t, f)
	})

	t.Run("replace", func(t *testing.T) {
		t.Parallel()
		var f = keaFake(t)
		f.on("GET", "/api/kea/dhcpv4/get_subnet", 200, `{"subnet4":{"subnet":"","description":"","option_data_autocollect":"1",`+
			`"option_data":{"routers":{"":{"value":"","selected":1}},"domain_name":""},"option":[],"pools":"",`+
			`"allocator":{"":{"value":"Default","selected":1},"random":{"value":"Random","selected":0}}}}`)
		f.on("POST", "/api/kea/dhcpv4/set_subnet/"+keaSubnetUuid, 200, answerSaved)
		var r = f.run("/kea/dhcp4/subnet", "add", "subnet=198.51.100.0/24", "description=again", "replace")
		wantExit(t, r, 0)
		if r.stdout != keaSubnetUuid+"\n" || !strings.Contains(r.stderr, "replaced") {
			t.Errorf("got %s", r)
		}
		wantJSON(t, wantOneMutation(t, f, "POST", "/api/kea/dhcpv4/set_subnet/"+keaSubnetUuid), map[string]any{"subnet4": map[string]any{
			"subnet": "198.51.100.0/24", "description": "again", "option_data_autocollect": "1",
			"option_data": map[string]any{"routers": "", "domain_name": ""}, "option": "", "pools": "", "allocator": "",
		}})
	})

	t.Run("validation errors name the arguments", func(t *testing.T) {
		t.Parallel()
		var f = keaFake(t)
		f.on("POST", "/api/kea/dhcpv4/add_subnet", 200, `{"result":"failed","validations":{"subnet4.option_data.routers":"bad","subnet4.pools":["Entry \"x\" is not a valid range or subnet."]}}`)
		wantFailure(t, f.run("/kea/dhcp4/subnet", "add", "subnet=192.0.2.0/24"), "routers: bad", "pools: Entry")
	})
}

func TestKeaSubnetSetRemove(t *testing.T) {
	t.Parallel()
	var f = keaFake(t)
	f.on("POST", "/api/kea/dhcpv4/set_subnet/"+keaSubnet2Uuid, 200, answerSaved)
	var r = f.run("/kea/dhcp4/subnet", "set", "lab", "pools=", "options=wpad,"+keaOptionUuid, "match-client-id=no", "description=")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("set must be silent: %q", r.stdout)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/kea/dhcpv4/set_subnet/"+keaSubnet2Uuid), map[string]any{"subnet4": map[string]any{
		"pools": "", "option": keaOptionUuid + "," + keaOptionUuid, "match-client-id": "0", "description": "",
	}})

	var nothing = keaFake(t)
	wantFailure(t, nothing.run("/kea/dhcp4/subnet", "set", "lab"), "nothing to change")
	wantFailure(t, nothing.run("/kea/dhcp4/subnet", "set", "nope", "description=x"), "not found")
	wantNoMutations(t, nothing)

	var removed = keaFake(t)
	removed.on("POST", "/api/kea/dhcpv4/del_subnet/"+keaSubnetUuid, 500,
		`{"errorMessage":"dhcp4 - r1 {dhcp4.reservations.reservation.`+keaReservationUuid+`}\n","errorTitle":"Item subnets.subnet4 {office} in use by:"}`)
	wantFailure(t, removed.run("/kea/dhcp4/subnet", "remove", "office"), "in use by", keaReservationUuid)
	removed.on("POST", "/api/kea/dhcpv4/del_subnet/"+keaSubnet2Uuid, 200, answerDeleted)
	wantExit(t, removed.run("/kea/dhcp4/subnet", "remove", "1"), 0)
}

func TestKeaReservation(t *testing.T) {
	t.Parallel()
	var f = keaFake(t)
	f.on("POST", "/api/kea/dhcpv4/add_reservation", 200, answerAdded("new-res"))

	// the subnet is found from the address
	var r = f.run("/kea/dhcp4/reservation", "add", "ip-address=203.0.113.9", "mac-address=02-00-5E-10-00-09", "hostname=cam", "routers=203.0.113.1")
	wantExit(t, r, 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/kea/dhcpv4/add_reservation"), map[string]any{"reservation": map[string]any{
		"subnet": keaSubnet2Uuid, "ip_address": "203.0.113.9", "hw_address": "02-00-5E-10-00-09", "hostname": "cam",
		"option_data": map[string]any{"routers": "203.0.113.1"},
	}})

	var print = f.run("/kea/dhcp4/reservation", "print")
	wantExit(t, print, 0)
	if got := keaTestLines(print.stdout); !reflect.DeepEqual(got, []string{"#|SUBNET|IP-ADDRESS|MAC/CLIENT-ID|HOSTNAME|DESCRIPTION",
		"0|198.51.100.0/24|198.51.100.50|02:00:5e:10:00:01|printer|-"}) {
		t.Errorf("print %q", got)
	}
	for _, selector := range []string{"printer", "02:00:5E:10:00:01", "198.51.100.50"} {
		var show = f.run("/kea/dhcp4/reservation", "show", selector)
		wantExit(t, show, 0)
		wantContains(t, "show "+selector, show.stdout, "subnet:", "198.51.100.0/24", "mac-address:")
	}

	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		var f = keaFake(t)
		wantFailure(t, f.run("/kea/dhcp4/reservation", "add", "ip-address=203.0.113.9"), "mac-address= or client-id= is required")
		wantFailure(t, f.run("/kea/dhcp4/reservation", "add", "ip-address=203.0.113.9", "mac-address=02:00:5e:10:00:09", "client-id=01:02"), "not both")
		wantFailure(t, f.run("/kea/dhcp4/reservation", "add", "mac-address=02:00:5e:10:00:09"), "subnet= is required")
		wantFailure(t, f.run("/kea/dhcp4/reservation", "add", "ip-address=203.0.113.9", "mac-address=zz"), "MAC address")
		wantFailure(t, f.run("/kea/dhcp4/reservation", "add", "ip-address=203.0.113.9", "client-id=0102"), "hex bytes")
		wantNoCalls(t, f)
		wantFailure(t, f.run("/kea/dhcp4/reservation", "add", "ip-address=10.0.0.9", "mac-address=02:00:5e:10:00:09"), "no DHCPv4 subnet contains 10.0.0.9")
		// same subnet and MAC address (in another notation)
		wantFailure(t, f.run("/kea/dhcp4/reservation", "add", "ip-address=198.51.100.51", "mac-address=02-00-5e-10-00-01"), "exists already", keaReservationUuid)
		wantFailure(t, f.run("/kea/dhcp4/reservation", "add", "subnet=nope", "ip-address=198.51.100.51", "mac-address=02:00:5e:10:00:01"),
			"subnet", `"198.51.100.0/24"`, `"203.0.113.0/24"`)
		wantNoMutations(t, f)
	})

	t.Run("set and remove", func(t *testing.T) {
		t.Parallel()
		var f = keaFake(t)
		f.on("POST", "/api/kea/dhcpv4/set_reservation/"+keaReservationUuid, 200, answerSaved)
		wantExit(t, f.run("/kea/dhcp4/reservation", "set", "printer", "subnet=lab", "ip-address=203.0.113.50"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", "/api/kea/dhcpv4/set_reservation/"+keaReservationUuid), map[string]any{"reservation": map[string]any{
			"subnet": keaSubnet2Uuid, "ip_address": "203.0.113.50",
		}})
		var removed = keaFake(t)
		removed.on("POST", "/api/kea/dhcpv4/del_reservation/"+keaReservationUuid, 200, answerDeleted)
		wantExit(t, removed.run("/kea/dhcp4/reservation", "remove", "printer"), 0)
		wantOneMutation(t, removed, "POST", "/api/kea/dhcpv4/del_reservation/"+keaReservationUuid)
	})
}

func TestKeaDhcp6(t *testing.T) {
	t.Parallel()
	const subnet6 = "a6000000-0000-4000-8000-000000000001"
	var f = newFakeOPN(t)
	f.search("/api/kea/dhcpv6/search_subnet", map[string]any{"uuid": subnet6, "subnet": "2001:db8:a5::/64", "interface": "lan",
		"%interface": "LAN", "dynamic_prefix": "0", "pools": "2001:db8:a5::100-2001:db8:a5::1ff", "option_data.dns_servers": "2001:db8:a5::53",
		"description": "v6", "option": ""})
	f.search("/api/kea/dhcpv6/search_reservation")
	f.search("/api/kea/dhcpv6/search_pd_pool", map[string]any{"uuid": "p1", "subnet": subnet6, "%subnet": "LAN 2001:db8:a5::/64",
		"prefix": "2001:db8:100::", "prefix_len": "56", "delegated_len": "64", "description": ""})
	f.on("POST", "/api/kea/dhcpv6/add_subnet", 200, answerAdded("s6"))
	f.on("POST", "/api/kea/dhcpv6/add_reservation", 200, answerAdded("r6"))
	f.on("POST", "/api/kea/dhcpv6/add_pd_pool", 200, answerAdded("p2"))

	wantExit(t, f.run("/kea/dhcp6/subnet", "add", "interface=lan", "dynamic-prefix"), 0)
	wantJSON(t, f.mutations()[0], map[string]any{"subnet6": map[string]any{"interface": "lan", "dynamic_prefix": "1"}})

	wantExit(t, f.run("/kea/dhcp6/reservation", "add", "ip-address=2001:db8:a5::50", "duid=00:01:00:01:aa:bb", "hostname=nas"), 0)
	wantJSON(t, f.mutations()[1], map[string]any{"reservation": map[string]any{"subnet": subnet6, "ip_address": "2001:db8:a5::50",
		"duid": "00:01:00:01:aa:bb", "hostname": "nas"}})

	// prefix in CIDR notation is split into prefix and prefix_len
	wantExit(t, f.run("/kea/dhcp6/pd-pool", "add", "subnet=v6", "prefix=2001:db8:200::/56", "delegated-length=60"), 0)
	wantJSON(t, f.mutations()[2], map[string]any{"pd_pool": map[string]any{"subnet": subnet6, "prefix": "2001:db8:200::",
		"prefix_len": "56", "delegated_len": "60"}})

	var pools = f.run("/kea/dhcp6/pd-pool", "print")
	wantExit(t, pools, 0)
	if got := keaTestLines(pools.stdout); !reflect.DeepEqual(got, []string{"#|SUBNET|PREFIX|DELEGATED-LENGTH|DESCRIPTION",
		"0|LAN 2001:db8:a5::/64|2001:db8:100::/56|64|-"}) {
		t.Errorf("print %q", got)
	}
	wantExit(t, f.run("/kea/dhcp6/pd-pool", "show", "2001:db8:100::/56"), 0)

	var refused = newFakeOPN(t)
	wantFailure(t, refused.run("/kea/dhcp6/subnet", "add", "interface=lan"), "subnet= is required")
	wantFailure(t, refused.run("/kea/dhcp6/subnet", "add", "subnet=198.51.100.0/24", "interface=lan"), "IPv6")
	wantFailure(t, refused.run("/kea/dhcp6/reservation", "add", "duid=00:01", "subnet=x"), "ip-address= or prefix= is required")
	wantFailure(t, refused.run("/kea/dhcp6/pd-pool", "add", "subnet=v6", "prefix=2001:db8::/48", "prefix-length=48"), "not both")
	wantNoCalls(t, refused)
}

func TestKeaOptionAndPeer(t *testing.T) {
	t.Parallel()
	var f = keaFake(t)
	f.search("/api/kea/dhcpv4/search_peer", map[string]any{"uuid": "peer1", "name": "fw1", "role": "primary", "%role": "Primary", "url": "http://198.51.100.2:8000/"})
	f.on("POST", "/api/kea/dhcpv4/add_option", 200, answerAdded("o2"))
	f.on("POST", "/api/kea/dhcpv4/add_peer", 200, answerAdded("peer2"))
	wantExit(t, f.run("/kea/dhcp4/option", "add", "description=pxe", "code=224", "data=0a0b0c", "match-code=60", "match-encoding=STRING", "match-data=PXEClient"), 0)
	wantJSON(t, f.mutations()[0], map[string]any{"option": map[string]any{"description": "pxe", "code": "224", "data": "0a0b0c",
		"match_code": "60", "match_encoding": "string", "match_data": "PXEClient"}})
	wantFailure(t, f.run("/kea/dhcp4/option", "add", "description=WPAD", "code=252", "data=00"), "exists already")
	wantFailure(t, f.run("/kea/dhcp4/option", "add", "description=x", "code=300", "data=00"), "code")
	wantFailure(t, f.run("/kea/dhcp4/option", "add", "description=x", "code=1", "data=00", "match-code=60", "match-data="), "both")

	var options = f.run("/kea/dhcp4/option", "print")
	if got := keaTestLines(options.stdout); !reflect.DeepEqual(got, []string{"#|CODE|ENCODING|DATA|MATCH|DESCRIPTION", "0|252|hex|0a0b|-|wpad"}) {
		t.Errorf("print %q", got)
	}

	wantExit(t, f.run("/kea/dhcp4/peer", "add", "name=fw2", "role=standby", "url=http://198.51.100.3:8000/"), 0)
	wantJSON(t, f.mutations()[1], map[string]any{"peer": map[string]any{"name": "fw2", "role": "standby", "url": "http://198.51.100.3:8000/"}})
	wantFailure(t, f.run("/kea/dhcp4/peer", "add", "name=fw1", "url=http://198.51.100.3:8000/"), "exists already")
	wantFailure(t, f.run("/kea/dhcp4/peer", "add", "name=fw3", "url=ftp://x"), "URL")
	if len(f.mutations()) != 2 {
		t.Errorf("mutations %v", f.mutations())
	}
}

func TestKeaSettings(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/kea/dhcpv4/get", 200, `{"dhcpv4":{"general":{"enabled":"0","manual_config":"0",`+
		`"interfaces":{"lan":{"value":"LAN","selected":1},"wan":{"value":"WAN","selected":0}},"valid_lifetime":"4000","fwrules":"1",`+
		`"dhcp_socket_type":{"udp":{"value":"udp","selected":0},"raw":{"value":"raw","selected":1}},`+
		`"compatibility":{"exclude-first-last-24":{"value":"exclude-first-last-24","selected":0},"lenient-option-parsing":{"value":"lenient-option-parsing","selected":1}}},`+
		`"lexpire":{"max_reclaim_time":""},"ha":{"enabled":"0","this_server_name":"","max_unacked_clients":"2","%this_server_name":"OPNsense"}}}`)
	f.on("POST", "/api/kea/dhcpv4/set", 200, answerSaved)
	var r = f.run("/kea/dhcp4/settings", "print")
	wantExit(t, r, 0)
	var lines = keaTestLines(r.stdout)
	for _, want := range []string{"enabled:|no", "interfaces:|lan", "valid-lifetime:|4000", "firewall-rules:|yes", "socket-type:|raw",
		"compatibility:|lenient-option-parsing", "ha:|no", "ha-max-unacked-clients:|2"} {
		if !slicesContain(lines, want) {
			t.Errorf("print lacks %q: %q", want, lines)
		}
	}
	var asJSON = f.run("/kea/dhcp4/settings", "print", "json")
	wantExit(t, asJSON, 0)
	var decoded map[string]string
	if err := json.Unmarshal([]byte(asJSON.stdout), &decoded); err != nil || decoded["general.interfaces"] != "lan" || decoded["ha.%this_server_name"] != "" {
		t.Errorf("json %v %q", err, asJSON.stdout)
	}

	wantExit(t, f.run("/kea/dhcp4/settings", "set", "interfaces=lan", "valid-lifetime=3600", "ha=no", "compatibility="), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/kea/dhcpv4/set"), map[string]any{"dhcpv4": map[string]any{
		"general": map[string]any{"interfaces": "lan", "valid_lifetime": "3600", "compatibility": ""}, "ha": map[string]any{"enabled": "0"},
	}})

	var refused = newFakeOPN(t)
	wantFailure(t, refused.run("/kea/dhcp4/settings", "set"), "nothing to change")
	wantFailure(t, refused.run("/kea/dhcp4/settings", "set", "socket-type=tcp"), "socket-type")
	wantFailure(t, refused.run("/kea/dhcp6/settings", "set", "mac-sources=nope"), "mac-sources")
	wantFailure(t, refused.run("/kea/ctrl-agent", "set", "http-host=2001:db8::1"), "IPv4")
	wantNoCalls(t, refused)

	var invalid = newFakeOPN(t)
	invalid.on("POST", "/api/kea/ddns/set", 200, `{"result":"failed","validations":{"ddns.general.server_port":["Please provide a valid port number."]}}`)
	wantFailure(t, invalid.run("/kea/ddns", "set", "server-port=53001"), "server-port: Please provide a valid port number.")
}

func TestKeaService(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/kea/service/status", 200, `{"status":"running","widget":{}}`)
	f.on("POST", "/api/kea/service/start", 200, `{"response":"OK"}`)
	f.on("POST", "/api/kea/service/stop", 200, `{"response":"OK"}`)
	f.on("POST", "/api/kea/service/restart", 200, `{"response":"OK"}`)
	f.on("POST", "/api/kea/service/reconfigure", 200, `{"status":"failed","status_msg":"Service \"kea\" failed to start."}`)
	var status = f.run("/kea/service", "status")
	wantExit(t, status, 0)
	if got := keaTestLines(status.stdout); !reflect.DeepEqual(got, []string{"status:|running"}) {
		t.Errorf("status %q", got)
	}
	// stop and restart need a confirmation, without it nothing is sent
	wantFailure(t, f.run("/kea/service", "stop"), "stops the Kea DHCP server", "confirm=yes")
	wantFailure(t, f.run("/kea/service", "restart"), "confirm=yes")
	wantNoMutations(t, f)
	wantExit(t, f.run("/kea/service", "stop", "confirm=yes"), 0)
	wantExit(t, f.run("/kea/service", "start"), 0)
	wantFailure(t, f.run("/kea/service", "apply"), "failed to start")
	var paths []string
	for _, call := range f.mutations() {
		paths = append(paths, call.Path)
	}
	if !reflect.DeepEqual(paths, []string{"/api/kea/service/stop", "/api/kea/service/start", "/api/kea/service/reconfigure"}) {
		t.Errorf("mutations %q", paths)
	}
}

func TestKeaComplete(t *testing.T) {
	t.Parallel()
	var f = keaFake(t)
	f.on("GET", "/api/kea/dhcpv4/get", 200, `{"dhcpv4":{"general":{"interfaces":{"lan":{"value":"LAN","selected":0},"opt1":{"value":"DMZ","selected":0}}}}}`)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/kea/dhcp4/subnet remove o":             {"office"},
		"/kea/dhcp4/reservation add subnet=203":  {"subnet=203.0.113.0/24"},
		"/kea/dhcp4/subnet set lab options=w":    {"options=wpad"},
		"/kea/dhcp4/settings set interfaces=opt": {"interfaces=opt1"},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}

func TestKeaHelp(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var r = f.run("/kea/dhcp4", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "settings", "subnet", "reservation", "option", "peer", "lease")
	var v6 = f.run("/kea/dhcp6", "?")
	wantContains(t, "stdout", v6.stdout, "pd-pool")
	var items = f.run("/kea/dhcp4/subnet", "?")
	wantContains(t, "stdout", items.stdout, "print", "show", "add", "set", "remove")
	wantNotContains(t, "stdout", items.stdout, "enable")
	wantNoCalls(t, f)
}
