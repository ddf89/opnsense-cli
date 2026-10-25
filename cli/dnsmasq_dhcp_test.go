package cli

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const (
	dnsmasqTagSearchPath    = "/api/dnsmasq/settings/search_tag"
	dnsmasqRangeSearchPath  = "/api/dnsmasq/settings/search_range"
	dnsmasqOptionSearchPath = "/api/dnsmasq/settings/search_option"
	dnsmasqBootSearchPath   = "/api/dnsmasq/settings/search_boot"
)

var dnsColumnSeparator = regexp.MustCompile(`\s{2,}`)

// dnsLines returns the non-empty output lines with the table columns joined by "|"
func dnsLines(output string) []string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, strings.Join(dnsColumnSeparator.Split(line, -1), "|"))
		}
	}
	return lines
}

func dnsmasqDhcpFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(dnsmasqTagSearchPath,
		map[string]any{"uuid": "t-lab", "tag": "lab"},
		map[string]any{"uuid": "t-pxe", "tag": "pxe"},
	)
	f.search(dnsmasqRangeSearchPath,
		map[string]any{"uuid": "r-lan", "interface": "lan", "%interface": "LAN", "set_tag": "", "start_addr": "192.168.1.100",
			"end_addr": "192.168.1.199", "subnet_mask": "", "constructor": "", "mode": "", "prefix_len": "", "lease_time": "",
			"domain_type": "range", "%domain_type": "Range", "domain": "", "nosync": "0", "ra_mode": "", "ra_priority": "",
			"ra_mtu": "", "ra_interval": "", "ra_router_lifetime": "", "description": ""},
		map[string]any{"uuid": "r-lab", "interface": "", "set_tag": "t-lab", "%set_tag": "lab", "start_addr": "192.0.2.10",
			"end_addr": "192.0.2.20", "mode": "", "lease_time": "3600", "domain_type": "range", "domain": "lab.example",
			"nosync": "1", "ra_mode": "slaac,ra-names", "description": "lab pool"},
	)
	f.search(dnsmasqOptionSearchPath,
		map[string]any{"uuid": "o-dns", "type": "set", "option": "6", "%option": "dns-server [6]", "option6": "", "interface": "lan",
			"tag": "t-lab,t-pxe", "%tag": "lab,pxe", "set_tag": "", "value": "192.0.2.53", "force": "1", "description": "lab dns"},
		map[string]any{"uuid": "o-match", "type": "match", "option": "77", "%option": "user-class [77]", "option6": "", "interface": "",
			"tag": "", "set_tag": "t-pxe", "value": "pxe", "force": "", "description": "pxe clients"},
	)
	f.search(dnsmasqBootSearchPath,
		map[string]any{"uuid": "b-pxe", "interface": "", "tag": "t-pxe", "filename": "pxelinux.0", "servername": "", "address": "192.0.2.69", "description": "pxe"},
	)
	f.on("GET", "/api/dnsmasq/settings/get_option", 200, `{"option":{"option":{"":{"value":"None","selected":1},
		"3":{"optgroup":"Common","value":"router [3]","selected":0},"6":{"optgroup":"Common","value":"dns-server [6]","selected":0},
		"77":{"optgroup":"Common","value":"user-class [77]","selected":0}},
		"option6":{"":{"value":"None","selected":1},"23":{"optgroup":"Common","value":"dns-server [23]","selected":0}}}}`)
	return f
}

func TestDnsmasqRangePrint(t *testing.T) {
	t.Parallel()
	var f = dnsmasqDhcpFake(t)
	var r = f.run("/dnsmasq/range", "print")
	wantExit(t, r, 0)
	var want = []string{
		"#|INTERFACE|START|END|MODE|SET-TAG|DOMAIN|LEASE-TIME|DESCRIPTION",
		"0|lan|192.168.1.100|192.168.1.199|-|-|-|-|-",
		"1|-|192.0.2.10|192.0.2.20|-|lab|lab.example|3600|lab pool",
	}
	if got := dnsLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}

	var detail = f.run("/dnsmasq/range", "show", "192.0.2.10-192.0.2.20")
	wantExit(t, detail, 0)
	wantContains(t, "show", detail.stdout, "uuid:", "r-lab", "set-tag:", "lab\n", "ra-mode:", "slaac,ra-names", "no-sync:", "yes")

	var asJSON = f.run("/dnsmasq/range", "print", "json")
	wantExit(t, asJSON, 0)
	wantContains(t, "json", asJSON.stdout, `"set_tag":"t-lab"`, `"%interface":"LAN"`)
	wantNoMutations(t, f)
}

func TestDnsmasqRangeAdd(t *testing.T) {
	t.Parallel()
	var f = dnsmasqDhcpFake(t)
	f.on("POST", "/api/dnsmasq/settings/add_range", 200, answerAdded("r-new"))
	var r = f.run("/dnsmasq/range", "add", "start=192.0.2.30", "end=192.0.2.40", "set-tag=PXE", "lease-time=600", "ra-mode=SLAAC,ra-names", "no-sync")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != "r-new" {
		t.Errorf("want the uuid, got %q", r.stdout)
	}
	var call = wantOneMutation(t, f, "POST", "/api/dnsmasq/settings/add_range")
	wantJSON(t, call, map[string]any{"range": map[string]any{"start_addr": "192.0.2.30", "end_addr": "192.0.2.40",
		"set_tag": "t-pxe", "lease_time": "600", "ra_mode": "slaac,ra-names", "nosync": "1"}})
}

func TestDnsmasqRangeAddValidation(t *testing.T) {
	t.Parallel()
	var f = dnsmasqDhcpFake(t)
	wantFailure(t, f.run("/dnsmasq/range", "add", "end=192.0.2.40"), "start")
	wantFailure(t, f.run("/dnsmasq/range", "add", "start=192.0.2.300"), "IPv4 or IPv6")
	wantFailure(t, f.run("/dnsmasq/range", "add", "start=192.0.2.30", "set-tag=nope"), "DHCP tag", "nope")
	wantFailure(t, f.run("/dnsmasq/range", "add", "start=192.0.2.30", "ra-mode=fast"), "must be one of")
	// same interface (any) and start address
	wantFailure(t, f.run("/dnsmasq/range", "add", "start=192.0.2.10", "end=192.0.2.11"), "exists already", "r-lab")
	wantNoMutations(t, f)
}

func TestDnsmasqRangeReplace(t *testing.T) {
	t.Parallel()
	var f = dnsmasqDhcpFake(t)
	f.on("POST", "/api/dnsmasq/settings/set_range/r-lab", 200, answerSaved)
	var r = f.run("/dnsmasq/range", "add", "start=192.0.2.10", "end=192.0.2.15", "replace")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "replaced")
	var call = wantOneMutation(t, f, "POST", "/api/dnsmasq/settings/set_range/r-lab")
	var body = call.json(t)["range"].(map[string]any)
	if body["end_addr"] != "192.0.2.15" || body["set_tag"] != "" || body["domain_type"] != "range" || body["nosync"] != "0" || body["description"] != "" {
		t.Errorf("replace must reset the fields not given: %v", body)
	}
}

func TestDnsmasqRangeSet(t *testing.T) {
	t.Parallel()
	var f = dnsmasqDhcpFake(t)
	f.on("POST", "/api/dnsmasq/settings/set_range/r-lab", 200, answerSaved)
	wantExit(t, f.run("/dnsmasq/range", "set", "lab pool", "set-tag=", "lease-time=60"), 0)
	var call = wantOneMutation(t, f, "POST", "/api/dnsmasq/settings/set_range/r-lab")
	wantJSON(t, call, map[string]any{"range": map[string]any{"set_tag": "", "lease_time": "60"}})

	var g = dnsmasqDhcpFake(t)
	wantFailure(t, g.run("/dnsmasq/range", "set", "1"), "nothing to change")
	wantFailure(t, g.run("/dnsmasq/range", "set", "1", "interface=lan", "start=192.168.1.100"), "exists already", "r-lan")
	wantNoMutations(t, g)
}

func TestDnsmasqRangeRemove(t *testing.T) {
	t.Parallel()
	var f = dnsmasqDhcpFake(t)
	f.on("POST", "/api/dnsmasq/settings/del_range/r-lan", 200, answerDeleted)
	wantExit(t, f.run("/dnsmasq/range", "remove", "192.168.1.100"), 0)
	wantOneMutation(t, f, "POST", "/api/dnsmasq/settings/del_range/r-lan")
}

func TestDnsmasqTag(t *testing.T) {
	t.Parallel()
	var f = dnsmasqDhcpFake(t)
	f.on("POST", "/api/dnsmasq/settings/add_tag", 200, answerAdded("t-new"))
	f.on("POST", "/api/dnsmasq/settings/del_tag/t-lab", 500,
		`{"errorMessage":"dnsmasq - lab pool {dnsmasq.dhcp_ranges.r-lab}\n","errorTitle":"Item dhcp_tags {t-lab} in use by:"}`)

	var r = f.run("/dnsmasq/tag", "print")
	wantExit(t, r, 0)
	if got := dnsLines(r.stdout); !reflect.DeepEqual(got, []string{"#|NAME", "0|lab", "1|pxe"}) {
		t.Errorf("print: %q", got)
	}
	wantFailure(t, f.run("/dnsmasq/tag", "add", "name=LAB"), "exists already")
	wantFailure(t, f.run("/dnsmasq/tag", "remove", "lab"), "in use by", "lab pool")
	wantExit(t, f.run("/dnsmasq/tag", "add", "name=guests"), 0)
	var calls = f.mutations()
	if len(calls) != 2 || calls[1].Path != "/api/dnsmasq/settings/add_tag" {
		t.Fatalf("unexpected mutations %v", calls)
	}
	wantJSON(t, calls[1], map[string]any{"tag": map[string]any{"tag": "guests"}})
}

func TestDnsmasqOptionPrint(t *testing.T) {
	t.Parallel()
	var f = dnsmasqDhcpFake(t)
	var r = f.run("/dnsmasq/option", "print")
	wantExit(t, r, 0)
	var want = []string{
		"#|TYPE|OPTION|OPTION6|INTERFACE|TAG|SET-TAG|VALUE|FORCE|DESCRIPTION",
		"0|set|dns-server [6]|-|lan|lab, pxe|-|192.0.2.53|yes|lab dns",
		"1|match|user-class [77]|-|-|-|pxe|pxe|no|pxe clients",
	}
	if got := dnsLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	var show = f.run("/dnsmasq/option", "show", "lab dns")
	wantExit(t, show, 0)
	wantContains(t, "show", show.stdout, "option:", "6\n", "tag:", "lab,pxe")
	wantNoMutations(t, f)
}

func TestDnsmasqOptionAdd(t *testing.T) {
	t.Parallel()
	var f = dnsmasqDhcpFake(t)
	f.on("POST", "/api/dnsmasq/settings/add_option", 200, answerAdded("o-new"))
	wantExit(t, f.run("/dnsmasq/option", "add", "option=DNS-Server", "value=192.0.2.53", "tag=lab"), 0)
	var call = wantOneMutation(t, f, "POST", "/api/dnsmasq/settings/add_option")
	wantJSON(t, call, map[string]any{"option": map[string]any{"type": "set", "option": "6", "value": "192.0.2.53", "tag": "t-lab"}})

	var g = dnsmasqDhcpFake(t)
	g.on("POST", "/api/dnsmasq/settings/add_option", 200, answerAdded("o-new"))
	wantExit(t, g.run("/dnsmasq/option", "add", "type=match", "option6=23", "set-tag=pxe"), 0)
	wantJSON(t, wantOneMutation(t, g, "POST", "/api/dnsmasq/settings/add_option"),
		map[string]any{"option": map[string]any{"type": "match", "option6": "23", "set_tag": "t-pxe"}})
}

func TestDnsmasqOptionAddValidation(t *testing.T) {
	t.Parallel()
	var f = dnsmasqDhcpFake(t)
	wantFailure(t, f.run("/dnsmasq/option", "add", "value=1"), "option= (DHCPv4) or option6=")
	wantFailure(t, f.run("/dnsmasq/option", "add", "option=6", "option6=23"), "not both")
	wantFailure(t, f.run("/dnsmasq/option", "add", "option=no-such-option"), "unknown option", "codes")
	wantFailure(t, f.run("/dnsmasq/option", "add", "type=match", "option=77"), "set-tag")
	wantFailure(t, f.run("/dnsmasq/option", "add", "type=sometimes", "option=6"), "must be one of")
	wantNoMutations(t, f)
}

func TestDnsmasqOptionSet(t *testing.T) {
	t.Parallel()
	var f = dnsmasqDhcpFake(t)
	f.on("POST", "/api/dnsmasq/settings/set_option/o-dns", 200, answerSaved)
	wantExit(t, f.run("/dnsmasq/option", "set", "0", "option6=dns-server", "value=[2001:db8::53]"), 0)
	// the type is always sent (OPNsense clears fields by it), switching to DHCPv6 clears the DHCPv4 option
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/dnsmasq/settings/set_option/o-dns"),
		map[string]any{"option": map[string]any{"type": "set", "option": "", "option6": "23", "value": "[2001:db8::53]"}})
}

func TestDnsmasqOptionCodes(t *testing.T) {
	t.Parallel()
	var f = dnsmasqDhcpFake(t)
	var r = f.run("/dnsmasq/option", "codes", "search=dns")
	wantExit(t, r, 0)
	if got := dnsLines(r.stdout); !reflect.DeepEqual(got, []string{"CODE|NAME|GROUP", "6|dns-server|Common"}) {
		t.Errorf("codes: %q", got)
	}
	var v6 = f.run("/dnsmasq/option", "codes", "v6", "json")
	wantExit(t, v6, 0)
	if strings.TrimSpace(v6.stdout) != `{"code":"23","group":"Common","name":"dns-server"}` {
		t.Errorf("codes v6 json: %q", v6.stdout)
	}
}

func TestDnsmasqBoot(t *testing.T) {
	t.Parallel()
	var f = dnsmasqDhcpFake(t)
	f.on("POST", "/api/dnsmasq/settings/add_boot", 200, answerAdded("b-new"))
	f.on("POST", "/api/dnsmasq/settings/set_boot/b-pxe", 200, answerSaved)
	var r = f.run("/dnsmasq/boot", "print")
	wantExit(t, r, 0)
	if got := dnsLines(r.stdout); !reflect.DeepEqual(got, []string{"#|INTERFACE|TAG|FILENAME|SERVERNAME|ADDRESS|DESCRIPTION",
		"0|-|pxe|pxelinux.0|-|192.0.2.69|pxe"}) {
		t.Errorf("print: %q", got)
	}
	wantFailure(t, f.run("/dnsmasq/boot", "add", "address=192.0.2.1"), "filename")
	wantExit(t, f.run("/dnsmasq/boot", "add", "filename=ipxe.efi", "tag=lab,pxe", "interface=lan"), 0)
	wantExit(t, f.run("/dnsmasq/boot", "set", "pxelinux.0", "servername=tftp.lab"), 0)
	var calls = f.mutations()
	if len(calls) != 2 {
		t.Fatalf("want 2 mutations, got %v", calls)
	}
	wantJSON(t, calls[0], map[string]any{"boot": map[string]any{"filename": "ipxe.efi", "tag": "t-lab,t-pxe", "interface": "lan"}})
	wantJSON(t, calls[1], map[string]any{"boot": map[string]any{"servername": "tftp.lab"}})
}

func TestDnsmasqRecordsHaveNoEnable(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	for _, menu := range []string{"/dnsmasq/range", "/dnsmasq/option", "/dnsmasq/boot", "/dnsmasq/tag"} {
		wantFailure(t, f.run(menu, "enable", "0"), "no such menu or command")
	}
	wantNoCalls(t, f)
}
