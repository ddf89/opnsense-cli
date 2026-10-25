package cli

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

const (
	firewallNatDnatPath   = "/api/firewall/d_nat/"
	firewallNatSnatPath   = "/api/firewall/source_nat/"
	firewallNatOnePath    = "/api/firewall/one_to_one/"
	firewallNatNptPath    = "/api/firewall/npt/"
	firewallNatApplyOK    = `{"status":"OK\n\n"}`
	firewallNatAnswerMove = `{"status":"ok"}`
)

// firewallNatDnatRow is a configured d_nat search_rule row as OPNsense 26.7 returns it (flattened source/destination)
func firewallNatDnatRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "sequence": "100", "disabled": "0", "nordr": "0", "interface": "wan", "%interface": "WAN",
		"ipprotocol": "inet", "%ipprotocol": "IPv4", "protocol": "tcp", "%protocol": "TCP",
		"source.network": "", "source.address": "", "source.port": "", "source.not": "0",
		"destination.network": "wanip", "destination.address": "", "destination.port": "8080", "destination.not": "0",
		"target": "198.51.100.5", "local-port": "80", "poolopts": "", "log": "0", "category": "", "categories": "",
		"descr": "", "tag": "", "tagged": "", "nosync": "0", "natreflection": "", "pass": "", "associated-rule-id": "",
		"category_colors": []any{}, "sort_order": "400000.0000100", "prio_group": "400000",
	}, overrides)
}

// firewallNatLockoutRow is the automatic anti-lockout rule d_nat lists
var firewallNatLockoutRow = map[string]any{
	"uuid": "lockout_0", "ipprotocol": "", "protocol": "tcp", "%protocol": "TCP", "disabled": "0", "nordr": "1",
	"interface": "lan", "%interface": "LAN", "destination.network": "lanip", "destination.port": "80",
	"descr": "Anti-Lockout Rule", "is_automatic": true, "sort_order": "100000.0000000", "prio_group": "100000",
}

func firewallNatDnatRows() []map[string]any {
	return []map[string]any{
		firewallNatLockoutRow,
		firewallNatDnatRow(map[string]any{"uuid": "d-web", "descr": "web"}),
		firewallNatDnatRow(map[string]any{"uuid": "d-ssh", "sequence": "200", "disabled": "1", "descr": "ssh",
			"destination.port": "2222", "local-port": "22", "target": "198.51.100.6"}),
		firewallNatDnatRow(map[string]any{"uuid": "d-d1", "sequence": "300", "descr": "dup"}),
		firewallNatDnatRow(map[string]any{"uuid": "d-d2", "sequence": "400", "descr": "dup"}),
	}
}

// firewallNatDnatOptions is get_rule of d_nat without uuid (trimmed)
const firewallNatDnatOptions = `{"rule":{"sequence":"500","disabled":"0","nordr":"0",` +
	`"interface":{"lan":{"value":"LAN","selected":0},"wan":{"value":"WAN","selected":0}},` +
	`"ipprotocol":{"":{"value":"any","selected":1},"inet":{"value":"IPv4","selected":0},"inet6":{"value":"IPv6","selected":0},"inet46":{"value":"IPv4+IPv6","selected":0}},` +
	`"protocol":{"":{"value":"any","selected":1},"tcp":{"value":"TCP","selected":0},"udp":{"value":"UDP","selected":0},"tcp\/udp":{"value":"TCP\/UDP","selected":0},"icmp":{"value":"ICMP","selected":0}},` +
	`"source":{"network":"","address":"","port":"","not":"0"},"destination":{"network":"","address":"","port":"","not":"0"},` +
	`"target":"","local-port":"","log":"0","category":[],"descr":"","created":{"username":"","time":"","description":""}}}`

// firewallNatSnatOptions is get_rule of source_nat without uuid (trimmed)
const firewallNatSnatOptions = `{"rule":{"enabled":"1","sequence":"100",` +
	`"interface":{"lan":{"value":"LAN","selected":1},"wan":{"value":"WAN","selected":0}},` +
	`"ipprotocol":{"inet":{"value":"IPv4","selected":1},"inet6":{"value":"IPv6","selected":0}},` +
	`"protocol":{"any":{"value":"any","selected":1},"TCP":{"value":"TCP","selected":0},"UDP":{"value":"UDP","selected":0},"TCP\/UDP":{"value":"TCP\/UDP","selected":0}},` +
	`"source_net":"any","categories":[],"description":""}}`

func firewallNatDnatFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(firewallNatDnatPath+"search_rule", rows...)
	f.on("GET", firewallNatDnatPath+"get_rule", 200, firewallNatDnatOptions)
	return f
}

// firewallNatSnatAutoRows are the automatic outbound rules source_nat lists in the automatic mode
var firewallNatSnatAutoRows = []map[string]any{
	{"uuid": "automatic_isakmp_wan", "enabled": "1", "sequence": "1", "interface": "wan", "ipprotocol": "inet", "protocol": "any",
		"source_net": "lan,lo0", "destination_port": "500", "staticnatport": "1", "target": "wanip",
		"description": "Auto created rule for ISAKMP", "is_automatic": true},
	{"uuid": "automatic_wan", "enabled": "1", "sequence": "2", "interface": "wan", "ipprotocol": "inet", "protocol": "any",
		"source_net": "lan,lo0", "destination_net": "any", "target": "wanip", "description": "Auto created rule", "is_automatic": true},
}

// firewallNatSnatCSV is download_rules of source_nat: the manual rules, which search_rule hides in the automatic mode
const firewallNatSnatCSV = "@uuid;enabled;nonat;nosync;sequence;interface;ipprotocol;protocol;source_net;source_not;source_port;destination_net;destination_not;destination_port;target;target_port;staticnatport;log;categories;tag;tagged;description\n" +
	"s-late;0;0;0;200;wan;inet;any;198.51.100.0/24;0;;any;0;;203.0.113.10;;0;0;;;;\"late rule\"\n" +
	"s-early;1;0;0;100;wan;inet;TCP;198.51.100.0/25;1;;203.0.113.0/24;0;443;;;1;1;;;;\"early; rule\"\n"

func firewallNatSnatFake(t *testing.T, mode string) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(firewallNatSnatPath+"search_rule", firewallNatSnatAutoRows...)
	f.onFunc("GET", firewallNatSnatPath+"download_rules", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/csv;charset=UTF-8")
		_, _ = w.Write([]byte(firewallNatSnatCSV))
	})
	f.on("GET", firewallNatSnatPath+"get_rule", 200, firewallNatSnatOptions)
	f.on("GET", firewallNatSnatPath+"get", 200, `{"filter":{"general":{"snat_mode":{"automatic":{"value":"Automatic","selected":`+
		map[bool]string{true: "1", false: "0"}[mode == "automatic"]+`},"hybrid":{"value":"Hybrid","selected":0},"advanced":{"value":"Manual","selected":`+
		map[bool]string{true: "1", false: "0"}[mode == "advanced"]+`},"disabled":{"value":"Disabled","selected":0}}}}}`)
	return f
}

var firewallNatColumnSeparator = regexp.MustCompile(`\s{2,}`)

// firewallNatTable splits table output into rows of cells (columns are separated by at least two spaces)
func firewallNatTable(t *testing.T, output string) [][]string {
	t.Helper()
	var rows [][]string
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			rows = append(rows, firewallNatColumnSeparator.Split(strings.TrimSpace(line), -1))
		}
	}
	return rows
}

func firewallNatWantRows(t *testing.T, output string, want ...string) {
	t.Helper()
	var rows = firewallNatTable(t, output)
	var got = make([]string, len(rows))
	for i, row := range rows {
		got[i] = strings.Join(row, "|")
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("table:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestFirewallNatPrint(t *testing.T) {
	t.Parallel()
	var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
	var r = f.run("/firewall/nat/destination", "print")
	wantExit(t, r, 0)
	firewallNatWantRows(t, r.stdout,
		"#|DISABLED|AUTO|INTERFACE|PROTOCOL|SOURCE|DESTINATION|TARGET|DESCRIPTION",
		"0|no|yes|lan|tcp|any|lanip port 80|no rdr|Anti-Lockout Rule",
		"1|no|-|wan|tcp|any|wanip port 8080|198.51.100.5 port 80|web",
		"2|yes|-|wan|tcp|any|wanip port 2222|198.51.100.6 port 22|ssh",
		"3|no|-|wan|tcp|any|wanip port 8080|198.51.100.5 port 80|dup",
		"4|no|-|wan|tcp|any|wanip port 8080|198.51.100.5 port 80|dup")
	wantSearchPhrases(t, f, firewallNatDnatPath+"search_rule", "")
	wantNoMutations(t, f)

	t.Run("search filters locally, also the automatic rules", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		var r = f.run("/firewall/nat/destination", "print", "search=2222")
		wantExit(t, r, 0)
		firewallNatWantRows(t, r.stdout,
			"#|DISABLED|AUTO|INTERFACE|PROTOCOL|SOURCE|DESTINATION|TARGET|DESCRIPTION",
			"0|yes|-|wan|tcp|any|wanip port 2222|198.51.100.6 port 22|ssh")
	})
	t.Run("detail", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		var r = f.run("/firewall/nat/destination", "print", "detail")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "0\n  uuid:", "automatic:           yes", "interface:           wan (WAN)",
			"destination-port:    2222", "target-port:         22", "filter-rule:         manual", "description:         ssh", "\n4\n")
	})
	t.Run("json is the raw API rows", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		var r = f.run("/firewall/nat/destination", "print", "json")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != 5 || !strings.Contains(lines[0], `"is_automatic":true`) || !strings.Contains(lines[1], `"destination.port":"8080"`) {
			t.Errorf("json output:\n%s", r.stdout)
		}
	})
	t.Run("the # of a filtered print selects in a script", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		f.on("POST", firewallNatDnatPath+"set_rule/d-ssh", 200, answerSaved)
		var r = f.runScript("/firewall/nat/destination\nprint search=ssh\nset 0 log\n")
		wantExit(t, r, 0)
		wantJSON(t, wantOneMutation(t, f, "POST", firewallNatDnatPath+"set_rule/d-ssh"), map[string]any{"rule": map[string]any{"log": "1"}})
	})
}

func TestFirewallNatSourcePrint(t *testing.T) {
	t.Parallel()
	var f = firewallNatSnatFake(t, "automatic")
	var r = f.run("/firewall/nat/source", "print")
	wantExit(t, r, 0)
	firewallNatWantRows(t, r.stdout,
		"#|DISABLED|AUTO|INTERFACE|PROTOCOL|SOURCE|DESTINATION|TARGET|DESCRIPTION",
		"0|no|yes|wan|any|lan,lo0|any port 500|wanip|Auto created rule for ISAKMP",
		"1|no|yes|wan|any|lan,lo0|any|wanip|Auto created rule",
		"2|no|-|wan|tcp|!198.51.100.0/25|203.0.113.0/24 port 443|interface address|early; rule",
		"3|yes|-|wan|any|198.51.100.0/24|any|203.0.113.10|late rule")
	wantContains(t, "stderr", r.stderr, "the outbound NAT mode is automatic: the manual rules are not used")

	var show = f.run("/firewall/nat/source", "show", "early; rule")
	wantExit(t, show, 0)
	wantContains(t, "stdout", show.stdout, "uuid:                s-early", "inactive:            yes", "static-port:         yes",
		"source-invert:       yes", "protocol:            tcp")

	var asJSON = f.run("/firewall/nat/source", "print", "json")
	wantExit(t, asJSON, 0)
	wantContains(t, "stdout", asJSON.stdout, `"uuid":"s-early"`, `"description":"early; rule"`)
	wantNoMutations(t, f)

	t.Run("hybrid lists the manual rules with search_rule, no hint", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.search(firewallNatSnatPath+"search_rule", map[string]any{"uuid": "s-early", "enabled": "1", "interface": "wan",
			"protocol": "TCP", "source_net": "198.51.100.0/25", "description": "early; rule"})
		f.onFunc("GET", firewallNatSnatPath+"download_rules", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("@uuid;enabled;sequence;interface;description\ns-early;1;100;wan;\"early; rule\"\n"))
		})
		var r = f.run("/firewall/nat/source", "print")
		wantExit(t, r, 0)
		if r.stderr != "" || strings.Count(r.stdout, "\n") != 2 {
			t.Errorf("output:\n%s", r)
		}
	})
}

func TestFirewallNatShow(t *testing.T) {
	t.Parallel()
	for _, selector := range []string{"d-web", "D-WEB", "web", "WEB", "1"} {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()
			var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
			var r = f.run("/firewall/nat/destination", "show", selector)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, "uuid:                d-web\n", "disabled:            no\n", "description:         web\n",
				"ip-protocol:         inet\n", "nat-reflection:      default\n")
		})
	}
	t.Run("ambiguous description", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		wantFailure(t, f.run("/firewall/nat/destination", "show", "dup"), "d-d1", "d-d2")
	})
	t.Run("unknown", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		wantFailure(t, f.run("/firewall/nat/destination", "show", "nope"), "not found")
	})
}

func TestFirewallNatAdd(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		path string
		args []string
		want map[string]any
	}{
		{"destination, nested fields and mapped values", firewallNatDnatPath, []string{"/firewall/nat/destination", "add", "interface=wan",
			"protocol=TCP", "destination=wanip", "destination-port=8080", "target=198.51.100.7", "target-port=80",
			"nat-reflection=enable", "filter-rule=pass", "pool-options=round-robin-sticky", "description=new web", "disabled"},
			map[string]any{"interface": "wan", "protocol": "tcp", "destination": map[string]any{"network": "wanip", "port": "8080"},
				"target": "198.51.100.7", "local-port": "80", "natreflection": "purenat", "pass": "pass",
				"poolopts": "round-robin sticky-address", "descr": "new web", "disabled": "1"}},
		{"destination, several interfaces, any protocol, enabled by default", firewallNatDnatPath, []string{"/firewall/nat/destination", "add",
			"interface=wan,lan", "protocol=any", "source=198.51.100.0/24", "source-invert", "target=198.51.100.8", "ip-protocol=inet"},
			map[string]any{"interface": "wan,lan", "protocol": "", "source": map[string]any{"network": "198.51.100.0/24", "not": "1"},
				"target": "198.51.100.8", "ipprotocol": "inet", "disabled": "0"}},
		{"source", firewallNatSnatPath, []string{"/firewall/nat/source", "add", "interface=wan", "protocol=tcp/udp",
			"source=198.51.100.0/24", "destination-port=443", "target=203.0.113.10", "static-port", "description=out", "disabled"},
			map[string]any{"interface": "wan", "protocol": "TCP/UDP", "source_net": "198.51.100.0/24", "destination_port": "443",
				"target": "203.0.113.10", "staticnatport": "1", "description": "out", "enabled": "0"}},
		{"one-to-one", firewallNatOnePath, []string{"/firewall/nat/one-to-one", "add", "interface=wan", "source=198.51.100.0/24",
			"external=203.0.113.0/24", "nat-reflection=disable", "description=office"},
			map[string]any{"interface": "wan", "source_net": "198.51.100.0/24", "external": "203.0.113.0/24", "natreflection": "disable",
				"description": "office", "enabled": "1"}},
		{"one-to-one nat type with an alias", firewallNatOnePath, []string{"/firewall/nat/one-to-one", "add", "interface=wan", "type=nat",
			"source=servers", "external=203.0.113.0/24", "sequence=5"},
			map[string]any{"interface": "wan", "type": "nat", "source_net": "servers", "external": "203.0.113.0/24", "sequence": "5",
				"enabled": "1"}},
		{"npt", firewallNatNptPath, []string{"/firewall/nat/npt", "add", "interface=wan", "internal-prefix=fd00:1::/48",
			"external-prefix=2001:db8:1::/48", "log", "disabled"},
			map[string]any{"interface": "wan", "source_net": "fd00:1::/48", "destination_net": "2001:db8:1::/48", "log": "1", "enabled": "0"}},
		{"npt with track interface", firewallNatNptPath, []string{"/firewall/nat/npt", "add", "interface=wan", "internal-prefix=fd00:1::/48",
			"track-interface=wan"},
			map[string]any{"interface": "wan", "source_net": "fd00:1::/48", "trackif": "wan", "enabled": "1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(tc.path + "search_rule")
			f.on("GET", tc.path+"get_rule", 200, firewallNatDnatOptions)
			if tc.path == firewallNatSnatPath {
				f.on("GET", tc.path+"get_rule", 200, firewallNatSnatOptions)
			}
			if tc.path == firewallNatNptPath {
				f.on("GET", tc.path+"get_rule", 200, `{"rule":{"interface":{"lan":{"value":"LAN","selected":1},"wan":{"value":"WAN","selected":0}},`+
					`"trackif":{"":{"value":"None","selected":1},"wan":{"value":"WAN","selected":0}}}}`)
			}
			f.on("POST", tc.path+"add_rule", 200, answerAdded("n-new"))
			var r = f.run(tc.args...)
			wantExit(t, r, 0)
			if r.stdout != "n-new\n" {
				t.Errorf("stdout must be the uuid: %q", r.stdout)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", tc.path+"add_rule"), map[string]any{"rule": tc.want})
		})
	}

	t.Run("place-before moves the new rule", func(t *testing.T) {
		t.Parallel()
		var rows = firewallNatDnatRows()
		var f = firewallNatDnatFake(t, rows...)
		f.on("POST", firewallNatDnatPath+"add_rule", 200, answerAdded("d-new"))
		f.onFunc("POST", firewallNatDnatPath+"move_rule_before/d-new/d-ssh", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(firewallNatAnswerMove))
		})
		// the new rule appears in the list after add
		f.search(firewallNatDnatPath+"search_rule", append(rows, firewallNatDnatRow(map[string]any{"uuid": "d-new", "sequence": "500"}))...)
		var r = f.run("/firewall/nat/destination", "add", "interface=wan", "target=198.51.100.9", "place-before=ssh")
		wantExit(t, r, 0)
		var mutations = f.mutations()
		if len(mutations) != 2 || mutations[0].Path != firewallNatDnatPath+"add_rule" || mutations[1].Path != firewallNatDnatPath+"move_rule_before/d-new/d-ssh" {
			t.Errorf("mutations %v", mutations)
		}
	})
	t.Run("place-before an automatic rule is refused before adding", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		wantFailure(t, f.run("/firewall/nat/destination", "add", "interface=wan", "target=198.51.100.9", "place-before=0"),
			"place-before", "generated by OPNsense")
		wantNoMutations(t, f)
	})

	t.Run("existing description fails without replace", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		wantFailure(t, f.run("/firewall/nat/destination", "add", "interface=wan", "target=198.51.100.9", "description=WEB"),
			"exists already", "d-web", "replace")
		wantNoMutations(t, f)
	})
	t.Run("replace resets the fields not given, keeps the position", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		f.on("POST", firewallNatDnatPath+"set_rule/d-web", 200, answerSaved)
		var r = f.run("/firewall/nat/destination", "add", "interface=lan", "target=198.51.100.9", "description=web", "replace")
		wantExit(t, r, 0)
		if r.stdout != "d-web\n" {
			t.Errorf("stdout must be the uuid: %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, `replaced the existing rule "web"`)
		wantJSON(t, wantOneMutation(t, f, "POST", firewallNatDnatPath+"set_rule/d-web"), map[string]any{"rule": map[string]any{
			"interface": "lan", "ipprotocol": "", "protocol": "", "target": "198.51.100.9", "local-port": "",
			"source":      map[string]any{"network": "", "not": "0", "port": ""},
			"destination": map[string]any{"network": "", "not": "0", "port": ""},
			"nordr":       "0", "poolopts": "", "natreflection": "", "pass": "", "log": "0", "tag": "", "tagged": "", "nosync": "0",
			"descr": "web", "disabled": "0",
		}})
	})
	t.Run("several rules with the description", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		wantFailure(t, f.run("/firewall/nat/destination", "add", "interface=wan", "target=198.51.100.9", "description=dup", "replace"), "d-d1", "d-d2")
		wantNoMutations(t, f)
	})
	t.Run("unknown interface lists the interfaces", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t)
		wantFailure(t, f.run("/firewall/nat/destination", "add", "interface=wan,opt9", "target=198.51.100.9"),
			`unknown interface "opt9"`, "lan, wan")
		wantNoMutations(t, f)
	})
	t.Run("unknown protocol", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t)
		wantFailure(t, f.run("/firewall/nat/destination", "add", "interface=wan", "protocol=sctp", "target=198.51.100.9"),
			`unknown protocol "sctp"`, "tcp/udp")
		wantNoMutations(t, f)
	})

	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"interface is required", []string{"/firewall/nat/destination", "add", "target=198.51.100.9"}, []string{"interface"}},
		{"ports need tcp or udp", []string{"/firewall/nat/destination", "add", "interface=wan", "destination-port=80"},
			[]string{"destination-port is only valid with protocol=tcp, udp or tcp/udp, not any"}},
		{"ports need tcp or udp (source NAT)", []string{"/firewall/nat/source", "add", "interface=wan", "protocol=icmp", "target-port=80"},
			[]string{"target-port is only valid", "not icmp"}},
		{"address family must match", []string{"/firewall/nat/destination", "add", "interface=wan", "ip-protocol=inet", "target=2001:db8::5"},
			[]string{"target 2001:db8::5 does not match ip-protocol=inet"}},
		{"source NAT family", []string{"/firewall/nat/source", "add", "interface=wan", "source=2001:db8::/32"},
			[]string{"source 2001:db8::/32 does not match ip-protocol=inet"}},
		{"no-rdr without target", []string{"/firewall/nat/destination", "add", "interface=wan", "no-rdr", "target=198.51.100.9"},
			[]string{"no-rdr does not redirect"}},
		{"source NAT target any", []string{"/firewall/nat/source", "add", "interface=wan", "target=any"}, []string{"target can not be any"}},
		{"invalid address", []string{"/firewall/nat/destination", "add", "interface=wan", "target=198.51.100.300"},
			[]string{"target must be an IP address"}},
		{"invalid port", []string{"/firewall/nat/destination", "add", "interface=wan", "protocol=tcp", "destination-port=70000"},
			[]string{"destination-port must be a port 1-65535"}},
		{"invalid port range", []string{"/firewall/nat/destination", "add", "interface=wan", "protocol=tcp", "destination-port=80-"},
			[]string{"destination-port must be a port"}},
		{"invalid interface", []string{"/firewall/nat/destination", "add", "interface=w an"}, []string{"interface must be an interface identifier"}},
		{"unknown mapped value", []string{"/firewall/nat/destination", "add", "interface=wan", "nat-reflection=on"},
			[]string{"nat-reflection must be one of default, enable, disable"}},
		{"description with newline", []string{"/firewall/nat/destination", "add", "interface=wan", "description=a\nb"},
			[]string{"description must not contain control characters"}},
		{"sequence range", []string{"/firewall/nat/destination", "add", "interface=wan", "sequence=0"}, []string{"sequence must be a number from 1 to 999999"}},
		{"hash key", []string{"/firewall/nat/source", "add", "interface=wan", "source-hash-key=0x12"}, []string{"source-hash-key must be 0x followed by 32 hex digits"}},
		{"one-to-one needs source and external", []string{"/firewall/nat/one-to-one", "add", "interface=wan", "source=198.51.100.1"}, []string{"external"}},
		{"binat prefix lengths", []string{"/firewall/nat/one-to-one", "add", "interface=wan", "source=198.51.100.0/24", "external=203.0.113.0/25"},
			[]string{"need the same prefix length"}},
		{"one-to-one families", []string{"/firewall/nat/one-to-one", "add", "interface=wan", "source=198.51.100.1", "external=2001:db8::1"},
			[]string{"both be IPv4 or both IPv6"}},
		{"one-to-one external is no alias", []string{"/firewall/nat/one-to-one", "add", "interface=wan", "source=a", "external=wanip"},
			[]string{"external must be an IP address or a network"}},
		{"npt needs an external prefix", []string{"/firewall/nat/npt", "add", "interface=wan", "internal-prefix=fd00::/48"},
			[]string{"give external-prefix or track-interface"}},
		{"npt prefix lengths", []string{"/firewall/nat/npt", "add", "interface=wan", "internal-prefix=fd00::/48", "external-prefix=2001:db8::/56"},
			[]string{"need the same prefix length"}},
		{"npt is IPv6", []string{"/firewall/nat/npt", "add", "interface=wan", "internal-prefix=10.0.0.0/8", "external-prefix=2001:db8::/56"},
			[]string{"internal-prefix must be an IPv6 prefix"}},
	} {
		t.Run(tc.name+", no API call", func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			wantFailure(t, f.run(tc.args...), tc.wants...)
			wantNoCalls(t, f)
		})
	}

	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t)
		f.on("POST", firewallNatDnatPath+"add_rule", 200, answerValidation("rule.target", "Address type should match selected TCP/IP protocol version."))
		wantFailure(t, f.run("/firewall/nat/destination", "add", "interface=wan", "target=wan_hosts"), "rule.target", "Address type should match")
	})
}

func TestFirewallNatSet(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		uuid string
		want map[string]any
	}{
		{"nested field only", []string{"web", "destination-port=8443"}, "d-web", map[string]any{"destination": map[string]any{"port": "8443"}}},
		{"by index and flags", []string{"2", "disabled=no", "log"}, "d-ssh", map[string]any{"disabled": "0", "log": "1"}},
		{"clear target port, protocol any (no ports left)", []string{"d-ssh", "destination-port=", "target-port=", "protocol=any"}, "d-ssh",
			map[string]any{"destination": map[string]any{"port": ""}, "local-port": "", "protocol": ""}},
		{"rename", []string{"d-web", "description=www"}, "d-web", map[string]any{"descr": "www"}},
		{"sequence", []string{"d-web", "sequence=50"}, "d-web", map[string]any{"sequence": "50"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
			f.on("POST", firewallNatDnatPath+"set_rule/"+tc.uuid, 200, answerSaved)
			var r = f.run(append([]string{"/firewall/nat/destination", "set"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("set must be silent: %q", r.stdout)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", firewallNatDnatPath+"set_rule/"+tc.uuid), map[string]any{"rule": tc.want})
		})
	}

	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"the current ports need tcp", []string{"d-web", "protocol=icmp"}, []string{"destination-port is only valid", "not icmp"}},
		{"automatic rules are refused", []string{"0", "log"}, []string{"generated by OPNsense"}},
		{"another rule has the description", []string{"d-web", "description=SSH"}, []string{"another rule with description", "d-ssh"}},
		{"unknown item", []string{"nope", "log"}, []string{"not found"}},
		{"ambiguous item", []string{"dup", "log"}, []string{"d-d1", "d-d2"}},
		{"no-rdr with the current target", []string{"d-web", "no-rdr"}, []string{"no-rdr does not redirect"}},
	} {
		t.Run(tc.name+", no change", func(t *testing.T) {
			t.Parallel()
			var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
			wantFailure(t, f.run(append([]string{"/firewall/nat/destination", "set"}, tc.args...)...), tc.wants...)
			wantNoMutations(t, f)
		})
	}

	t.Run("nothing to change, no API call", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		wantFailure(t, f.run("/firewall/nat/destination", "set", "d-web"), "nothing to change")
		wantNoCalls(t, f)
	})
	t.Run("removed meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		f.on("POST", firewallNatDnatPath+"set_rule/d-web", 200, answerFailedBare)
		wantFailure(t, f.run("/firewall/nat/destination", "set", "d-web", "log"), "not found")
	})
	t.Run("inactive source NAT rules can be changed", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatSnatFake(t, "automatic")
		f.on("POST", firewallNatSnatPath+"set_rule/s-late", 200, answerSaved)
		wantExit(t, f.run("/firewall/nat/source", "set", "late rule", "target=203.0.113.11"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", firewallNatSnatPath+"set_rule/s-late"), map[string]any{"rule": map[string]any{"target": "203.0.113.11"}})
	})
}

func TestFirewallNatRemove(t *testing.T) {
	t.Parallel()
	var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
	f.on("POST", firewallNatDnatPath+"del_rule/d-ssh", 200, answerDeleted)
	var r = f.run("/firewall/nat/destination", "remove", "ssh")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("remove must be silent: %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", firewallNatDnatPath+"del_rule/d-ssh")

	for _, tc := range []struct {
		selector string
		wants    []string
	}{{"0", []string{"generated by OPNsense"}}, {"nope", []string{"not found"}}, {"dup", []string{"d-d1", "d-d2"}}} {
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		wantFailure(t, f.run("/firewall/nat/destination", "remove", tc.selector), tc.wants...)
		wantNoMutations(t, f)
	}

	t.Run("removed meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		f.on("POST", firewallNatDnatPath+"del_rule/d-ssh", 200, answerNotFound)
		wantFailure(t, f.run("/firewall/nat/destination", "remove", "d-ssh"), "not found")
	})
}

func TestFirewallNatEnableDisable(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		menu, command, item, path, answer, wantInfo string
	}{
		// d_nat toggles the disabled flag: /1 disables
		{"/firewall/nat/destination", "disable", "web", firewallNatDnatPath + "toggle_rule/d-web/1", `{"result":"Disabled"}`, ""},
		{"/firewall/nat/destination", "enable", "web", firewallNatDnatPath + "toggle_rule/d-web/0", `{"result":"Enabled"}`, "already enabled"},
		{"/firewall/nat/destination", "enable", "ssh", firewallNatDnatPath + "toggle_rule/d-ssh/0", `{"result":"Enabled"}`, ""},
		// the others toggle the enabled flag: /0 disables
		{"/firewall/nat/source", "disable", "early; rule", firewallNatSnatPath + "toggle_rule/s-early/0", `{"result":"Disabled","changed":true}`, ""},
		{"/firewall/nat/source", "disable", "late rule", firewallNatSnatPath + "toggle_rule/s-late/0", `{"result":"Disabled","changed":false}`, "already disabled"},
	} {
		t.Run(tc.command+" "+tc.item, func(t *testing.T) {
			t.Parallel()
			var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
			if strings.Contains(tc.menu, "source") {
				f = firewallNatSnatFake(t, "automatic")
			}
			f.on("POST", tc.path, 200, tc.answer)
			var r = f.run(tc.menu, tc.command, tc.item)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("must be silent: %q", r.stdout)
			}
			if tc.wantInfo != "" {
				wantContains(t, "stderr", r.stderr, tc.wantInfo)
			} else if r.stderr != "" && !strings.Contains(r.stderr, "outbound NAT mode") {
				t.Errorf("stderr: %q", r.stderr)
			}
			wantOneMutation(t, f, "POST", tc.path)
		})
	}

	t.Run("automatic rules are refused", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatSnatFake(t, "automatic")
		var r = f.run("/firewall/nat/source", "disable", "automatic_wan") // its description "Auto created rule" upsets wantFailure
		wantExit(t, r, 1)
		wantContains(t, "stderr", r.stderr, "automatic_wan", "generated by OPNsense")
		wantNoMutations(t, f)
	})
	t.Run("removed meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		f.on("POST", firewallNatDnatPath+"toggle_rule/d-web/1", 200, `{"result":"failed"}`)
		wantFailure(t, f.run("/firewall/nat/destination", "disable", "d-web"), "not found")
	})
}

func TestFirewallNatMove(t *testing.T) {
	t.Parallel()
	t.Run("before another rule", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		f.on("POST", firewallNatDnatPath+"move_rule_before/d-ssh/d-web", 200, firewallNatAnswerMove)
		wantExit(t, f.run("/firewall/nat/destination", "move", "ssh", "destination=web"), 0)
		wantOneMutation(t, f, "POST", firewallNatDnatPath+"move_rule_before/d-ssh/d-web")
	})
	t.Run("to the end", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		f.on("POST", firewallNatDnatPath+"set_rule/d-web", 200, answerSaved)
		wantExit(t, f.run("/firewall/nat/destination", "move", "web"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", firewallNatDnatPath+"set_rule/d-web"), map[string]any{"rule": map[string]any{"sequence": "500"}})
	})
	t.Run("the last rule stays", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()[:3]...)
		wantExit(t, f.run("/firewall/nat/destination", "move", "ssh"), 0)
		wantNoMutations(t, f)
	})
	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"before an automatic rule", []string{"web", "destination=0"}, []string{"destination", "generated by OPNsense"}},
		{"an automatic rule", []string{"0", "destination=web"}, []string{"generated by OPNsense"}},
		{"before itself", []string{"web", "destination=d-web"}, []string{"before itself"}},
		{"unknown destination", []string{"web", "destination=nope"}, []string{"not found"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
			wantFailure(t, f.run(append([]string{"/firewall/nat/destination", "move"}, tc.args...)...), tc.wants...)
			wantNoMutations(t, f)
		})
	}
	t.Run("OPNsense refuses", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
		f.on("POST", firewallNatDnatPath+"move_rule_before/d-ssh/d-web", 500, `{"errorMessage":"Either source or destination is not a rule managed with this component","errorTitle":""}`)
		wantFailure(t, f.run("/firewall/nat/destination", "move", "ssh", "destination=web"), "not a rule managed")
	})
}

func TestFirewallNatApply(t *testing.T) {
	t.Parallel()
	for _, menu := range []string{"source", "destination", "one-to-one", "npt"} {
		t.Run(menu, func(t *testing.T) {
			t.Parallel()
			var path = map[string]string{"source": firewallNatSnatPath, "destination": firewallNatDnatPath,
				"one-to-one": firewallNatOnePath, "npt": firewallNatNptPath}[menu] + "apply"
			var f = newFakeOPN(t)
			f.on("POST", path, 200, firewallNatApplyOK)
			var r = f.run("/firewall/nat/"+menu, "apply", "confirm=yes")
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("apply must be silent: %q", r.stdout)
			}
			wantOneMutation(t, f, "POST", path)
		})
	}
	t.Run("failure status", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("POST", firewallNatNptPath+"apply", 200, `{"status":"Execute error"}`)
		wantFailure(t, f.run("/firewall/nat/npt", "apply", "confirm=yes"), "Execute error")
	})
	t.Run("needs confirm non-interactively, nothing sent", func(t *testing.T) {
		t.Parallel()
		for _, menu := range []string{"source", "destination", "one-to-one", "npt"} {
			var f = newFakeOPN(t)
			wantFailure(t, f.run("/firewall/nat/"+menu, "apply"), "cut off access", "confirm=yes")
			wantNoCalls(t, f)
		}
	})
	t.Run("the help names the confirmation", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		var r = f.run("/firewall/nat/destination", "apply", "?")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "no rollback", "confirm=yes")
		wantNoCalls(t, f)
	})
}

func TestFirewallNatMode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ mode, want string }{{"automatic", "mode:  automatic"}, {"advanced", "mode:  manual"}} {
		var f = firewallNatSnatFake(t, tc.mode)
		var r = f.run("/firewall/nat/source/mode", "print")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, tc.want)
		wantNoMutations(t, f)
	}

	for _, tc := range []struct{ arg, want string }{{"manual", "advanced"}, {"hybrid", "hybrid"}, {"Disabled", "disabled"}} {
		var f = newFakeOPN(t)
		f.on("POST", firewallNatSnatPath+"set", 200, answerSaved)
		var r = f.run("/firewall/nat/source", "mode", "set", "mode="+tc.arg)
		wantExit(t, r, 0)
		wantJSON(t, wantOneMutation(t, f, "POST", firewallNatSnatPath+"set"),
			map[string]any{"filter": map[string]any{"general": map[string]any{"snat_mode": tc.want}}})
	}

	var f = newFakeOPN(t)
	wantFailure(t, f.run("/firewall/nat/source/mode", "set", "mode=advanced"), "mode must be one of automatic, hybrid, manual, disabled")
	wantFailure(t, f.run("/firewall/nat/source/mode", "set"), "mode")
	wantNoCalls(t, f)
}

func TestFirewallNatCompletion(t *testing.T) {
	t.Parallel()
	var f = firewallNatDnatFake(t, firewallNatDnatRows()...)
	var session = fakeSession(t, f)
	for line, want := range map[string]string{
		"/firewall/nat/destination set w":                 "web",
		"/firewall/nat/destination add interface=w":       "interface=wan",
		"/firewall/nat/destination add protocol=tcp/":     "protocol=tcp/udp",
		"/firewall/nat/destination move ssh destination=": "destination=dup",
	} {
		var got, _ = session.Complete(line)
		var found bool
		for _, candidate := range got {
			found = found || candidate == want
		}
		if !found {
			t.Errorf("Complete(%q) = %q, lacks %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}
