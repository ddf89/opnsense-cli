package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const (
	firewallRuleBase       = "/api/firewall/filter/"
	firewallRuleSearchPath = firewallRuleBase + "search_rule"
	firewallRuleStatsPath  = "/api/firewall/filter_util/rule_stats"

	firewallRuleAutoId   = "01e83daa25c4483dee217a7ecd7c9a88"
	firewallRuleLanUuid  = "d621e174-154f-4ebb-9465-6e2fac4b2bcb"
	firewallRuleWebUuid  = "10adf92d-0e07-4c4d-bd0e-76e0938214f2"
	firewallRuleFloatId  = "4d2e9d7d-5dc0-45f8-989d-822dfad7ef72"
	firewallRuleCategory = "a1b2c3d4-0000-4000-8000-000000000001"
	firewallRuleRevision = "1729876543.1234"
)

// firewallRuleAutoRow is an automatic rule as search_rule returns it in 26.7
func firewallRuleAutoRow() map[string]any {
	return map[string]any{
		"log": true, "disablereplyto": 1, "ipprotocol": "", "#priority": 5, "enabled": "1", "action": "pass", "replyto": "",
		"interface": "LAN", "description": "anti-lockout rule", "source_net": "", "source_port": "", "destination_net": "(self)",
		"destination_port": "443", "ref": "system_advanced_firewall.php#noantilockout", "uuid": firewallRuleAutoId,
		"direction": "in", "%direction": "In", "%action": "Pass", "protocol": "tcp", "sort_order": "000005.1000030",
		"legacy": true, "is_automatic": true, "category_colors": []any{},
	}
}

// firewallRuleMvcRow is a user rule as search_rule returns it in 26.7 (trimmed to the fields used)
func firewallRuleMvcRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": firewallRuleLanUuid, "enabled": "1", "statetype": "keep", "sequence": "1", "sort_order": "400000.0000001",
		"prio_group": "400000", "action": "pass", "%action": "Pass", "quick": "1", "interfacenot": "0", "interface": "lan",
		"%interface": "LAN", "direction": "in", "ipprotocol": "inet", "protocol": "any", "source_net": "lan", "source_not": "0",
		"source_port": "", "destination_net": "any", "destination_not": "0", "destination_port": "", "gateway": "", "log": "0",
		"categories": "", "sched": "", "tag": "", "max": "", "nosync": "0", "description": "Default allow LAN to any rule",
		"category_colors": []any{}, "alias_meta_source_net": []any{map[string]any{"value": "lan", "%value": "LAN network"}},
	}, overrides)
}

func firewallRuleRows() []map[string]any {
	return []map[string]any{
		firewallRuleAutoRow(),
		firewallRuleMvcRow(nil),
		firewallRuleMvcRow(map[string]any{"uuid": firewallRuleWebUuid, "sequence": "111", "sort_order": "400000.0000111",
			"enabled": "0", "action": "block", "protocol": "TCP", "source_net": "10.0.0.0/8", "source_not": "1",
			"destination_net": "198.51.100.0/24", "destination_port": "443", "log": "1", "quick": "0", "categories": firewallRuleCategory,
			"gateway": "WAN_DHCP", "max": "100", "nosync": "1", "description": "block web"}),
		firewallRuleMvcRow(map[string]any{"uuid": firewallRuleFloatId, "sequence": "5", "sort_order": "200000.0000005",
			"prio_group": "200000", "interface": "", "%interface": "", "direction": "any", "ipprotocol": "inet46",
			"description": "floating"}),
	}
}

// firewallRuleFake serves search_rule with rows (recording the bodies) and the helper endpoints
func firewallRuleFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.onFunc("POST", firewallRuleSearchPath, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		var raw, _ = io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		var answer = rows
		if body["show_all"] == "1" {
			answer = nil
			for _, row := range rows {
				answer = append(answer, withFields(row, map[string]any{"pf_rules": 2, "evaluations": 7, "packets": 3, "bytes": 120, "states": 1}))
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": answer, "rowCount": len(answer), "total": len(answer), "current": 1})
	})
	f.on("GET", firewallRuleBase+"get_interface_list", 200, `{"floating":{"label":"Floating","items":[{"value":"__floating","label":"Floating","type":"floating"}]},`+
		`"groups":{"label":"Groups","items":[{"value":"vpns","label":"VPNs","type":"group"}]},`+
		`"interfaces":{"label":"Interfaces","items":[{"value":"lan","label":"LAN","type":"interface"},{"value":"opt1","label":"DMZ","type":"interface"},{"value":"wan","label":"WAN","type":"interface"}]},`+
		`"any":{"label":"Any","items":[{"value":"__any","label":"All rules","type":"any"}]}}`)
	f.on("GET", firewallRuleBase+"list_categories", 200, `{"rows":[{"uuid":"`+firewallRuleCategory+`","name":"web","color":"","used":1}]}`)
	f.on("GET", firewallRuleBase+"list_network_select_options", 200, `{"single":{"label":"Single host or Network"},`+
		`"aliases":{"label":"Aliases","items":{"bogons":"bogons"}},"networks":{"label":"Networks","items":{"any":"any","(self)":"This Firewall","lan":"LAN network","lanip":"LAN address"}}}`)
	f.on("GET", firewallRuleBase+"list_port_select_options", 200, `{"single":{"label":"Single port or range"},"aliases":{"label":"Aliases","items":[]},`+
		`"ports":{"label":"Ports","items":{"":"any","http":"HTTP (80)","https":"HTTPS (443)"}}}`)
	f.on("GET", firewallRuleBase+"get_rule", 200, `{"rule":{"enabled":"1","sequence":"211","categories":[],`+
		`"protocol":{"any":{"value":"any","selected":1},"TCP":{"value":"TCP","selected":0},"UDP":{"value":"UDP","selected":0},"TCP/UDP":{"value":"TCP/UDP","selected":0}},`+
		`"gateway":{"":{"value":"default","selected":1},"WAN_DHCP":{"value":"WAN_DHCP - 10.0.2.2","selected":0}}}}`)
	f.on("GET", firewallRuleStatsPath, 200, `{"status":"ok","stats":{"`+firewallRuleWebUuid+`":{"pf_rules":2,"evaluations":70,"packets":30,"bytes":1200,"states":4}}}`)
	return f
}

// firewallRuleWrites returns the calls which change something (all but GETs and the POSTed search)
func firewallRuleWrites(f *fakeOPN) []apiCall {
	var writes []apiCall
	for _, call := range f.mutations() {
		if call.Path != firewallRuleSearchPath {
			writes = append(writes, call)
		}
	}
	return writes
}

func firewallRuleWantNoWrites(t *testing.T, f *fakeOPN) {
	t.Helper()
	if writes := firewallRuleWrites(f); len(writes) != 0 {
		t.Errorf("want no writes, got %v", writes)
	}
}

// firewallRuleWantWrites asserts the paths of the writes in order and returns them
func firewallRuleWantWrites(t *testing.T, f *fakeOPN, paths ...string) []apiCall {
	t.Helper()
	var writes = firewallRuleWrites(f)
	var got []string
	for _, call := range writes {
		got = append(got, call.Path)
	}
	if !reflect.DeepEqual(got, paths) {
		t.Fatalf("writes: got %q, want %q", got, paths)
	}
	return writes
}

// firewallRuleSearchBodies returns the bodies POSTed to search_rule
func firewallRuleSearchBodies(t *testing.T, f *fakeOPN) []map[string]any {
	var bodies []map[string]any
	for _, call := range f.calls() {
		if call.Path == firewallRuleSearchPath {
			bodies = append(bodies, call.json(t))
		}
	}
	return bodies
}

// firewallRuleAddBody is the body add sends for a rule with only the given arguments
func firewallRuleAddBody(overrides map[string]any) map[string]any {
	return map[string]any{"rule": withFields(map[string]any{
		"action": "pass", "enabled": "1", "quick": "1", "interface": "", "interfacenot": "0", "direction": "in",
		"ipprotocol": "inet", "protocol": "any", "source_net": "any", "source_not": "0", "source_port": "",
		"destination_net": "any", "destination_not": "0", "destination_port": "", "icmptype": "", "icmp6type": "",
		"log": "0", "categories": "", "sched": "", "description": "", "gateway": "", "replyto": "", "disablereplyto": "0",
		"statetype": "keep", "state-policy": "", "statetimeout": "", "allowopts": "0", "nosync": "0", "nopfsync": "0",
		"max": "", "max-src-nodes": "", "max-src-states": "", "max-src-conn": "", "max-src-conn-rate": "",
		"max-src-conn-rates": "", "overload": "", "adaptivestart": "", "adaptiveend": "", "udp-first": "",
		"udp-multiple": "", "udp-single": "", "tcpflags1": "", "tcpflags2": "", "tcpflags_any": "0", "prio": "",
		"set-prio": "", "set-prio-low": "", "tag": "", "tagged": "", "tos": "", "divert-to": "", "shaper1": "", "shaper2": "",
	}, overrides)}
}

var firewallRuleHeader = []string{"#", "DISABLED", "FLAGS", "ACTION", "INTERFACE", "DIR", "IP", "PROTOCOL", "SOURCE", "DESTINATION", "PORT", "DESCRIPTION"}

func TestFirewallRulePrint(t *testing.T) {
	t.Parallel()
	var f = firewallRuleFake(t, firewallRuleRows()...)
	var r = f.run("/firewall/rule", "print")
	wantExit(t, r, 0)
	var rows = systemCronWantTable(t, r.stdout, firewallRuleHeader, 11, "anti-lockout rule", "Default allow LAN to any rule", "block web", "floating")
	if len(rows) == 5 {
		var want = [][]string{
			{"0", "no", "AL", "pass", "LAN", "in", "any", "tcp", "any", "(self)", "443", "anti-lockout rule"},
			{"1", "no", "-", "pass", "lan", "in", "ipv4", "any", "lan", "any", "-", "Default allow LAN to any rule"},
			{"2", "yes", "LN", "block", "lan", "in", "ipv4", "tcp", "!10.0.0.0/8", "198.51.100.0/24", "443", "block web"},
			{"3", "no", "-", "pass", "any", "any", "any", "any", "lan", "any", "-", "floating"},
		}
		if !reflect.DeepEqual(rows[1:], want) {
			t.Errorf("rows:\n got  %q\n want %q", rows[1:], want)
		}
	}
	if bodies := firewallRuleSearchBodies(t, f); len(bodies) != 1 || bodies[0]["searchPhrase"] != "" || bodies[0]["interface"] != nil {
		t.Errorf("unexpected search %v", bodies)
	}
	firewallRuleWantNoWrites(t, f)

	t.Run("filters are sent to OPNsense", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		wantExit(t, f.run("/firewall/rule", "print", "interface=LAN,dmz", "search=block web", "category=WEB"), 0)
		wantExit(t, f.run("/firewall/rule", "print", "floating"), 0)
		var bodies = firewallRuleSearchBodies(t, f)
		if len(bodies) != 2 || bodies[0]["interface"] != "lan,opt1" || bodies[0]["searchPhrase"] != "block web" ||
			!reflect.DeepEqual(bodies[0]["category"], []any{firewallRuleCategory}) || bodies[1]["interface"] != "" {
			t.Errorf("unexpected searches %v", bodies)
		}
	})
	t.Run("without automatic rules", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		var r = f.run("/firewall/rule", "print", "automatic=no")
		wantExit(t, r, 0)
		systemCronWantTable(t, r.stdout, firewallRuleHeader, 11, "Default allow LAN to any rule", "block web", "floating")
	})
	t.Run("stats", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		var r = f.run("/firewall/rule", "print", "stats")
		wantExit(t, r, 0)
		var rows = systemCronTable(r.stdout)
		if len(rows) != 5 || !reflect.DeepEqual(rows[0][12:], []string{"EVALUATIONS", "PACKETS", "BYTES", "STATES"}) ||
			!reflect.DeepEqual(rows[1][12:], []string{"7", "3", "120", "1"}) {
			t.Errorf("want the counters:\n%s", r.stdout)
		}
		if bodies := firewallRuleSearchBodies(t, f); bodies[0]["show_all"] != "1" {
			t.Errorf("stats must ask for show_all: %v", bodies)
		}
	})
	t.Run("json prints the raw rows", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		var r = f.run("/firewall/rule", "print", "json")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		var row map[string]any
		if len(lines) != 4 || json.Unmarshal([]byte(lines[0]), &row) != nil || row["is_automatic"] != true || row["#priority"] != float64(5) {
			t.Errorf("want the raw rows:\n%s", r.stdout)
		}
	})
	t.Run("detail", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		var r = f.run("/firewall/rule", "print", "detail")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "  origin:            system_advanced_firewall.php#noantilockout",
			"  categories:        web\n", "  gateway:           WAN_DHCP", "  max-states:        100", "  no-sync:           yes",
			"  quick:             no")
	})
	t.Run("floating and interface, no API call", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t)
		wantFailure(t, f.run("/firewall/rule", "print", "floating", "interface=lan"), "can not be combined")
		wantNoCalls(t, f)
	})
}

func TestFirewallRuleShow(t *testing.T) {
	t.Parallel()
	var f = firewallRuleFake(t, firewallRuleRows()...)
	for _, selector := range []string{"BLOCK WEB", "2", firewallRuleWebUuid} {
		var r = f.run("/firewall/rule", "show", selector)
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "uuid:              "+firewallRuleWebUuid, "automatic:         no", "disabled:          yes",
			"source:            !10.0.0.0/8", "destination-port:  443", "log:               yes", "categories:        web",
			"evaluations:       70", "states:            4")
	}
	var r = f.run("/firewall/rule", "show", "anti-lockout rule")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "automatic:         yes", "origin:            system_advanced_firewall.php#noantilockout")
	wantFailure(t, f.run("/firewall/rule", "show", "nope"), "not found")
	firewallRuleWantNoWrites(t, f)
}

func TestFirewallRuleAdd(t *testing.T) {
	t.Parallel()

	t.Run("all fields are sent, the uuid is printed", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		f.on("POST", firewallRuleBase+"add_rule", 200, answerAdded("u-new"))
		var r = f.run("/firewall/rule", "add", "interface=LAN", "action=block", "disabled", "protocol=tcp", "source=!10.1.0.0/16",
			"destination=198.51.100.0/24", "destination-port=https", "log", "categories=web", "description=no web",
			"gateway=WAN_DHCP", "max-states=10", "tcp-flags=syn", "tcp-flags-of=syn,ack", "ip-protocol=any")
		wantExit(t, r, 0)
		if r.stdout != "u-new\n" || r.stderr != "" {
			t.Errorf("want only the uuid on stdout: %s", r)
		}
		var writes = firewallRuleWantWrites(t, f, firewallRuleBase+"add_rule")
		wantJSON(t, writes[0], firewallRuleAddBody(map[string]any{
			"interface": "lan", "action": "block", "enabled": "0", "protocol": "TCP", "source_net": "10.1.0.0/16", "source_not": "1",
			"destination_net": "198.51.100.0/24", "destination_port": "https", "log": "1", "categories": firewallRuleCategory,
			"description": "no web", "gateway": "WAN_DHCP", "max": "10", "tcpflags1": "syn", "tcpflags2": "syn,ack", "ipprotocol": "inet46",
		}))
	})
	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t)
		f.on("POST", firewallRuleBase+"add_rule", 200, answerAdded("u-new"))
		wantExit(t, f.run("/firewall/rule", "add", "interface=opt1,wan", "sequence=7"), 0)
		wantJSON(t, firewallRuleWantWrites(t, f, firewallRuleBase+"add_rule")[0],
			firewallRuleAddBody(map[string]any{"interface": "opt1,wan", "sequence": "7"}))
	})
	t.Run("place-before moves the new rule", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		f.on("POST", firewallRuleBase+"add_rule", 200, answerAdded("8a5e0a10-0000-4000-8000-000000000001"))
		f.on("POST", firewallRuleBase+"move_rule_before/8a5e0a10-0000-4000-8000-000000000001/"+firewallRuleWebUuid, 200, `{"status":"ok"}`)
		var r = f.run("/firewall/rule", "add", "interface=lan", "action=block", "description=new", "place-before=block web")
		wantExit(t, r, 0)
		firewallRuleWantWrites(t, f, firewallRuleBase+"add_rule", firewallRuleBase+"move_rule_before/8a5e0a10-0000-4000-8000-000000000001/"+firewallRuleWebUuid)
	})
	t.Run("place-before failing after the add", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		f.on("POST", firewallRuleBase+"add_rule", 200, answerAdded("8a5e0a10-0000-4000-8000-000000000001"))
		f.on("POST", firewallRuleBase+"move_rule_before/8a5e0a10-0000-4000-8000-000000000001/"+firewallRuleFloatId, 500,
			`{"errorMessage":"Cannot move 'Interface Rule' before 'Floating Rule'.","errorTitle":"Filter"}`)
		var r = f.run("/firewall/rule", "add", "interface=lan", "description=new", "place-before=floating")
		wantExit(t, r, 1)
		wantContains(t, "output", r.stdout+r.stderr, "8a5e0a10-0000-4000-8000-000000000001\n", "was saved, but could not be placed",
			"Cannot move 'Interface Rule' before 'Floating Rule'.")
	})
	t.Run("place-before an automatic rule is refused before adding", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		wantFailure(t, f.run("/firewall/rule", "add", "interface=lan", "place-before=0"), "automatic rule")
		firewallRuleWantNoWrites(t, f)
	})
	t.Run("existing description fails without replace", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		wantFailure(t, f.run("/firewall/rule", "add", "interface=lan", "description=BLOCK WEB"), "exists already", firewallRuleWebUuid)
		firewallRuleWantNoWrites(t, f)
	})
	t.Run("replace replaces the rule completely, keeping its position", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		f.on("POST", firewallRuleBase+"set_rule/"+firewallRuleWebUuid, 200, answerSaved)
		var r = f.run("/firewall/rule", "add", "interface=lan", "action=reject", "description=block web", "replace")
		wantExit(t, r, 0)
		if r.stdout != firewallRuleWebUuid+"\n" {
			t.Errorf("stdout must be the uuid: %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, `replaced the existing rule "block web"`)
		wantJSON(t, firewallRuleWantWrites(t, f, firewallRuleBase+"set_rule/"+firewallRuleWebUuid)[0],
			firewallRuleAddBody(map[string]any{"interface": "lan", "action": "reject", "description": "block web"}))
	})
	t.Run("unknown interface and category", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		wantFailure(t, f.run("/firewall/rule", "add", "interface=opt9"), `unknown interface "opt9"`, "lan, opt1, wan, vpns")
		wantFailure(t, f.run("/firewall/rule", "add", "interface=lan", "categories=nope"), `unknown category "nope"`, "web")
		firewallRuleWantNoWrites(t, f)
	})
	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t)
		f.on("POST", firewallRuleBase+"add_rule", 200, answerValidation("rule.source_net", "nope is not a valid source IP address or alias."))
		wantFailure(t, f.run("/firewall/rule", "add", "interface=lan", "source=nope"), "rule.source_net", "not a valid source")
	})
	t.Run("ports need TCP or UDP", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t)
		wantFailure(t, f.run("/firewall/rule", "add", "interface=lan", "destination-port=80"), "TCP")
		firewallRuleWantNoWrites(t, f)
	})

	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"bad action", []string{"action=drop"}, []string{"action must be one of pass, block, reject"}},
		{"bad direction", []string{"direction=both"}, []string{"direction must be one of in, out, any"}},
		{"bad network", []string{"source=10.0.0.0/8 x"}, []string{"invalid network"}},
		{"any combined", []string{"destination=any,lan"}, []string{"any can not be combined"}},
		{"inverted list", []string{"source=!lan,wan"}, []string{"only a single network can be inverted"}},
		{"invert contradiction", []string{"source=!lan", "source-invert=no"}, []string{"source-invert=no"}},
		{"inverted interfaces", []string{"interface=lan,wan", "interface-invert"}, []string{"exactly one interface"}},
		{"bad port", []string{"protocol=TCP", "destination-port=80;x"}, []string{"invalid port"}},
		{"port out of range", []string{"protocol=TCP", "destination-port=99999"}, []string{"0-65535"}},
		{"bad sequence", []string{"sequence=0"}, []string{"sequence must be a number from 1 to 999999"}},
		{"bad tcp flag", []string{"tcp-flags=syn,foo"}, []string{"tcp-flags must be one of"}},
		{"bad priority", []string{"priority=8"}, []string{"priority must be one of"}},
		{"conn rate alone", []string{"max-src-conn-rate=5", "max-src-conn-rate-seconds="}, []string{"together"}},
		{"newline in description", []string{"description=a\nb"}, []string{"control characters"}},
	} {
		t.Run(tc.name+", no API call", func(t *testing.T) {
			t.Parallel()
			var f = firewallRuleFake(t, firewallRuleRows()...)
			wantFailure(t, f.run(append([]string{"/firewall/rule", "add"}, tc.args...)...), tc.wants...)
			wantNoCalls(t, f)
		})
	}
}

func TestFirewallRuleSet(t *testing.T) {
	t.Parallel()

	t.Run("only the given fields", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		f.on("POST", firewallRuleBase+"set_rule/"+firewallRuleWebUuid, 200, answerSaved)
		var r = f.run("/firewall/rule", "set", "block web", "source=lan", "destination-port=", "description=x", "quick", "interface=")
		wantExit(t, r, 0)
		if r.stdout != "" || r.stderr != "" {
			t.Errorf("set must be silent: %s", r)
		}
		wantJSON(t, firewallRuleWantWrites(t, f, firewallRuleBase+"set_rule/"+firewallRuleWebUuid)[0], map[string]any{"rule": map[string]any{
			"source_net": "lan", "source_not": "0", "destination_port": "", "description": "x", "quick": "1", "interface": "",
		}})
	})
	t.Run("invert flag alone", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		f.on("POST", firewallRuleBase+"set_rule/"+firewallRuleLanUuid, 200, answerSaved)
		wantExit(t, f.run("/firewall/rule", "set", "1", "destination-invert"), 0)
		wantJSON(t, firewallRuleWantWrites(t, f, firewallRuleBase+"set_rule/"+firewallRuleLanUuid)[0],
			map[string]any{"rule": map[string]any{"destination_not": "1"}})
	})
	t.Run("log alone uses the log switch", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		f.on("POST", firewallRuleBase+"toggle_rule_log/"+firewallRuleLanUuid+"/1", 200, `{"status":"ok"}`)
		wantExit(t, f.run("/firewall/rule", "set", firewallRuleLanUuid, "log"), 0)
		firewallRuleWantWrites(t, f, firewallRuleBase+"toggle_rule_log/"+firewallRuleLanUuid+"/1")
	})
	t.Run("ports need TCP or UDP, also against the stored protocol", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		wantFailure(t, f.run("/firewall/rule", "set", "1", "destination-port=80"), "needs protocol TCP")
		firewallRuleWantNoWrites(t, f)
	})
	t.Run("automatic rules are refused", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		wantFailure(t, f.run("/firewall/rule", "set", "anti-lockout rule", "log=no"), "automatic rule", "system_advanced_firewall.php#noantilockout")
		firewallRuleWantNoWrites(t, f)
	})
	t.Run("unknown rule", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		wantFailure(t, f.run("/firewall/rule", "set", "00000000-0000-4000-8000-000000000000", "log"), "not found")
		firewallRuleWantNoWrites(t, f)
	})
	t.Run("nothing to change, no API call", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		wantFailure(t, f.run("/firewall/rule", "set", "1"), "nothing to change")
		wantNoCalls(t, f)
	})
}

func TestFirewallRuleRemoveEnableDisable(t *testing.T) {
	t.Parallel()

	t.Run("remove", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		f.on("POST", firewallRuleBase+"del_rule/"+firewallRuleWebUuid, 200, answerDeleted)
		var r = f.run("/firewall/rule", "remove", "block web")
		wantExit(t, r, 0)
		if r.stdout != "" || r.stderr != "" {
			t.Errorf("remove must be silent: %s", r)
		}
		firewallRuleWantWrites(t, f, firewallRuleBase+"del_rule/"+firewallRuleWebUuid)
	})
	t.Run("remove of a rule deleted meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		f.on("POST", firewallRuleBase+"del_rule/"+firewallRuleWebUuid, 200, answerNotFound)
		wantFailure(t, f.run("/firewall/rule", "remove", "block web"), "not found")
	})
	t.Run("enable and disable", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		f.on("POST", firewallRuleBase+"toggle_rule/"+firewallRuleWebUuid+"/1", 200, `{"result":"Enabled","changed":true}`)
		f.on("POST", firewallRuleBase+"toggle_rule/"+firewallRuleLanUuid+"/1", 200, `{"result":"Enabled","changed":false}`)
		wantExit(t, f.run("/firewall/rule", "enable", "block web"), 0)
		var r = f.run("/firewall/rule", "enable", "1")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, `rule "Default allow LAN to any rule" is already enabled`)
		firewallRuleWantWrites(t, f, firewallRuleBase+"toggle_rule/"+firewallRuleWebUuid+"/1", firewallRuleBase+"toggle_rule/"+firewallRuleLanUuid+"/1")
	})
	t.Run("automatic rules are refused", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t, firewallRuleRows()...)
		for _, command := range []string{"remove", "enable", "disable"} {
			wantFailure(t, f.run("/firewall/rule", command, firewallRuleAutoId), "automatic rule")
		}
		firewallRuleWantNoWrites(t, f)
	})
}

func TestFirewallRuleMove(t *testing.T) {
	t.Parallel()
	var f = firewallRuleFake(t, firewallRuleRows()...)
	f.on("POST", firewallRuleBase+"move_rule_before/"+firewallRuleWebUuid+"/"+firewallRuleLanUuid, 200, `{"status":"ok"}`)
	f.on("POST", firewallRuleBase+"move_rule_before/"+firewallRuleWebUuid+"/"+firewallRuleFloatId, 500,
		`{"errorMessage":"Cannot move 'Interface Rule' before 'Floating Rule'.","errorTitle":"Filter"}`)
	var r = f.run("/firewall/rule", "move", "block web", "before=1")
	wantExit(t, r, 0)
	if r.stdout != "" || r.stderr != "" {
		t.Errorf("move must be silent: %s", r)
	}
	r = f.run("/firewall/rule", "move", "block web", "before=floating")
	wantExit(t, r, 1)
	wantContains(t, "stderr", r.stderr, "error: Cannot move 'Interface Rule' before 'Floating Rule'.")
	firewallRuleWantWrites(t, f, firewallRuleBase+"move_rule_before/"+firewallRuleWebUuid+"/"+firewallRuleLanUuid,
		firewallRuleBase+"move_rule_before/"+firewallRuleWebUuid+"/"+firewallRuleFloatId)

	var g = firewallRuleFake(t, firewallRuleRows()...)
	wantFailure(t, g.run("/firewall/rule", "move", "block web", "before=0"), "before:", "automatic rule")
	wantFailure(t, g.run("/firewall/rule", "move", "block web"), "before")
	firewallRuleWantNoWrites(t, g)
}

func TestFirewallRuleApply(t *testing.T) {
	t.Parallel()

	t.Run("needs confirmation, no API call", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t)
		wantFailure(t, f.run("/firewall/rule", "apply"), "confirm")
		wantNoCalls(t, f)
	})
	t.Run("26.7 without savepoints applies directly", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t)
		f.on("POST", firewallRuleBase+"savepoint", 404, `{"errorMessage":"Endpoint not found"}`)
		f.on("POST", firewallRuleBase+"apply", 200, `{"status":"OK\n\n"}`)
		var r = f.run("/firewall/rule", "apply", "confirm=yes")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "no savepoints", "without rollback")
		firewallRuleWantWrites(t, f, firewallRuleBase+"savepoint", firewallRuleBase+"apply")
	})
	t.Run("with savepoint and rollback", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t)
		f.on("POST", firewallRuleBase+"savepoint", 200, `{"status":"ok","retention":"60","revision":"`+firewallRuleRevision+`"}`)
		f.on("POST", firewallRuleBase+"apply/"+firewallRuleRevision, 200, `{"status":"OK\n\n"}`)
		var r = f.run("/firewall/rule", "apply", "confirm=yes")
		wantExit(t, r, 0)
		if r.stdout != "" {
			t.Errorf("apply prints only messages: %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, "/firewall/rule confirm-apply "+firewallRuleRevision, "within 60 seconds")
		firewallRuleWantWrites(t, f, firewallRuleBase+"savepoint", firewallRuleBase+"apply/"+firewallRuleRevision)
	})
	t.Run("no-rollback", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t)
		f.on("POST", firewallRuleBase+"apply", 200, `{"status":"OK\n\n"}`)
		wantExit(t, f.run("/firewall/rule", "apply", "no-rollback", "confirm=yes"), 0)
		firewallRuleWantWrites(t, f, firewallRuleBase+"apply")
	})
	t.Run("failure", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t)
		f.on("POST", firewallRuleBase+"apply", 200, `{"status":"error"}`)
		wantFailure(t, f.run("/firewall/rule", "apply", "no-rollback", "confirm=yes"), "applying the filter rules failed")
	})
	t.Run("confirm-apply uses the revision of the last apply in the session", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t)
		f.on("POST", firewallRuleBase+"savepoint", 200, `{"status":"ok","retention":"60","revision":"`+firewallRuleRevision+`"}`)
		f.on("POST", firewallRuleBase+"apply/"+firewallRuleRevision, 200, `{"status":"OK\n\n"}`)
		f.on("POST", firewallRuleBase+"cancel_rollback/"+firewallRuleRevision, 200, `{"status":""}`)
		var r = f.runScript("/firewall/rule\napply confirm=yes\nconfirm-apply\n")
		wantExit(t, r, 0)
		firewallRuleWantWrites(t, f, firewallRuleBase+"savepoint", firewallRuleBase+"apply/"+firewallRuleRevision,
			firewallRuleBase+"cancel_rollback/"+firewallRuleRevision)
	})
	t.Run("confirm-apply too late", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t)
		f.on("POST", firewallRuleBase+"cancel_rollback/"+firewallRuleRevision, 200, `{"status":"Execute error"}`)
		wantFailure(t, f.run("/firewall/rule", "confirm-apply", firewallRuleRevision), "no rollback", "reverted already")
	})
	t.Run("confirm-apply on 26.7", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t)
		f.on("POST", firewallRuleBase+"cancel_rollback/"+firewallRuleRevision, 404, `{"errorMessage":"Endpoint not found"}`)
		wantFailure(t, f.run("/firewall/rule", "confirm-apply", firewallRuleRevision), "no filter savepoints")
	})
	t.Run("confirm-apply without revision, no API call", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t)
		wantFailure(t, f.run("/firewall/rule", "confirm-apply"), "give the savepoint revision")
		wantFailure(t, f.run("/firewall/rule", "confirm-apply", "1;x"), "revision")
		wantNoCalls(t, f)
	})
	t.Run("revert", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleFake(t)
		f.on("POST", firewallRuleBase+"revert/"+firewallRuleRevision, 200, `{"status":"ok"}`)
		wantFailure(t, f.run("/firewall/rule", "revert", firewallRuleRevision), "confirm")
		firewallRuleWantNoWrites(t, f)
		wantExit(t, f.run("/firewall/rule", "revert", firewallRuleRevision, "confirm=yes"), 0)
		firewallRuleWantWrites(t, f, firewallRuleBase+"revert/"+firewallRuleRevision)
	})
}

func TestFirewallRuleComplete(t *testing.T) {
	t.Parallel()
	var f = firewallRuleFake(t, firewallRuleRows()...)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/firewall/rule remove bl":             {`"block web"`},
		"/firewall/rule add interface=o":       {"interface=opt1"},
		"/firewall/rule add protocol=T":        {"protocol=TCP", "protocol=TCP/UDP"},
		"/firewall/rule add source=la":         {"source=lan", "source=lanip"},
		"/firewall/rule add destination-port=": {"destination-port=http", "destination-port=https"},
		"/firewall/rule add categories=":       {"categories=web"},
		"/firewall/rule add gateway=":          {"gateway=WAN_DHCP"},
		"/firewall/rule set 1 action=":         {"action=block", "action=pass", "action=reject"},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	firewallRuleWantNoWrites(t, f)
}

func TestFirewallRuleHelp(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var r = f.run("/firewall/rule", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "print", "add", "move", "apply", "confirm-apply", "revert")
	r = f.run("/firewall/rule", "apply", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "confirm-apply", "26.7", "no-rollback")
	wantNoCalls(t, f)
}
