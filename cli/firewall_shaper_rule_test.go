package cli

import (
	"reflect"
	"strings"
	"testing"
)

const (
	firewallShaperRuleSearchPath = "/api/trafficshaper/settings/search_rules"
	firewallShaperRuleGetPath    = "/api/trafficshaper/settings/get_rule"
	firewallShaperRuleAddPath    = "/api/trafficshaper/settings/add_rule"
	firewallShaperRuleSetPath    = "/api/trafficshaper/settings/set_rule/"
	firewallShaperRuleDelPath    = "/api/trafficshaper/settings/del_rule/"
	firewallShaperRuleTogglePath = "/api/trafficshaper/settings/toggle_rule/"
)

// firewallShaperRuleGetAnswer is get_rule (a new rule) on a box with two pipes, a queue and a queue named like a pipe
const firewallShaperRuleGetAnswer = `{"rule":{"enabled":"1","sequence":"31",` +
	`"interface":{"lan":{"value":"LAN","selected":0},"lo0":{"value":"Loopback","selected":0},"wan":{"value":"WAN","selected":1},"opt1":{"value":"DMZ","selected":0}},` +
	`"interface2":{"":{"value":"None","selected":1},"lan":{"value":"LAN","selected":0},"wan":{"value":"WAN","selected":0}},` +
	`"proto":{"ip":{"value":"ip","selected":1}},"source":{"any":{"value":"any","selected":1}},"src_port":"any",` +
	`"target":{"p-down":{"value":"WAN down","selected":0},"p-up":{"value":"WAN up","selected":0},` +
	`"q-interactive":{"value":"interactive","selected":0},"q-same":{"value":"WAN UP","selected":0}},"description":""}}`

func firewallShaperRuleRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "enabled": "1", "sequence": "10", "interface": "wan", "%interface": "WAN", "interface2": "", "proto": "ip",
		"iplen": "", "source": "any", "source_not": "0", "src_port": "any", "destination": "any", "destination_not": "0",
		"dst_port": "any", "dscp": "", "direction": "", "target": "p-down", "%target": "WAN down", "description": "all down",
		"origin": "TrafficShaper",
	}, overrides)
}

var firewallShaperRuleRows = []map[string]any{
	firewallShaperRuleRow(map[string]any{"uuid": "r-all"}),
	firewallShaperRuleRow(map[string]any{"uuid": "r-voip", "sequence": "20", "interface": "lan", "%interface": "LAN", "interface2": "wan",
		"%interface2": "WAN", "proto": "udp", "source": "192.0.2.0/24,2001:db8::/32", "source_not": "1", "dst_port": "5060",
		"destination": "198.51.100.10", "direction": "in", "%direction": "In", "target": "q-interactive", "%target": "interactive",
		"description": "voip", "enabled": "0"}),
	firewallShaperRuleRow(map[string]any{"uuid": "r-nodesc", "sequence": "30", "description": ""}),
}

func firewallShaperRuleBody(overrides map[string]any) map[string]any {
	return map[string]any{"rule": withFields(map[string]any{
		"enabled": "1", "sequence": "31", "interface": "wan", "interface2": "", "proto": "ip", "iplen": "", "source": "any",
		"source_not": "0", "src_port": "any", "destination": "any", "destination_not": "0", "dst_port": "any", "dscp": "",
		"direction": "", "target": "q-interactive", "description": "",
	}, overrides)}
}

func newFirewallShaperRuleFake(t *testing.T) *fakeOPN {
	var f = newFakeOPN(t)
	f.search(firewallShaperRuleSearchPath, firewallShaperRuleRows...)
	f.on("GET", firewallShaperRuleGetPath, 200, firewallShaperRuleGetAnswer)
	f.on("POST", firewallShaperRuleAddPath, 200, answerAdded("r-new"))
	for _, row := range firewallShaperRuleRows {
		var uuid = row["uuid"].(string)
		f.on("POST", firewallShaperRuleSetPath+uuid, 200, answerSaved)
		f.on("POST", firewallShaperRuleDelPath+uuid, 200, answerDeleted)
		f.on("POST", firewallShaperRuleTogglePath+uuid+"/0", 200, `{"result":"Disabled","changed":true}`)
	}
	return f
}

func TestFirewallShaperRulePrint(t *testing.T) {
	t.Parallel()
	var f = newFirewallShaperRuleFake(t)
	var r = f.run("/firewall/shaper/rule", "print")
	wantExit(t, r, 0)
	var rows = dnsmasqTableRows(r.stdout)
	var want = [][]string{
		{"#", "DISABLED", "SEQUENCE", "INTERFACE", "PROTOCOL", "SOURCE", "DESTINATION", "DIRECTION", "TARGET", "DESCRIPTION"},
		{"0", "no", "10", "WAN", "ip", "any", "any", "both", "WAN down", "all down"},
		{"1", "yes", "20", "LAN, WAN", "udp", "!192.0.2.0/24, 2001:db8::/32", "198.51.100.10 port 5060", "in", "interactive", "voip"},
		{"2", "no", "30", "WAN", "ip", "any", "any", "both", "WAN down", "-"},
	}
	if len(rows) != len(want) {
		t.Fatalf("want %d lines:\n%s", len(want), r.stdout)
	}
	for i := range want {
		if strings.Join(rows[i], "|") != strings.Join(want[i], "|") {
			t.Errorf("line %d: got %q, want %q", i, rows[i], want[i])
		}
	}
	r = f.run("/firewall/shaper/rule", "show", "VOIP")
	wantExit(t, r, 0)
	var fields = dnsmasqParseFields(r.stdout)
	if fields["uuid"] != "r-voip" || fields["interface2"] != "WAN" || fields["source-invert"] != "yes" || fields["target"] != "interactive" ||
		fields["destination-port"] != "5060" || fields["disabled"] != "yes" {
		t.Errorf("show: %v", fields)
	}
	wantNoMutations(t, f)
}

func TestFirewallShaperRuleAdd(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		args         []string
		wantPath     string
		wantBody     map[string]any
		wantUuid     string
		wantReplaced bool
	}{
		{name: "minimal: after the last rule on wan", args: []string{"target=Interactive"},
			wantPath: firewallShaperRuleAddPath, wantBody: firewallShaperRuleBody(nil), wantUuid: "r-new"},
		{name: "all fields", args: []string{"target=p-up", "sequence=5", "interface=DMZ", "interface2=lan", "protocol=TCP",
			"ip-length=1500", "source=192.0.2.0/24, 2001:DB8::/32", "source-invert", "source-port=1000-2000",
			"destination=198.51.100.7", "destination-invert=yes", "destination-port=https", "dscp=EF,af11", "direction=out",
			"description=web", "disabled"},
			wantPath: firewallShaperRuleAddPath, wantBody: firewallShaperRuleBody(map[string]any{"target": "p-up", "sequence": "5",
				"interface": "opt1", "interface2": "lan", "proto": "tcp", "iplen": "1500", "source": "192.0.2.0/24,2001:db8::/32",
				"source_not": "1", "src_port": "1000-2000", "destination": "198.51.100.7", "destination_not": "1",
				"dst_port": "https", "dscp": "ef,af11", "direction": "out", "description": "web", "enabled": "0"}),
			wantUuid: "r-new"},
		{name: "any, both and none", args: []string{"target=WAN down", "source=any", "destination=", "direction=both",
			"interface2=none", "source-port=ANY"},
			wantPath: firewallShaperRuleAddPath, wantBody: firewallShaperRuleBody(map[string]any{"target": "p-down"}), wantUuid: "r-new"},
		{name: "replace by description", args: []string{"target=interactive", "description=Voip", "replace"},
			wantPath: firewallShaperRuleSetPath + "r-voip", wantBody: firewallShaperRuleBody(map[string]any{"description": "Voip"}),
			wantUuid: "r-voip", wantReplaced: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFirewallShaperRuleFake(t)
			var r = f.run(append([]string{"/firewall/shaper/rule", "add"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != tc.wantUuid+"\n" {
				t.Errorf("stdout %q, want only the uuid %q", r.stdout, tc.wantUuid)
			}
			if tc.wantReplaced {
				wantContains(t, "stderr", r.stderr, "replaced")
			}
			wantJSON(t, wantOneMutation(t, f, "POST", tc.wantPath), tc.wantBody)
		})
	}
}

func TestFirewallShaperRuleAddErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		args      []string
		wantErr   []string
		wantCalls bool
	}{
		{name: "missing target", args: []string{"description=x"}, wantErr: []string{"target", "required"}},
		{name: "invalid source", args: []string{"target=x", "source=lan"}, wantErr: []string{"source", "lan"}},
		{name: "any with networks", args: []string{"target=x", "destination=any,192.0.2.1"}, wantErr: []string{"any can not be combined"}},
		{name: "invalid port", args: []string{"target=x", "destination-port=80:90"}, wantErr: []string{"destination-port", "80:90"}},
		{name: "port out of range", args: []string{"target=x", "source-port=70000"}, wantErr: []string{"source-port", "70000"}},
		{name: "invalid protocol", args: []string{"target=x", "protocol=sctp"}, wantErr: []string{"protocol", "sctp"}},
		{name: "invalid dscp", args: []string{"target=x", "dscp=ef,af99"}, wantErr: []string{"dscp", "af99"}},
		{name: "invalid direction", args: []string{"target=x", "direction=up"}, wantErr: []string{"direction", "up"}},
		{name: "invalid sequence", args: []string{"target=x", "sequence=0"}, wantErr: []string{"sequence"}},
		{name: "replace without description", args: []string{"target=x", "replace"}, wantErr: []string{"description"}},
		{name: "unknown target", args: []string{"target=bulk"}, wantErr: []string{"unknown pipe or queue", "bulk", "interactive (q-interactive)"}, wantCalls: true},
		{name: "ambiguous target", args: []string{"target=wan up"}, wantErr: []string{"p-up", "q-same", "uuid"}, wantCalls: true},
		{name: "unknown interface", args: []string{"target=p-up", "interface=opt9"}, wantErr: []string{"unknown interface", "opt9", "DMZ (opt1)"}, wantCalls: true},
		{name: "existing description", args: []string{"target=p-up", "description=VOIP"}, wantErr: []string{"exists", "r-voip"}, wantCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFirewallShaperRuleFake(t)
			wantFailure(t, f.run(append([]string{"/firewall/shaper/rule", "add"}, tc.args...)...), tc.wantErr...)
			if !tc.wantCalls {
				wantNoCalls(t, f)
			}
			wantNoMutations(t, f)
		})
	}
}

func TestFirewallShaperRuleSet(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		args     []string
		wantPath string
		wantBody map[string]any
		wantGet  bool
	}{
		{name: "only the given fields, no options needed", args: []string{"voip", "source=", "destination-port=", "dscp=", "disabled=no"},
			wantPath: firewallShaperRuleSetPath + "r-voip",
			wantBody: map[string]any{"rule": map[string]any{"source": "any", "dst_port": "any", "dscp": "", "enabled": "1"}}},
		{name: "target and interfaces resolved", args: []string{"2", "target=WAN down", "interface=lan", "interface2="},
			wantPath: firewallShaperRuleSetPath + "r-nodesc",
			wantBody: map[string]any{"rule": map[string]any{"target": "p-down", "interface": "lan", "interface2": ""}}, wantGet: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFirewallShaperRuleFake(t)
			var r = f.run(append([]string{"/firewall/shaper/rule", "set"}, tc.args...)...)
			wantExit(t, r, 0)
			wantJSON(t, wantOneMutation(t, f, "POST", tc.wantPath), tc.wantBody)
			var gets = 0
			for _, call := range f.calls() {
				if call.Path == firewallShaperRuleGetPath {
					gets++
				}
			}
			if (gets > 0) != tc.wantGet {
				t.Errorf("get_rule calls: %d", gets)
			}
		})
	}

	var f = newFirewallShaperRuleFake(t)
	wantFailure(t, f.run("/firewall/shaper/rule", "set", "voip"), "nothing to change")
	wantFailure(t, f.run("/firewall/shaper/rule", "set", "voip", "description=all down"), "another rule", "r-all")
	wantFailure(t, f.run("/firewall/shaper/rule", "set", "nobody", "protocol=tcp"), "not found")
	wantNoMutations(t, f)
}

func TestFirewallShaperRuleRemoveDisableComplete(t *testing.T) {
	t.Parallel()
	var f = newFirewallShaperRuleFake(t)
	wantExit(t, f.run("/firewall/shaper/rule", "remove", "all down"), 0)
	wantOneMutation(t, f, "POST", firewallShaperRuleDelPath+"r-all")

	f = newFirewallShaperRuleFake(t)
	wantExit(t, f.run("/firewall/shaper/rule", "disable", "2"), 0)
	wantOneMutation(t, f, "POST", firewallShaperRuleTogglePath+"r-nodesc/0")

	f = newFirewallShaperRuleFake(t)
	f.search(firewallShaperPipeSearchPath, firewallShaperPipeRows...)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/firewall/shaper/rule remove v":        {"voip"},
		"/firewall/shaper/rule add target=WAN":  {`target="WAN UP"`, `target="WAN down"`, `target="WAN up"`},
		"/firewall/shaper/rule add interface=o": {"interface=opt1"},
		"/firewall/shaper/queue add pipe=WAN":   {`pipe="WAN down guests"`, `pipe="WAN down"`, `pipe="WAN up"`},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}
