package cli

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const (
	openvpnClientOverrideSearchPath = "/api/openvpn/client_overwrites/search"
	openvpnClientOverrideGetPath    = "/api/openvpn/client_overwrites/get"
	openvpnClientOverrideAddPath    = "/api/openvpn/client_overwrites/add"
	openvpnClientOverrideSetPath    = "/api/openvpn/client_overwrites/set/"
	openvpnClientOverrideDelPath    = "/api/openvpn/client_overwrites/del/"
	openvpnClientOverrideTogglePath = "/api/openvpn/client_overwrites/toggle/"
)

// openvpnClientOverrideGetAnswer is client_overwrites/get of a box with three server instances (two named "home")
const openvpnClientOverrideGetAnswer = `{"cso":{"enabled":"1","servers":{` +
	`"s-office":{"value":"office (1194 / UDP)","selected":0},` +
	`"s-home1":{"value":"home (1195 / UDP)","selected":0},` +
	`"s-home2":{"value":"home (1196 / TCP)","selected":0}},` +
	`"common_name":"","block":"0","push_reset":"0","tunnel_network":"","tunnel_networkv6":""}}`

// openvpnClientOverrideRow is a 26.7 shaped search row
func openvpnClientOverrideRow(overrides map[string]any) map[string]any {
	var row = withFields(map[string]any{
		"uuid": "", "enabled": "1", "servers": "", "common_name": "alice", "block": "0", "push_reset": "0",
		"tunnel_network": "", "tunnel_networkv6": "", "local_networks": "", "remote_networks": "", "route_gateway": "",
		"redirect_gateway": "", "%redirect_gateway": "", "register_dns": "0", "dns_domain": "", "dns_domain_search": "",
		"dns_servers": "", "ntp_servers": "", "wins_servers": "", "description": "",
	}, overrides)
	if row["servers"] != "" {
		if _, labelled := row["%servers"]; !labelled {
			row["%servers"] = "office (1194 / UDP)"
		}
	}
	return row
}

var openvpnClientOverrideRows = []map[string]any{
	openvpnClientOverrideRow(map[string]any{"uuid": "u-alice", "tunnel_network": "10.8.0.8/30", "tunnel_networkv6": "fd00:8::8/64", "description": "alice laptop"}),
	openvpnClientOverrideRow(map[string]any{"uuid": "u-bob-office", "common_name": "bob", "servers": "s-office", "enabled": "0", "block": "1"}),
	openvpnClientOverrideRow(map[string]any{"uuid": "u-bob-home", "common_name": "bob", "servers": "s-home1,s-home2", "%servers": "home (1195 / UDP), home (1196 / TCP)"}),
	openvpnClientOverrideRow(map[string]any{"uuid": "u-alice2", "common_name": "alice2", "description": "not alice"}),
}

// openvpnClientOverrideBody is the full {"cso":{...}} body add sends, with all defaults
func openvpnClientOverrideBody(overrides map[string]any) map[string]any {
	return map[string]any{"cso": withFields(map[string]any{
		"enabled": "1", "servers": "", "common_name": "carol", "block": "0", "push_reset": "0", "tunnel_network": "",
		"tunnel_networkv6": "", "local_networks": "", "remote_networks": "", "route_gateway": "", "redirect_gateway": "",
		"register_dns": "0", "dns_domain": "", "dns_domain_search": "", "dns_servers": "", "ntp_servers": "",
		"wins_servers": "", "description": "",
	}, overrides)}
}

func newOpenvpnClientOverrideFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	var f = newFakeOPN(t)
	f.search(openvpnClientOverrideSearchPath, rows...)
	f.on("GET", openvpnClientOverrideGetPath, 200, openvpnClientOverrideGetAnswer)
	f.on("POST", openvpnClientOverrideAddPath, 200, answerAdded("u-new"))
	for _, row := range rows {
		var uuid = row["uuid"].(string)
		f.on("POST", openvpnClientOverrideSetPath+uuid, 200, answerSaved)
		f.on("POST", openvpnClientOverrideDelPath+uuid, 200, answerDeleted)
		f.on("POST", openvpnClientOverrideTogglePath+uuid+"/0", 200, `{"result":"Disabled","changed":true}`)
		f.on("POST", openvpnClientOverrideTogglePath+uuid+"/1", 200, `{"result":"Enabled","changed":true}`)
	}
	return f
}

func TestOpenvpnClientOverridePrint(t *testing.T) {
	t.Parallel()
	var f = newOpenvpnClientOverrideFake(t, openvpnClientOverrideRows...)
	var r = f.run("/vpn/openvpn/client-override", "print")
	wantExit(t, r, 0)
	var rows = dnsmasqTableRows(r.stdout)
	var want = [][]string{
		{"#", "DISABLED", "COMMON-NAME", "SERVERS", "TUNNEL-NETWORK", "BLOCK", "DESCRIPTION"},
		{"0", "no", "alice", "all", "10.8.0.8/30, fd00:8::8/64", "no", "alice laptop"},
		{"1", "yes", "bob", "office (1194 / UDP)", "-", "yes", "-"},
		{"2", "no", "bob", "home (1195 / UDP), home (1196 / TCP)", "-", "no", "-"},
		{"3", "no", "alice2", "all", "-", "no", "not alice"},
	}
	if len(rows) != len(want) {
		t.Fatalf("want %d lines:\n%s", len(want), r.stdout)
	}
	for i := range want {
		if strings.Join(rows[i], "|") != strings.Join(want[i], "|") {
			t.Errorf("line %d: got %q, want %q", i, rows[i], want[i])
		}
	}

	r = f.run("/vpn/openvpn/client-override", "print", "json")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 4 {
		t.Fatalf("want 4 JSON lines:\n%s", r.stdout)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil || first["uuid"] != "u-alice" || first["tunnel_networkv6"] != "fd00:8::8/64" {
		t.Errorf("want the raw row, got %s (%v)", lines[0], err)
	}

	r = f.run("/vpn/openvpn/client-override", "print", "detail", "search=bob")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "uuid:", "u-bob-office", "common-name:", "servers:", "office (1194 / UDP)",
		"disabled:", "block:", "tunnel-network6:", "redirect-gateway:", "wins-servers:", "register-dns:")
	wantNotContains(t, "stdout", r.stdout, "u-alice")
	wantSearchPhrases(t, f, openvpnClientOverrideSearchPath, "", "", "bob")
	wantNoMutations(t, f)
}

func TestOpenvpnClientOverrideShow(t *testing.T) {
	t.Parallel()
	var f = newOpenvpnClientOverrideFake(t, openvpnClientOverrideRows...)
	for _, item := range []string{"alice", "ALICE", "u-alice", "0"} {
		var r = f.run("/vpn/openvpn/client-override", "show", item)
		wantExit(t, r, 0)
		var fields = dnsmasqParseFields(r.stdout)
		if fields["uuid"] != "u-alice" || fields["servers"] != "all" || fields["tunnel-network"] != "10.8.0.8/30" || fields["disabled"] != "no" {
			t.Errorf("show %s: %v", item, fields)
		}
	}
	// bob has an override for two sets of servers
	wantFailure(t, f.run("/vpn/openvpn/client-override", "show", "bob"), "u-bob-office", "u-bob-home", "uuid")
	wantFailure(t, f.run("/vpn/openvpn/client-override", "show", "ali"), "not found")
	wantNoMutations(t, f)
}

func TestOpenvpnClientOverrideAdd(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		args         []string
		wantPath     string
		wantBody     map[string]any
		wantUuid     string
		wantReplaced bool
	}{
		{
			name:     "minimal",
			args:     []string{"common-name=carol"},
			wantPath: openvpnClientOverrideAddPath,
			wantBody: openvpnClientOverrideBody(nil),
			wantUuid: "u-new",
		},
		{
			name: "all fields, normalized",
			args: []string{"common-name=carol", "servers=Office,s-home2,office", "tunnel-network=10.8.0.12/30",
				"tunnel-network6=FD00:8:0::c/64", "local-networks=192.168.10.0/24, 10.0.0.1,FD00:1::/64",
				"remote-networks=192.168.20.0/24", "redirect-gateway=DEF1,!ipv4,bypass-dhcp", "push-reset", "block=yes",
				"route-gateway=10.8.0.13", "dns-domain=example.lan", "dns-domain-search=a.example.lan,b.example.lan",
				"dns-servers=10.0.0.53,FD00::53", "ntp-servers=10.0.0.123", "wins-servers=10.0.0.137", "register-dns",
				"description=carol phone", "disabled"},
			wantPath: openvpnClientOverrideAddPath,
			wantBody: openvpnClientOverrideBody(map[string]any{
				"enabled": "0", "servers": "s-office,s-home2", "tunnel_network": "10.8.0.12/30", "tunnel_networkv6": "fd00:8::c/64",
				"local_networks": "192.168.10.0/24,10.0.0.1,fd00:1::/64", "remote_networks": "192.168.20.0/24",
				"redirect_gateway": "def1,!ipv4,bypass-dhcp", "push_reset": "1", "block": "1", "route_gateway": "10.8.0.13",
				"dns_domain": "example.lan", "dns_domain_search": "a.example.lan,b.example.lan", "dns_servers": "10.0.0.53,fd00::53",
				"ntp_servers": "10.0.0.123", "wins_servers": "10.0.0.137", "register_dns": "1", "description": "carol phone",
			}),
			wantUuid: "u-new",
		},
		{
			name:     "same common name, other servers",
			args:     []string{"common-name=bob", "servers=s-home1"},
			wantPath: openvpnClientOverrideAddPath,
			wantBody: openvpnClientOverrideBody(map[string]any{"common_name": "bob", "servers": "s-home1"}),
			wantUuid: "u-new",
		},
		{
			name:     "common names are case-sensitive",
			args:     []string{"common-name=Alice"},
			wantPath: openvpnClientOverrideAddPath,
			wantBody: openvpnClientOverrideBody(map[string]any{"common_name": "Alice"}),
			wantUuid: "u-new",
		},
		{
			name:         "replace overwrites the same common name and servers completely",
			args:         []string{"common-name=bob", "servers=s-home2,s-home1", "block", "replace"},
			wantPath:     openvpnClientOverrideSetPath + "u-bob-home",
			wantBody:     openvpnClientOverrideBody(map[string]any{"common_name": "bob", "servers": "s-home2,s-home1", "block": "1"}),
			wantUuid:     "u-bob-home",
			wantReplaced: true,
		},
		{
			name:     "replace of a new key adds",
			args:     []string{"common-name=carol", "replace"},
			wantPath: openvpnClientOverrideAddPath,
			wantBody: openvpnClientOverrideBody(nil),
			wantUuid: "u-new",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newOpenvpnClientOverrideFake(t, openvpnClientOverrideRows...)
			var r = f.run(append([]string{"/vpn/openvpn/client-override", "add"}, tc.args...)...)
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

func TestOpenvpnClientOverrideAddErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		args      []string
		answer    string
		wantErr   []string
		wantCalls bool
	}{
		{name: "missing common name", args: []string{"tunnel-network=10.8.0.8/30"}, wantErr: []string{"common-name", "required"}},
		{name: "empty common name", args: []string{"common-name="}, wantErr: []string{"common-name", "must not be empty"}},
		{name: "slash in common name", args: []string{"common-name=a/b"}, wantErr: []string{"common-name", "slash"}},
		{name: "tunnel network without prefix", args: []string{"common-name=c", "tunnel-network=10.8.0.8"}, wantErr: []string{"tunnel-network", "10.8.0.8"}},
		{name: "IPv6 tunnel network as IPv4", args: []string{"common-name=c", "tunnel-network=fd00::/64"}, wantErr: []string{"tunnel-network", "IPv4"}},
		{name: "IPv4 tunnel network as IPv6", args: []string{"common-name=c", "tunnel-network6=10.8.0.8/30"}, wantErr: []string{"tunnel-network6", "IPv6"}},
		{name: "invalid local network", args: []string{"common-name=c", "local-networks=192.168.1.0/24,lan"}, wantErr: []string{"local-networks", "lan"}},
		{name: "invalid remote network", args: []string{"common-name=c", "remote-networks=10.0.0.0/33"}, wantErr: []string{"remote-networks", "10.0.0.0/33"}},
		{name: "route gateway with prefix", args: []string{"common-name=c", "route-gateway=10.8.0.1/24"}, wantErr: []string{"route-gateway", "10.8.0.1/24"}},
		{name: "invalid dns server", args: []string{"common-name=c", "dns-servers=10.0.0.53,dns"}, wantErr: []string{"dns-servers", "dns"}},
		{name: "invalid wins server", args: []string{"common-name=c", "wins-servers=10.0.0.0/24"}, wantErr: []string{"wins-servers"}},
		{name: "invalid dns domain", args: []string{"common-name=c", "dns-domain=bad domain"}, wantErr: []string{"dns-domain", "bad domain"}},
		{name: "invalid redirect flag", args: []string{"common-name=c", "redirect-gateway=def1,bogus"}, wantErr: []string{"redirect-gateway", "bogus"}},
		{name: "invalid flag", args: []string{"common-name=c", "block=maybe"}, wantErr: []string{"block", "maybe"}},
		{name: "unknown server", args: []string{"common-name=c", "servers=lab"}, wantErr: []string{"lab", "office", "s-home1"}, wantCalls: true},
		{name: "ambiguous server", args: []string{"common-name=c", "servers=home"}, wantErr: []string{"home", "s-home1", "s-home2", "uuid"}, wantCalls: true},
		{name: "existing key", args: []string{"common-name=bob", "servers=office"},
			wantErr: []string{"bob", "exists", "u-bob-office", "replace"}, wantCalls: true},
		{name: "existing key for all servers", args: []string{"common-name=alice"},
			wantErr: []string{"alice", "exists", "u-alice"}, wantCalls: true},
		{name: "OPNsense validation", args: []string{"common-name=c"},
			answer:  answerValidation("cso.common_name", "Text does not validate."),
			wantErr: []string{"common-name: Text does not validate."}, wantCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(openvpnClientOverrideSearchPath, openvpnClientOverrideRows...)
			f.on("GET", openvpnClientOverrideGetPath, 200, openvpnClientOverrideGetAnswer)
			if tc.answer != "" {
				f.on("POST", openvpnClientOverrideAddPath, 200, tc.answer)
			}
			var r = f.run(append([]string{"/vpn/openvpn/client-override", "add"}, tc.args...)...)
			wantFailure(t, r, tc.wantErr...)
			if !tc.wantCalls {
				wantNoCalls(t, f)
			}
			if tc.answer == "" {
				wantNoMutations(t, f)
			}
		})
	}
}

func TestOpenvpnClientOverrideSet(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		args     []string
		wantPath string
		wantBody map[string]any
	}{
		{name: "only the given fields", args: []string{"alice", "tunnel-network=10.8.0.16/30", "description=", "disabled"},
			wantPath: openvpnClientOverrideSetPath + "u-alice",
			wantBody: map[string]any{"cso": map[string]any{"tunnel_network": "10.8.0.16/30", "description": "", "enabled": "0"}}},
		{name: "by #", args: []string{"3", "block=no", "disabled=no"},
			wantPath: openvpnClientOverrideSetPath + "u-alice2",
			wantBody: map[string]any{"cso": map[string]any{"block": "0", "enabled": "1"}}},
		{name: "servers by name", args: []string{"u-bob-office", "servers=s-home1"},
			wantPath: openvpnClientOverrideSetPath + "u-bob-office",
			wantBody: map[string]any{"cso": map[string]any{"servers": "s-home1"}}},
		{name: "empty servers is all servers", args: []string{"u-bob-office", "servers="},
			wantPath: openvpnClientOverrideSetPath + "u-bob-office",
			wantBody: map[string]any{"cso": map[string]any{"servers": ""}}},
		{name: "clear lists", args: []string{"alice", "local-networks=", "redirect-gateway="},
			wantPath: openvpnClientOverrideSetPath + "u-alice",
			wantBody: map[string]any{"cso": map[string]any{"local_networks": "", "redirect_gateway": ""}}},
		{name: "rename", args: []string{"alice2", "common-name=carol"},
			wantPath: openvpnClientOverrideSetPath + "u-alice2",
			wantBody: map[string]any{"cso": map[string]any{"common_name": "carol"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newOpenvpnClientOverrideFake(t, openvpnClientOverrideRows...)
			var r = f.run(append([]string{"/vpn/openvpn/client-override", "set"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("set must be silent, got %q", r.stdout)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", tc.wantPath), tc.wantBody)
		})
	}
}

func TestOpenvpnClientOverrideSetErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		args    []string
		wantErr []string
	}{
		{name: "nothing to change", args: []string{"alice"}, wantErr: []string{"nothing to change"}},
		{name: "unknown item", args: []string{"0f0f0f0f-1111-4222-8333-444455556666", "description=x"}, wantErr: []string{"not found"}},
		{name: "index out of range", args: []string{"9", "description=x"}, wantErr: []string{"#9"}},
		{name: "ambiguous common name", args: []string{"bob", "description=x"}, wantErr: []string{"u-bob-office", "u-bob-home"}},
		{name: "rename onto an existing key", args: []string{"alice2", "common-name=alice"}, wantErr: []string{"alice", "u-alice", "exists"}},
		{name: "servers onto an existing key", args: []string{"u-bob-home", "servers=office"}, wantErr: []string{"bob", "u-bob-office", "exists"}},
		{name: "unknown server", args: []string{"alice", "servers=lab"}, wantErr: []string{"lab", "not found"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newOpenvpnClientOverrideFake(t, openvpnClientOverrideRows...)
			wantFailure(t, f.run(append([]string{"/vpn/openvpn/client-override", "set"}, tc.args...)...), tc.wantErr...)
			wantNoMutations(t, f)
		})
	}
}

func TestOpenvpnClientOverrideRemove(t *testing.T) {
	t.Parallel()
	var f = newOpenvpnClientOverrideFake(t, openvpnClientOverrideRows...)
	var r = f.run("/vpn/openvpn/client-override", "remove", "alice")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("remove must be silent, got %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", openvpnClientOverrideDelPath+"u-alice")

	f = newOpenvpnClientOverrideFake(t, openvpnClientOverrideRows...)
	wantFailure(t, f.run("/vpn/openvpn/client-override", "remove", "bob"), "u-bob-office", "u-bob-home")
	wantFailure(t, f.run("/vpn/openvpn/client-override", "remove", "nobody"), "not found")
	wantNoMutations(t, f)

	// the script refers to the # of the print before
	f = newOpenvpnClientOverrideFake(t, openvpnClientOverrideRows...)
	r = f.runScript("/vpn/openvpn/client-override\nprint search=bob\nremove 1\n")
	wantExit(t, r, 0)
	wantOneMutation(t, f, "POST", openvpnClientOverrideDelPath+"u-bob-home")
}

func TestOpenvpnClientOverrideEnableDisable(t *testing.T) {
	t.Parallel()
	var f = newOpenvpnClientOverrideFake(t, openvpnClientOverrideRows...)
	var r = f.run("/vpn/openvpn/client-override", "disable", "alice")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("disable must be silent, got %q", r.stdout)
	}
	var call = wantOneMutation(t, f, "POST", openvpnClientOverrideTogglePath+"u-alice/0")
	if call.Body == "" {
		t.Errorf("toggle needs a body")
	}

	f = newOpenvpnClientOverrideFake(t, openvpnClientOverrideRows...)
	wantExit(t, f.run("/vpn/openvpn/client-override", "enable", "u-bob-office"), 0)
	wantOneMutation(t, f, "POST", openvpnClientOverrideTogglePath+"u-bob-office/1")

	f = newOpenvpnClientOverrideFake(t, openvpnClientOverrideRows...)
	r = f.run("/vpn/openvpn/client-override", "enable", "alice")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "already enabled")
	wantNoMutations(t, f)

	// an override removed in the meantime
	f = newFakeOPN(t)
	f.search(openvpnClientOverrideSearchPath, openvpnClientOverrideRows...)
	f.on("POST", openvpnClientOverrideTogglePath+"u-alice/0", 200, `{"result":"failed"}`)
	wantFailure(t, f.run("/vpn/openvpn/client-override", "disable", "alice"), "not found", "u-alice")
}

func TestOpenvpnClientOverrideComplete(t *testing.T) {
	t.Parallel()
	var f = newOpenvpnClientOverrideFake(t, openvpnClientOverrideRows...)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/vpn/openvpn/client-override remove ali": {"alice", "alice2"},
		"/vpn/openvpn/client-override show b":     {"bob"},
		// the two servers named home are offered by uuid
		"/vpn/openvpn/client-override add servers=":        {"servers=office", "servers=s-home1", "servers=s-home2"},
		"/vpn/openvpn/client-override set alice servers=o": {"servers=office"},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}
