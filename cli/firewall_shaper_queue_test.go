package cli

import (
	"strings"
	"testing"
)

const (
	firewallShaperQueueSearchPath = "/api/trafficshaper/settings/search_queues"
	firewallShaperQueueAddPath    = "/api/trafficshaper/settings/add_queue"
	firewallShaperQueueSetPath    = "/api/trafficshaper/settings/set_queue/"
	firewallShaperQueueDelPath    = "/api/trafficshaper/settings/del_queue/"
	firewallShaperQueueTogglePath = "/api/trafficshaper/settings/toggle_queue/"
)

func firewallShaperQueueRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "number": "10000", "enabled": "1", "pipe": "p-down", "%pipe": "WAN down", "weight": "100", "mask": "none",
		"%mask": "(none)", "buckets": "", "codel_enable": "0", "codel_target": "", "codel_interval": "", "codel_ecn_enable": "0",
		"pie_enable": "0", "description": "interactive", "origin": "TrafficShaper",
	}, overrides)
}

var firewallShaperQueueRows = []map[string]any{
	firewallShaperQueueRow(map[string]any{"uuid": "q-interactive", "weight": "80"}),
	firewallShaperQueueRow(map[string]any{"uuid": "q-bulk", "number": "10001", "weight": "20", "description": "bulk", "enabled": "0"}),
}

func firewallShaperQueueBody(overrides map[string]any) map[string]any {
	return map[string]any{"queue": withFields(map[string]any{
		"enabled": "1", "pipe": "p-down", "weight": "100", "mask": "none", "buckets": "", "codel_enable": "0", "codel_target": "",
		"codel_interval": "", "codel_ecn_enable": "0", "pie_enable": "0", "description": "voip",
	}, overrides)}
}

func newFirewallShaperQueueFake(t *testing.T) *fakeOPN {
	var f = newFakeOPN(t)
	// two pipes share the description "twin"
	f.search(firewallShaperPipeSearchPath, append(firewallShaperPipeRows,
		firewallShaperPipeRow(map[string]any{"uuid": "p-twin1", "description": "twin"}),
		firewallShaperPipeRow(map[string]any{"uuid": "p-twin2", "description": "Twin"}))...)
	f.search(firewallShaperQueueSearchPath, firewallShaperQueueRows...)
	f.on("POST", firewallShaperQueueAddPath, 200, answerAdded("q-new"))
	for _, row := range firewallShaperQueueRows {
		var uuid = row["uuid"].(string)
		f.on("POST", firewallShaperQueueSetPath+uuid, 200, answerSaved)
		f.on("POST", firewallShaperQueueDelPath+uuid, 200, answerDeleted)
		f.on("POST", firewallShaperQueueTogglePath+uuid+"/1", 200, `{"result":"Enabled","changed":true}`)
	}
	return f
}

func TestFirewallShaperQueuePrint(t *testing.T) {
	t.Parallel()
	var f = newFirewallShaperQueueFake(t)
	var r = f.run("/firewall/shaper/queue", "print")
	wantExit(t, r, 0)
	var rows = dnsmasqTableRows(r.stdout)
	var want = [][]string{
		{"#", "DISABLED", "NUMBER", "PIPE", "WEIGHT", "MASK", "DESCRIPTION"},
		{"0", "no", "10000", "WAN down", "80", "none", "interactive"},
		{"1", "yes", "10001", "WAN down", "20", "none", "bulk"},
	}
	if len(rows) != len(want) {
		t.Fatalf("want %d lines:\n%s", len(want), r.stdout)
	}
	for i := range want {
		if strings.Join(rows[i], "|") != strings.Join(want[i], "|") {
			t.Errorf("line %d: got %q, want %q", i, rows[i], want[i])
		}
	}
	r = f.run("/firewall/shaper/queue", "show", "BULK")
	wantExit(t, r, 0)
	if fields := dnsmasqParseFields(r.stdout); fields["uuid"] != "q-bulk" || fields["pipe"] != "WAN down" || fields["weight"] != "20" {
		t.Errorf("show: %v", fields)
	}
	r = f.run("/firewall/shaper/queue", "print", "json")
	wantExit(t, r, 0)
	if lines := strings.Split(strings.TrimSpace(r.stdout), "\n"); len(lines) != 2 || !strings.Contains(lines[1], `"%pipe":"WAN down"`) {
		t.Errorf("want raw rows:\n%s", r.stdout)
	}
	wantNoMutations(t, f)
}

func TestFirewallShaperQueueAdd(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		args     []string
		wantPath string
		wantBody map[string]any
		wantUuid string
	}{
		{name: "pipe by description", args: []string{"pipe=wan DOWN", "description=voip"},
			wantPath: firewallShaperQueueAddPath, wantBody: firewallShaperQueueBody(nil), wantUuid: "q-new"},
		{name: "pipe by uuid, all fields", args: []string{"pipe=p-up", "weight=90", "mask=dst-ip", "buckets=64", "pie",
			"description=voip", "disabled"},
			wantPath: firewallShaperQueueAddPath, wantBody: firewallShaperQueueBody(map[string]any{"pipe": "p-up", "weight": "90",
				"mask": "dst-ip", "buckets": "64", "pie_enable": "1", "enabled": "0"}), wantUuid: "q-new"},
		{name: "replace", args: []string{"pipe=WAN up", "description=Bulk", "codel", "codel-ecn", "replace"},
			wantPath: firewallShaperQueueSetPath + "q-bulk", wantBody: firewallShaperQueueBody(map[string]any{"pipe": "p-up",
				"description": "Bulk", "codel_enable": "1", "codel_ecn_enable": "1"}), wantUuid: "q-bulk"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFirewallShaperQueueFake(t)
			var r = f.run(append([]string{"/firewall/shaper/queue", "add"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != tc.wantUuid+"\n" {
				t.Errorf("stdout %q, want only the uuid %q", r.stdout, tc.wantUuid)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", tc.wantPath), tc.wantBody)
		})
	}

	for _, tc := range []struct {
		name    string
		args    []string
		wantErr []string
	}{
		{"missing pipe", []string{"description=voip"}, []string{"pipe", "required"}},
		{"unknown pipe", []string{"pipe=LAN", "description=voip"}, []string{"unknown pipe", "LAN", "WAN down (p-down)"}},
		{"ambiguous pipe", []string{"pipe=twin", "description=voip"}, []string{"p-twin1", "p-twin2", "uuid"}},
		{"weight out of range", []string{"pipe=WAN up", "weight=0", "description=voip"}, []string{"weight", "1 to 100"}},
		{"codel and pie", []string{"pipe=WAN up", "codel", "pie", "description=voip"}, []string{"codel and pie"}},
		{"existing description", []string{"pipe=WAN up", "description=INTERACTIVE"}, []string{"exists", "q-interactive"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFirewallShaperQueueFake(t)
			wantFailure(t, f.run(append([]string{"/firewall/shaper/queue", "add"}, tc.args...)...), tc.wantErr...)
			wantNoMutations(t, f)
		})
	}
}

func TestFirewallShaperQueueSetRemoveEnable(t *testing.T) {
	t.Parallel()
	var f = newFirewallShaperQueueFake(t)
	wantExit(t, f.run("/firewall/shaper/queue", "set", "bulk", "pipe=WAN up", "weight=", "mask="), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", firewallShaperQueueSetPath+"q-bulk"),
		map[string]any{"queue": map[string]any{"pipe": "p-up", "weight": "100", "mask": "none"}})

	f = newFirewallShaperQueueFake(t)
	wantFailure(t, f.run("/firewall/shaper/queue", "set", "bulk"), "nothing to change")
	wantFailure(t, f.run("/firewall/shaper/queue", "set", "bulk", "description=interactive"), "another queue", "q-interactive")
	wantFailure(t, f.run("/firewall/shaper/queue", "set", "bulk", "pipe=nope"), "unknown pipe")
	wantNoMutations(t, f)

	f = newFirewallShaperQueueFake(t)
	wantExit(t, f.run("/firewall/shaper/queue", "remove", "interactive"), 0)
	wantOneMutation(t, f, "POST", firewallShaperQueueDelPath+"q-interactive")

	f = newFirewallShaperQueueFake(t)
	wantExit(t, f.run("/firewall/shaper/queue", "enable", "bulk"), 0)
	wantOneMutation(t, f, "POST", firewallShaperQueueTogglePath+"q-bulk/1")
}
