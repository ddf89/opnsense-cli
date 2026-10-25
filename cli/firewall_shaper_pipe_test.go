package cli

import (
	"strings"
	"testing"
)

const (
	firewallShaperPipeSearchPath = "/api/trafficshaper/settings/search_pipes"
	firewallShaperPipeAddPath    = "/api/trafficshaper/settings/add_pipe"
	firewallShaperPipeSetPath    = "/api/trafficshaper/settings/set_pipe/"
	firewallShaperPipeDelPath    = "/api/trafficshaper/settings/del_pipe/"
	firewallShaperPipeTogglePath = "/api/trafficshaper/settings/toggle_pipe/"
)

// firewallShaperPipeRow is a 26.7 shaped search_pipes row
func firewallShaperPipeRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "number": "10000", "enabled": "1", "bandwidth": "100", "bandwidthMetric": "Mbit", "%bandwidthMetric": "Mbit/s",
		"queue": "", "mask": "none", "%mask": "(none)", "buckets": "", "scheduler": "", "codel_enable": "0", "codel_target": "",
		"codel_interval": "", "codel_ecn_enable": "0", "pie_enable": "0", "fqcodel_quantum": "", "fqcodel_limit": "",
		"fqcodel_flows": "", "origin": "TrafficShaper", "delay": "", "description": "WAN down",
	}, overrides)
}

var firewallShaperPipeRows = []map[string]any{
	firewallShaperPipeRow(map[string]any{"uuid": "p-down", "scheduler": "fq_codel"}),
	firewallShaperPipeRow(map[string]any{"uuid": "p-up", "number": "10001", "bandwidth": "20", "enabled": "0", "description": "WAN up", "mask": "src-ip"}),
	firewallShaperPipeRow(map[string]any{"uuid": "p-guest", "number": "10002", "bandwidth": "512", "bandwidthMetric": "Kbit", "description": "WAN down guests"}),
}

// firewallShaperPipeBody is the full {"pipe":{...}} body add sends, with all defaults
func firewallShaperPipeBody(overrides map[string]any) map[string]any {
	return map[string]any{"pipe": withFields(map[string]any{
		"enabled": "1", "bandwidth": "10", "bandwidthMetric": "Mbit", "queue": "", "mask": "none", "buckets": "", "scheduler": "",
		"codel_enable": "0", "codel_target": "", "codel_interval": "", "codel_ecn_enable": "0", "pie_enable": "0",
		"fqcodel_quantum": "", "fqcodel_limit": "", "fqcodel_flows": "", "delay": "", "description": "lab",
	}, overrides)}
}

func newFirewallShaperPipeFake(t *testing.T) *fakeOPN {
	var f = newFakeOPN(t)
	f.search(firewallShaperPipeSearchPath, firewallShaperPipeRows...)
	f.on("POST", firewallShaperPipeAddPath, 200, answerAdded("p-new"))
	for _, row := range firewallShaperPipeRows {
		var uuid = row["uuid"].(string)
		f.on("POST", firewallShaperPipeSetPath+uuid, 200, answerSaved)
		f.on("POST", firewallShaperPipeDelPath+uuid, 200, answerDeleted)
		f.on("POST", firewallShaperPipeTogglePath+uuid+"/0", 200, `{"result":"Disabled","changed":true}`)
		f.on("POST", firewallShaperPipeTogglePath+uuid+"/1", 200, `{"result":"Enabled","changed":true}`)
	}
	return f
}

func TestFirewallShaperPipePrint(t *testing.T) {
	t.Parallel()
	var f = newFirewallShaperPipeFake(t)
	var r = f.run("/firewall/shaper/pipe", "print")
	wantExit(t, r, 0)
	var rows = dnsmasqTableRows(r.stdout)
	var want = [][]string{
		{"#", "DISABLED", "NUMBER", "BANDWIDTH", "MASK", "SCHEDULER", "DESCRIPTION"},
		{"0", "no", "10000", "100 Mbit/s", "none", "fq_codel", "WAN down"},
		{"1", "yes", "10001", "20 Mbit/s", "src-ip", "wfq", "WAN up"},
		{"2", "no", "10002", "512 Kbit/s", "none", "wfq", "WAN down guests"},
	}
	if len(rows) != len(want) {
		t.Fatalf("want %d lines:\n%s", len(want), r.stdout)
	}
	for i := range want {
		if strings.Join(rows[i], "|") != strings.Join(want[i], "|") {
			t.Errorf("line %d: got %q, want %q", i, rows[i], want[i])
		}
	}

	r = f.run("/firewall/shaper/pipe", "print", "json")
	wantExit(t, r, 0)
	if lines := strings.Split(strings.TrimSpace(r.stdout), "\n"); len(lines) != 3 || !strings.Contains(lines[0], `"%bandwidthMetric":"Mbit/s"`) {
		t.Errorf("want 3 raw rows:\n%s", r.stdout)
	}

	r = f.run("/firewall/shaper/pipe", "print", "detail", "search=up")
	wantExit(t, r, 0)
	wantContains(t, r.stdout, r.stdout, "uuid:", "p-up", "bandwidth:", "20 Mbit/s", "disabled:", "yes", "fq-codel-flows:")

	r = f.run("/firewall/shaper/pipe", "show", "wan down")
	wantExit(t, r, 0)
	var fields = dnsmasqParseFields(r.stdout)
	if fields["uuid"] != "p-down" || fields["scheduler"] != "fq_codel" || fields["number"] != "10000" {
		t.Errorf("show: %v", fields)
	}
	wantNoMutations(t, f)
}

func TestFirewallShaperPipeAdd(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		args         []string
		wantPath     string
		wantBody     map[string]any
		wantUuid     string
		wantReplaced bool
	}{
		{name: "bandwidth with unit", args: []string{"bandwidth=10Mbit", "description=lab"},
			wantPath: firewallShaperPipeAddPath, wantBody: firewallShaperPipeBody(nil), wantUuid: "p-new"},
		{name: "bandwidth without unit is Kbit", args: []string{"bandwidth=512", "description=lab"},
			wantPath: firewallShaperPipeAddPath, wantBody: firewallShaperPipeBody(map[string]any{"bandwidth": "512", "bandwidthMetric": "Kbit"}), wantUuid: "p-new"},
		{name: "metric argument", args: []string{"bandwidth=2", "bandwidth-metric=gbit", "description=lab"},
			wantPath: firewallShaperPipeAddPath, wantBody: firewallShaperPipeBody(map[string]any{"bandwidth": "2", "bandwidthMetric": "Gbit"}), wantUuid: "p-new"},
		{name: "all fields", args: []string{"bandwidth=100 Mbit/s", "queue-size=50", "mask=SRC-IP", "buckets=256", "scheduler=fq_codel",
			"codel", "codel-target=5", "codel-interval=100", "codel-ecn", "fq-codel-quantum=1514", "fq-codel-limit=10240",
			"fq-codel-flows=1024", "delay=20", "description=lab", "disabled"},
			wantPath: firewallShaperPipeAddPath, wantBody: firewallShaperPipeBody(map[string]any{
				"bandwidth": "100", "queue": "50", "mask": "src-ip", "buckets": "256", "scheduler": "fq_codel", "codel_enable": "1",
				"codel_target": "5", "codel_interval": "100", "codel_ecn_enable": "1", "fqcodel_quantum": "1514",
				"fqcodel_limit": "10240", "fqcodel_flows": "1024", "delay": "20", "enabled": "0"}), wantUuid: "p-new"},
		{name: "wfq is the empty scheduler", args: []string{"bandwidth=10M", "scheduler=wfq", "pie", "description=lab"},
			wantPath: firewallShaperPipeAddPath, wantBody: firewallShaperPipeBody(map[string]any{"pie_enable": "1"}), wantUuid: "p-new"},
		{name: "replace by description", args: []string{"bandwidth=10Mbit", "description=wan UP", "replace"},
			wantPath: firewallShaperPipeSetPath + "p-up", wantBody: firewallShaperPipeBody(map[string]any{"description": "wan UP"}),
			wantUuid: "p-up", wantReplaced: true},
		{name: "replace of a new description adds", args: []string{"bandwidth=10Mbit", "description=lab", "replace"},
			wantPath: firewallShaperPipeAddPath, wantBody: firewallShaperPipeBody(nil), wantUuid: "p-new"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFirewallShaperPipeFake(t)
			var r = f.run(append([]string{"/firewall/shaper/pipe", "add"}, tc.args...)...)
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

func TestFirewallShaperPipeAddErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		args      []string
		answer    string
		wantErr   []string
		wantCalls bool
	}{
		{name: "missing bandwidth", args: []string{"description=lab"}, wantErr: []string{"bandwidth", "required"}},
		{name: "missing description", args: []string{"bandwidth=1M"}, wantErr: []string{"description", "required"}},
		{name: "invalid bandwidth", args: []string{"bandwidth=fast", "description=lab"}, wantErr: []string{"bandwidth", "fast"}},
		{name: "unknown unit", args: []string{"bandwidth=1Tbit", "description=lab"}, wantErr: []string{"Tbit"}},
		{name: "too much bandwidth", args: []string{"bandwidth=5Gbit", "description=lab"}, wantErr: []string{"exceeds", "4 Gbit/s"}},
		{name: "too much Kbit", args: []string{"bandwidth=4294968", "description=lab"}, wantErr: []string{"exceeds", "4294967 Kbit/s"}},
		{name: "contradicting metric", args: []string{"bandwidth=1Mbit", "bandwidth-metric=Gbit", "description=lab"}, wantErr: []string{"contradict"}},
		{name: "invalid metric", args: []string{"bandwidth=1", "bandwidth-metric=Tbit", "description=lab"}, wantErr: []string{"bandwidth-metric", "Tbit"}},
		{name: "queue size too small", args: []string{"bandwidth=1M", "queue-size=1", "description=lab"}, wantErr: []string{"queue-size", "2 to 100"}},
		{name: "invalid mask", args: []string{"bandwidth=1M", "mask=src", "description=lab"}, wantErr: []string{"mask", "src"}},
		{name: "invalid scheduler", args: []string{"bandwidth=1M", "scheduler=cake", "description=lab"}, wantErr: []string{"scheduler", "cake"}},
		{name: "codel and pie", args: []string{"bandwidth=1M", "codel", "pie", "description=lab"}, wantErr: []string{"codel and pie"}},
		{name: "delay too long", args: []string{"bandwidth=1M", "delay=3001", "description=lab"}, wantErr: []string{"delay", "3000"}},
		{name: "existing description", args: []string{"bandwidth=1M", "description=WAN Down"},
			wantErr: []string{"WAN Down", "exists", "p-down", "replace"}, wantCalls: true},
		{name: "OPNsense validation", args: []string{"bandwidth=1M", "description=lab"},
			answer:  answerValidation("pipe.bandwidth", "Bandwidth out of range."),
			wantErr: []string{"pipe.bandwidth", "Bandwidth out of range."}, wantCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(firewallShaperPipeSearchPath, firewallShaperPipeRows...)
			if tc.answer != "" {
				f.on("POST", firewallShaperPipeAddPath, 200, tc.answer)
			}
			wantFailure(t, f.run(append([]string{"/firewall/shaper/pipe", "add"}, tc.args...)...), tc.wantErr...)
			if !tc.wantCalls {
				wantNoCalls(t, f)
			}
			if tc.answer == "" {
				wantNoMutations(t, f)
			}
		})
	}
}

func TestFirewallShaperPipeSet(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		args     []string
		wantPath string
		wantBody map[string]any
	}{
		{name: "bandwidth with unit sets the metric", args: []string{"wan up", "bandwidth=1Gbit"},
			wantPath: firewallShaperPipeSetPath + "p-up", wantBody: map[string]any{"pipe": map[string]any{"bandwidth": "1", "bandwidthMetric": "Gbit"}}},
		{name: "bandwidth without unit keeps the metric", args: []string{"0", "bandwidth=50"},
			wantPath: firewallShaperPipeSetPath + "p-down", wantBody: map[string]any{"pipe": map[string]any{"bandwidth": "50"}}},
		{name: "metric only", args: []string{"p-guest", "bandwidth-metric=mbit"},
			wantPath: firewallShaperPipeSetPath + "p-guest", wantBody: map[string]any{"pipe": map[string]any{"bandwidthMetric": "Mbit"}}},
		{name: "clear and flags", args: []string{"WAN down", "scheduler=", "mask=", "delay=", "disabled=no", "codel=no"},
			wantPath: firewallShaperPipeSetPath + "p-down",
			wantBody: map[string]any{"pipe": map[string]any{"scheduler": "", "mask": "none", "delay": "", "enabled": "1", "codel_enable": "0"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFirewallShaperPipeFake(t)
			var r = f.run(append([]string{"/firewall/shaper/pipe", "set"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("set must be silent, got %q", r.stdout)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", tc.wantPath), tc.wantBody)
		})
	}

	for _, tc := range []struct {
		args    []string
		wantErr []string
	}{
		{[]string{"wan up"}, []string{"nothing to change"}},
		{[]string{"lab", "delay=5"}, []string{"not found"}},
		{[]string{"wan up", "description=WAN down"}, []string{"another pipe", "p-down"}},
		{[]string{"wan up", "bandwidth=5000Mbit"}, []string{"exceeds"}},
	} {
		var f = newFirewallShaperPipeFake(t)
		wantFailure(t, f.run(append([]string{"/firewall/shaper/pipe", "set"}, tc.args...)...), tc.wantErr...)
		wantNoMutations(t, f)
	}
}

func TestFirewallShaperPipeRemove(t *testing.T) {
	t.Parallel()
	var f = newFirewallShaperPipeFake(t)
	var r = f.run("/firewall/shaper/pipe", "remove", "WAN up")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("remove must be silent, got %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", firewallShaperPipeDelPath+"p-up")

	// in use by a queue: OPNsense refuses with HTTP 500
	f = newFakeOPN(t)
	f.search(firewallShaperPipeSearchPath, firewallShaperPipeRows...)
	f.on("POST", firewallShaperPipeDelPath+"p-down", 500,
		`{"errorMessage":"TrafficShaper - interactive {TrafficShaper.queues.queue.q-1}\n","errorTitle":"Item pipes.pipe {WAN down} in use by:"}`)
	wantFailure(t, f.run("/firewall/shaper/pipe", "remove", "wan down"), "in use by", "interactive", "q-1")
}

func TestFirewallShaperPipeEnableDisable(t *testing.T) {
	t.Parallel()
	var f = newFirewallShaperPipeFake(t)
	wantExit(t, f.run("/firewall/shaper/pipe", "enable", "WAN up"), 0)
	if call := wantOneMutation(t, f, "POST", firewallShaperPipeTogglePath+"p-up/1"); call.Body == "" {
		t.Errorf("toggle needs a body")
	}

	f = newFirewallShaperPipeFake(t)
	wantExit(t, f.run("/firewall/shaper/pipe", "disable", "0"), 0)
	wantOneMutation(t, f, "POST", firewallShaperPipeTogglePath+"p-down/0")

	f = newFirewallShaperPipeFake(t)
	var r = f.run("/firewall/shaper/pipe", "disable", "wan up")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "already disabled")
	wantNoMutations(t, f)
}
