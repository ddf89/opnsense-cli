package diagnostics

import (
	"errors"
	coreapi "opnsense-cli/opnsense/api"
	"reflect"
	"strings"
	"testing"
)

func TestFirewallStatisticsGet(t *testing.T) {
	var api, calls = firewallStateTestApi(t, map[string]string{
		"GET /api/diagnostics/firewall/pf_statistics/info": `{"info":{"state-table":{"current-entries":{"total":40},"searches":{"total":65680,"rate":23.9}},` +
			`"counters":{"match":{"total":2020,"rate":0.7}}}}`,
		"GET /api/diagnostics/firewall/pf_statistics/memory":   `{"memory":{"states":200500,"src-nodes":200500,"frags":5000}}`,
		"GET /api/diagnostics/firewall/pf_statistics/timeouts": `{"timeouts":{"tcp.first":"120s","adaptive.start":"0 states"}}`,
		"GET /api/diagnostics/firewall/pf_statistics/interfaces": `{"interfaces":{"all":{"cleared":"2026-10-25T14:05:45","references":20,"in4_pass_packets":0},` +
			`"vtnet0":{"cleared":"2026-10-25T14:05:45","references":24,"in4_pass_packets":35707,"in4_pass_bytes":5429970,"in6_pass_packets":14,"in6_pass_bytes":784,"out6_block_packets":4,"out6_block_bytes":0}}}`,
		"GET /api/diagnostics/firewall/pf_statistics/rules": `{"rules":{"filter rules":{"@0 scrub in all fragment reassemble":{"evaluations":130127,"packets":55846,"bytes":4242276,"states":0,"inserted":"uid 0 pid 0 ","state_creations":0,"time":"n\/a"},` +
			`"@20 pass out log quick inet6 proto ipv6-icmp":{"evaluations":2,"packets":2,"bytes":144,"states":1,"state_creations":2,"time":"sun oct 25","14":"","35":"43 2026"}},` +
			`"nat rules":{"@0 no nat proto carp all":{"evaluations":743,"packets":0,"bytes":0,"states":0}}}}`,
	})
	var stats, err = api.FirewallStatisticsGet()
	if err != nil {
		t.Fatal(err)
	}
	if len(calls()) != 5 {
		t.Errorf("want one request per section, got %+v", calls())
	}
	var wantInfo = []FirewallStatisticsCounter{
		{Table: "state-table", Name: "current-entries", Total: 40},
		{Table: "state-table", Name: "searches", Total: 65680, Rate: 23.9, HasRate: true},
		{Table: "counters", Name: "match", Total: 2020, Rate: 0.7, HasRate: true},
	}
	if !reflect.DeepEqual(stats.Info, wantInfo) {
		t.Errorf("info in API order:\n got  %+v\n want %+v", stats.Info, wantInfo)
	}
	if !reflect.DeepEqual(stats.Memory, []FirewallStatisticsValue{{"states", "200500"}, {"src-nodes", "200500"}, {"frags", "5000"}}) {
		t.Errorf("memory %+v", stats.Memory)
	}
	if !reflect.DeepEqual(stats.Timeouts, []FirewallStatisticsValue{{"tcp.first", "120s"}, {"adaptive.start", "0 states"}}) {
		t.Errorf("timeouts %+v", stats.Timeouts)
	}
	if len(stats.Interfaces) != 2 || stats.Interfaces[1].Name != "vtnet0" || stats.Interfaces[1].References != 24 ||
		stats.Interfaces[1].Cleared != "2026-10-25T14:05:45" || stats.Interfaces[1].Packets("in", "pass") != 35721 ||
		stats.Interfaces[1].Bytes("in", "pass") != 5430754 || stats.Interfaces[1].Packets("out", "block") != 4 {
		t.Errorf("interfaces %+v", stats.Interfaces)
	}
	var wantRules = []FirewallStatisticsRule{
		{Ruleset: "filter rules", Rule: "@0 scrub in all fragment reassemble", Evaluations: 130127, Packets: 55846, Bytes: 4242276},
		{Ruleset: "filter rules", Rule: "@20 pass out log quick inet6 proto ipv6-icmp", Evaluations: 2, Packets: 2, Bytes: 144, States: 1, StateCreations: 2},
		{Ruleset: "nat rules", Rule: "@0 no nat proto carp all", Evaluations: 743},
	}
	if !reflect.DeepEqual(stats.Rules, wantRules) {
		t.Errorf("rules:\n got  %+v\n want %+v", stats.Rules, wantRules)
	}
	if !strings.HasPrefix(string(stats.Raw["memory"]), `{"memory":{"states":200500`) {
		t.Errorf("raw memory %s", stats.Raw["memory"])
	}

	// one section
	stats, err = api.FirewallStatisticsGet("timeouts")
	if err != nil || stats.Info != nil || len(stats.Timeouts) != 2 || len(stats.Raw) != 1 {
		t.Errorf("only timeouts: %+v, %v", stats, err)
	}
}

func TestFirewallStatisticsGetErrors(t *testing.T) {
	var api, calls = firewallStateTestApi(t, map[string]string{"GET /api/diagnostics/firewall/pf_statistics/info": `[]`})
	if _, err := api.FirewallStatisticsGet("bogus"); err == nil || len(calls()) != 0 {
		t.Errorf("unknown section: want an error without request, got %v", err)
	}
	// OPNsense answers [] for sections it does not know (and without a section)
	if _, err := api.FirewallStatisticsGet("info"); err == nil {
		t.Error("want an error for []")
	}
	var broken, _ = firewallStateTestApi(t, map[string]string{"GET /api/diagnostics/firewall/pf_statistics/info": `{"info":{"state-table":{"searches":{"total":"x"}}}}`})
	if _, err := broken.FirewallStatisticsGet("info"); err == nil {
		t.Error("want a decoding error")
	}
	var notFound, _ = firewallStateTestApi(t, nil)
	var httpErr *coreapi.HttpError
	if _, err := notFound.FirewallStatisticsGet("memory"); !errors.As(err, &httpErr) {
		t.Errorf("want the HTTP error, got %v", err)
	}
}
