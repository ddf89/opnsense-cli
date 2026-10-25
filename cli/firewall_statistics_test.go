package cli

import (
	"strings"
	"testing"
)

const (
	firewallStatisticsPath       = "/api/diagnostics/firewall/pf_statistics/"
	firewallStatisticsStatesPath = "/api/diagnostics/firewall/pf_states"
)

// firewallStatisticsAnswers are trimmed pf_statistics answers of OPNsense 26.7
var firewallStatisticsAnswers = map[string]string{
	"info": `{"info":{"state-table":{"current-entries":{"total":40},"searches":{"total":65680,"rate":23.9}},` +
		`"counters":{"match":{"total":2020,"rate":0.7}}}}`,
	"memory":   `{"memory":{"states":200500,"src-nodes":200500,"frags":5000}}`,
	"timeouts": `{"timeouts":{"tcp.first":"120s","adaptive.start":"0 states"}}`,
	"interfaces": `{"interfaces":{"all":{"cleared":"2026-10-25T14:05:45","references":20,"in4_pass_packets":0},` +
		`"vtnet0":{"cleared":"2026-10-25T14:05:45","references":24,"in4_pass_packets":35707,"in4_pass_bytes":5429970,"in6_pass_packets":14,"in6_pass_bytes":784,"out6_block_packets":4,"out6_block_bytes":0}}}`,
	"rules": `{"rules":{"filter rules":{"@0 scrub in all fragment reassemble":{"evaluations":130127,"packets":55846,"bytes":4242276,"states":0,"time":"n\/a"}},` +
		`"nat rules":{"@0 no nat proto carp all":{"evaluations":743,"packets":0,"bytes":0,"states":0}}}}`,
}

func firewallStatisticsFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	for section, answer := range firewallStatisticsAnswers {
		f.on("GET", firewallStatisticsPath+section, 200, answer)
	}
	f.on("GET", firewallStatisticsStatesPath, 200, `{"current":"33","limit":"200500"}`)
	return f
}

func TestFirewallStatisticsPrint(t *testing.T) {
	t.Parallel()
	var f = firewallStatisticsFake(t)
	var r = f.run("/firewall/statistics", "print")
	wantExit(t, r, 0)
	var headings []string
	for _, line := range strings.Split(r.stdout, "\n") {
		if strings.HasSuffix(line, ":") {
			headings = append(headings, line)
		}
	}
	if strings.Join(headings, " ") != "info: memory: timeouts: interfaces: rules:" {
		t.Errorf("want every section under its name in GUI order, got %q:\n%s", headings, r.stdout)
	}
	wantContains(t, "stdout", r.stdout,
		"TABLE        COUNTER          TOTAL  RATE", "state-table  current-entries  40     -", "state-table  searches         65680  23.9/s",
		"LIMIT", "src-nodes  200500", "TIMEOUT", "adaptive.start  0 states",
		"INTERFACE", "vtnet0     24          35721 (5.4 MB)  0 (0 B)   0 (0 B)   4 (0 B)",
		"RULESET", "filter   130127       55846    4.2 MB  0       @0 scrub in all fragment reassemble", "nat      743")
	if len(f.calls()) != 5 {
		t.Errorf("want one request per section, got %v", f.calls())
	}
	wantNoMutations(t, f)
}

func TestFirewallStatisticsPrintSections(t *testing.T) {
	t.Parallel()
	var f = firewallStatisticsFake(t)
	var r = f.run("/firewall/statistics", "print", "section=memory")
	wantExit(t, r, 0)
	systemLoggingWantTable(t, r.stdout, []string{"LIMIT", "VALUE"}, 0, "states", "src-nodes", "frags")
	if len(f.calls()) != 1 || f.calls()[0].Path != firewallStatisticsPath+"memory" {
		t.Errorf("want only the memory section, got %v", f.calls())
	}

	r = f.run("/firewall/statistics", "print", "section=Timeouts,info", "json")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 2 || lines[0] != firewallStatisticsAnswers["timeouts"] || lines[1] != firewallStatisticsAnswers["info"] {
		t.Errorf("want the raw sections in the given order:\n%s", r.stdout)
	}
	wantFailure(t, f.run("/firewall/statistics", "print", "section=bogus"), "section", "info, memory")

	var broken = newFakeOPN(t)
	broken.on("GET", firewallStatisticsPath+"info", 200, `[]`)
	wantFailure(t, broken.run("/firewall/statistics", "print", "section=info"), "unexpected answer")
}

func TestFirewallStatisticsStates(t *testing.T) {
	t.Parallel()
	var f = firewallStatisticsFake(t)
	var r = f.run("/firewall/statistics", "states")
	wantExit(t, r, 0)
	var fields = systemLoggingFields(r.stdout)
	if fields["current"] != "33" || fields["limit"] != "200500" || fields["used"] != "0.0%" {
		t.Errorf("unexpected fields %v:\n%s", fields, r.stdout)
	}
	r = f.run("/firewall/statistics", "states", "json")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != `{"current":33,"limit":200500}` {
		t.Errorf("json: %q", r.stdout)
	}

	var failing = newFakeOPN(t)
	failing.on("GET", firewallStatisticsStatesPath, 200, `{"result":"failed"}`)
	wantFailure(t, failing.run("/firewall/statistics", "states"), "unexpected answer")
}
