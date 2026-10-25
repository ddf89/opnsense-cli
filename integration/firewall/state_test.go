//go:build integration

package integrationfirewall

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"opnsense-cli/opnsense/api/diagnostics"
)

// The state table, the sessions and the pf statistics are only read live: del_state, kill_states, flush_states
// and flush_sources are never called against the shared instance (they cut the connections of everybody,
// including this test). They are covered by the unit tests in opnsense/api/diagnostics and cli

var stateIdPattern = regexp.MustCompile(`^[0-9a-f]+/[0-9a-f]+$`)

func stateDiagnosticsApi(t *testing.T) *diagnostics.DiagnosticsApi {
	t.Helper()
	return &diagnostics.DiagnosticsApi{OPNsense: coreApi(t)}
}

func TestStateList(t *testing.T) {
	var diag = stateDiagnosticsApi(t)
	var states, err = diag.FirewallStateList(diagnostics.FirewallStateQuery{})
	if err != nil {
		t.Fatalf("FirewallStateList: %v", err)
	}
	// at least the connection of this test
	if len(states) == 0 {
		t.Fatal("no states")
	}
	var ids = map[string]bool{}
	var labelled diagnostics.FirewallState
	for _, state := range states {
		if !stateIdPattern.MatchString(state.Id) || ids[state.Id] {
			t.Errorf("invalid or duplicate id in %+v", state)
		}
		ids[state.Id] = true
		if state.Proto == "" || (state.IpProto != "ipv4" && state.IpProto != "ipv6") || state.Iface == "" || state.SrcAddr == "" ||
			state.DstAddr == "" || state.State == "" || len(state.Pkts) != 2 || len(state.Bytes) != 2 || len(state.Raw) == 0 {
			t.Errorf("incomplete state %+v", state)
		}
		if labelled.Label == "" && state.Label != "" {
			labelled = state
		}
	}

	// a network clause matches the addresses: 0.0.0.0/0 selects the IPv4 states
	var ipv4, ipv4Err = diag.FirewallStateList(diagnostics.FirewallStateQuery{Search: "0.0.0.0/0"})
	if ipv4Err != nil {
		t.Fatal(ipv4Err)
	}
	if len(ipv4) == 0 {
		t.Error("search 0.0.0.0/0 found no state")
	}
	for _, state := range ipv4 {
		if state.IpProto != "ipv4" {
			t.Errorf("search 0.0.0.0/0 returned %+v", state)
		}
	}

	if labelled.Label == "" {
		t.Skip("no state with a rule id")
	}
	var byRule, ruleErr = diag.FirewallStateList(diagnostics.FirewallStateQuery{RuleId: labelled.Label})
	if ruleErr != nil {
		t.Fatal(ruleErr)
	}
	if len(byRule) == 0 {
		t.Errorf("rule id %s found no state", labelled.Label)
	}
	for _, state := range byRule {
		if !strings.Contains(state.Label, labelled.Label) {
			t.Errorf("rule id %s returned %+v", labelled.Label, state)
		}
	}
}

func TestStateSearchIsCaseSensitive(t *testing.T) {
	var diag = stateDiagnosticsApi(t)
	var lower, err = diag.FirewallStateList(diagnostics.FirewallStateQuery{Search: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	var upper, upperErr = diag.FirewallStateList(diagnostics.FirewallStateQuery{Search: "TCP"})
	if upperErr != nil {
		t.Fatal(upperErr)
	}
	// the connection of this test is TCP (proto "tcp"); TCP only matches states with the upper case text somewhere
	if len(lower) == 0 || len(upper) >= len(lower) {
		t.Errorf("search tcp found %d, TCP %d states: want fewer with TCP", len(lower), len(upper))
	}
	for _, state := range upper {
		if !strings.Contains(string(state.Raw), "TCP") {
			t.Errorf("search TCP returned %s", state.Raw)
		}
	}
}

func TestStateRuleIds(t *testing.T) {
	var ids, err = stateDiagnosticsApi(t).FirewallRuleIds()
	if err != nil {
		t.Fatalf("FirewallRuleIds: %v", err)
	}
	if len(ids) == 0 {
		t.Fatal("no rule ids")
	}
	for _, id := range ids {
		if len(id.Id) < 32 || id.Descr == "" {
			t.Errorf("unexpected rule id %+v", id)
		}
	}
}

func TestStateCount(t *testing.T) {
	var diag = stateDiagnosticsApi(t)
	var count, err = diag.FirewallStateCountGet()
	if err != nil {
		t.Fatalf("FirewallStateCountGet: %v", err)
	}
	if count.Current <= 0 || count.Limit <= count.Current {
		t.Errorf("unexpected count %+v", count)
	}
	// the limit is the states hard limit of pfctl -sm
	var statistics, statisticsErr = diag.FirewallStatisticsGet("memory")
	if statisticsErr != nil {
		t.Fatal(statisticsErr)
	}
	for _, value := range statistics.Memory {
		if value.Name == "states" && value.Value != strconv.FormatInt(count.Limit, 10) {
			t.Errorf("state limit %d differs from the memory limit %s", count.Limit, value.Value)
		}
	}
}

func TestSessionList(t *testing.T) {
	var diag = stateDiagnosticsApi(t)
	var sessions, err = diag.FirewallSessionList(diagnostics.FirewallSessionQuery{})
	if err != nil {
		t.Fatalf("FirewallSessionList: %v", err)
	}
	if len(sessions) == 0 {
		t.Fatal("no sessions")
	}
	for _, session := range sessions {
		if session.Proto == "" || (session.Dir != "in" && session.Dir != "out") || session.SrcAddr == "" || session.DstAddr == "" ||
			session.Rule == "" || len(session.Raw) == 0 {
			t.Errorf("incomplete session %+v", session)
		}
	}

	// unlike the states, the session search is case-insensitive
	var upper, upperErr = diag.FirewallSessionList(diagnostics.FirewallSessionQuery{Search: "TCP"})
	if upperErr != nil {
		t.Fatal(upperErr)
	}
	if len(upper) == 0 {
		t.Error("search TCP found no session")
	}
	var ipv4, ipv4Err = diag.FirewallSessionList(diagnostics.FirewallSessionQuery{Search: "0.0.0.0/0"})
	if ipv4Err != nil {
		t.Fatal(ipv4Err)
	}
	for _, session := range ipv4 {
		if strings.Contains(session.SrcAddr, ":") && strings.Contains(session.DstAddr, ":") {
			t.Errorf("search 0.0.0.0/0 returned %+v", session)
		}
	}
}

func TestStatisticsGet(t *testing.T) {
	var statistics, err = stateDiagnosticsApi(t).FirewallStatisticsGet()
	if err != nil {
		t.Fatalf("FirewallStatisticsGet: %v", err)
	}
	var currentEntries = false
	for _, counter := range statistics.Info {
		currentEntries = currentEntries || counter.Table == "state-table" && counter.Name == "current-entries" && counter.Total > 0 && !counter.HasRate
	}
	if !currentEntries {
		t.Errorf("no state-table current-entries in %+v", statistics.Info)
	}
	var names = func(values []diagnostics.FirewallStatisticsValue) string {
		var result []string
		for _, value := range values {
			result = append(result, value.Name)
		}
		return strings.Join(result, ",")
	}
	if !strings.Contains(names(statistics.Memory), "states") || !strings.Contains(names(statistics.Timeouts), "tcp.established") {
		t.Errorf("memory %+v, timeouts %+v", statistics.Memory, statistics.Timeouts)
	}
	var all = false
	for _, i := range statistics.Interfaces {
		all = all || i.Name == "all"
	}
	if !all {
		t.Errorf("no interface all in %+v", statistics.Interfaces)
	}
	var filter, nat = 0, 0
	for _, rule := range statistics.Rules {
		if !strings.HasPrefix(rule.Rule, "@") {
			t.Errorf("rule without number: %+v", rule)
		}
		switch rule.Ruleset {
		case "filter rules":
			filter++
		case "nat rules":
			nat++
		}
	}
	if filter == 0 {
		t.Errorf("no filter rules (%d NAT rules)", nat)
	}
	if len(statistics.Raw) != 5 {
		t.Errorf("want the raw answers of 5 sections, got %d", len(statistics.Raw))
	}
}

// pf_statistics without a section (or an unknown one) answers [] instead of every section
func TestStatisticsWithoutSection(t *testing.T) {
	var core = coreApi(t)
	for _, method := range []string{"pf_statistics", "pf_statistics/bogus"} {
		var raw json.RawMessage
		if err := core.DoJSON("GET", core.EndpointForPluginControllerMethod("diagnostics", "firewall", method), nil, &raw); err != nil {
			t.Fatal(err)
		}
		if string(raw) != "[]" {
			t.Errorf("%s: want [], got %.200s", method, raw)
		}
	}
}
