package cli

import (
	"strings"
	"testing"
	"time"
)

const (
	firewallStateQueryPath   = "/api/diagnostics/firewall/query_states"
	firewallStateDelPath     = "/api/diagnostics/firewall/del_state/"
	firewallStateKillPath    = "/api/diagnostics/firewall/kill_states"
	firewallStateFlushPath   = "/api/diagnostics/firewall/flush_states"
	firewallStateSourcesPath = "/api/diagnostics/firewall/flush_sources"
	firewallStateRuleIdsPath = "/api/diagnostics/firewall/list_rule_ids"
	firewallStateNamesPath   = "/api/diagnostics/interface/getInterfaceNames"

	firewallStateIdLan = "6f14de6a00000000/0449ade0"
	firewallStateIdNtp = "7714de6a00000000/0449ade0"
	firewallStateIdV6  = "8814de6a00000000/0449ade0"
)

// firewallStateRows are trimmed query_states rows of OPNsense 26.7: a GUI connection (floating), an NTP query with
// NAT over WAN and an IPv6 connection on LAN
const firewallStateRows = `{"rows":[` +
	`{"label":"3345e04986bd5750d23b77cbbb21271f","descr":"anti-lockout rule","nat_addr":null,"nat_port":null,"gateway":null,"iface":"all","proto":"tcp","ipproto":"ipv4","flags":[],"direction":"in","dst_addr":"192.168.1.1","dst_port":"443","src_addr":"192.168.1.2","src_port":"55816","state":"ESTABLISHED:ESTABLISHED","age":"00:01:26","expires":"23:59:58","pkts":[15,17],"bytes":[2751,5493],"rule":"86","id":"6f14de6a00000000\/0449ade0","interface":"all"},` +
	`{"label":"d621e174-154f-4ebb-9465-6e2fac4b2bcb","descr":"Default allow LAN to any rule","nat_addr":"192.168.1.50","nat_port":"40000","gateway":null,"iface":"vtnet1","proto":"udp","ipproto":"ipv4","flags":["no-df"],"direction":"out","dst_addr":"212.34.149.56","dst_port":"123","src_addr":"10.0.2.15","src_port":"61000","state":"MULTIPLE:SINGLE","age":"00:00:30","expires":"00:00:30","pkts":[1,1],"bytes":[76,76],"rule":"95","id":"7714de6a00000000\/0449ade0","interface":"WAN"},` +
	`{"label":"6d19c02b-60ef-47a2-be81-d5a213fc394f","descr":"","nat_addr":null,"nat_port":null,"gateway":null,"iface":"vtnet0","proto":"tcp","ipproto":"ipv6","flags":[],"direction":"in","dst_addr":"fd00::1","dst_port":"22","src_addr":"fd00::50","src_port":"50000","state":"ESTABLISHED:ESTABLISHED","age":"100:00:00","expires":"23:00:00","pkts":[2000,3000],"bytes":[300000,4000000],"rule":"97","id":"8814de6a00000000\/0449ade0","interface":"LAN"}` +
	`],"rowCount":3,"total":3,"current":1}`

func firewallStateFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("POST", firewallStateQueryPath, 200, firewallStateRows)
	f.on("GET", firewallStateNamesPath, 200, `{"vtnet0":"LAN","vtnet1":"WAN","lo0":"Loopback"}`)
	f.on("GET", firewallStateRuleIdsPath, 200, `{"items":[`+
		`{"id":"3345e04986bd5750d23b77cbbb21271f","descr":"anti-lockout rule"},`+
		`{"id":"b7cd97a164650b538506fb551a0369e7","descr":"Block bogon IPv4 networks from WAN"},`+
		`{"id":"d621e174-154f-4ebb-9465-6e2fac4b2bcb","descr":"Default allow LAN to any rule"}]}`)
	for _, id := range []string{firewallStateIdLan, firewallStateIdNtp, firewallStateIdV6} {
		f.on("POST", firewallStateDelPath+id, 200, `{"result":"killed 1 states from 1 specified\n"}`)
	}
	f.on("POST", firewallStateKillPath, 200, `{"result":"ok","dropped_states":1}`)
	f.on("POST", firewallStateFlushPath, 200, `{"result":"ok"}`)
	f.on("POST", firewallStateSourcesPath, 200, `{"result":"ok"}`)
	return f
}

// firewallStateDrops returns the mutating calls: every POST except the state query (which is a POST too)
func firewallStateDrops(f *fakeOPN) []apiCall {
	var drops []apiCall
	for _, call := range f.mutations() {
		if call.Path != firewallStateQueryPath {
			drops = append(drops, call)
		}
	}
	return drops
}

func firewallStateWantNoDrops(t *testing.T, f *fakeOPN) {
	t.Helper()
	if drops := firewallStateDrops(f); len(drops) != 0 {
		t.Errorf("want no mutating API calls, got %v", drops)
	}
}

func firewallStateWantOneDrop(t *testing.T, f *fakeOPN, method string, path string) {
	t.Helper()
	var drops = firewallStateDrops(f)
	if len(drops) != 1 || drops[0].Method != method || drops[0].Path != path {
		t.Fatalf("want exactly one %s %s, got %v", method, path, drops)
	}
}

// firewallStateWaitForCount waits until stdout contains text n times (n refreshes), failing the test after 5s
func firewallStateWaitForCount(p *opnProcess, text string, n int) {
	p.t.Helper()
	var deadline = time.Now().Add(5 * time.Second)
	for strings.Count(p.stdout.String(), text) < n {
		if time.Now().After(deadline) || !p.running() {
			p.t.Fatalf("waiting for %d times %q:\n%s", n, text, p.result())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func firewallState(args ...string) []string {
	return append([]string{"/firewall/state"}, args...)
}

var firewallStateTableHeader = []string{"#", "INTERFACE", "PROTO", "DIR", "SOURCE", "DESTINATION", "STATE", "AGE", "EXPIRES", "PACKETS", "BYTES", "RULE"}

func TestFirewallStatePrint(t *testing.T) {
	t.Parallel()
	var f = firewallStateFake(t)
	var r = f.run(firewallState("print")...)
	wantExit(t, r, 0)
	var rows = systemLoggingWantTable(t, r.stdout, firewallStateTableHeader, 4, "192.168.1.2:55816", "10.0.2.15:61000", "[fd00::50]:50000")
	if got := strings.Join(rows[2], "|"); got != "1|WAN (vtnet1)|udp|out|10.0.2.15:61000|212.34.149.56:123|MULTIPLE:SINGLE|00:00:30|00:00:30|2|152 B|Default allow LAN to any rule" {
		t.Errorf("row 1: %s", got)
	}
	if got := strings.Join(rows[1], "|"); got != "0|all|tcp|in|192.168.1.2:55816|192.168.1.1:443|ESTABLISHED:ESTABLISHED|00:01:26|23:59:58|32|8.2 kB|anti-lockout rule" {
		t.Errorf("row 0: %s", got)
	}
	if rows[3][11] != "6d19c02b-60ef-47a2-be81-d5a213fc394f" {
		t.Errorf("a rule without description shows its id, got %q", rows[3][11])
	}
	var call = f.calls()[0]
	wantJSON(t, call, map[string]any{"current": float64(1), "rowCount": float64(10000000)})
	firewallStateWantNoDrops(t, f)
}

func TestFirewallStatePrintFilters(t *testing.T) {
	t.Parallel()
	var f = firewallStateFake(t)
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"interface=wan"}, []string{"10.0.2.15:61000"}},
		{[]string{"interface=vtnet0,ALL"}, []string{"192.168.1.2:55816", "[fd00::50]:50000"}},
		{[]string{"protocol=udp"}, []string{"10.0.2.15:61000"}},
		{[]string{"protocol=IPv6"}, []string{"[fd00::50]:50000"}},
		{[]string{"src=10.0.0.0/8"}, []string{"10.0.2.15:61000"}},
		{[]string{"dst=fd00::/64"}, []string{"[fd00::50]:50000"}},
		{[]string{"port=443"}, []string{"192.168.1.2:55816"}},
		{[]string{"port=61000", "protocol=tcp"}, nil},
		{[]string{"rule=3345e04986bd5750d23b77cbbb21271f"}, []string{"192.168.1.2:55816"}},
		{[]string{"sort=bytes", "reverse"}, []string{"[fd00::50]:50000", "192.168.1.2:55816", "10.0.2.15:61000"}},
		{[]string{"sort=age"}, []string{"10.0.2.15:61000", "192.168.1.2:55816", "[fd00::50]:50000"}},
		{[]string{"sort=source"}, []string{"10.0.2.15:61000", "192.168.1.2:55816", "[fd00::50]:50000"}},
		{[]string{"sort=expires", "limit=2"}, []string{"10.0.2.15:61000", "[fd00::50]:50000"}},
	} {
		var r = f.run(firewallState(append([]string{"print"}, tc.args...)...)...)
		wantExit(t, r, 0)
		systemLoggingWantTable(t, r.stdout, firewallStateTableHeader, 4, tc.want...)
	}
	wantFailure(t, f.run(firewallState("print", "reverse")...), "reverse needs sort=")
	wantFailure(t, f.run(firewallState("print", "src=10.0.0.300")...), "src")
	wantFailure(t, f.run(firewallState("print", "sort=color")...), "sort")
	firewallStateWantNoDrops(t, f)
}

func TestFirewallStatePrintServerFilters(t *testing.T) {
	t.Parallel()
	var f = firewallStateFake(t)
	wantExit(t, f.run(firewallState("print", "search=192.168.1.0/24:443 tcp", "rule=3345e04986bd5750d23b77cbbb21271f")...), 0)
	wantJSON(t, f.calls()[0], map[string]any{"current": float64(1), "rowCount": float64(10000000),
		"searchPhrase": "192.168.1.0/24:443 tcp", "ruleid": "3345e04986bd5750d23b77cbbb21271f"})
}

func TestFirewallStatePrintJSONAndDetail(t *testing.T) {
	t.Parallel()
	var f = firewallStateFake(t)
	var r = f.run(firewallState("print", "json", "protocol=udp")...)
	wantExit(t, r, 0)
	if !strings.HasPrefix(r.stdout, `{"label":"d621e174-154f-4ebb-9465-6e2fac4b2bcb","descr":"Default allow LAN to any rule","nat_addr":"192.168.1.50"`) ||
		strings.Count(r.stdout, "\n") != 1 {
		t.Errorf("want the raw state on one line:\n%s", r.stdout)
	}

	r = f.run(firewallState("print", "detail", "protocol=udp")...)
	wantExit(t, r, 0)
	var fields = systemLoggingFields(r.stdout)
	for key, want := range map[string]string{
		"id": firewallStateIdNtp, "interface": "WAN (vtnet1)", "family": "ipv4", "nat": "192.168.1.50:40000",
		"packets": "2 (1:1)", "bytes": "152 (76:76)", "rule": "95", "rule-id": "d621e174-154f-4ebb-9465-6e2fac4b2bcb", "flags": "no-df",
	} {
		if fields[key] != want {
			t.Errorf("%s: got %q, want %q\n%s", key, fields[key], want, r.stdout)
		}
	}
}

func TestFirewallStateFollow(t *testing.T) {
	t.Parallel()
	var f = firewallStateFake(t)
	var p = f.start(firewallState("print", "follow", "interval=20ms", "protocol=udp")...)
	firewallStateWaitForCount(p, "10.0.2.15:61000", 3)
	var r = p.interrupt()
	wantExit(t, r, 0)
	var refreshes = strings.Count(r.stdout, "10.0.2.15:61000")
	if refreshes < 2 || strings.Count(r.stdout, "--- ") != refreshes || strings.Contains(r.stdout, "192.168.1.2") {
		t.Errorf("want several filtered refreshes, each with a separator:\n%s", r.stdout)
	}
	firewallStateWantNoDrops(t, f)
}

func TestFirewallStateRemove(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		script string
		args   []string
		want   string
	}{
		{name: "by #", args: []string{"1"}, want: firewallStateIdNtp},
		{name: "by id", args: []string{firewallStateIdV6}, want: firewallStateIdV6},
		{name: "after a filtered print", script: "/firewall/state\nprint protocol=tcp sort=bytes reverse\nremove 0 confirm=yes\n", want: firewallStateIdV6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = firewallStateFake(t)
			var r runResult
			if tc.script != "" {
				r = f.runScript(tc.script)
			} else {
				r = f.run(firewallState(append(append([]string{"remove"}, tc.args...), "confirm=yes")...)...)
			}
			wantExit(t, r, 0)
			if strings.Contains(r.stdout, "killed") || (tc.script == "" && r.stdout != "") {
				t.Errorf("remove must be silent, got %q", r.stdout)
			}
			firewallStateWantOneDrop(t, f, "POST", firewallStateDelPath+tc.want)
		})
	}
}

func TestFirewallStateRemoveGuardsAndErrors(t *testing.T) {
	t.Parallel()
	var f = firewallStateFake(t)
	wantFailure(t, f.run(firewallState("remove", "0")...), firewallStateRemoveConfirm, "confirm=yes")
	wantFailure(t, f.run(firewallState("remove", "0", "confirm=no")...), "confirm=yes")
	wantNoCalls(t, f)

	wantFailure(t, f.run(firewallState("remove", "3", "confirm=yes")...), "not found", "#3")
	wantFailure(t, f.run(firewallState("remove", "aaaa/bbbb", "confirm=yes")...), "not found", "aaaa/bbbb")
	firewallStateWantNoDrops(t, f)

	var gone = firewallStateFake(t)
	gone.on("POST", firewallStateDelPath+firewallStateIdLan, 200, `{"result":"killed 0 states from 1 specified\n"}`)
	wantFailure(t, gone.run(firewallState("remove", "0", "confirm=yes")...), "not found", firewallStateIdLan)
}

func TestFirewallStateKill(t *testing.T) {
	t.Parallel()
	var f = firewallStateFake(t)
	var r = f.run(firewallState("kill", "protocol=tcp", "confirm=yes")...)
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "dropped 2 states")
	if r.stdout != "" {
		t.Errorf("kill prints nothing on stdout, got %q", r.stdout)
	}
	var mutations = firewallStateDrops(f)
	if len(mutations) != 2 || mutations[0].Path != firewallStateDelPath+firewallStateIdLan || mutations[1].Path != firewallStateDelPath+firewallStateIdV6 {
		t.Errorf("want the two TCP states dropped one by one, got %v", mutations)
	}

	var server = firewallStateFake(t)
	r = server.run(firewallState("kill", "search=192.168.1.2", "confirm=yes")...)
	wantExit(t, r, 0)
	// the fake ignores searchPhrase and answers every state: all of them are dropped, kill_states is never used
	wantJSON(t, server.calls()[0], map[string]any{"current": float64(1), "rowCount": float64(10000000), "searchPhrase": "192.168.1.2"})
	if len(firewallStateDrops(server)) != 3 {
		t.Errorf("want 3 drops, got %v", firewallStateDrops(server))
	}

	var none = firewallStateFake(t)
	r = none.run(firewallState("kill", "src=203.0.113.0/24", "confirm=yes")...)
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "dropped 0 states")
	firewallStateWantNoDrops(t, none)
}

func TestFirewallStateKillGuards(t *testing.T) {
	t.Parallel()
	var f = firewallStateFake(t)
	wantFailure(t, f.run(firewallState("kill")...), "at least one filter", "flush")
	wantFailure(t, f.run(firewallState("kill", "confirm=yes")...), "at least one filter")
	wantFailure(t, f.run(firewallState("kill", "search=", "interface=", "confirm=yes")...), "at least one filter")
	wantFailure(t, f.run(firewallState("kill", "protocol=tcp")...), firewallStateKillConfirm, "confirm=yes")
	wantNoCalls(t, f)

	// a drop failing midway stops and reports the progress
	var failing = firewallStateFake(t)
	failing.on("POST", firewallStateDelPath+firewallStateIdV6, 200, `{"result":"pfctl: DIOCKILLSTATES: Operation not permitted"}`)
	wantFailure(t, failing.run(firewallState("kill", "protocol=tcp", "confirm=yes")...), "dropped 1 of 2 states", "Operation not permitted")
}

func TestFirewallStateFlush(t *testing.T) {
	t.Parallel()
	var f = firewallStateFake(t)
	// the extra flag is checked before the confirmation
	wantFailure(t, f.run(firewallState("flush")...), firewallStateFlushFlag)
	wantFailure(t, f.run(firewallState("flush", "confirm=yes")...), firewallStateFlushFlag)
	wantFailure(t, f.run(firewallState("flush", firewallStateFlushFlag+"=no", "confirm=yes")...), firewallStateFlushFlag)
	wantFailure(t, f.run(firewallState("flush", firewallStateFlushFlag)...), firewallStateFlushConfirm, "confirm=yes")
	wantFailure(t, f.run(firewallState("flush-sources")...), firewallStateFlushSourcesConfirm, "confirm=yes")
	wantNoCalls(t, f)

	var r = f.run(firewallState("flush", firewallStateFlushFlag, "confirm=yes")...)
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("flush must be silent, got %q", r.stdout)
	}
	firewallStateWantOneDrop(t, f, "POST", firewallStateFlushPath)

	var sources = firewallStateFake(t)
	wantExit(t, sources.run(firewallState("flush-sources", "confirm=yes")...), 0)
	firewallStateWantOneDrop(t, sources, "POST", firewallStateSourcesPath)

	var failing = newFakeOPN(t)
	failing.on("POST", firewallStateFlushPath, 200, `{"result":"failed"}`)
	wantFailure(t, failing.run(firewallState("flush", firewallStateFlushFlag, "confirm=yes")...), "flush_states failed")
}

func TestFirewallStateRuleIds(t *testing.T) {
	t.Parallel()
	var f = firewallStateFake(t)
	var r = f.run(firewallState("rule-ids")...)
	wantExit(t, r, 0)
	systemLoggingWantTable(t, r.stdout, []string{"RULE-ID", "DESCRIPTION"}, 1,
		"anti-lockout rule", "Block bogon IPv4 networks from WAN", "Default allow LAN to any rule")
	r = f.run(firewallState("rule-ids", "search=LAN")...)
	wantExit(t, r, 0)
	systemLoggingWantTable(t, r.stdout, []string{"RULE-ID", "DESCRIPTION"}, 0, "d621e174-154f-4ebb-9465-6e2fac4b2bcb")
	r = f.run(firewallState("rule-ids", "json", "search=bogon")...)
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != `{"id":"b7cd97a164650b538506fb551a0369e7","descr":"Block bogon IPv4 networks from WAN"}` {
		t.Errorf("json: %q", r.stdout)
	}
	firewallStateWantNoDrops(t, f)
}

func TestFirewallStateComplete(t *testing.T) {
	t.Parallel()
	var f = firewallStateFake(t)
	var session = fakeSession(t, f)
	var candidates, _ = session.Complete("/firewall/state print rule=b7")
	if strings.Join(candidates, " ") != "rule=b7cd97a164650b538506fb551a0369e7" {
		t.Errorf("rule completion: %q", candidates)
	}
}
