package cli

import (
	"strings"
	"testing"
)

const firewallSessionPath = "/api/diagnostics/firewall/query_pf_top"

// firewallSessionRows is a trimmed query_pf_top answer of OPNsense 26.7 (a NAT session added)
const firewallSessionRows = `{"total":3,"rowCount":3,"current":1,"rows":[` +
	`{"proto":"tcp","dir":"in","src_addr":"192.168.1.2","src_port":"55816","dst_addr":"192.168.1.1","dst_port":"443","gw_addr":null,"gw_port":null,"state":"TIME_WAIT:TIME_WAIT","age":87,"expire":3,"pkts":32,"bytes":8244,"avg":94,"rule":"86","label":"3345e04986bd5750d23b77cbbb21271f","descr":"anti-lockout rule"},` +
	`{"proto":"tcp","dir":"in","src_addr":"192.168.1.2","src_port":"57528","dst_addr":"192.168.1.1","dst_port":"443","gw_addr":null,"gw_port":null,"state":"ESTABLISHED:ESTABLISHED","age":3725,"expire":86399,"pkts":917,"bytes":491029,"avg":131,"rule":"86","label":"3345e04986bd5750d23b77cbbb21271f","descr":"anti-lockout rule"},` +
	`{"proto":"udp","dir":"out","src_addr":"10.0.2.15","src_port":"61000","dst_addr":"212.34.149.56","dst_port":"123","gw_addr":"192.168.1.50","gw_port":"40000","state":"MULTIPLE:SINGLE","age":30,"expire":30,"pkts":2,"bytes":152,"avg":500,"rule":"95"}]}`

var firewallSessionHeader = []string{"PROTO", "DIR", "SOURCE", "DESTINATION", "GATEWAY", "STATE", "AGE", "EXPIRE", "PACKETS", "BYTES", "RATE", "RULE"}

func firewallSessionFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("POST", firewallSessionPath, 200, firewallSessionRows)
	return f
}

func TestFirewallSessionPrint(t *testing.T) {
	t.Parallel()
	var f = firewallSessionFake(t)
	var r = f.run("/firewall/session", "print")
	wantExit(t, r, 0)
	// the most bytes first
	var rows = systemLoggingWantTable(t, r.stdout, firewallSessionHeader, 2, "192.168.1.2:57528", "192.168.1.2:55816", "10.0.2.15:61000")
	if got := strings.Join(rows[1], "|"); got != "tcp|in|192.168.1.2:57528|192.168.1.1:443|-|ESTABLISHED:ESTABLISHED|01:02:05|23:59:59|917|491.0 kB|131 B/s|anti-lockout rule" {
		t.Errorf("row 0: %s", got)
	}
	if got := strings.Join(rows[3], "|"); got != "udp|out|10.0.2.15:61000|212.34.149.56:123|192.168.1.50:40000|MULTIPLE:SINGLE|00:00:30|00:00:30|2|152 B|500 B/s|@95" {
		t.Errorf("row 2: %s", got)
	}
	wantJSON(t, f.calls()[0], map[string]any{})

	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"sort=rate"}, []string{"10.0.2.15:61000", "192.168.1.2:57528", "192.168.1.2:55816"}},
		{[]string{"sort=age", "ascending"}, []string{"10.0.2.15:61000", "192.168.1.2:55816", "192.168.1.2:57528"}},
		{[]string{"sort=source", "ascending", "limit=2"}, []string{"10.0.2.15:61000", "192.168.1.2:55816"}},
		{[]string{"limit=1"}, []string{"192.168.1.2:57528"}},
	} {
		var r = f.run(append([]string{"/firewall/session", "print"}, tc.args...)...)
		wantExit(t, r, 0)
		systemLoggingWantTable(t, r.stdout, firewallSessionHeader, 2, tc.want...)
	}
	for _, call := range f.calls() {
		if call.Path != firewallSessionPath {
			t.Errorf("unexpected call %v", call)
		}
	}
}

func TestFirewallSessionPrintQueryAndJSON(t *testing.T) {
	t.Parallel()
	var f = firewallSessionFake(t)
	var r = f.run("/firewall/session", "print", "json", "search=192.168.1.0/24 https", "rule=3345e04986bd5750d23b77cbbb21271f", "limit=1")
	wantExit(t, r, 0)
	wantJSON(t, f.calls()[0], map[string]any{"searchPhrase": "192.168.1.0/24 https", "ruleid": "3345e04986bd5750d23b77cbbb21271f"})
	if !strings.HasPrefix(r.stdout, `{"proto":"tcp","dir":"in","src_addr":"192.168.1.2","src_port":"57528"`) || strings.Count(r.stdout, "\n") != 1 {
		t.Errorf("want the busiest raw session on one line:\n%s", r.stdout)
	}

	var failing = newFakeOPN(t)
	wantFailure(t, failing.run("/firewall/session", "print"), "empty response")
}

func TestFirewallSessionFollow(t *testing.T) {
	t.Parallel()
	var f = firewallSessionFake(t)
	var p = f.start("/firewall/session", "print", "follow", "interval=20ms", "limit=1")
	firewallStateWaitForCount(p, "57528", 3)
	var r = p.interrupt()
	wantExit(t, r, 0)
	var refreshes = strings.Count(r.stdout, "57528")
	if refreshes < 2 || strings.Count(r.stdout, "--- ") != refreshes || strings.Contains(r.stdout, "55816") {
		t.Errorf("want several refreshes of one row, each with a separator:\n%s", r.stdout)
	}
}

func TestFirewallSessionDuration(t *testing.T) {
	t.Parallel()
	for seconds, want := range map[int64]string{0: "00:00:00", 59: "00:00:59", 3725: "01:02:05", 90061: "25:01:01"} {
		if got := firewallSessionDuration(seconds); got != want {
			t.Errorf("%d: got %q, want %q", seconds, got, want)
		}
	}
	for value, want := range map[string]int64{"00:01:26": 86, "100:00:00": 360000, "": -1, "1d02h": -1} {
		if got := firewallStateSeconds(value); got != want {
			t.Errorf("%q: got %d, want %d", value, got, want)
		}
	}
}
