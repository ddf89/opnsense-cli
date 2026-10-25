package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const (
	firewallLogPath     = "/api/diagnostics/firewall/log"
	firewallStreamPath  = "/api/diagnostics/firewall/stream_log"
	firewallFiltersPath = "/api/diagnostics/firewall/log_filters"
	firewallStatsPath   = "/api/diagnostics/firewall/stats"
	firewallNamesPath   = "/api/diagnostics/interface/getInterfaceNames"
	firewallNames       = `{"vtnet0":"LAN","vtnet1":"WAN","lo0":"Loopback"}`
	firewallFilters     = `{"action":["pass","block","rdr","nat","binat"],"interface_name":["LAN","Loopback","WAN"],"dir":["in","out"]}`
)

var firewallSpec = []string{"rulenr", "subrulenr", "anchorname", "rid", "interface", "reason", "action", "dir", "ipversion",
	"tos", "ecn", "ttl", "id", "offset", "ipflags", "protonum", "protoname", "length", "src", "dst", "srcport", "dstport",
	"datalen", "tcpflags", "seq", "ack", "urp", "tcpopts"}

// firewallEntry is a 26.7 firewall log record, n makes it unique (timestamp, source port, digest)
func firewallEntry(n int, overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"rulenr": "86", "subrulenr": "", "anchorname": "", "rid": "02f4bab031b57d1e30553ce08e0ec131", "interface": "vtnet0",
		"reason": "match", "action": "pass", "dir": "in", "ipversion": "4", "tos": "0x0", "ecn": "", "ttl": "64", "id": "0",
		"offset": "0", "ipflags": "DF", "protonum": "6", "protoname": "tcp", "length": "60", "src": "192.168.1.2",
		"dst": "192.168.1.1", "srcport": fmt.Sprint(32970 + n), "dstport": "443", "datalen": "0", "tcpflags": "S",
		"seq": "1", "ack": "", "urp": "64240", "tcpopts": "",
		"__timestamp__": fmt.Sprintf("2026-10-25T00:03:%02d", n), "__host__": "OPNsense.internal",
		"__digest__": fmt.Sprintf("48cc%028d", n), "__spec__": firewallSpec, "label": "anti-lockout rule",
	}, overrides)
}

// firewallStreamEntry is the same record as sent by stream_log: other digest (hashed with the newline), plus a counter
func firewallStreamEntry(entry map[string]any) string {
	return sseData(logJSON(withFields(entry, map[string]any{
		"__digest__": "ffff" + entry["__digest__"].(string)[4:], "counter": 1,
	})))
}

func firewallLine(n int) string {
	return fmt.Sprintf("2026-10-25T00:03:%02d  pass   in   LAN       tcp    192.168.1.2:%d -> 192.168.1.1:443  [anti-lockout rule]", n, 32970+n)
}

// firewallLogHandler serves the firewall log like OPNsense from all (oldest first): the newest ?limit records newest
// first, with ?digest only the records newer than it plus the digest record itself. Before available() returns n,
// only the first n records exist
func firewallLogHandler(all []map[string]any, available func(request int) int) http.HandlerFunc {
	var mu sync.Mutex
	var requests int
	return func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		var n = available(requests)
		requests++
		mu.Unlock()
		var existing = all[:n]
		var limit = len(existing)
		_, _ = fmt.Sscan(r.URL.Query().Get("limit"), &limit)

		var answer = make([]map[string]any, 0)
		for i := len(existing) - 1; i >= 0 && len(answer) < limit; i-- {
			answer = append(answer, existing[i])
			if existing[i]["__digest__"] == r.URL.Query().Get("digest") {
				break
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(answer)
	}
}

func newFirewallFake(t *testing.T, entries ...map[string]any) *fakeOPN {
	var f = newFakeOPN(t)
	f.on("GET", firewallNamesPath, 200, firewallNames)
	f.on("GET", firewallFiltersPath, 200, firewallFilters)
	f.onFunc("GET", firewallLogPath, firewallLogHandler(entries, func(int) int { return len(entries) }))
	return f
}

func firewallLogCalls(f *fakeOPN) []apiCall {
	var result []apiCall
	for _, call := range f.calls() {
		if call.Path == firewallLogPath {
			result = append(result, call)
		}
	}
	return result
}

// firewallParseFields parses "name: value" lines
func firewallParseFields(stdout string) map[string]string {
	var fields = map[string]string{}
	for _, line := range logStdoutLines(stdout) {
		var name, value, _ = strings.Cut(line, ":")
		fields[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	return fields
}

func TestFirewallLogTail(t *testing.T) {
	t.Parallel()
	var f = newFirewallFake(t, firewallEntry(1, nil), firewallEntry(2, nil), firewallEntry(3, nil))
	var r = f.run("/firewall/log", "print", "lines=2")
	wantExit(t, r, 0)
	if got, want := logStdoutLines(r.stdout), []string{firewallLine(2), firewallLine(3)}; !reflect.DeepEqual(got, want) {
		t.Errorf("want the 2 newest, oldest first:\n got  %q\n want %q", got, want)
	}
	var calls = firewallLogCalls(f)
	if len(calls) != 1 || calls[0].Query.Get("limit") != "2" || calls[0].Query.Has("digest") {
		t.Errorf("log requests: %v", calls)
	}
	wantNoMutations(t, f)

	r = f.run("/firewall", "log", "print")
	wantExit(t, r, 0)
	if len(logStdoutLines(r.stdout)) != 3 || firewallLogCalls(f)[1].Query.Get("limit") != "50" {
		t.Errorf("default lines=50:\n%s", r.stdout)
	}

	// lines=0 without follow reads nothing
	r = f.run("/firewall/log", "print", "lines=0")
	wantExit(t, r, 0)
	if r.stdout != "" || len(firewallLogCalls(f)) != 2 {
		t.Errorf("lines=0: %q, %v", r.stdout, firewallLogCalls(f))
	}
}

func TestFirewallLogFormat(t *testing.T) {
	t.Parallel()
	var f = newFirewallFake(t,
		firewallEntry(1, map[string]any{"interface": "vtnet9", "label": "", "rulenr": "12", "action": "block", "dir": "out"}),
		firewallEntry(2, map[string]any{"ipversion": "6", "src": "fd00::2", "dst": "fd00::1", "protoname": "udp", "protonum": "17", "srcport": "546", "dstport": "547"}),
		firewallEntry(3, map[string]any{"protoname": "icmp", "protonum": "1", "srcport": "", "dstport": "", "interface": "vtnet1"}),
		firewallEntry(4, map[string]any{"protoname": "", "protonum": "112", "srcport": "", "dstport": ""}),
	)
	var r = f.run("/firewall/log", "print")
	wantExit(t, r, 0)
	var want = []string{
		"2026-10-25T00:03:01  block  out  vtnet9    tcp    192.168.1.2:32971 -> 192.168.1.1:443  [rule 12]",
		"2026-10-25T00:03:02  pass   in   LAN       udp    [fd00::2]:546 -> [fd00::1]:547  [anti-lockout rule]",
		"2026-10-25T00:03:03  pass   in   WAN       icmp   192.168.1.2 -> 192.168.1.1  [anti-lockout rule]",
		"2026-10-25T00:03:04  pass   in   LAN       112    192.168.1.2 -> 192.168.1.1  [anti-lockout rule]",
	}
	if got := logStdoutLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("format:\n got  %q\n want %q", got, want)
	}
}

func TestFirewallLogJson(t *testing.T) {
	t.Parallel()
	var entries = []map[string]any{firewallEntry(1, nil), firewallEntry(2, map[string]any{"extra_field": "kept"})}
	var f = newFirewallFake(t, entries...)
	var r = f.run("/firewall/log", "print", "json")
	wantExit(t, r, 0)
	var lines = logStdoutLines(r.stdout)
	if len(lines) != 2 {
		t.Fatalf("want 2 ndjson lines:\n%s", r.stdout)
	}
	for i, line := range lines {
		var got map[string]any
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("line %d is not JSON: %v: %s", i, err, line)
		}
		var want map[string]any
		_ = json.Unmarshal([]byte(logJSON(entries[i])), &want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("line %d is not the raw record:\n got  %v\n want %v", i, got, want)
		}
	}
}

func TestFirewallLogFilterArgs(t *testing.T) {
	t.Parallel()
	var entries = []map[string]any{
		firewallEntry(1, map[string]any{"action": "block", "interface": "vtnet1", "src": "203.0.113.7", "dst": "198.51.100.1", "dstport": "22"}),
		firewallEntry(2, map[string]any{"dir": "out", "protoname": "udp", "protonum": "17", "dstport": "53", "label": "allow dns"}),
		firewallEntry(3, map[string]any{"ipversion": "6", "src": "fd00::2", "dst": "fd00::1", "protoname": "ipv6-icmp", "protonum": "58", "srcport": "", "dstport": ""}),
		firewallEntry(4, nil),
		firewallEntry(5, map[string]any{"src": "10.1.2.3", "srcport": "443", "dstport": "51000"}),
	}
	for _, tc := range []struct {
		name string
		args []string
		want []int
	}{
		{"action", []string{"action=BLOCK"}, []int{1}},
		{"interface by name", []string{"interface=wan"}, []int{1}},
		{"interface by device", []string{"interface=vtnet1"}, []int{1}},
		{"dir", []string{"dir=out"}, []int{2}},
		{"dir is case-insensitive", []string{"dir=OUT"}, []int{2}},
		{"proto by name", []string{"proto=UDP"}, []int{2}},
		{"proto by number", []string{"proto=58"}, []int{3}},
		{"src address", []string{"src=203.0.113.7"}, []int{1}},
		{"src network", []string{"src=192.168.1.0/24"}, []int{2, 4}},
		{"src IPv6 network", []string{"src=fd00::/64"}, []int{3}},
		{"dst", []string{"dst=198.51.100.0/24"}, []int{1}},
		{"port matches source or destination", []string{"port=443"}, []int{4, 5}},
		{"search any field case-insensitive", []string{"search=ALLOW DNS"}, []int{2}},
		{"search interface name", []string{"search=wan"}, []int{1}},
		{"combined with AND", []string{"action=pass", "port=443", "src=192.168.1.0/24"}, []int{4}},
		{"lines limits the matches", []string{"port=443", "lines=1"}, []int{5}},
		{"lines keeps the newest matches", []string{"action=pass", "lines=2"}, []int{4, 5}},
		{"no match", []string{"action=rdr"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFirewallFake(t, entries...)
			var r = f.run(append([]string{"/firewall/log", "print"}, tc.args...)...)
			wantExit(t, r, 0)
			var want []string
			for _, n := range tc.want {
				want = append(want, fmt.Sprintf("2026-10-25T00:03:%02d", n))
			}
			var got []string
			for _, line := range logStdoutLines(r.stdout) {
				got = append(got, strings.Fields(line)[0])
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("records %q, want %q:\n%s", got, want, r.stdout)
			}
			// filtering searches the newest scan= records
			if limit := firewallLogCalls(f)[0].Query.Get("limit"); limit != "1000" {
				t.Errorf("limit %q, want the default scan of 1000", limit)
			}
		})
	}

	t.Run("scan", func(t *testing.T) {
		t.Parallel()
		var f = newFirewallFake(t, entries...)
		var r = f.run("/firewall/log", "print", "action=pass", "scan=2")
		wantExit(t, r, 0)
		if limit := firewallLogCalls(f)[0].Query.Get("limit"); limit != "50" {
			t.Errorf("scan below lines: limit %q, want 50", limit)
		}
		r = f.run("/firewall/log", "print", "action=pass", "scan=3", "lines=1")
		wantExit(t, r, 0)
		if limit := firewallLogCalls(f)[1].Query.Get("limit"); limit != "3" {
			t.Errorf("limit %q, want scan=3", limit)
		}
	})
}

func TestFirewallLogErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		args    []string
		wantErr []string
	}{
		{"negative lines", []string{"lines=-1"}, []string{"lines", "negative"}},
		{"negative scan", []string{"scan=-1"}, []string{"scan", "negative"}},
		{"zero interval", []string{"follow", "interval=0s"}, []string{"interval", "positive"}},
		{"invalid interval", []string{"follow", "interval=soon"}, []string{"interval", "duration"}},
		{"invalid src", []string{"src=192.168.1.300"}, []string{"src", "192.168.1.300"}},
		{"invalid dst", []string{"dst=lan net"}, []string{"dst", "lan net"}},
		{"invalid network", []string{"dst=10.0.0.0/33"}, []string{"dst", "10.0.0.0/33"}},
		{"invalid port", []string{"port=http"}, []string{"port", "http"}},
		{"positional argument", []string{"lan"}, []string{`unexpected "lan"`}},
		{"unknown dir", []string{"dir=inbound"}, []string{"dir", "inbound", "in, out"}},
		{"unknown argument", []string{"protocol=tcp"}, []string{"protocol"}},
		{"interval without follow", []string{"interval=2s"}, []string{"interval", "only applies to follow"}},
		{"interval with stream", []string{"stream", "interval=2s"}, []string{"interval", "stream"}},
		{"interval with follow and stream", []string{"follow", "stream", "interval=2s"}, []string{"interval", "stream"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFirewallFake(t, firewallEntry(1, nil))
			var r = f.run(append([]string{"/firewall/log", "print"}, tc.args...)...)
			wantFailure(t, r, tc.wantErr...)
			// invalid values fail before anything is requested
			wantNoCalls(t, f)
		})
	}

	t.Run("unknown action is checked against the API", func(t *testing.T) {
		t.Parallel()
		var f = newFirewallFake(t, firewallEntry(1, nil))
		var r = f.run("/firewall/log", "print", "action=allow")
		wantFailure(t, r, "action", "allow", "pass, block")
		if len(firewallLogCalls(f)) != 0 {
			t.Errorf("the log must not be read: %v", f.calls())
		}
		wantNoMutations(t, f)
	})

	t.Run("actions unavailable skips the check", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", firewallNamesPath, 200, firewallNames)
		f.on("GET", firewallFiltersPath, 403, `{"status":403,"message":"Forbidden"}`)
		f.onFunc("GET", firewallLogPath, firewallLogHandler([]map[string]any{firewallEntry(1, map[string]any{"action": "block"})}, func(int) int { return 1 }))
		var r = f.run("/firewall/log", "print", "action=block")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "warning", "action=")
		wantContains(t, "stdout", r.stdout, "block")
	})

	t.Run("null answer", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", firewallNamesPath, 200, firewallNames)
		f.on("GET", firewallLogPath, 200, `null`)
		var r = f.run("/firewall/log", "print")
		wantFailure(t, r, "no firewall log answer")
	})

	t.Run("interface names unavailable", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", firewallNamesPath, 403, `{"status":403,"message":"Forbidden"}`)
		f.onFunc("GET", firewallLogPath, firewallLogHandler([]map[string]any{firewallEntry(1, nil)}, func(int) int { return 1 }))
		var r = f.run("/firewall/log", "print")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "warning", "interface names")
		wantContains(t, "stdout", r.stdout, "vtnet0") // devices instead of names
	})
}

func TestFirewallLogFollowPoll(t *testing.T) {
	t.Parallel()
	var all = []map[string]any{firewallEntry(1, nil), firewallEntry(2, nil), firewallEntry(3, map[string]any{"action": "block"}),
		firewallEntry(4, nil), firewallEntry(5, nil)}
	var f = newFakeOPN(t)
	f.on("GET", firewallNamesPath, 200, firewallNames)
	f.on("GET", firewallFiltersPath, 200, firewallFilters)
	// 2 records at the start, then one more per poll
	f.onFunc("GET", firewallLogPath, firewallLogHandler(all, func(request int) int { return min(2+request, len(all)) }))

	var p = f.start("/firewall/log", "print", "follow", "lines=1", "interval=20ms", "action=pass")
	p.waitFor(firewallLine(5))
	var r = p.interrupt()
	wantExit(t, r, 0)
	// the tail (newest matching of the first 2), then every new matching record once
	if got, want := logStdoutLines(r.stdout), []string{firewallLine(2), firewallLine(4), firewallLine(5)}; !reflect.DeepEqual(got, want) {
		t.Errorf("follow:\n got  %q\n want %q", got, want)
	}
	var calls = firewallLogCalls(f)
	if calls[0].Query.Has("digest") || calls[1].Query.Get("digest") != all[1]["__digest__"] {
		t.Errorf("first poll must continue after the newest record of the tail: %v", calls[:2])
	}
	if f.streamConnections(firewallStreamPath) != 0 {
		t.Error("follow must poll, not use the lossy stream")
	}
}

func TestFirewallLogFollowPollErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		status     int
		wantExit   int
		wantStderr string
	}{
		{"401 ends follow", 401, 1, "401"},
		{"404 ends follow", 404, 1, "404"},
		{"500 is retried", 500, 0, "retrying"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on("GET", firewallNamesPath, 200, firewallNames)
			var all = []map[string]any{firewallEntry(1, nil), firewallEntry(2, nil)}
			var ok = firewallLogHandler(all, func(request int) int { return min(1+request/2, 2) })
			var mu sync.Mutex
			var requests int
			f.onFunc("GET", firewallLogPath, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				var n = requests
				requests++
				mu.Unlock()
				if n == 1 { // the first poll fails
					w.WriteHeader(tc.status)
					_, _ = fmt.Fprintf(w, `{"status":%d,"message":"poll failed"}`, tc.status)
					return
				}
				ok(w, r)
			})
			var p = f.start("/firewall/log", "print", "follow", "interval=20ms")
			var r runResult
			if tc.wantExit == 0 {
				p.waitFor(firewallLine(2)) // after the 1s backoff
				r = p.interrupt()
			} else {
				r = p.wait()
			}
			wantExit(t, r, tc.wantExit)
			wantContains(t, "stderr", r.stderr, tc.wantStderr)
			if strings.Count(r.stdout, firewallLine(1)) != 1 {
				t.Errorf("record 1 must be printed exactly once:\n%s", r.stdout)
			}
		})
	}
}

// stream: OPNsense replays the last records on every (re)connect, they must not be printed twice
func TestFirewallLogStream(t *testing.T) {
	t.Parallel()
	var e = []map[string]any{nil, firewallEntry(1, nil), firewallEntry(2, nil), firewallEntry(3, nil), firewallEntry(4, nil), firewallEntry(5, nil)}
	var f = newFirewallFake(t, e[1], e[2])
	f.stream(firewallStreamPath,
		sseConn{Keepalive: true, Drop: true, Events: []string{firewallStreamEntry(e[1]), firewallStreamEntry(e[2]), firewallStreamEntry(e[3])}},
		sseConn{Keepalive: true, Events: []string{firewallStreamEntry(e[2]), firewallStreamEntry(e[3]), firewallStreamEntry(e[4]),
			"event: message\ndata: ", firewallStreamEntry(e[5])}},
	)
	var p = f.start("/firewall/log", "print", "stream", "lines=2")
	p.waitFor(firewallLine(5))
	var r = p.interrupt()
	wantExit(t, r, 0)
	var want = []string{firewallLine(1), firewallLine(2), firewallLine(3), firewallLine(4), firewallLine(5)}
	if got := logStdoutLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("stream:\n got  %q\n want %q", got, want)
	}
	wantNotContains(t, "output", r.stdout+r.stderr, "keepalive")
	wantContains(t, "stderr", r.stderr, "reconnecting")
	if n := f.streamConnections(firewallStreamPath); n != 2 {
		t.Errorf("want 2 stream connections, got %d", n)
	}
	if len(firewallLogCalls(f)) != 1 {
		t.Errorf("stream must not poll the log: %v", firewallLogCalls(f))
	}
}

func TestFirewallLogStreamJsonAndFilter(t *testing.T) {
	t.Parallel()
	var f = newFirewallFake(t)
	var blocked = firewallEntry(7, map[string]any{"action": "block"})
	f.stream(firewallStreamPath, sseConn{Keepalive: true, Events: []string{firewallStreamEntry(firewallEntry(6, nil)), firewallStreamEntry(blocked)}})
	var p = f.start("/firewall/log", "print", "stream", "lines=0", "json", "action=block")
	p.waitFor(`"action":"block"`)
	var r = p.interrupt()
	wantExit(t, r, 0)
	var lines = logStdoutLines(r.stdout)
	if len(lines) != 1 {
		t.Fatalf("want only the blocked record:\n%s", r.stdout)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil || record["__timestamp__"] != blocked["__timestamp__"] {
		t.Errorf("not the raw JSON record: %v: %s", err, lines[0])
	}
}

func TestFirewallLogFiltersCommand(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", firewallNamesPath, 200, firewallNames)
	f.on("GET", firewallFiltersPath, 200, firewallFilters)
	var r = f.run("/firewall/log", "filters")
	wantExit(t, r, 0)
	var got = firewallParseFields(r.stdout)
	var want = map[string]string{
		"action":    "pass, block, rdr, nat, binat",
		"interface": "LAN, Loopback, WAN",
		"devices":   "lo0 (Loopback), vtnet0 (LAN), vtnet1 (WAN)",
		"dir":       "in, out",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("filters:\n got  %q\n want %q", got, want)
	}
	wantNoMutations(t, f)

	f.on("GET", firewallFiltersPath, 403, `{"status":403,"message":"Forbidden"}`)
	wantFailure(t, f.run("/firewall/log", "filters"), "403")
}

func TestFirewallLogStats(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", firewallStatsPath, 200, `[{"label":"LAN","value":120},{"label":"WAN","value":7},{"label":"other","value":0}]`)
	var r = f.run("/firewall/log", "stats")
	wantExit(t, r, 0)
	if got, want := logTableRows(r.stdout), [][]string{{"INTERFACE", "COUNT"}, {"LAN", "120"}, {"WAN", "7"}, {"other", "0"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("stats:\n got  %q\n want %q", got, want)
	}
	if call := f.calls()[0]; call.Query.Get("group_by") != "interface" || call.Query.Get("limit") != "5000" {
		t.Errorf("stats request: %s", call)
	}

	r = f.run("/firewall/log", "stats", "by=proto", "scan=100")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "PROTONAME")
	if call := f.calls()[1]; call.Query.Get("group_by") != "protoname" || call.Query.Get("limit") != "100" {
		t.Errorf("stats request: %s", call)
	}

	r = f.run("/firewall/log", "stats", "by=rule")
	wantExit(t, r, 0)
	if call := f.calls()[2]; call.Query.Get("group_by") != "label" {
		t.Errorf("stats request: %s", call)
	}

	r = f.run("/firewall/log", "stats", "json")
	wantExit(t, r, 0)
	if r.stdout != `{"label":"LAN","value":120}`+"\n"+`{"label":"WAN","value":7}`+"\n"+`{"label":"other","value":0}`+"\n" {
		t.Errorf("stats json:\n%s", r.stdout)
	}

	var calls = len(f.calls())
	wantFailure(t, f.run("/firewall/log", "stats", "scan=-5"), "scan", "negative")
	if len(f.calls()) != calls {
		t.Errorf("invalid scan must not be sent")
	}
	wantNoMutations(t, f)
}

func TestFirewallHelp(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var r = f.run("/firewall", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "/firewall:", "log")
	r = f.run("/firewall/log", "print", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "lines=<number>", "default 50", "follow[=yes|no]", "stream[=yes|no]",
		"interval=<duration>", "default 1s", "dir=in|out", "src=<string>", "scan=<number>", "default 1000", "json[=yes|no]")
	wantNoCalls(t, f)
}
