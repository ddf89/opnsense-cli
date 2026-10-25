package cmd

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

const diagMenuPath = "/api/core/menu/tree"

// diagMenuTree is a trimmed api/core/menu/tree answer: "system" exists in core and a plugin, "access" only in two plugins
const diagMenuTree = `[
 {"VisibleName":"System","Url":"","Children":[
  {"VisibleName":"Log Files","Url":"","Children":[
   {"VisibleName":"General","Url":"/ui/diagnostics/log/core/system","Children":[]},
   {"VisibleName":"Backend","Url":"/ui/diagnostics/log/core/configd","Children":[]}]}]},
 {"VisibleName":"Services","Url":"","Children":[
  {"VisibleName":"Dnsmasq DNS & DHCP","Url":"","Children":[
   {"VisibleName":"Log File","Url":"/ui/diagnostics/log/core/dnsmasq","Children":[]}]},
  {"VisibleName":"Foo","Url":"","Children":[
   {"VisibleName":"Log File","Url":"/ui/diagnostics/log/foo/system","Children":[]}]},
  {"VisibleName":"Proxy","Url":"","Children":[
   {"VisibleName":"Access Log","Url":"/ui/diagnostics/log/bar/access","Children":[]},
   {"VisibleName":"Other Access Log","Url":"/ui/diagnostics/log/baz/access","Children":[]}]}]}
]`

// diagLogRow is a 26.7 log search row
func diagLogRow(timestamp string, severity string, process string, pid string, rnum int, line string) map[string]any {
	return map[string]any{"timestamp": timestamp, "parser": "SysLogFormatRFC5424", "facility": 3, "severity": severity,
		"process_name": process, "pid": pid, "rnum": rnum, "line": line}
}

func diagJSON(value any) string {
	var encoded, _ = json.Marshal(value)
	return string(encoded)
}

// newest first, as OPNsense answers
var diagLogRows = []map[string]any{
	diagLogRow("2026-10-25T00:03:15", "Error", "dhcp6c", "31413", 1, " transmit failed: Network is down"),
	diagLogRow("2026-10-25T00:03:14", "", "kernel", "", 2, " vtnet1: link state changed to UP"),
	diagLogRow("2026-10-25T00:03:13", "Notice", "dhcp6c", "31413", 3, " Sending Solicit on vtnet1"),
}

var diagLogLines = []string{
	"2026-10-25T00:03:13 Notice dhcp6c[31413]: Sending Solicit on vtnet1",
	"2026-10-25T00:03:14 - kernel: vtnet1: link state changed to UP",
	"2026-10-25T00:03:15 Error dhcp6c[31413]: transmit failed: Network is down",
}

func diagLogAnswer(rows []map[string]any) string {
	return diagJSON(map[string]any{"filters": "", "rows": rows, "total_rows": len(rows) + 1, "origin": "system",
		"rowCount": len(rows), "total": len(rows) + 1, "current": 1})
}

func stdoutLines(stdout string) []string {
	var trimmed = strings.TrimRight(stdout, "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func TestDiagLogList(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", diagMenuPath, 200, diagMenuTree)
	var r = f.run("diag", "log", "list")
	wantExit(t, r, 0)
	var want = [][]string{
		{"NAME", "MODULE", "SCOPE", "MENU"},
		{"core/system", "core", "system", "System > Log Files > General"},
		{"configd", "core", "configd", "System > Log Files > Backend"},
		{"dnsmasq", "core", "dnsmasq", "Services > Dnsmasq DNS & DHCP > Log File"},
		{"foo/system", "foo", "system", "Services > Foo > Log File"},
		{"bar/access", "bar", "access", "Services > Proxy > Access Log"},
		{"baz/access", "baz", "access", "Services > Proxy > Other Access Log"},
	}
	if got := tableRows(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("table:\n got  %q\n want %q", got, want)
	}
	wantNoMutations(t, f)
}

func TestDiagLogShowTail(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		args     []string
		wantPath string
		wantBody map[string]any
		menu     bool // the name is resolved with the menu
	}{
		{name: "defaults", args: []string{"system"}, wantPath: "/api/diagnostics/log/core/system",
			wantBody: map[string]any{"current": 1.0, "rowCount": 50.0, "searchPhrase": "", "severity": ""}, menu: true},
		{name: "module/scope skips the menu", args: []string{"core/configd", "-n", "3"}, wantPath: "/api/diagnostics/log/core/configd",
			wantBody: map[string]any{"current": 1.0, "rowCount": 3.0, "searchPhrase": "", "severity": ""}},
		{name: "plugin log by unique scope", args: []string{"dnsmasq", "--lines", "9999"}, wantPath: "/api/diagnostics/log/core/dnsmasq",
			wantBody: map[string]any{"current": 1.0, "rowCount": 9999.0, "searchPhrase": "", "severity": ""}, menu: true},
		{name: "plugin log by module/scope", args: []string{"foo/system"}, wantPath: "/api/diagnostics/log/foo/system",
			wantBody: map[string]any{"current": 1.0, "rowCount": 50.0, "searchPhrase": "", "severity": ""}},
		{name: "filters", args: []string{"core/system", "--search", "vtnet1 solicit", "--severity", "err,Warn,notice,INFO,crit,emerg,alert,debug"},
			wantPath: "/api/diagnostics/log/core/system",
			wantBody: map[string]any{"current": 1.0, "rowCount": 50.0, "searchPhrase": "vtnet1 solicit",
				"severity": "Error,Warning,Notice,Informational,Critical,Emergency,Alert,Debug"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on("GET", diagMenuPath, 200, diagMenuTree)
			f.on("POST", tc.wantPath, 200, diagLogAnswer(diagLogRows))
			var r = f.run(append([]string{"diag", "log", "show"}, tc.args...)...)
			wantExit(t, r, 0)
			if got := stdoutLines(r.stdout); !reflect.DeepEqual(got, diagLogLines) {
				t.Errorf("want oldest first:\n got  %q\n want %q", got, diagLogLines)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", tc.wantPath), tc.wantBody)
			if menuCalls := f.streamConnections(diagMenuPath); (menuCalls > 0) != tc.menu {
				t.Errorf("menu lookups: %d, want lookup %v", menuCalls, tc.menu)
			}
		})
	}
}

func TestDiagLogShowJson(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", "/api/diagnostics/log/core/system", 200, diagLogAnswer(diagLogRows))
	var r = f.run("diag", "log", "show", "core/system", "--json")
	wantExit(t, r, 0)
	var lines = stdoutLines(r.stdout)
	if len(lines) != 3 {
		t.Fatalf("want 3 ndjson lines:\n%s", r.stdout)
	}
	for i, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("line %d is not JSON: %v: %s", i, err, line)
		}
		var source = diagLogRows[len(diagLogRows)-1-i]
		for _, key := range []string{"timestamp", "severity", "process_name", "pid", "parser"} {
			if record[key] != source[key] {
				t.Errorf("line %d %s = %v, want %v", i, key, record[key], source[key])
			}
		}
		if record["line"] != strings.TrimSpace(source["line"].(string)) {
			t.Errorf("line %d line = %q, want it trimmed", i, record["line"])
		}
	}
}

func TestDiagLogShowEmpty(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	// OPNsense answers unknown logs like empty ones, so module/scope names are passed on unchecked
	f.on("POST", "/api/diagnostics/log/core/nosuchlog", 200, diagLogAnswer(nil))
	var r = f.run("diag", "log", "show", "core/nosuchlog")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("stdout must be empty: %q", r.stdout)
	}
	wantContains(t, "stderr", r.stderr, "No lines found", "core/nosuchlog")
}

func TestDiagLogShowUnknownName(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"nosuchlog"}, {"nosuchlog", "-f"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on("GET", diagMenuPath, 200, diagMenuTree)
			var r = f.run(append([]string{"diag", "log", "show"}, args...)...)
			wantFailure(t, r, "nosuchlog", "opn diag log list")
			// the log search is a POST, so this also proves the unknown log was not queried
			wantNoMutations(t, f)
		})
	}
}

func TestDiagLogShowZeroLinesIsQuiet(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var r = f.run("diag", "log", "show", "core/system", "-n", "0")
	wantExit(t, r, 0)
	if r.stdout != "" || strings.Contains(r.stderr, "No lines found") {
		t.Errorf("-n 0 must print nothing, got stdout %q stderr %q", r.stdout, r.stderr)
	}
}

func TestDiagLogShowErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		args    []string
		wantErr []string
		noCalls bool
	}{
		{name: "missing name", args: nil, wantErr: []string{"accepts 1 arg"}, noCalls: true},
		{name: "two names", args: []string{"system", "configd"}, wantErr: []string{"accepts 1 arg"}, noCalls: true},
		{name: "negative lines", args: []string{"system", "-n", "-1"}, wantErr: []string{"--lines"}, noCalls: true},
		{name: "too many lines", args: []string{"system", "-n", "10000"}, wantErr: []string{"--lines"}, noCalls: true},
		{name: "unknown severity", args: []string{"system", "--severity", "error,loud"}, wantErr: []string{"--severity", "loud", "Informational"}, noCalls: true},
		{name: "invalid name", args: []string{"core/system/x"}, wantErr: []string{"invalid log name"}, noCalls: true},
		{name: "empty module", args: []string{"/system"}, wantErr: []string{"invalid log name"}, noCalls: true},
		{name: "scope only in several plugins", args: []string{"access"}, wantErr: []string{"bar/access", "baz/access"}},
		{name: "server error", args: []string{"core/broken"}, wantErr: []string{"500"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on("GET", diagMenuPath, 200, diagMenuTree)
			f.on("POST", "/api/diagnostics/log/core/broken", 500, `{"message":"internal error"}`)
			var r = f.run(append([]string{"diag", "log", "show"}, tc.args...)...)
			wantFailure(t, r, tc.wantErr...)
			if tc.noCalls {
				wantNoCalls(t, f)
			}
		})
	}
}

func TestDiagLogClear(t *testing.T) {
	t.Parallel()
	t.Run("requires --yes", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		var r = f.run("diag", "log", "clear", "core/system")
		wantFailure(t, r, "--yes")
		wantNoCalls(t, f)
	})
	t.Run("clears", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", diagMenuPath, 200, diagMenuTree)
		f.on("POST", "/api/diagnostics/log/core/configd/clear", 200, `{"status":"ok"}`)
		var r = f.run("diag", "log", "clear", "configd", "--yes")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "core/configd")
		wantOneMutation(t, f, "POST", "/api/diagnostics/log/core/configd/clear")
	})
	t.Run("failure", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("POST", "/api/diagnostics/log/core/configd/clear", 200, `{"status":"failed"}`)
		var r = f.run("diag", "log", "clear", "core/configd", "--yes")
		wantExit(t, r, 1)
		wantContains(t, "output", r.stderr, "failed")
		wantNotContains(t, "stdout", r.stdout, "cleared")
	})
}

// --- --follow

const diagLogLivePath = "/api/diagnostics/log/core/system/live"

// diagLogBacklog is a live stream backlog event (SSE event "message"), diagLogNew a new line (SSE event "log")
func diagLogBacklog(row map[string]any) string {
	return sseData(diagJSON(row))
}

func diagLogNew(row map[string]any) string {
	var live = withFields(row, map[string]any{"rnum": 0, "line": row["line"].(string) + "\n"})
	return "event: log\n" + sseData(diagJSON(live))
}

func diagLogNumbered(n int) map[string]any {
	return diagLogRow(fmt.Sprintf("2026-10-25T01:00:%02d", n), "Notice", "test", "1", 0, fmt.Sprintf(" line %d", n))
}

func diagLogNumberedLine(n int) string {
	return fmt.Sprintf("2026-10-25T01:00:%02d Notice test[1]: line %d", n, n)
}

func TestDiagLogFollow(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.stream(diagLogLivePath, sseConn{Keepalive: true, Events: []string{
		diagLogBacklog(diagLogRows[2]), diagLogBacklog(diagLogRows[1]), // backlog, oldest first
		diagLogNew(diagLogRows[0]),
		"event: unknown\ndata: {\"ignored\":true}",
		diagLogNew(diagLogNumbered(1)),
	}})
	f.on("GET", diagMenuPath, 200, diagMenuTree)

	var p = f.start("diag", "log", "show", "system", "--follow", "-n", "2", "--search", "vtnet1", "--severity", "notice,err")
	p.waitFor(diagLogNumberedLine(1))
	var r = p.interrupt()
	wantExit(t, r, 0)
	var want = append(append([]string{}, diagLogLines...), diagLogNumberedLine(1))
	if got := stdoutLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("follow output:\n got  %q\n want %q", got, want)
	}
	wantNotContains(t, "output", r.stdout+r.stderr, "keepalive", "ignored")

	var calls = f.calls()
	var live = calls[len(calls)-1]
	if live.Path != diagLogLivePath || live.Query.Get("offset") != "2" || live.Query.Get("searchPhrase") != "vtnet1" ||
		live.Query.Get("severity") != "Notice,Error" {
		t.Errorf("live request: %s", live)
	}
	wantNoMutations(t, f) // the stream sends the tail itself, no separate search
}

func TestDiagLogFollowJson(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.stream(diagLogLivePath, sseConn{Keepalive: true, Events: []string{
		diagLogBacklog(diagLogRows[2]), diagLogNew(diagLogNumbered(1)), diagLogNew(diagLogNumbered(2)),
	}})
	var p = f.start("diag", "log", "show", "core/system", "-f", "--json")
	p.waitFor(`line 2"`)
	var r = p.interrupt()
	wantExit(t, r, 0)
	var lines = stdoutLines(r.stdout)
	if len(lines) != 3 {
		t.Fatalf("want 3 ndjson lines:\n%s", r.stdout)
	}
	for i, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Errorf("line %d is not JSON: %v: %s", i, err, line)
		}
		if strings.HasSuffix(record["line"].(string), "\n") || strings.HasPrefix(record["line"].(string), " ") {
			t.Errorf("line %d not trimmed: %q", i, record["line"])
		}
	}
	if live := f.calls()[0]; live.Query.Get("offset") != "50" {
		t.Errorf("default -n with --follow: offset %q, want 50", live.Query.Get("offset"))
	}
}

func TestDiagLogFollowOnlyNewLines(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.stream(diagLogLivePath, sseConn{Keepalive: true})
	var p = f.start("diag", "log", "show", "core/system", "-f", "-n", "0")
	// keepalives only: wait until the stream is connected, then the process must keep running silently
	f.waitForConnections(diagLogLivePath, 1)
	time.Sleep(300 * time.Millisecond)
	if !p.running() {
		t.Fatalf("opn exited on an idle stream:\n%s", p.result())
	}
	var r = p.interrupt()
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("keepalives must not be printed: %q", r.stdout)
	}
	if live := f.calls()[0]; live.Query.Get("offset") != "0" {
		t.Errorf("offset %q, want 0", live.Query.Get("offset"))
	}
}

// a dropped stream is reconnected, the backlog of the new stream recovers missed lines without printing any line twice
func TestDiagLogFollowReconnect(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.stream(diagLogLivePath,
		sseConn{Drop: true, Events: []string{
			diagLogBacklog(diagLogNumbered(1)), diagLogBacklog(diagLogNumbered(2)), diagLogNew(diagLogNumbered(3)),
		}},
		// reconnect asks for the remembered lines as backlog: 2 and 3 are known, 4 was logged during the outage
		sseConn{Keepalive: true, Events: []string{
			diagLogBacklog(diagLogNumbered(2)), diagLogBacklog(diagLogNumbered(3)), diagLogBacklog(diagLogNumbered(4)),
			diagLogNew(diagLogNumbered(5)),
		}},
	)
	var p = f.start("diag", "log", "show", "core/system", "-f", "-n", "2")
	p.waitFor(diagLogNumberedLine(5))
	var r = p.interrupt()
	wantExit(t, r, 0)
	var want = []string{diagLogNumberedLine(1), diagLogNumberedLine(2), diagLogNumberedLine(3), diagLogNumberedLine(4), diagLogNumberedLine(5)}
	if got := stdoutLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("after reconnect:\n got  %q\n want %q", got, want)
	}
	wantContains(t, "stderr", r.stderr, "reconnecting")
	var offsets []string
	for _, call := range f.calls() {
		offsets = append(offsets, call.Query.Get("offset"))
	}
	if !reflect.DeepEqual(offsets, []string{"2", "3"}) {
		t.Errorf("live offsets %q, want first the tail (2) then the remembered lines (3)", offsets)
	}
}

func TestDiagLogFollowStreamErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		conn    sseConn
		wantErr []string
	}{
		{"404", sseConn{Status: 404, ContentType: "text/html", Body: "<html>Page not found</html>"}, []string{"404"}},
		{"401", sseConn{Status: 401, ContentType: "application/json", Body: `{"status":401,"message":"Authentication Failed"}`}, []string{"401"}},
		{"not an event stream", sseConn{Status: 200, ContentType: "application/json", Body: `{"status":"ok"}`}, []string{"event stream", "application/json"}},
		{"empty 200", sseConn{Status: 200, ContentType: "text/html"}, []string{"event stream"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.stream(diagLogLivePath, tc.conn)
			var r = f.run("diag", "log", "show", "core/system", "-f")
			wantFailure(t, r, tc.wantErr...)
			if r.stdout != "" {
				t.Errorf("stdout must be empty: %q", r.stdout)
			}
			if n := f.streamConnections(diagLogLivePath); n != 1 {
				t.Errorf("want no reconnect for a permanent error, got %d connections", n)
			}
		})
	}
}

// Ctrl-C while waiting to reconnect a dropped stream ends the command at once with exit 0
func TestDiagLogFollowInterruptWhileReconnecting(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.stream(diagLogLivePath, sseConn{Drop: true, Events: []string{diagLogBacklog(diagLogNumbered(1))}})
	var p = f.start("diag", "log", "show", "core/system", "-f")
	p.waitFor(diagLogNumberedLine(1))
	var deadline = time.Now().Add(5 * time.Second)
	for !strings.Contains(p.stderr.String(), "reconnecting") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	var started = time.Now()
	var r = p.interrupt()
	wantExit(t, r, 0)
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Errorf("exit took %s, the reconnect wait must be interruptible", elapsed)
	}
	if got := stdoutLines(r.stdout); len(got) != 1 {
		t.Errorf("want the one line:\n%s", r.stdout)
	}
}
