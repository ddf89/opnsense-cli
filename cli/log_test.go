package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

const logMenuPath = "/api/core/menu/tree"

// logMenuTree is a trimmed api/core/menu/tree answer: "system" exists in core and a plugin, "access" only in two plugins
const logMenuTree = `[
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

// logRow is a 26.7 log search row
func logRow(timestamp string, severity string, process string, pid string, rnum int, line string) map[string]any {
	return map[string]any{"timestamp": timestamp, "parser": "SysLogFormatRFC5424", "facility": 3, "severity": severity,
		"process_name": process, "pid": pid, "rnum": rnum, "line": line}
}

func logJSON(value any) string {
	var encoded, _ = json.Marshal(value)
	return string(encoded)
}

// newest first, as OPNsense answers
var logRows = []map[string]any{
	logRow("2026-10-25T00:03:15", "Error", "dhcp6c", "31413", 1, " transmit failed: Network is down"),
	logRow("2026-10-25T00:03:14", "", "kernel", "", 2, " vtnet1: link state changed to UP"),
	logRow("2026-10-25T00:03:13", "Notice", "dhcp6c", "31413", 3, " Sending Solicit on vtnet1"),
}

var logRowLines = []string{
	"2026-10-25T00:03:13 Notice dhcp6c[31413]: Sending Solicit on vtnet1",
	"2026-10-25T00:03:14 - kernel: vtnet1: link state changed to UP",
	"2026-10-25T00:03:15 Error dhcp6c[31413]: transmit failed: Network is down",
}

func logAnswer(rows []map[string]any) string {
	return logJSON(map[string]any{"filters": "", "rows": rows, "total_rows": len(rows) + 1, "origin": "system",
		"rowCount": len(rows), "total": len(rows) + 1, "current": 1})
}

// logStdoutLines splits output into lines, nil for no output
func logStdoutLines(stdout string) []string {
	var trimmed = strings.TrimRight(stdout, "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

var logColumnGap = regexp.MustCompile(`\s{2,}`)

// logTableRows splits a table (columns separated by at least 2 spaces) into its cells
func logTableRows(stdout string) [][]string {
	var rows [][]string
	for _, line := range logStdoutLines(stdout) {
		rows = append(rows, logColumnGap.Split(strings.TrimSpace(line), -1))
	}
	return rows
}

func TestLogFiles(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", logMenuPath, 200, logMenuTree)
	var r = f.run("/log", "files")
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
	if got := logTableRows(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("table:\n got  %q\n want %q", got, want)
	}
	wantNoMutations(t, f)

	var asJSON = f.run("/log", "files", "json")
	wantExit(t, asJSON, 0)
	wantContains(t, "stdout", asJSON.stdout,
		`{"menu":"System > Log Files > Backend","module":"core","name":"configd","scope":"configd"}`)
}

func TestLogPrintTail(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		args     []string
		wantPath string
		wantBody map[string]any
		menu     bool // the name is resolved with the menu
	}{
		{name: "defaults to the system log", args: nil, wantPath: "/api/diagnostics/log/core/system",
			wantBody: map[string]any{"current": 1.0, "rowCount": 50.0, "searchPhrase": "", "severity": ""}, menu: true},
		{name: "positional name", args: []string{"system"}, wantPath: "/api/diagnostics/log/core/system",
			wantBody: map[string]any{"current": 1.0, "rowCount": 50.0, "searchPhrase": "", "severity": ""}, menu: true},
		{name: "module/scope skips the menu", args: []string{"log=core/configd", "lines=3"}, wantPath: "/api/diagnostics/log/core/configd",
			wantBody: map[string]any{"current": 1.0, "rowCount": 3.0, "searchPhrase": "", "severity": ""}},
		{name: "plugin log by unique scope", args: []string{"dnsmasq", "lines=9999"}, wantPath: "/api/diagnostics/log/core/dnsmasq",
			wantBody: map[string]any{"current": 1.0, "rowCount": 9999.0, "searchPhrase": "", "severity": ""}, menu: true},
		{name: "plugin log by module/scope", args: []string{"foo/system"}, wantPath: "/api/diagnostics/log/foo/system",
			wantBody: map[string]any{"current": 1.0, "rowCount": 50.0, "searchPhrase": "", "severity": ""}},
		{name: "filters", args: []string{"core/system", "search=vtnet1 solicit", "severity=err,Warn,notice,INFO,crit,emerg,alert,debug"},
			wantPath: "/api/diagnostics/log/core/system",
			wantBody: map[string]any{"current": 1.0, "rowCount": 50.0, "searchPhrase": "vtnet1 solicit",
				"severity": "Error,Warning,Notice,Informational,Critical,Emergency,Alert,Debug"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on("GET", logMenuPath, 200, logMenuTree)
			f.on("POST", tc.wantPath, 200, logAnswer(logRows))
			var r = f.run(append([]string{"/log", "print"}, tc.args...)...)
			wantExit(t, r, 0)
			if got := logStdoutLines(r.stdout); !reflect.DeepEqual(got, logRowLines) {
				t.Errorf("want oldest first:\n got  %q\n want %q", got, logRowLines)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", tc.wantPath), tc.wantBody)
			if menuCalls := f.streamConnections(logMenuPath); (menuCalls > 0) != tc.menu {
				t.Errorf("menu lookups: %d, want lookup %v", menuCalls, tc.menu)
			}
		})
	}
}

func TestLogPrintJson(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", "/api/diagnostics/log/core/system", 200, logAnswer(logRows))
	var r = f.run("/log", "print", "core/system", "json")
	wantExit(t, r, 0)
	var lines = logStdoutLines(r.stdout)
	if len(lines) != 3 {
		t.Fatalf("want 3 ndjson lines:\n%s", r.stdout)
	}
	for i, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("line %d is not JSON: %v: %s", i, err, line)
		}
		var source = logRows[len(logRows)-1-i]
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

func TestLogPrintEmpty(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	// OPNsense answers unknown logs like empty ones, so module/scope names are passed on unchecked
	f.on("POST", "/api/diagnostics/log/core/nosuchlog", 200, logAnswer(nil))
	var r = f.run("/log", "print", "core/nosuchlog")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("stdout must be empty: %q", r.stdout)
	}
	wantContains(t, "stderr", r.stderr, "no lines found", "core/nosuchlog")
}

func TestLogPrintUnknownName(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"nosuchlog"}, {"nosuchlog", "follow"}, {"log=nosuchlog", "json"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on("GET", logMenuPath, 200, logMenuTree)
			var r = f.run(append([]string{"/log", "print"}, args...)...)
			wantFailure(t, r, "nosuchlog", "/log files")
			wantNotContains(t, "output", r.stderr, "diag log list")
			// the log search is a POST and the live stream a GET of .../live, so this proves the log was not read
			wantNoMutations(t, f)
			if calls := f.calls(); len(calls) != 1 || calls[0].Path != logMenuPath {
				t.Errorf("only the menu must be read: %v", calls)
			}
		})
	}
}

func TestLogPrintZeroLinesIsQuiet(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var r = f.run("/log", "print", "core/system", "lines=0")
	wantExit(t, r, 0)
	if r.stdout != "" || strings.Contains(r.stderr, "no lines found") {
		t.Errorf("lines=0 must print nothing, got stdout %q stderr %q", r.stdout, r.stderr)
	}
	wantNoCalls(t, f)
}

func TestLogPrintErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		args    []string
		wantErr []string
		noCalls bool
	}{
		{name: "two names", args: []string{"system", "configd"}, wantErr: []string{"log given twice"}, noCalls: true},
		{name: "negative lines", args: []string{"system", "lines=-1"}, wantErr: []string{"lines", "0 to 9999"}, noCalls: true},
		{name: "too many lines", args: []string{"system", "lines=10000"}, wantErr: []string{"lines", "0 to 9999"}, noCalls: true},
		{name: "lines not a number", args: []string{"system", "lines=many"}, wantErr: []string{"lines", "number"}, noCalls: true},
		{name: "unknown severity", args: []string{"system", "severity=error,loud"}, wantErr: []string{"severity", "loud", "Informational"}, noCalls: true},
		{name: "unknown argument", args: []string{"system", "level=error"}, wantErr: []string{"level"}, noCalls: true},
		{name: "invalid name", args: []string{"core/system/x"}, wantErr: []string{"invalid log name"}, noCalls: true},
		{name: "empty module", args: []string{"/system"}, wantErr: []string{"invalid log name"}, noCalls: true},
		{name: "empty name", args: []string{"log="}, wantErr: []string{"log name must not be empty"}, noCalls: true},
		{name: "scope only in several plugins", args: []string{"access"}, wantErr: []string{"bar/access", "baz/access"}},
		{name: "server error", args: []string{"core/broken"}, wantErr: []string{"500"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on("GET", logMenuPath, 200, logMenuTree)
			f.on("POST", "/api/diagnostics/log/core/broken", 500, `{"message":"internal error"}`)
			var r = f.run(append([]string{"/log", "print"}, tc.args...)...)
			wantFailure(t, r, tc.wantErr...)
			if tc.noCalls {
				wantNoCalls(t, f)
			}
		})
	}
}

func TestLogClear(t *testing.T) {
	t.Parallel()
	t.Run("requires confirm", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		var r = f.run("/log", "clear", "core/system")
		wantFailure(t, r, "confirm=yes", "cannot be undone")
		wantNoCalls(t, f)
	})
	t.Run("requires a log", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		var r = f.run("/log", "clear", "confirm=yes")
		wantFailure(t, r, "log=<string> is required")
		wantNoCalls(t, f)
	})
	t.Run("clears silently", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", logMenuPath, 200, logMenuTree)
		f.on("POST", "/api/diagnostics/log/core/configd/clear", 200, `{"status":"ok"}`)
		var r = f.run("/log", "clear", "configd", "confirm=yes")
		wantExit(t, r, 0)
		if r.stdout != "" {
			t.Errorf("success must be silent: %q", r.stdout)
		}
		wantOneMutation(t, f, "POST", "/api/diagnostics/log/core/configd/clear")
	})
	t.Run("in a script", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("POST", "/api/diagnostics/log/core/configd/clear", 200, `{"status":"ok"}`)
		var r = f.runScript("/log\nclear core/configd\n")
		wantFailure(t, r, "stdin:2:", "confirm=yes")
		wantNoCalls(t, f)
		r = f.runScript("/log\nclear log=core/configd confirm\n")
		wantExit(t, r, 0)
		wantOneMutation(t, f, "POST", "/api/diagnostics/log/core/configd/clear")
	})
	t.Run("unknown log", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", logMenuPath, 200, logMenuTree)
		var r = f.run("/log", "clear", "nosuchlog", "confirm")
		wantFailure(t, r, "nosuchlog", "/log files")
		wantNoMutations(t, f)
	})
	t.Run("failure", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("POST", "/api/diagnostics/log/core/configd/clear", 200, `{"status":"failed"}`)
		var r = f.run("/log", "clear", "core/configd", "confirm=yes")
		wantExit(t, r, 1)
		wantContains(t, "stderr", r.stderr, "failed")
		if r.stdout != "" {
			t.Errorf("stdout must be empty: %q", r.stdout)
		}
	})
}

func TestLogHelp(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var r = f.run("/log", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "/log:", "print", "files", "clear")
	r = f.run("/log", "print", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "log=<string>", "default system", "may be given without name", "lines=<number>",
		"default 50", "follow[=yes|no]", "severity=<list>", "json[=yes|no]")
	r = f.run("/log", "clear", "?")
	wantContains(t, "stdout", r.stdout, "cannot be undone", "confirm[=yes|no]", "required")
	wantNoCalls(t, f)
}

// --- follow

const logLivePath = "/api/diagnostics/log/core/system/live"

// logBacklog is a live stream backlog event (SSE event "message"), logNew a new line (SSE event "log")
func logBacklog(row map[string]any) string {
	return sseData(logJSON(row))
}

func logNew(row map[string]any) string {
	var live = withFields(row, map[string]any{"rnum": 0, "line": row["line"].(string) + "\n"})
	return "event: log\n" + sseData(logJSON(live))
}

func logNumbered(n int) map[string]any {
	return logRow(fmt.Sprintf("2026-10-25T01:00:%02d", n), "Notice", "test", "1", 0, fmt.Sprintf(" line %d", n))
}

func logNumberedLine(n int) string {
	return fmt.Sprintf("2026-10-25T01:00:%02d Notice test[1]: line %d", n, n)
}

func TestLogPrintFollow(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.stream(logLivePath, sseConn{Keepalive: true, Events: []string{
		logBacklog(logRows[2]), logBacklog(logRows[1]), // backlog, oldest first
		logNew(logRows[0]),
		"event: unknown\ndata: {\"ignored\":true}",
		logNew(logNumbered(1)),
	}})
	f.on("GET", logMenuPath, 200, logMenuTree)

	var p = f.start("/log", "print", "follow", "lines=2", "search=vtnet1", "severity=notice,err")
	p.waitFor(logNumberedLine(1))
	var r = p.interrupt()
	wantExit(t, r, 0)
	var want = append(append([]string{}, logRowLines...), logNumberedLine(1))
	if got := logStdoutLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("follow output:\n got  %q\n want %q", got, want)
	}
	wantNotContains(t, "output", r.stdout+r.stderr, "keepalive", "ignored")

	var calls = f.calls()
	var live = calls[len(calls)-1]
	if live.Path != logLivePath || live.Query.Get("offset") != "2" || live.Query.Get("searchPhrase") != "vtnet1" ||
		live.Query.Get("severity") != "Notice,Error" {
		t.Errorf("live request: %s", live)
	}
	wantNoMutations(t, f) // the stream sends the tail itself, no separate search
}

func TestLogPrintFollowJson(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.stream(logLivePath, sseConn{Keepalive: true, Events: []string{
		logBacklog(logRows[2]), logNew(logNumbered(1)), logNew(logNumbered(2)),
	}})
	var p = f.start("/log", "print", "core/system", "follow", "json")
	p.waitFor(`line 2"`)
	var r = p.interrupt()
	wantExit(t, r, 0)
	var lines = logStdoutLines(r.stdout)
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
		t.Errorf("default lines with follow: offset %q, want 50", live.Query.Get("offset"))
	}
}

func TestLogPrintFollowOnlyNewLines(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.stream(logLivePath, sseConn{Keepalive: true})
	var p = f.start("/log", "print", "core/system", "follow", "lines=0")
	// keepalives only: wait until the stream is connected, then the process must keep running silently
	f.waitForConnections(logLivePath, 1)
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
func TestLogPrintFollowReconnect(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.stream(logLivePath,
		sseConn{Drop: true, Events: []string{
			logBacklog(logNumbered(1)), logBacklog(logNumbered(2)), logNew(logNumbered(3)),
		}},
		// reconnect asks for the remembered lines as backlog: 2 and 3 are known, 4 was logged during the outage
		sseConn{Keepalive: true, Events: []string{
			logBacklog(logNumbered(2)), logBacklog(logNumbered(3)), logBacklog(logNumbered(4)),
			logNew(logNumbered(5)),
		}},
	)
	var p = f.start("/log", "print", "core/system", "follow", "lines=2")
	p.waitFor(logNumberedLine(5))
	var r = p.interrupt()
	wantExit(t, r, 0)
	var want = []string{logNumberedLine(1), logNumberedLine(2), logNumberedLine(3), logNumberedLine(4), logNumberedLine(5)}
	if got := logStdoutLines(r.stdout); !reflect.DeepEqual(got, want) {
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

// Ctrl-C while waiting to reconnect a dropped stream ends the command at once with exit 0
func TestLogPrintFollowInterruptWhileReconnecting(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.stream(logLivePath, sseConn{Drop: true, Events: []string{logBacklog(logNumbered(1))}})
	var p = f.start("/log", "print", "core/system", "follow")
	p.waitFor(logNumberedLine(1))
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
	if got := logStdoutLines(r.stdout); len(got) != 1 {
		t.Errorf("want the one line:\n%s", r.stdout)
	}
}

// --- cross-cutting stream behaviour of /log print follow and /firewall/log print stream

type logStreamCase struct {
	name   string
	args   []string
	path   string           // the event stream endpoint
	setup  func(f *fakeOPN) // other endpoints the command needs
	events []string         // events printing want
	want   string           // printed for events
	replay []string         // events of a second connection after a drop, default events
}

var logStreamCases = []logStreamCase{
	{
		name: "log print follow", args: []string{"/log", "print", "core/system", "follow"}, path: logLivePath,
		events: []string{logBacklog(logRows[2]), logNew(logRows[1])},
		want:   "link state changed to UP",
		// the reconnect asks for the 2 remembered lines as backlog
		replay: []string{logBacklog(logRows[2]), logBacklog(logRows[1]), logNew(logRows[0])},
	},
	{
		name: "firewall log print stream", args: []string{"/firewall/log", "print", "stream", "lines=0"}, path: firewallStreamPath,
		setup: func(f *fakeOPN) {
			f.on("GET", firewallNamesPath, 200, firewallNames)
			f.on("GET", firewallLogPath, 200, `[]`)
		},
		events: []string{firewallStreamEntry(firewallEntry(1, nil)), firewallStreamEntry(firewallEntry(2, nil))},
		want:   firewallLine(2),
	},
}

func (tc logStreamCase) fake(t *testing.T, conns ...sseConn) *fakeOPN {
	var f = newFakeOPN(t)
	if tc.setup != nil {
		tc.setup(f)
	}
	f.stream(tc.path, conns...)
	return f
}

// Ctrl-C (and SIGTERM) end a follow run cleanly: exit 0, everything received printed, keepalives never
func TestLogStreamInterrupt(t *testing.T) {
	t.Parallel()
	for _, tc := range logStreamCases {
		for _, signal := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
			t.Run(tc.name+"/"+signal.String(), func(t *testing.T) {
				t.Parallel()
				var f = tc.fake(t, sseConn{Keepalive: true, Events: tc.events})
				var p = f.start(tc.args...)
				p.waitFor(tc.want)
				time.Sleep(120 * time.Millisecond) // a few keepalives while idle
				if err := p.cmd.Process.Signal(signal); err != nil {
					t.Fatal(err)
				}
				var r = p.wait()
				wantExit(t, r, 0)
				wantNotContains(t, "output", r.stdout+r.stderr, "keepalive")
				if strings.Count(r.stdout, tc.want) != 1 {
					t.Errorf("%q printed %d times:\n%s", tc.want, strings.Count(r.stdout, tc.want), r.stdout)
				}
				if n := f.streamConnections(tc.path); n != 1 {
					t.Errorf("want 1 stream connection, got %d", n)
				}
			})
		}
	}
}

// a stream that only sends keepalives keeps the command running silently until Ctrl-C
func TestLogStreamIdle(t *testing.T) {
	t.Parallel()
	for _, tc := range logStreamCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = tc.fake(t, sseConn{Keepalive: true})
			var p = f.start(tc.args...)
			f.waitForConnections(tc.path, 1)
			time.Sleep(200 * time.Millisecond)
			if !p.running() {
				t.Fatalf("exited on an idle stream:\n%s", p.result())
			}
			var r = p.interrupt()
			wantExit(t, r, 0)
			if strings.TrimSpace(r.stdout) != "" {
				t.Errorf("nothing must be printed for keepalives: %q", r.stdout)
			}
		})
	}
}

// permanent stream errors end the command with a clear message instead of retrying forever
func TestLogStreamErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range logStreamCases {
		for _, sc := range []struct {
			name    string
			conn    sseConn
			wantErr []string
		}{
			{"404", sseConn{Status: 404, ContentType: "text/html", Body: "<html><body>Not Found</body></html>"}, []string{"404"}},
			{"401", sseConn{Status: 401, ContentType: "application/json", Body: `{"status":401,"message":"Authentication Failed"}`}, []string{"401"}},
			{"403", sseConn{Status: 403, ContentType: "application/json", Body: `{"status":403,"message":"Forbidden"}`}, []string{"403"}},
			{"json instead of a stream", sseConn{Status: 200, ContentType: "application/json", Body: `{"status":"ok"}`}, []string{"event stream", "application/json"}},
			{"empty 200", sseConn{Status: 200, ContentType: "text/html; charset=UTF-8"}, []string{"event stream"}},
		} {
			t.Run(tc.name+"/"+sc.name, func(t *testing.T) {
				t.Parallel()
				var f = tc.fake(t, sc.conn)
				var r = f.start(tc.args...).wait()
				wantFailure(t, r, sc.wantErr...)
				if r.stdout != "" {
					t.Errorf("stdout must be empty: %q", r.stdout)
				}
				if n := f.streamConnections(tc.path); n != 1 {
					t.Errorf("want no retry of a permanent error, got %d connections", n)
				}
			})
		}
	}
}

// garbage in an event (e.g. a PHP error page) ends the command with a message, it is never printed as data
func TestLogStreamInvalidEvent(t *testing.T) {
	t.Parallel()
	for _, tc := range logStreamCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = tc.fake(t, sseConn{Keepalive: true, Events: []string{sseData("<b>Fatal error</b>: something broke")}})
			var r = f.start(tc.args...).wait()
			wantFailure(t, r, "event")
			if r.stdout != "" {
				t.Errorf("stdout must be empty: %q", r.stdout)
			}
		})
	}
}

// when OPNsense closes the stream in the middle (e.g. a web GUI restart) it is reconnected and the replayed
// backlog is not printed twice
func TestLogStreamDropped(t *testing.T) {
	t.Parallel()
	for _, tc := range logStreamCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var replay = tc.replay
			if replay == nil {
				replay = tc.events
			}
			var f = tc.fake(t, sseConn{Drop: true, Events: tc.events}, sseConn{Keepalive: true, Events: replay})
			var p = f.start(tc.args...)
			p.waitFor(tc.want)
			var deadline = time.Now().Add(3 * time.Second)
			for p.running() && f.streamConnections(tc.path) < 2 && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if f.streamConnections(tc.path) < 2 {
				t.Fatalf("did not reconnect after the stream was closed:\n%s", p.result())
			}
			time.Sleep(200 * time.Millisecond)
			var r = p.interrupt()
			wantExit(t, r, 0)
			wantContains(t, "stderr", r.stderr, "reconnecting")
			if n := strings.Count(r.stdout, tc.want); n != 1 {
				t.Errorf("%q printed %d times after reconnect:\n%s", tc.want, n, r.stdout)
			}
		})
	}
}

// logStartScript runs the CLI in script mode in the background with script as stdin, like f.start
func logStartScript(f *fakeOPN, script string) *opnProcess {
	f.t.Helper()
	var p = &opnProcess{t: f.t, stdout: &syncBuffer{}, stderr: &syncBuffer{}, exited: make(chan struct{})}
	p.cmd = exec.Command(opnBinary)
	p.cmd.Dir = f.t.TempDir()
	p.cmd.Env = append([]string{"TZ=UTC"}, f.env()...)
	p.cmd.Stdin = strings.NewReader(script)
	p.cmd.Stdout = p.stdout
	p.cmd.Stderr = p.stderr
	if err := p.cmd.Start(); err != nil {
		f.t.Fatalf("starting opn: %v", err)
	}
	go func() {
		p.err = p.cmd.Wait()
		close(p.exited)
	}()
	f.t.Cleanup(func() {
		_ = p.cmd.Process.Kill()
		<-p.exited
	})
	return p
}

// Ctrl-C during a follow in a script cancels only that command: the script goes on with the next line
func TestLogStreamInScript(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.stream(logLivePath, sseConn{Keepalive: true, Events: []string{logBacklog(logRows[2])}})
	f.on("GET", logMenuPath, 200, logMenuTree)
	var p = logStartScript(f, "/log\nprint core/system follow\nfiles\n")
	p.waitFor(logRowLines[0])
	var r = p.interrupt()
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, logRowLines[0], "Services > Proxy > Access Log")
}

func TestLogComplete(t *testing.T) {
	t.Parallel()
	var f = newFirewallFake(t)
	f.on("GET", logMenuPath, 200, logMenuTree)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		// the positional log completes without its name, alongside the argument names
		"/log print ": {"bar/access", "baz/access", "configd", "core/system", "dnsmasq", "follow", "foo/system", "json",
			"lines=", "log=", "search=", "severity="},
		"/log print d":                     {"dnsmasq"},
		"/log print con":                   {"configd"},
		"/log clear ba":                    {"bar/access", "baz/access"},
		"/log print log=":                  {"log=bar/access", "log=baz/access", "log=configd", "log=core/system", "log=dnsmasq", "log=foo/system"},
		"/log print log=co":                {"log=configd", "log=core/system"},
		"/log clear log=d":                 {"log=dnsmasq"},
		"/log print severity=err,w":        {"severity=err,warning"},
		"/firewall/log print action=b":     {"action=binat", "action=block"},
		"/firewall/log print interface=v":  {"interface=vtnet0", "interface=vtnet1"},
		"/firewall/log print interface=w":  {"interface=wan"},
		"/firewall/log print dir=":         {"dir=in", "dir=out"},
		"/firewall/log stats by=proto":     {"by=proto", "by=protoname"},
		"/firewall/log print follow strea": {"stream"},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}
