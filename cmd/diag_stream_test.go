package cmd

// Cross-cutting tests of all diag commands that stream (text/event-stream) or poll until Ctrl-C

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type diagStreamCase struct {
	name   string
	args   []string
	path   string           // the event stream endpoint
	setup  func(f *fakeOPN) // other endpoints the command needs
	events []string         // events printing want
	want   string           // printed for events
	replay []string         // events of a second connection after a drop, default events
}

const diagTrafficStreamPath = "/api/diagnostics/traffic/stream/1"
const diagCpuStreamPath = "/api/diagnostics/cpu_usage/stream"

func diagTrafficEvent(time string, inbytes int) string {
	return sseData(`{"interfaces":{"lan":{"inbytes":` + strconv.Itoa(inbytes) + `,"outbytes":469,"inpkts":1,"outpkts":2,"inerrs":0,"outerrs":0,"collisions":0,"name":"LAN"}},"time":` + time + `}`)
}

// diagStreamCases are all commands reading an event stream until Ctrl-C
var diagStreamCases = []diagStreamCase{
	{
		name: "log show --follow", args: []string{"diag", "log", "show", "core/system", "-f"}, path: diagLogLivePath,
		events: []string{diagLogBacklog(diagLogRows[2]), diagLogNew(diagLogRows[1])},
		want:   "link state changed to UP",
		// the reconnect asks for the 2 remembered lines as backlog
		replay: []string{diagLogBacklog(diagLogRows[2]), diagLogBacklog(diagLogRows[1]), diagLogNew(diagLogRows[0])},
	},
	{
		name: "firewall log --stream", args: []string{"diag", "firewall", "log", "--stream", "-n", "0"}, path: diagFwStreamPath,
		setup: func(f *fakeOPN) {
			f.on("GET", diagFwNamesPath, 200, diagFwNames)
			f.on("GET", diagFwLogPath, 200, `[]`)
		},
		events: []string{diagFwStreamEntry(diagFwEntry(1, nil)), diagFwStreamEntry(diagFwEntry(2, nil))},
		want:   diagFwLine(2),
	},
	{
		name: "traffic --follow", args: []string{"diag", "traffic", "-f"}, path: diagTrafficStreamPath,
		events: []string{diagTrafficEvent("1792886639.0", 0), diagTrafficEvent("1792886640.0", 1000), diagTrafficEvent("1792886641.0", 2000)},
		want:   "16.0 kbit/s",
	},
	{
		name: "traffic --follow --json", args: []string{"diag", "traffic", "-f", "--json"}, path: diagTrafficStreamPath,
		events: []string{diagTrafficEvent("1792886639.0", 0), diagTrafficEvent("1792886640.0", 1000)},
		want:   `"inbytes":1000`,
	},
	{
		name: "cpu --follow", args: []string{"diag", "cpu", "-f"}, path: diagCpuStreamPath,
		events: []string{sseData(`{"total":3,"user":2,"nice":0,"sys":1,"intr":0,"idle":97}`), sseData(`{"total":42,"user":30,"nice":0,"sys":10,"intr":2,"idle":58}`)},
		want:   "42%",
	},
}

func (tc diagStreamCase) fake(t *testing.T, conns ...sseConn) *fakeOPN {
	var f = newFakeOPN(t)
	if tc.setup != nil {
		tc.setup(f)
	}
	f.stream(tc.path, conns...)
	return f
}

// Ctrl-C (and SIGTERM) end a follow run cleanly: exit 0, everything received printed, keepalives never
func TestDiagStreamInterrupt(t *testing.T) {
	t.Parallel()
	for _, tc := range diagStreamCases {
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
func TestDiagStreamIdle(t *testing.T) {
	t.Parallel()
	for _, tc := range diagStreamCases {
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
func TestDiagStreamErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range diagStreamCases {
		for _, sc := range []struct {
			name    string
			conn    sseConn
			wantErr []string
		}{
			{"404", sseConn{Status: 404, ContentType: "text/html", Body: "<html><body>Not Found</body></html>"}, []string{"404"}},
			{"403", sseConn{Status: 403, ContentType: "application/json", Body: `{"status":403,"message":"Forbidden"}`}, []string{"403"}},
			{"json instead of a stream", sseConn{Status: 200, ContentType: "application/json", Body: `{"status":"ok"}`}, []string{"event stream", "application/json"}},
			{"empty 200", sseConn{Status: 200, ContentType: "text/html; charset=UTF-8"}, []string{"event stream"}},
		} {
			t.Run(tc.name+"/"+sc.name, func(t *testing.T) {
				t.Parallel()
				var f = tc.fake(t, sc.conn)
				var p = f.start(tc.args...)
				var r = p.wait()
				wantFailure(t, r, sc.wantErr...)
				if n := f.streamConnections(tc.path); n != 1 {
					t.Errorf("want no retry of a permanent error, got %d connections", n)
				}
			})
		}
	}
}

// garbage in an event (e.g. a PHP error page) ends the command with a message, it is never printed as data
func TestDiagStreamInvalidEvent(t *testing.T) {
	t.Parallel()
	for _, tc := range diagStreamCases {
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

// what happens when OPNsense closes the stream in the middle of --follow (e.g. a web GUI restart):
// either reconnect without printing anything twice, or end with a non-zero exit and a message - never hang or exit 0
func TestDiagStreamDropped(t *testing.T) {
	t.Parallel()
	for _, tc := range diagStreamCases {
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
			if !p.running() {
				var r = p.result()
				t.Logf("no reconnect, exit %d: %s", r.code, strings.TrimSpace(r.stderr))
				wantExit(t, r, 1)
				if strings.TrimSpace(r.stderr) == "" {
					t.Error("ended without a message")
				}
				return
			}
			if f.streamConnections(tc.path) < 2 {
				t.Fatalf("neither reconnected nor exited after the stream was closed:\n%s", p.result())
			}
			time.Sleep(200 * time.Millisecond)
			var r = p.interrupt()
			wantExit(t, r, 0)
			t.Logf("reconnected: %s", strings.TrimSpace(r.stderr))
			if tc.path == diagLogLivePath || tc.path == diagFwStreamPath {
				// these replay the backlog on reconnect, which must be de-duplicated
				if n := strings.Count(r.stdout, tc.want); n != 1 {
					t.Errorf("%q printed %d times after reconnect:\n%s", tc.want, n, r.stdout)
				}
			}
		})
	}
}

// polling follow commands also end cleanly on Ctrl-C
func TestDiagPollInterrupt(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/diagnostics/activity/get_activity", 200,
		`{"headers":["last pid: 4242;  load averages:  0.10,  0.12,  0.09"],"details":[{"PID":"11","THR":"100003","USERNAME":"root","PRI":"155","NICE":"ki31","SIZE":"0B","RES":"64K","STATE":"RUN","C":"0","TIME":"9:59","WCPU":"99.00%","COMMAND":"[idle{idle: cpu0}]"}]}`)
	var p = f.start("diag", "activity", "-f", "--json", "--interval", "20ms")
	p.waitFor(`"headers"`)
	f.waitForConnections("/api/diagnostics/activity/get_activity", 3)
	var r = p.interrupt()
	wantExit(t, r, 0)
	for i, line := range stdoutLines(r.stdout) {
		if !strings.HasPrefix(line, `{"headers"`) {
			t.Errorf("line %d is not an ndjson record: %q", i, line)
		}
	}
}
