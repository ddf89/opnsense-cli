package cli

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	ifaceTestStream           = "/api/diagnostics/traffic/stream/1"
	ifaceTestInterfaces       = "/api/diagnostics/traffic/interface"
	ifaceTestInterfacesAnswer = `{"interfaces":{"lan":{"device":"vtnet0","mtu":"1500","bytes received":"4908196",` +
		`"bytes transmitted":"15538584","packets received":"24506","packets transmitted":"30761","input errors":"1",` +
		`"output errors":"0","collisions":"0","name":"LAN"},"wan":{"device":"vtnet1","mtu":"1500","bytes received":"507660",` +
		`"bytes transmitted":"118877","packets received":"1245","packets transmitted":"1284","input errors":"0",` +
		`"output errors":"0","collisions":"0","name":"WAN"}},"time":1792886793.949564}`
)

// ifaceTestSample is a traffic stream event of lan (LAN) and wan (WAN, 2 input errors)
func ifaceTestSample(time float64, lanIn int, lanOut int) string {
	return fmt.Sprintf(`{"interfaces":{"lan":{"inbytes":%d,"outbytes":%d,"inpkts":%d,"outpkts":%d,"inerrs":0,"outerrs":0,"collisions":0,"name":"LAN"},`+
		`"wan":{"inbytes":0,"outbytes":0,"inpkts":0,"outpkts":0,"inerrs":2,"outerrs":0,"collisions":0,"name":"WAN"}},"time":%.6f}`,
		lanIn, lanOut, lanIn/100, lanOut/100, time)
}

// ifaceTestEvents turns event data into held open stream connection with keepalives
func ifaceTestEvents(data ...string) sseConn {
	var conn = sseConn{Keepalive: true}
	for _, d := range data {
		conn.Events = append(conn.Events, sseData(d))
	}
	return conn
}

func ifaceTestCount(f *fakeOPN, path string) int {
	var n = 0
	for _, call := range f.calls() {
		if call.Path == path {
			n++
		}
	}
	return n
}

func ifaceTestLines(stdout string) []string {
	var trimmed = strings.TrimRight(stdout, "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

// --- print

func TestInterfacePrint(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", ifaceTestInterfaces, 200, ifaceTestInterfacesAnswer)
	var r = f.run("/interface", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "#", "INTERFACE", "lan", "vtnet0", "1500", "4.9 MB", "15.5 MB", "24506", "wan", "507.7 kB")
	var lines = ifaceTestLines(r.stdout)
	if len(lines) != 3 || !strings.HasPrefix(lines[1], "0  lan") || !strings.HasSuffix(lines[1], "1") || !strings.HasPrefix(lines[2], "1  wan") {
		t.Errorf("want header, #0 lan (1 error), #1 wan:\n%s", r.stdout)
	}

	r = f.run("/interface", "print", "detail")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "0\n  interface:", "lan", "bytes received:", "4908196", "1\n  interface:", "vtnet1")

	r = f.run("/interface", "print", "json")
	wantExit(t, r, 0)
	var jsonLines = ifaceTestLines(r.stdout)
	if len(jsonLines) != 2 {
		t.Fatalf("want one JSON object per interface:\n%s", r.stdout)
	}
	wantContains(t, "lan", jsonLines[0], `"interface":"lan"`, `"bytes received":"4908196"`)
	wantContains(t, "wan", jsonLines[1], `"interface":"wan"`, `"device":"vtnet1"`)
	wantNoMutations(t, f)

	var failing = newFakeOPN(t)
	failing.on("GET", ifaceTestInterfaces, 403, `{"status":403,"message":"Forbidden"}`)
	wantFailure(t, failing.run("/interface", "print"), "HTTP 403")
}

// --- monitor-traffic

func TestInterfaceMonitorTrafficOnce(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	// baseline, then 2s with 250000 bytes in = 1 Mbit/s, 12500 bytes out = 50 kbit/s
	f.stream("/api/diagnostics/traffic/stream/2", ifaceTestEvents(
		ifaceTestSample(1000, 0, 0), ifaceTestSample(1002, 250000, 12500), ifaceTestSample(1004, 1, 1)))
	var r = f.run("/interface", "monitor-traffic", "interval=2", "once")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "INTERFACE", "IN-PKT/S", "lan", "LAN", "1.0 Mbit/s", "50.0 kbit/s", "1250", "62.5", "wan", "0 bit/s")
	var lines = ifaceTestLines(r.stdout)
	if len(lines) != 3 || !strings.HasSuffix(lines[2], "2") {
		t.Errorf("want header, lan and wan (2 errors):\n%s", r.stdout)
	}
	if calls := f.calls(); len(calls) != 1 || calls[0].Method != "GET" {
		t.Errorf("want one GET, got %v", calls)
	}
}

func TestInterfaceMonitorTrafficFilter(t *testing.T) {
	t.Parallel()
	for _, filter := range []string{"wan", "WAN", "Wan,"} {
		var f = newFakeOPN(t)
		f.stream(ifaceTestStream, ifaceTestEvents(ifaceTestSample(1000, 0, 0), ifaceTestSample(1001, 1000, 0)))
		var r = f.run("/interface", "monitor-traffic", "interface="+filter, "once")
		wantExit(t, r, 0)
		if !strings.Contains(r.stdout, "wan") || strings.Contains(r.stdout, "lan") {
			t.Errorf("interface=%s: want only wan:\n%s", filter, r.stdout)
		}
	}
	var f = newFakeOPN(t)
	f.stream(ifaceTestStream, ifaceTestEvents(ifaceTestSample(1000, 0, 0), ifaceTestSample(1001, 1000, 0)))
	wantFailure(t, f.run("/interface", "monitor-traffic", "interface=lan,opt7"), `unknown interface "opt7"`, "available: lan, wan")
}

func TestInterfaceMonitorTrafficJSON(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.stream(ifaceTestStream, ifaceTestEvents(ifaceTestSample(1000, 0, 0), ifaceTestSample(1001, 1000, 0)))
	var r = f.run("/interface", "monitor-traffic", "once", "json")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != ifaceTestSample(1001, 1000, 0) {
		t.Errorf("want the raw 2nd event (the baseline is skipped), got %q", r.stdout)
	}
}

func TestInterfaceMonitorTrafficFollow(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.stream(ifaceTestStream, ifaceTestEvents(ifaceTestSample(1000, 0, 0), ifaceTestSample(1001, 125, 0), ifaceTestSample(1002, 125000, 0)))
	var p = f.start("/interface", "monitor-traffic")
	p.waitFor("1.0 Mbit/s")
	time.Sleep(100 * time.Millisecond)
	if !p.running() {
		t.Fatalf("monitor-traffic must run until Ctrl-C:\n%s", p.result())
	}
	var r = p.interrupt()
	wantExit(t, r, 0)
	var lines = ifaceTestLines(r.stdout)
	if len(lines) != 5 || !strings.HasPrefix(lines[0], "TIME") {
		t.Fatalf("want a header and 4 lines:\n%s", r.stdout)
	}
	wantContains(t, "output", lines[1], "lan", "LAN", "1.0 kbit/s")
	wantContains(t, "output", lines[3], "lan", "1.0 Mbit/s", "1250")
	// fixed columns: all lines equally aligned
	if strings.Index(lines[1], "LAN") != strings.Index(lines[0], "NAME") {
		t.Errorf("columns not aligned:\n%s", r.stdout)
	}
}

func TestInterfaceArgValidation(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"/interface", "monitor-traffic", "interval=0"},
		{"/interface", "monitor-traffic", "interval=1.5"},
		{"/interface", "monitor-traffic", "interval=500ms"},
		{"/interface", "monitor-traffic", "now"},
		{"/interface", "print", "now"},
	} {
		var f = newFakeOPN(t)
		wantFailure(t, f.run(args...))
		wantNoCalls(t, f)
	}
}

func TestInterfaceUnits(t *testing.T) {
	t.Parallel()
	for value, want := range map[float64]string{0: "0 bit/s", 999: "999 bit/s", 1000: "1.0 kbit/s", 1500000: "1.5 Mbit/s", 2.5e9: "2.5 Gbit/s", 3e12: "3.0 Tbit/s", 5e15: "5000.0 Tbit/s"} {
		if got := ifaceBits(value); got != want {
			t.Errorf("bits %v: want %q, got %q", value, want, got)
		}
	}
	for value, want := range map[float64]string{0: "0 B", 512: "512 B", 28400: "28.4 kB", 9.7e6: "9.7 MB"} {
		if got := ifaceBytes(value); got != want {
			t.Errorf("bytes %v: want %q, got %q", value, want, got)
		}
	}
	for value, want := range map[float64]string{0: "0", 12: "12", 12.5: "12.5"} {
		if got := ifacePackets(value); got != want {
			t.Errorf("packets %v: want %q, got %q", value, want, got)
		}
	}
}

// --- streams: cross-cutting tests of the commands reading an event stream until Ctrl-C (also used by /system/resource monitor)

type ifaceStreamCase struct {
	name   string
	args   []string
	path   string           // the event stream endpoint
	setup  func(f *fakeOPN) // other endpoints the command needs
	events []string         // events printing want
	want   string           // printed for events
}

func ifaceTrafficEvent(time string, inbytes int) string {
	return sseData(fmt.Sprintf(`{"interfaces":{"lan":{"inbytes":%d,"outbytes":469,"inpkts":1,"outpkts":2,"inerrs":0,"outerrs":0,"collisions":0,"name":"LAN"}},"time":%s}`, inbytes, time))
}

var ifaceStreamCases = []ifaceStreamCase{
	{
		name: "monitor-traffic", args: []string{"/interface", "monitor-traffic"}, path: ifaceTestStream,
		events: []string{ifaceTrafficEvent("1792886639.0", 0), ifaceTrafficEvent("1792886640.0", 1000), ifaceTrafficEvent("1792886641.0", 2000)},
		want:   "16.0 kbit/s",
	},
	{
		name: "monitor-traffic json", args: []string{"/interface", "monitor-traffic", "json"}, path: ifaceTestStream,
		events: []string{ifaceTrafficEvent("1792886639.0", 0), ifaceTrafficEvent("1792886640.0", 1000)},
		want:   `"inbytes":1000`,
	},
}

func TestInterfaceStreams(t *testing.T) {
	t.Parallel()
	ifaceStreamSuite(t, ifaceStreamCases)
}

func (tc ifaceStreamCase) fake(t *testing.T, conns ...sseConn) *fakeOPN {
	var f = newFakeOPN(t)
	if tc.setup != nil {
		tc.setup(f)
	}
	f.stream(tc.path, conns...)
	return f
}

// ifaceStreamSuite runs the stream behaviour tests for every case
func ifaceStreamSuite(t *testing.T, cases []ifaceStreamCase) {
	for _, tc := range cases {
		// Ctrl-C (and SIGTERM) end the run cleanly: exit 0, everything received printed, keepalives never
		for _, signal := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
			t.Run(tc.name+"/interrupt "+signal.String(), func(t *testing.T) {
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

		// a stream that only sends keepalives keeps the command running silently until Ctrl-C
		t.Run(tc.name+"/idle", func(t *testing.T) {
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

		// permanent stream errors end the command with a clear message instead of retrying forever
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
				var r = f.start(tc.args...).wait()
				wantFailure(t, r, sc.wantErr...)
				if n := f.streamConnections(tc.path); n != 1 {
					t.Errorf("want no retry of a permanent error, got %d connections", n)
				}
			})
		}

		// garbage in an event (e.g. a PHP error page) ends the command with a message, it is never printed as data
		t.Run(tc.name+"/invalid event", func(t *testing.T) {
			t.Parallel()
			var f = tc.fake(t, sseConn{Keepalive: true, Events: []string{sseData("<b>Fatal error</b>: something broke")}})
			var r = f.start(tc.args...).wait()
			wantFailure(t, r, "event")
			if r.stdout != "" {
				t.Errorf("stdout must be empty: %q", r.stdout)
			}
		})

		// OPNsense closes the stream (e.g. a web GUI restart): reconnect with a message and go on
		t.Run(tc.name+"/dropped", func(t *testing.T) {
			t.Parallel()
			var f = tc.fake(t, sseConn{Drop: true, Events: tc.events}, sseConn{Keepalive: true, Events: tc.events})
			var p = f.start(tc.args...)
			p.waitFor(tc.want)
			f.waitForConnections(tc.path, 2)
			var deadline = time.Now().Add(3 * time.Second)
			for strings.Count(p.stdout.String(), tc.want) < 2 && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			var r = p.interrupt()
			wantExit(t, r, 0)
			wantContains(t, "stderr", r.stderr, "stream closed by OPNsense, reconnecting in 1s")
			if n := strings.Count(r.stdout, tc.want); n != 2 {
				t.Errorf("want %q once per connection (the baseline of the reconnect skipped), got %d:\n%s", tc.want, n, r.stdout)
			}
		})
	}
}
