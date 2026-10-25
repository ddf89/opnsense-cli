package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/diagnostics"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- helpers shared by the diag traffic / cpu / activity / system tests

// diagTrafficTestApi returns a DiagnosticsApi talking to the fake OPNsense in-process
func diagTrafficTestApi(t *testing.T, f *fakeOPN) *diagnostics.DiagnosticsApi {
	t.Helper()
	var serverUrl, err = url.Parse(f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &diagnostics.DiagnosticsApi{OPNsense: &coreapi.OPNsense{
		BaseUrl: *serverUrl, ApiKey: testApiKey, ApiSecret: testApiSecret, NoSslVerify: true,
	}}
}

// diagTrafficTestSSE serves the data as "event: message" events with keepalives and keeps the stream open
// until the client goes away
func diagTrafficTestSSE(data ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream;charset=UTF-8")
		var flusher = w.(http.Flusher)
		for _, d := range data {
			_, _ = fmt.Fprintf(w, "event: keepalive\ndata: \n\nevent: message\ndata: %s\n\n", d)
			flusher.Flush()
		}
		<-r.Context().Done()
	}
}

// diagTrafficTestSample is a traffic stream event of lan (LAN) and wan (WAN)
func diagTrafficTestSample(time float64, lanIn int, lanOut int) string {
	return fmt.Sprintf(`{"interfaces":{"lan":{"inbytes":%d,"outbytes":%d,"inpkts":%d,"outpkts":%d,"inerrs":0,"outerrs":0,"collisions":0,"name":"LAN"},`+
		`"wan":{"inbytes":0,"outbytes":0,"inpkts":0,"outpkts":0,"inerrs":2,"outerrs":0,"collisions":0,"name":"WAN"}},"time":%.6f}`,
		lanIn, lanOut, lanIn/100, lanOut/100, time)
}

// diagTrafficTestSleeper counts the pauses of a poll loop and cancels after max of them
type diagTrafficTestSleeper struct {
	mu     sync.Mutex
	delays []time.Duration
	max    int
	cancel context.CancelFunc
}

func (s *diagTrafficTestSleeper) sleep(_ context.Context, d time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delays = append(s.delays, d)
	if len(s.delays) >= s.max {
		s.cancel()
		return false
	}
	return true
}

func diagTrafficTestCount(f *fakeOPN, path string) int {
	var n = 0
	for _, call := range f.calls() {
		if call.Path == path {
			n++
		}
	}
	return n
}

const (
	diagTrafficTestStream           = "/api/diagnostics/traffic/stream/1"
	diagTrafficTestInterfaces       = "/api/diagnostics/traffic/interface"
	diagTrafficTestInterfacesAnswer = `{"interfaces":{"lan":{"device":"vtnet0","mtu":"1500","bytes received":"4908196",` +
		`"bytes transmitted":"15538584","packets received":"24506","packets transmitted":"30761","input errors":"1",` +
		`"output errors":"0","collisions":"0","name":"LAN"},"wan":{"device":"vtnet1","mtu":"1500","bytes received":"507660",` +
		`"bytes transmitted":"118877","packets received":"1245","packets transmitted":"1284","input errors":"0",` +
		`"output errors":"0","collisions":"0","name":"WAN"}},"time":1792886793.949564}`
)

// --- diag traffic

func TestDiagTrafficOneSample(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	// baseline, then 2s with 250000 bytes in = 1 Mbit/s, 12500 bytes out = 50 kbit/s
	f.onFunc("GET", "/api/diagnostics/traffic/stream/2", diagTrafficTestSSE(
		diagTrafficTestSample(1000, 0, 0), diagTrafficTestSample(1002, 250000, 12500), diagTrafficTestSample(1004, 1, 1)))
	var r = f.run("diag", "traffic", "--interval", "2")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "INTERFACE", "IN PKT/S", "lan", "LAN", "1.0 Mbit/s", "50.0 kbit/s", "1250", "62.5", "wan", "0 bit/s")
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 3 || !strings.HasSuffix(lines[2], "2") {
		t.Errorf("want header, lan and wan (2 errors):\n%s", r.stdout)
	}
	if calls := f.calls(); len(calls) != 1 || calls[0].Method != "GET" {
		t.Errorf("want one GET, got %v", calls)
	}
}

func TestDiagTrafficInterfaceFilter(t *testing.T) {
	t.Parallel()
	for _, filter := range []string{"wan", "WAN", "Wan,"} {
		var f = newFakeOPN(t)
		f.onFunc("GET", diagTrafficTestStream, diagTrafficTestSSE(diagTrafficTestSample(1000, 0, 0), diagTrafficTestSample(1001, 1000, 0)))
		var r = f.run("diag", "traffic", "--interface", filter)
		wantExit(t, r, 0)
		if !strings.Contains(r.stdout, "wan") || strings.Contains(r.stdout, "lan") {
			t.Errorf("--interface %s: want only wan:\n%s", filter, r.stdout)
		}
	}
	var f = newFakeOPN(t)
	f.onFunc("GET", diagTrafficTestStream, diagTrafficTestSSE(diagTrafficTestSample(1000, 0, 0), diagTrafficTestSample(1001, 1000, 0)))
	wantFailure(t, f.run("diag", "traffic", "--interface", "opt7"), `unknown interface "opt7"`, "available: lan, wan")
}

func TestDiagTrafficJson(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.onFunc("GET", diagTrafficTestStream, diagTrafficTestSSE(diagTrafficTestSample(1000, 0, 0), diagTrafficTestSample(1001, 1000, 0)))
	var r = f.run("diag", "traffic", "--json")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != diagTrafficTestSample(1001, 1000, 0) {
		t.Errorf("want the raw 2nd event (the baseline is skipped), got %q", r.stdout)
	}
}

func TestDiagTrafficFlagValidation(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"diag", "traffic", "--interval", "0"},
		{"diag", "traffic", "now"},
		{"diag", "traffic", "top", "-n", "-1"},
		{"diag", "traffic", "top", "--interval", "0s"},
		{"diag", "activity", "-n", "-1"},
		{"diag", "activity", "--interval", "0s"},
		{"diag", "cpu", "now"},
		{"diag", "system", "now"},
	} {
		var f = newFakeOPN(t)
		wantFailure(t, f.run(args...))
		wantNoCalls(t, f)
	}
}

func TestDiagTrafficFollowInProcess(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.onFunc("GET", diagTrafficTestStream, diagTrafficTestSSE(
		diagTrafficTestSample(1000, 0, 0), diagTrafficTestSample(1001, 125, 0), diagTrafficTestSample(1002, 125000, 0)))
	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	var out = &diagTrafficTestWriter{onWrite: func(s string) {
		if strings.Count(s, "\n") >= 5 { // header + 2 intervals x 2 interfaces
			cancel()
		}
	}}
	var err = diagTrafficExecute(ctx, diagTrafficTestApi(t, f), out, diagTrafficOptions{Interval: 1, Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	var lines = strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 5 || !strings.HasPrefix(lines[0], "TIME") {
		t.Fatalf("want a header and 4 lines:\n%s", out)
	}
	wantContains(t, "output", lines[1], "lan", "LAN", "1.0 kbit/s")
	wantContains(t, "output", lines[3], "lan", "1.0 Mbit/s", "1250")
	// fixed columns: all lines equally aligned
	if strings.Index(lines[1], "LAN") != strings.Index(lines[0], "NAME") {
		t.Errorf("columns not aligned:\n%s", out)
	}
}

// diagTrafficTestWriter is a concurrency safe buffer calling onWrite with everything written so far
type diagTrafficTestWriter struct {
	mu      sync.Mutex
	buffer  strings.Builder
	onWrite func(string)
}

func (w *diagTrafficTestWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.buffer.Write(p)
	var s = w.buffer.String()
	w.mu.Unlock()
	if w.onWrite != nil {
		w.onWrite(s)
	}
	return len(p), nil
}

func (w *diagTrafficTestWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String()
}

func TestDiagTrafficUnits(t *testing.T) {
	t.Parallel()
	for value, want := range map[float64]string{0: "0 bit/s", 999: "999 bit/s", 1000: "1.0 kbit/s", 1500000: "1.5 Mbit/s", 2.5e9: "2.5 Gbit/s", 3e12: "3.0 Tbit/s", 5e15: "5000.0 Tbit/s"} {
		if got := diagTrafficBits(value); got != want {
			t.Errorf("bits %v: want %q, got %q", value, want, got)
		}
	}
	for value, want := range map[float64]string{0: "0 B", 512: "512 B", 28400: "28.4 kB", 9.7e6: "9.7 MB"} {
		if got := diagTrafficBytes(value); got != want {
			t.Errorf("bytes %v: want %q, got %q", value, want, got)
		}
	}
	for value, want := range map[float64]string{0: "0", 12: "12", 12.5: "12.5"} {
		if got := diagTrafficPackets(value); got != want {
			t.Errorf("packets %v: want %q, got %q", value, want, got)
		}
	}
}

// --- diag traffic interfaces

func TestDiagTrafficInterfaces(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", diagTrafficTestInterfaces, 200, diagTrafficTestInterfacesAnswer)
	var r = f.run("diag", "traffic", "interfaces")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "INTERFACE", "lan", "vtnet0", "1500", "4.9 MB", "15.5 MB", "24506", "wan", "507.7 kB")
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 3 || !strings.HasSuffix(lines[1], "1") {
		t.Errorf("want header, lan (1 error), wan:\n%s", r.stdout)
	}

	r = f.run("diag", "traffic", "interfaces", "--json")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, `"bytes received": "4908196"`, `"device": "vtnet1"`)

	var failing = newFakeOPN(t)
	failing.on("GET", diagTrafficTestInterfaces, 403, `{"status":403,"message":"Forbidden"}`)
	wantFailure(t, failing.run("diag", "traffic", "interfaces"), "HTTP 403")
}

// --- diag traffic top

const diagTrafficTestTopAnswer = `{"lan":{"records":[{"address":"192.168.1.2","rate_bits_in":91400,"rate_bits_out":22600,` +
	`"rate_bits":114000,"cumulative_bytes_in":20000,"cumulative_bytes_out":8400,"cumulative_bytes":28400,"tags":["private"],` +
	`"details":[],"rname":"client.lan","rate_in":"91.4 kb","rate_out":"22.6 kb","rate":"114.0 kb","cumulative_in":"20.0 kb",` +
	`"cumulative_out":"8.4 kb","cumulative":"28.4 kb"},{"address":"10.0.0.9","rate_bits_in":10,"rate_bits_out":0,"rate_bits":10,` +
	`"cumulative_bytes":2,"tags":[],"details":[],"rname":""}],"status":"ok"},"wan":{"records":[],"status":"timeout"}}`

func TestDiagTrafficTop(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", diagTrafficTestInterfaces, 200, diagTrafficTestInterfacesAnswer)
	f.on("GET", "/api/diagnostics/traffic/top/lan,wan", 200, diagTrafficTestTopAnswer)
	var r = f.run("diag", "traffic", "top")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "lan:", "ADDRESS", "192.168.1.2", "client.lan", "91.4 kbit/s", "22.6 kbit/s", "114.0 kbit/s",
		"28.4 kB", "private", "10.0.0.9", "wan: measurement timed out")

	r = f.run("diag", "traffic", "top", "-n", "1")
	wantExit(t, r, 0)
	if strings.Contains(r.stdout, "10.0.0.9") {
		t.Errorf("-n 1 shows more than one host:\n%s", r.stdout)
	}

	r = f.run("diag", "traffic", "top", "--json")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != diagTrafficTestTopAnswer {
		t.Errorf("want the raw answer, got %q", r.stdout)
	}
}

func TestDiagTrafficTopInterfaceSelection(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", diagTrafficTestInterfaces, 200, diagTrafficTestInterfacesAnswer)
	f.on("GET", "/api/diagnostics/traffic/top/wan", 200, `{"wan":{"records":[],"status":"ok"}}`)
	// by description, case insensitive, duplicates removed
	var r = f.run("diag", "traffic", "top", "--interface", "WAN,wan")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "wan: no traffic")

	// unknown to the totals: passed on, OPNsense leaves it out of the answer
	f.on("GET", "/api/diagnostics/traffic/top/opt9", 200, `[]`)
	wantFailure(t, f.run("diag", "traffic", "top", "--interface", "opt9"), "did not measure opt9")
}

func TestDiagTrafficTopFollowInProcess(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", diagTrafficTestInterfaces, 200, diagTrafficTestInterfacesAnswer)
	f.on("GET", "/api/diagnostics/traffic/top/lan", 200, `{"lan":{"records":[],"status":"ok"}}`)
	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	var sleeper = &diagTrafficTestSleeper{max: 3, cancel: cancel}
	var out strings.Builder
	var err = diagTrafficTopExecute(ctx, diagTrafficTestApi(t, f), &out, diagTrafficTopOptions{
		Interfaces: []string{"lan"}, Follow: true, Interval: 7 * time.Second, Sleep: sleeper.sleep,
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := diagTrafficTestCount(f, "/api/diagnostics/traffic/top/lan"); n != 3 {
		t.Errorf("want 3 queries, got %d", n)
	}
	if n := diagTrafficTestCount(f, diagTrafficTestInterfaces); n != 1 {
		t.Errorf("want the interfaces resolved once, got %d", n)
	}
	if strings.Count(out.String(), "lan: no traffic") != 3 || strings.Count(out.String(), "--- ") != 3 {
		t.Errorf("want 3 refreshes with a separator:\n%s", out.String())
	}
	if fmt.Sprint(sleeper.delays) != "[7s 7s 7s]" {
		t.Errorf("unexpected pauses %v", sleeper.delays)
	}
}
