package cli

import (
	"strings"
	"testing"
)

const torchTestAnswer = `{"lan":{"records":[{"address":"192.168.1.2","rate_bits_in":91400,"rate_bits_out":22600,` +
	`"rate_bits":114000,"cumulative_bytes_in":20000,"cumulative_bytes_out":8400,"cumulative_bytes":28400,"tags":["private"],` +
	`"details":[],"rname":"client.lan","rate_in":"91.4 kb","rate_out":"22.6 kb","rate":"114.0 kb","cumulative_in":"20.0 kb",` +
	`"cumulative_out":"8.4 kb","cumulative":"28.4 kb"},{"address":"10.0.0.9","rate_bits_in":10,"rate_bits_out":0,"rate_bits":10,` +
	`"cumulative_bytes":2,"tags":[],"details":[],"rname":""}],"status":"ok"},"wan":{"records":[],"status":"timeout"}}`

func TestTorchOnce(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", ifaceTestInterfaces, 200, ifaceTestInterfacesAnswer)
	f.on("GET", "/api/diagnostics/traffic/top/lan,wan", 200, torchTestAnswer)
	var r = f.run("/tool", "torch", "once")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "lan:", "ADDRESS", "192.168.1.2", "client.lan", "91.4 kbit/s", "22.6 kbit/s", "114.0 kbit/s",
		"28.4 kB", "private", "10.0.0.9", "wan: measurement timed out")
	wantNotContains(t, "stdout", r.stdout, "--- ")

	r = f.run("/tool", "torch", "once", "lines=1")
	wantExit(t, r, 0)
	if strings.Contains(r.stdout, "10.0.0.9") {
		t.Errorf("lines=1 shows more than one host:\n%s", r.stdout)
	}

	r = f.run("/tool", "torch", "once", "json")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != torchTestAnswer {
		t.Errorf("want the raw answer, got %q", r.stdout)
	}
	wantNoMutations(t, f)
}

func TestTorchInterfaceSelection(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", ifaceTestInterfaces, 200, ifaceTestInterfacesAnswer)
	f.on("GET", "/api/diagnostics/traffic/top/wan", 200, `{"wan":{"records":[],"status":"ok"}}`)
	// by description, case insensitive, duplicates removed
	var r = f.run("/tool", "torch", "interface=WAN,wan", "once")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "wan: no traffic")

	// unknown to the totals: passed on, OPNsense leaves it out of the answer
	f.on("GET", "/api/diagnostics/traffic/top/opt9", 200, `[]`)
	wantFailure(t, f.run("/tool", "torch", "interface=opt9", "once"), "did not measure opt9")

	var failing = newFakeOPN(t)
	failing.on("GET", ifaceTestInterfaces, 403, `{"status":403,"message":"Forbidden"}`)
	wantFailure(t, failing.run("/tool", "torch", "once"), "HTTP 403")
}

func TestTorchFollow(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", ifaceTestInterfaces, 200, ifaceTestInterfacesAnswer)
	f.on("GET", "/api/diagnostics/traffic/top/lan", 200, `{"lan":{"records":[],"status":"ok"}}`)
	var p = f.start("/tool", "torch", "interface=lan", "interval=20ms")
	f.waitForConnections("/api/diagnostics/traffic/top/lan", 3)
	p.waitFor("lan: no traffic")
	var r = p.interrupt()
	wantExit(t, r, 0)
	var refreshes = strings.Count(r.stdout, "lan: no traffic")
	if refreshes < 3 || strings.Count(r.stdout, "--- ") != refreshes {
		t.Errorf("want at least 3 refreshes, each with a separator (not a terminal):\n%s", r.stdout)
	}
	if n := ifaceTestCount(f, ifaceTestInterfaces); n != 1 {
		t.Errorf("want the interfaces resolved once, got %d", n)
	}

	// a failing query ends the follow
	var failing = newFakeOPN(t)
	failing.on("GET", ifaceTestInterfaces, 200, ifaceTestInterfacesAnswer)
	failing.on("GET", "/api/diagnostics/traffic/top/lan", 500, `{"status":500}`)
	wantFailure(t, failing.start("/tool", "torch", "interface=lan", "interval=20ms").wait(), "HTTP 500")
	if n := ifaceTestCount(failing, "/api/diagnostics/traffic/top/lan"); n != 1 {
		t.Errorf("want no further query after an error, got %d", n)
	}
}

func TestTorchArgValidation(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"/tool", "torch", "lines=-1"},
		{"/tool", "torch", "interval=0s"},
		{"/tool", "torch", "interval=-1s"},
		{"/tool", "torch", "now"},
	} {
		var f = newFakeOPN(t)
		wantFailure(t, f.run(args...))
		wantNoCalls(t, f)
	}
}
