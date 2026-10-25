package cli

import (
	"net/http"
	"strings"
	"testing"
)

const (
	systemActivityTestPath   = "/api/diagnostics/activity/get_activity"
	systemActivityTestAnswer = `{"headers":["last pid: 34390;  load averages:    1.56,    0.82,    0.65  up 0+00:43:41    00:07:37",` +
		`"CPU: 50.0% user,  0.0% nice, 13.7% system,  2.3% interrupt, 34.0% idle"],"details":[` +
		`{"C":"0","PID":"11","THR":"100003","USERNAME":"root","PRI":"199","NICE":"ki31","SIZE":"0B","RES":"16K","STATE":"RUN","TIME":"41:27","WCPU":"33.23%","COMMAND":"[idle]"},` +
		`{"C":"0","PID":"65995","THR":"100369","USERNAME":"root","PRI":"13","NICE":"0","SIZE":"205M","RES":"47M","STATE":"select","TIME":"0:01","WCPU":"14.55%","COMMAND":"/usr/local/bin/php-cgi"},` +
		`{"C":"0","PID":"","THR":"100001","USERNAME":"root","PRI":"-16","NICE":"-","SIZE":"0B","RES":"16K","STATE":"WAIT","TIME":"0:00","WCPU":"0.00%","COMMAND":"[kernel]"}]}`
)

func TestSystemActivityPrint(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", systemActivityTestPath, 200, systemActivityTestAnswer)
	var r = f.run("/system/activity", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "load averages", "CPU: 50.0% user", "PID", "WCPU", "COMMAND", "[idle]", "33.23%",
		"/usr/local/bin/php-cgi", "[kernel]")
	var lines = strings.Split(r.stdout, "\n")
	if lines[2] != "" || !strings.HasPrefix(lines[3], "PID") || !strings.HasPrefix(lines[6], "-") {
		t.Errorf("want headers, a blank line, the table (empty PID shown as -):\n%s", r.stdout)
	}

	r = f.run("/system", "activity", "print", "lines=1")
	wantExit(t, r, 0)
	if !strings.Contains(r.stdout, "[idle]") || strings.Contains(r.stdout, "php-cgi") {
		t.Errorf("lines=1 must show only the busiest thread:\n%s", r.stdout)
	}

	r = f.run("/system/activity", "print", "json")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != systemActivityTestAnswer {
		t.Errorf("want the raw answer on one line, got %q", r.stdout)
	}
	wantNoMutations(t, f)
}

func TestSystemActivityErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		status int
		body   string
		want   string
	}{
		{403, `{"status":403,"message":"Forbidden"}`, "HTTP 403"},
		{200, `{}`, "no headers"},
		{200, ``, "empty response"},
	} {
		var f = newFakeOPN(t)
		f.on("GET", systemActivityTestPath, tc.status, tc.body)
		wantFailure(t, f.run("/system/activity", "print"), tc.want)
	}
}

func TestSystemActivityFollow(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", systemActivityTestPath, 200, systemActivityTestAnswer)
	var p = f.start("/system/activity", "print", "follow", "lines=2", "interval=20ms")
	f.waitForConnections(systemActivityTestPath, 4)
	p.waitFor("php-cgi")
	var r = p.interrupt()
	wantExit(t, r, 0)
	var refreshes = strings.Count(r.stdout, "php-cgi")
	if refreshes < 3 || strings.Count(r.stdout, "--- ") != refreshes || strings.Contains(r.stdout, "[kernel]") {
		t.Errorf("want at least 3 refreshes of 2 threads, each with a separator (not a terminal):\n%s", r.stdout)
	}
}

func TestSystemActivityFollowJSON(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", systemActivityTestPath, 200, systemActivityTestAnswer)
	var p = f.start("/system/activity", "print", "follow", "json", "interval=20ms")
	p.waitFor(`"headers"`)
	f.waitForConnections(systemActivityTestPath, 3)
	var r = p.interrupt()
	wantExit(t, r, 0)
	for i, line := range ifaceTestLines(r.stdout) {
		if line != systemActivityTestAnswer {
			t.Errorf("line %d is not the raw answer: %q", i, line)
		}
	}
}

func TestSystemActivityFollowStopsOnError(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", systemActivityTestPath, 500, `{"status":500,"message":"Internal Error"}`)
	var r = f.start("/system/activity", "print", "follow", "interval=20ms").wait()
	wantFailure(t, r, "HTTP 500")
	if n := ifaceTestCount(f, systemActivityTestPath); n != 1 {
		t.Errorf("want no polling after an error, got %d queries", n)
	}
}

// Ctrl-C during a slow query ends the command at once, without error
func TestSystemActivityInterruptDuringQuery(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var release = make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.onFunc("GET", systemActivityTestPath, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	var p = f.start("/system/activity", "print", "follow")
	f.waitForConnections(systemActivityTestPath, 1)
	var r = p.interrupt()
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("nothing must be printed: %q", r.stdout)
	}
}

func TestSystemActivityArgValidation(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"/system/activity", "print", "lines=-1"},
		{"/system/activity", "print", "interval=0s"},
		{"/system/activity", "print", "interval=soon"},
		{"/system/activity", "print", "now"},
	} {
		var f = newFakeOPN(t)
		wantFailure(t, f.run(args...))
		wantNoCalls(t, f)
	}
}
