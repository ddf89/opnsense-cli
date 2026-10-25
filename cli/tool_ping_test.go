package cli

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const (
	toolPingTestId   = "438d6fbc-7404-4615-a0e4-0e57abbed0e9"
	toolPingTestSet  = "/api/diagnostics/ping/set"
	toolPingTestJobs = "/api/diagnostics/ping/search_jobs"
)

// toolPingTestRow is a search_jobs row of the test job with sent/received packets (sent < 0: no statistics yet)
func toolPingTestRow(status string, sent int, received int, lastError string) string {
	var stats = `"loss":null,"send":null,"received":null,"min":null,"max":null,"avg":null,"std-dev":null`
	if sent >= 0 {
		stats = fmt.Sprintf(`"loss":"0.0%%","send":%d,"received":%d,"min":0.018,"max":0.033,"avg":0.027,"std-dev":0.005`, sent, received)
	}
	var errorValue = "null"
	if lastError != "" {
		errorValue = fmt.Sprintf("%q", lastError)
	}
	return fmt.Sprintf(`{"hostname":"192.168.1.1","fam":"ip","source_address":"","packetsize":"","disable_frag":"0","interval":"",`+
		`"description":"opn ping","id":%q,"status":%q,%s,"last_error":%s}`, toolPingTestId, status, stats, errorValue)
}

// toolPingTestFake registers set/start/stop/remove of the test job; search_jobs answers the rows one after the
// other per poll (the last one repeats). A poll is two requests, see toolPingFresh
func toolPingTestFake(t *testing.T, rows ...string) *fakeOPN {
	var f = newFakeOPN(t)
	f.on("POST", toolPingTestSet, 200, `{"result":"ok","uuid":"`+toolPingTestId+`"}`)
	f.on("POST", "/api/diagnostics/ping/start/"+toolPingTestId, 200, `{"status":"ok"}`)
	f.on("POST", "/api/diagnostics/ping/stop/"+toolPingTestId, 200, `{"status":"ok","stopped_processes":1}`)
	f.on("POST", "/api/diagnostics/ping/remove/"+toolPingTestId, 200, `{"status":"ok","stopped_processes":1}`)
	var mu sync.Mutex
	var n = 0
	f.onFunc("GET", toolPingTestJobs, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		var row = rows[min(n/2, len(rows)-1)]
		n++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"total":1,"rowCount":1,"current":1,"rows":[`+row+`]}`)
	})
	return f
}

// toolPingTestMutations returns the non GET calls as "METHOD path" without the job id
func toolPingTestMutations(f *fakeOPN) []string {
	var result []string
	for _, call := range f.mutations() {
		result = append(result, call.Method+" "+strings.TrimSuffix(call.Path, "/"+toolPingTestId))
	}
	return result
}

func TestToolPingCount(t *testing.T) {
	t.Parallel()
	var f = toolPingTestFake(t,
		toolPingTestRow("running", -1, 0, ""),
		toolPingTestRow("running", 1, 1, ""),
		toolPingTestRow("running", 1, 1, ""),
		toolPingTestRow("running", 3, 2, ""),
		toolPingTestRow("running", 4, 3, ""),
	)
	var r = f.run("/tool", "ping", "192.168.1.1", "count=3", "size=1400", "do-not-fragment", "interval=2s", "source=192.168.1.1")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 4 {
		t.Fatalf("want a header, 2 lines and the summary:\n%s", r.stdout)
	}
	wantContains(t, "header", lines[0], "SENT", "RECEIVED", "LOSS", "MIN-RTT", "AVG-RTT", "MAX-RTT", "STATUS")
	if fields := strings.Fields(lines[1]); len(fields) != 6 || fields[0] != "1" || fields[1] != "1" || fields[2] != "0%" || fields[3] != "0.018ms" {
		t.Errorf("first line %q", lines[1])
	}
	if fields := strings.Fields(lines[2]); fields[0] != "3" || fields[1] != "2" || fields[2] != "33.3%" {
		t.Errorf("second line %q", lines[2])
	}
	if lines[3] != "sent=3 received=2 packet-loss=33.3% min-rtt=0.018ms avg-rtt=0.027ms max-rtt=0.033ms" {
		t.Errorf("summary %q", lines[3])
	}

	var set = f.mutations()[0]
	wantJSON(t, set, map[string]any{"ping": map[string]any{"settings": map[string]any{
		"hostname": "192.168.1.1", "fam": "ip", "source_address": "192.168.1.1", "packetsize": "1400", "disable_frag": "1",
		"interval": "2", "description": "opn ping"}}})
	var want = []string{"POST " + toolPingTestSet, "POST /api/diagnostics/ping/start", "POST /api/diagnostics/ping/remove"}
	if got := toolPingTestMutations(f); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("mutations %q, want %q", got, want)
	}
	if n := ifaceTestCount(f, toolPingTestJobs); n != 8 {
		t.Errorf("want 4 polls (8 requests) until 3 packets were sent, got %d", n)
	}
}

func TestToolPingJSONAndIPv6(t *testing.T) {
	t.Parallel()
	var f = toolPingTestFake(t, toolPingTestRow("running", 1, 1, ""), toolPingTestRow("running", 2, 2, ""))
	var r = f.run("/tool", "ping", "fd00::1", "count=2", "json")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], `{"hostname":"192.168.1.1"`) || !strings.Contains(lines[1], `"send":2`) {
		t.Errorf("want the 2 raw rows:\n%s", r.stdout)
	}
	if settings := f.mutations()[0].json(t)["ping"].(map[string]any)["settings"].(map[string]any); settings["fam"] != "ip6" ||
		settings["interval"] != "" || settings["packetsize"] != "" || settings["disable_frag"] != "0" {
		t.Errorf("settings %v", settings)
	}
}

func TestToolPingInterrupt(t *testing.T) {
	t.Parallel()
	var f = toolPingTestFake(t, toolPingTestRow("running", 1, 1, ""), toolPingTestRow("running", 2, 2, ""))
	var p = f.start("/tool", "ping", "192.168.1.1")
	p.waitFor("     2         2")
	var r = p.interrupt()
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "sent=2 received=2 packet-loss=0%")
	var got = toolPingTestMutations(f)
	if len(got) != 3 || got[2] != "POST /api/diagnostics/ping/remove" {
		t.Errorf("the job must be removed after Ctrl-C: %q", got)
	}
}

func TestToolPingEndsEarly(t *testing.T) {
	t.Parallel()
	var f = toolPingTestFake(t, toolPingTestRow("stopped", -1, 0, "cannot resolve a7.invalid: Unknown host"))
	wantFailure(t, f.run("/tool", "ping", "a7.invalid", "count=3"), "ping 192.168.1.1: cannot resolve a7.invalid: Unknown host")
	if got := toolPingTestMutations(f); len(got) != 3 || got[2] != "POST /api/diagnostics/ping/remove" {
		t.Errorf("the job must be removed: %q", got)
	}

	var stopped = toolPingTestFake(t, toolPingTestRow("running", 1, 0, "sendto: Host is down"), toolPingTestRow("stopped", 1, 0, ""))
	var r = stopped.run("/tool", "ping", "192.168.1.1")
	wantFailure(t, r, "ended (stopped by someone else?)")
	wantContains(t, "stdout", r.stdout, "100%", "sendto: Host is down")

	// the job vanished
	var vanished = toolPingTestFake(t, `{"id":"other","status":"running"}`)
	wantFailure(t, vanished.run("/tool", "ping", "192.168.1.1"), "not found: ping job "+toolPingTestId)
}

func TestToolPingFailures(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", toolPingTestSet, 200, `{"result":"failed","validations":{"ping.settings.hostname":"Provide a valid hostname or address to ping."}}`)
	wantFailure(t, f.run("/tool", "ping", "bad_host"), "Provide a valid hostname")
	if len(f.mutations()) != 1 {
		t.Errorf("nothing to clean up without a job: %v", f.mutations())
	}

	var start = toolPingTestFake(t, toolPingTestRow("running", 1, 1, ""))
	start.on("POST", "/api/diagnostics/ping/start/"+toolPingTestId, 200, `{"status":"failed","status_msg":"already active (pids: 1)"}`)
	wantFailure(t, start.run("/tool", "ping", "192.168.1.1"), "already active")
	if got := toolPingTestMutations(start); len(got) != 3 || got[2] != "POST /api/diagnostics/ping/remove" {
		t.Errorf("the job must be removed after a failed start: %q", got)
	}

	var cleanup = toolPingTestFake(t, toolPingTestRow("running", 1, 1, ""))
	cleanup.on("POST", "/api/diagnostics/ping/remove/"+toolPingTestId, 200, `{"status":"failed"}`)
	var r = cleanup.run("/tool", "ping", "192.168.1.1", "count=1")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "warning: could not remove the ping job "+toolPingTestId)
}

func TestToolPingArgValidation(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"/tool", "ping"},
		{"/tool", "ping", "a b"},
		{"/tool", "ping", "../x"},
		{"/tool", "ping", "10.0.0.1", "count=0"},
		{"/tool", "ping", "10.0.0.1", "size=70000"},
		{"/tool", "ping", "10.0.0.1", "interval=0.5"},
		{"/tool", "ping", "10.0.0.1", "interval=121s"},
		{"/tool", "ping", "10.0.0.1", "source=host"},
		{"/tool", "ping", "10.0.0.1", "family=ipv6"},
		{"/tool", "ping", "fd00::1", "source=10.0.0.1"},
		{"/tool", "ping", "10.0.0.1", "family=ipx"},
	} {
		var f = newFakeOPN(t)
		wantFailure(t, f.run(args...))
		wantNoCalls(t, f)
	}
}
