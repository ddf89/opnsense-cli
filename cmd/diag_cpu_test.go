package cmd

import (
	"context"
	"net/http"
	"opnsense-cli/opnsense/api/diagnostics"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	diagCpuTestStream = "/api/diagnostics/cpu_usage/stream"
	diagCpuTestType   = "/api/diagnostics/cpu_usage/getCPUType"
	diagCpuTestBoot   = `{"total":5,"user":4,"nice":0,"sys":1,"intr":0,"idle":95}`
	diagCpuTestBusy   = `{"total":83,"user":64,"nice":1,"sys":17,"intr":1,"idle":17}`
)

func TestDiagCpu(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", diagCpuTestType, 200, `["Intel(R) Core(TM) Ultra 7 165U (1 cores, 1 threads)"]`)
	f.onFunc("GET", diagCpuTestStream, diagTrafficTestSSE(diagCpuTestBoot, diagCpuTestBusy))
	var r = f.run("diag", "cpu")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "model:", "Ultra 7 165U", "total:      83%", "user:       64%", "nice:       1%",
		"system:     17%", "interrupt:  1%", "idle:       17%")
	wantNotContains(t, "stdout", r.stdout, "95%") // the average since boot is skipped

	r = f.run("diag", "cpu", "--json")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != diagCpuTestBusy {
		t.Errorf("want the raw 2nd event, got %q", r.stdout)
	}
}

func TestDiagCpuErrors(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", diagCpuTestType, 403, `{"status":403,"message":"Forbidden"}`)
	wantFailure(t, f.run("diag", "cpu"), "HTTP 403")
	if n := diagTrafficTestCount(f, diagCpuTestStream); n != 0 {
		t.Errorf("want no stream after the failed type query, got %d", n)
	}

	var f2 = newFakeOPN(t)
	f2.on("GET", diagCpuTestType, 200, `["cpu"]`)
	f2.on("GET", diagCpuTestStream, 404, `{"errorMessage":"Endpoint not found"}`)
	wantFailure(t, f2.run("diag", "cpu"), "HTTP 404")
	if n := diagTrafficTestCount(f2, diagCpuTestStream); n != 1 {
		t.Errorf("want no retry of a 404, got %d connections", n)
	}
}

func TestDiagCpuFollowInProcess(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.onFunc("GET", diagCpuTestStream, diagTrafficTestSSE(diagCpuTestBoot, diagCpuTestBusy, `{"total":0,"user":0,"nice":0,"sys":0,"intr":0,"idle":100}`))
	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	var out = &diagTrafficTestWriter{onWrite: func(s string) {
		if strings.Count(s, "\n") >= 3 {
			cancel()
		}
	}}
	var now = func() time.Time { return time.Date(2026, 10, 25, 1, 2, 3, 0, time.UTC) }
	if err := diagCpuExecute(ctx, diagTrafficTestApi(t, f), out, true, false, diagnostics.TrafficFollowOptions{}, now); err != nil {
		t.Fatal(err)
	}
	var lines = strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "TIME") || !strings.HasPrefix(lines[1], "01:02:03") {
		t.Fatalf("want a header and 2 lines:\n%s", out)
	}
	wantContains(t, "output", lines[1], "83%", "64%", "17%")
	wantContains(t, "output", lines[2], "0%", "100%")
	if n := diagTrafficTestCount(f, diagCpuTestType); n != 0 {
		t.Errorf("--follow must not query the CPU type, got %d", n)
	}
}

func TestDiagCpuFollowReconnects(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var connections atomic.Int32
	f.onFunc("GET", diagCpuTestStream, func(w http.ResponseWriter, r *http.Request) {
		if connections.Add(1) == 1 {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("event: message\ndata: " + diagCpuTestBoot + "\n\nevent: message\ndata: " + diagCpuTestBusy + "\n\n"))
			return // dropped
		}
		diagTrafficTestSSE(diagCpuTestBoot, `{"total":42,"user":30,"nice":0,"sys":10,"intr":2,"idle":58}`)(w, r)
	})
	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	var out = &diagTrafficTestWriter{onWrite: func(s string) {
		if strings.Contains(s, "42%") {
			cancel()
		}
	}}
	var reconnects []error // only appended by the follow loop of this goroutine
	var options = diagnostics.TrafficFollowOptions{
		Sleep:       func(context.Context, time.Duration) bool { return true },
		OnReconnect: func(err error, _ time.Duration) { reconnects = append(reconnects, err) },
	}
	if err := diagCpuExecute(ctx, diagTrafficTestApi(t, f), out, true, false, options, time.Now); err != nil {
		t.Fatal(err)
	}
	wantContains(t, "output", out.String(), "83%", "42%")
	if len(reconnects) != 1 || diagTrafficTestCount(f, diagCpuTestStream) != 2 {
		t.Errorf("want one reconnect, got %v", reconnects)
	}
}
