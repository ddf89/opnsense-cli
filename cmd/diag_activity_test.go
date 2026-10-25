package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	diagActivityTestPath   = "/api/diagnostics/activity/get_activity"
	diagActivityTestAnswer = `{"headers":["last pid: 34390;  load averages:    1.56,    0.82,    0.65  up 0+00:43:41    00:07:37",` +
		`"CPU: 50.0% user,  0.0% nice, 13.7% system,  2.3% interrupt, 34.0% idle"],"details":[` +
		`{"C":"0","PID":"11","THR":"100003","USERNAME":"root","PRI":"199","NICE":"ki31","SIZE":"0B","RES":"16K","STATE":"RUN","TIME":"41:27","WCPU":"33.23%","COMMAND":"[idle]"},` +
		`{"C":"0","PID":"65995","THR":"100369","USERNAME":"root","PRI":"13","NICE":"0","SIZE":"205M","RES":"47M","STATE":"select","TIME":"0:01","WCPU":"14.55%","COMMAND":"/usr/local/bin/php-cgi"},` +
		`{"C":"0","PID":"","THR":"100001","USERNAME":"root","PRI":"-16","NICE":"-","SIZE":"0B","RES":"16K","STATE":"WAIT","TIME":"0:00","WCPU":"0.00%","COMMAND":"[kernel]"}]}`
)

func TestDiagActivity(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", diagActivityTestPath, 200, diagActivityTestAnswer)
	var r = f.run("diag", "activity")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "load averages", "CPU: 50.0% user", "PID", "WCPU", "COMMAND", "[idle]", "33.23%",
		"/usr/local/bin/php-cgi", "[kernel]")
	var lines = strings.Split(r.stdout, "\n")
	if lines[2] != "" || !strings.HasPrefix(lines[3], "PID") || !strings.HasPrefix(lines[6], "-") {
		t.Errorf("want headers, a blank line, the table (empty PID shown as -):\n%s", r.stdout)
	}

	r = f.run("diag", "activity", "-n", "1")
	wantExit(t, r, 0)
	if !strings.Contains(r.stdout, "[idle]") || strings.Contains(r.stdout, "php-cgi") {
		t.Errorf("-n 1 must show only the busiest thread:\n%s", r.stdout)
	}

	r = f.run("diag", "activity", "--json")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != diagActivityTestAnswer {
		t.Errorf("want the raw answer on one line, got %q", r.stdout)
	}
}

func TestDiagActivityErrors(t *testing.T) {
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
		f.on("GET", diagActivityTestPath, tc.status, tc.body)
		wantFailure(t, f.run("diag", "activity"), tc.want)
	}
}

func TestDiagActivityFollowInProcess(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", diagActivityTestPath, 200, diagActivityTestAnswer)
	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	var sleeper = &diagTrafficTestSleeper{max: 4, cancel: cancel}
	var out strings.Builder
	var err = diagActivityExecute(ctx, diagTrafficTestApi(t, f), &out, diagActivityOptions{
		Lines: 2, Follow: true, Interval: 3 * time.Second, Sleep: sleeper.sleep,
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := diagTrafficTestCount(f, diagActivityTestPath); n != 4 {
		t.Errorf("want 4 queries, got %d", n)
	}
	if strings.Count(out.String(), "--- ") != 4 || strings.Count(out.String(), "php-cgi") != 4 || strings.Contains(out.String(), "[kernel]") {
		t.Errorf("want 4 refreshes of 2 threads:\n%s", out.String())
	}

	// a terminal is redrawn instead
	var ctx2, cancel2 = context.WithCancel(context.Background())
	defer cancel2()
	var out2 strings.Builder
	_ = diagActivityExecute(ctx2, diagTrafficTestApi(t, f), &out2, diagActivityOptions{
		Follow: true, Interval: time.Second, Clear: true, Sleep: (&diagTrafficTestSleeper{max: 2, cancel: cancel2}).sleep,
	})
	if strings.Count(out2.String(), "\033[H\033[2J") != 2 || strings.Contains(out2.String(), "--- ") {
		t.Errorf("want 2 screen clears:\n%q", out2.String())
	}
}

func TestDiagActivityFollowStopsOnError(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", diagActivityTestPath, 401, `{"status":401,"message":"Authentication Failed"}`)
	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	var sleeper = &diagTrafficTestSleeper{max: 10, cancel: cancel}
	var err = diagActivityExecute(ctx, diagTrafficTestApi(t, f), &strings.Builder{}, diagActivityOptions{
		Follow: true, Interval: time.Second, Sleep: sleeper.sleep,
	})
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || len(sleeper.delays) != 0 {
		t.Errorf("want HTTP 401 without polling on, got %v after %d pauses", err, len(sleeper.delays))
	}
}

func TestDiagActivityPollLoop(t *testing.T) {
	t.Parallel()
	// cancelled while fn runs: no error, no further call
	var ctx, cancel = context.WithCancel(context.Background())
	var calls = 0
	var err = diagActivityPollLoop(ctx, time.Hour, nil, func() error {
		calls++
		cancel()
		return errors.New("request aborted")
	})
	if err != nil || calls != 1 {
		t.Errorf("want nil after 1 call, got %v after %d", err, calls)
	}
	// the real sleep returns when ctx is cancelled
	var ctx2, cancel2 = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	var start = time.Now()
	if diagActivitySleep(ctx2, time.Hour) || time.Since(start) > 5*time.Second {
		t.Error("diagActivitySleep ignored the cancelled context")
	}
	if !diagActivitySleep(context.Background(), time.Millisecond) {
		t.Error("diagActivitySleep did not sleep")
	}
}
