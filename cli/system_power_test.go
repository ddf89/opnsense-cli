package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	systemPowerRebootPath = "/api/core/system/reboot"
	systemPowerHaltPath   = "/api/core/system/halt"
	systemPowerStatusPath = "/api/core/system/status"
	systemPowerStatusUp   = `{"metadata":{"system":{"status":2,"message":"No pending messages","title":"System"},` +
		`"translations":{"dialogTitle":"System Status","dialogCloseButton":"Close"},"subsystems":[]}}`
)

// systemPowerStatusScript answers the n-th status request with states[n] ("up" or "down" = 502), the last one repeats
func systemPowerStatusScript(f *fakeOPN, states ...string) {
	var mu sync.Mutex
	var n = 0
	f.onFunc("GET", systemPowerStatusPath, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		var state = states[min(n, len(states)-1)]
		n++
		mu.Unlock()
		if state == "up" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(systemPowerStatusUp))
			return
		}
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
	})
}

func TestSystemPowerRefusesWithoutConfirm(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"reboot"},
		{"reboot", "wait"},
		{"reboot", "confirm=no"},
		{"reboot", "yes"},
		{"shutdown"},
		{"halt"},
		{"poweroff"},
		{"shutdown", "confirm=no"},
	} {
		t.Run(systemBackupName(args), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on("POST", systemPowerRebootPath, 200, systemBackupStatusOk)
			f.on("POST", systemPowerHaltPath, 200, systemBackupStatusOk)
			var r = f.run(append([]string{"/system"}, args...)...)
			wantFailure(t, r)
			wantNoCalls(t, f)
		})
	}
	t.Run("a script does not reboot", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		wantFailure(t, f.runScript("/system\nreboot\n"), "confirm=yes")
		wantFailure(t, f.runScript("/system shutdown\n"), "confirm=yes")
		wantNoCalls(t, f)
	})
}

func TestSystemPowerRefusesWithoutConfirmNeedsNoEnvironment(t *testing.T) {
	t.Parallel()
	var r = runOpn(t, nil, "/system", "shutdown")
	wantFailure(t, r, "physical or console", "confirm=yes")
	wantNotContains(t, "output", r.stderr, "OPN_URL")

	r = runOpn(t, nil, "/system", "reboot", "wait")
	wantFailure(t, r, "reboots the firewall", "confirm=yes")
	wantNotContains(t, "output", r.stderr, "OPN_URL")
}

func TestSystemPowerActions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args    []string
		path    string
		status  int
		answer  string
		wantOk  bool
		wantOut string
	}{
		{[]string{"reboot", "confirm"}, systemPowerRebootPath, 200, systemBackupStatusOk, true, "reboot of"},
		{[]string{"reboot", "confirm"}, systemPowerRebootPath, 200, `{"status":"failed"}`, false, `"failed"`},
		{[]string{"reboot", "confirm"}, systemPowerRebootPath, 200, ``, false, "empty response"},
		{[]string{"reboot", "confirm"}, systemPowerRebootPath, 401, `{"status":401,"message":"Authentication Failed"}`, false, "HTTP 401"},
		{[]string{"reboot", "confirm"}, systemPowerRebootPath, 404, `{"errorMessage":"Endpoint not found"}`, false, "HTTP 404: Endpoint not found"},
		{[]string{"shutdown", "confirm"}, systemPowerHaltPath, 200, systemBackupStatusOk, true, "power off of"},
		{[]string{"halt", "confirm=yes"}, systemPowerHaltPath, 200, systemBackupStatusOk, true, "will not come back"},
		{[]string{"poweroff", "confirm"}, systemPowerHaltPath, 200, `{"status":"failed"}`, false, `"failed"`},
		{[]string{"shutdown", "confirm"}, systemPowerHaltPath, 401, `{"status":401,"message":"Authentication Failed"}`, false, "HTTP 401"},
		{[]string{"shutdown", "confirm"}, systemPowerHaltPath, 404, `{"errorMessage":"Endpoint not found"}`, false, "HTTP 404"},
	} {
		t.Run(systemBackupName(tc.args)+"/"+tc.answer, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on("POST", tc.path, tc.status, tc.answer)
			var r = f.run(append([]string{"/system"}, tc.args...)...)
			if tc.wantOk {
				wantExit(t, r, 0)
			} else {
				wantFailure(t, r)
			}
			wantContains(t, "output", r.stdout+r.stderr, tc.wantOut)
			if r.stdout != "" {
				t.Errorf("want empty stdout, got %q", r.stdout)
			}
			if len(f.calls()) != 1 {
				t.Errorf("want exactly one call, got %v", f.calls())
			}
			wantOneMutation(t, f, "POST", tc.path)
		})
	}
}

func TestSystemPowerRebootArgValidation(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"reboot", "confirm", "timeout=1m"},
		{"reboot", "confirm", "poll-interval=1s"},
		{"reboot", "confirm", "wait", "timeout=0s"},
		{"reboot", "confirm", "wait", "timeout=-1m"},
		{"reboot", "confirm", "wait", "poll-interval=0"},
		{"reboot", "confirm", "wait", "timeout=soon"},
		{"reboot", "confirm", "now"},
		{"shutdown", "confirm", "now"},
	} {
		t.Run(systemBackupName(args), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			wantFailure(t, f.run(append([]string{"/system"}, args...)...))
			wantNoCalls(t, f)
		})
	}
}

// cross-argument errors come before the confirmation question: no question, no request
func TestSystemPowerCheckBeforeConfirm(t *testing.T) {
	t.Parallel()
	const want = "reboot: timeout and poll-interval are only used together with wait"
	for _, args := range [][]string{{"reboot", "timeout=1m"}, {"reboot", "poll-interval=1s", "wait=no"}} {
		t.Run(systemBackupName(args), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			var r = f.run(append([]string{"/system"}, args...)...)
			wantFailure(t, r, want)
			wantNotContains(t, "output", r.stderr, "confirm=yes")
			r = f.runScript("/system " + strings.Join(args, " ") + "\n")
			wantFailure(t, r, "stdin:1: "+want)
			wantNotContains(t, "output", r.stderr, "confirm=yes")
			wantNoCalls(t, f)
		})
	}
}

// systemPowerAskSession is a session on the real menu tree that records questions (answering yes) and fails
// when the API would be configured
func systemPowerAskSession(t *testing.T) (*Session, *[]string) {
	t.Helper()
	var out bytes.Buffer
	var session = NewSession(&out, &out)
	var asked []string
	session.Ask = func(question string) (bool, error) {
		asked = append(asked, question)
		return true, nil
	}
	session.Configure = func() (*coreapi.OPNsense, error) {
		t.Errorf("the API must not be used")
		return nil, errors.New("no api in this test")
	}
	return session, &asked
}

func TestSystemPowerCheckAsksNothing(t *testing.T) {
	t.Parallel()
	for line, want := range map[string]string{
		"/system reboot timeout=1m":                "only used together with wait",
		"/system reboot wait=no poll-interval=1s":  "only used together with wait",
		"/system/backup revert current":            "revert: item must be a backup",
		"/system/backup remove item=CURRENT":       "remove: item must be a backup",
		"/system/backup download overwrite file=-": "download: overwrite has no effect",
	} {
		var session, asked = systemPowerAskSession(t)
		var err = session.ExecuteLine(line)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err %v, want %q", line, err, want)
		}
		if len(*asked) != 0 {
			t.Errorf("%q asked %q", line, *asked)
		}
	}
}

func TestSystemPowerRebootWaitBinary(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", systemPowerRebootPath, 200, systemBackupStatusOk)
	systemPowerStatusScript(f, "up", "down", "down", "up")
	var r = f.run("/system", "reboot", "confirm", "wait", "timeout=5s", "poll-interval=10ms")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "reboot of", "waiting up to 5s", "went down", "back up")
	wantOneMutation(t, f, "POST", systemPowerRebootPath)
	var calls = f.calls()
	if len(calls) != 5 || calls[0].Path != systemPowerRebootPath {
		t.Errorf("want the reboot followed by 4 status probes, got %v", calls)
	}
}

func TestSystemPowerRebootWaitBinaryNeverWentDown(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", systemPowerRebootPath, 200, systemBackupStatusOk)
	systemPowerStatusScript(f, "up")
	var r = f.run("/system", "reboot", "confirm", "wait", "timeout=200ms", "poll-interval=10ms")
	wantFailure(t, r, "never went down")
	wantOneMutation(t, f, "POST", systemPowerRebootPath)
}

// Ctrl-C stops waiting (not the reboot) without an error
func TestSystemPowerRebootWaitInterrupt(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", systemPowerRebootPath, 200, systemBackupStatusOk)
	systemPowerStatusScript(f, "up")
	var p = f.start("/system", "reboot", "confirm", "wait", "poll-interval=1h")
	f.waitForConnections(systemPowerStatusPath, 1)
	var r = p.interrupt()
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "stopped waiting")
	wantOneMutation(t, f, "POST", systemPowerRebootPath)
}

// --- in-process tests of the wait logic with a fake clock

type systemPowerTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *systemPowerTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *systemPowerTestClock) Sleep(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// systemPowerTestContext returns a Context for in-process runs writing everything to out
func systemPowerTestContext(ctx context.Context, out *bytes.Buffer) *Context {
	var session = NewSession(out, out)
	return &Context{Context: ctx, Out: out, ErrOut: out, Session: session, Menu: Root}
}

// systemPowerTestApi returns a SystemApi talking to the fake OPNsense in-process
func systemPowerTestApi(t *testing.T, f *fakeOPN) *system.SystemApi {
	t.Helper()
	var serverUrl, err = url.Parse(f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &system.SystemApi{OPNsense: &coreapi.OPNsense{
		BaseUrl: *serverUrl, ApiKey: testApiKey, ApiSecret: testApiSecret, NoSslVerify: true,
	}}
}

func systemPowerRebootInProcess(t *testing.T, timeout time.Duration, states ...string) (*fakeOPN, string, error) {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("POST", systemPowerRebootPath, 200, systemBackupStatusOk)
	systemPowerStatusScript(f, states...)
	var clock = &systemPowerTestClock{now: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	var out bytes.Buffer
	var err = systemPowerRebootExecute(systemPowerTestContext(context.Background(), &out), systemPowerTestApi(t, f), true,
		system.PowerWaitOptions{Timeout: timeout, PollInterval: 5 * time.Second}, systemPowerClock{Now: clock.Now, Sleep: clock.Sleep})
	return f, out.String(), err
}

func TestSystemPowerRebootWaitDownThenUp(t *testing.T) {
	t.Parallel()
	var f, out, err = systemPowerRebootInProcess(t, time.Minute, "up", "up", "down", "down", "up")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	wantContains(t, "output", out, "waiting up to 1m0s", "went down after 10s", "back up after 20s")
	if len(f.calls()) != 6 {
		t.Errorf("want reboot + 5 probes, got %v", f.calls())
	}
}

func TestSystemPowerRebootWaitTimeoutDown(t *testing.T) {
	t.Parallel()
	var _, out, err = systemPowerRebootInProcess(t, 30*time.Second, "up", "down")
	if err == nil || !strings.Contains(err.Error(), "timed out after 30s waiting for the system to come back up") {
		t.Fatalf("want come back timeout, got %v\n%s", err, out)
	}
	wantContains(t, "output", out, "went down after 5s")
	wantNotContains(t, "output", out, "is back up")
}

func TestSystemPowerRebootWaitNeverWentDown(t *testing.T) {
	t.Parallel()
	var f, out, err = systemPowerRebootInProcess(t, 20*time.Second, "up")
	if err == nil || !strings.Contains(err.Error(), "never went down") {
		t.Fatalf("want never went down, got %v\n%s", err, out)
	}
	if len(f.calls()) != 6 { // reboot + probes at 0, 5, 10, 15, 20s
		t.Errorf("want reboot + 5 probes, got %v", f.calls())
	}
}

func TestSystemPowerRebootNoWaitMakesNoProbe(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", systemPowerRebootPath, 200, systemBackupStatusOk)
	var out bytes.Buffer
	if err := systemPowerRebootExecute(systemPowerTestContext(context.Background(), &out), systemPowerTestApi(t, f), false,
		system.PowerWaitOptions{}, systemPowerClock{}); err != nil {
		t.Fatal(err)
	}
	if len(f.calls()) != 1 {
		t.Errorf("want only the reboot call, got %v", f.calls())
	}
}

func TestSystemPowerRebootWaitCancelled(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", systemPowerRebootPath, 200, systemBackupStatusOk)
	systemPowerStatusScript(f, "up")
	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	var done = make(chan error, 1)
	go func() {
		done <- systemPowerRebootExecute(systemPowerTestContext(ctx, &out), systemPowerTestApi(t, f), true,
			system.PowerWaitOptions{Timeout: time.Hour, PollInterval: time.Hour}, systemPowerClock{})
	}()
	f.waitForConnections(systemPowerStatusPath, 1)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("cancelled wait: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the wait did not stop on cancel")
	}
	wantContains(t, "output", out.String(), "stopped waiting")
}
