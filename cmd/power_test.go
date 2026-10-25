package cmd

import (
	"bytes"
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
	powerRebootPath = "/api/core/system/reboot"
	powerHaltPath   = "/api/core/system/halt"
	powerStatusPath = "/api/core/system/status"
	powerStatusUp   = `{"metadata":{"system":{"status":2,"message":"No pending messages","title":"System"},` +
		`"translations":{"dialogTitle":"System Status","dialogCloseButton":"Close"},"subsystems":[]}}`
)

// powerTestApi returns a SystemApi talking to the fake OPNsense in-process
func powerTestApi(t *testing.T, f *fakeOPN) *system.SystemApi {
	t.Helper()
	var serverUrl, err = url.Parse(f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &system.SystemApi{OPNsense: &coreapi.OPNsense{
		BaseUrl: *serverUrl, ApiKey: testApiKey, ApiSecret: testApiSecret, NoSslVerify: true,
	}}
}

// powerStatusScript answers the n-th status request with states[n] ("up" or "down" = 502), the last one repeats
func powerStatusScript(f *fakeOPN, states ...string) {
	var mu sync.Mutex
	var n = 0
	f.onFunc("GET", powerStatusPath, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		var state = states[min(n, len(states)-1)]
		n++
		mu.Unlock()
		if state == "up" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(powerStatusUp))
			return
		}
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
	})
}

func powerWantOnePost(t *testing.T, f *fakeOPN, path string) {
	t.Helper()
	var mutations = f.mutations()
	if len(mutations) != 1 || mutations[0].Method != "POST" || mutations[0].Path != path {
		t.Errorf("want exactly one POST %s, got %v", path, mutations)
	}
}

func TestPowerRefusesWithoutYes(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"power", "reboot"},
		{"power", "reboot", "--wait"},
		{"power", "reboot", "--yes=false"},
		{"power", "off"},
		{"power", "halt"},
		{"power", "poweroff"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on("POST", powerRebootPath, 200, `{"status":"ok"}`)
			f.on("POST", powerHaltPath, 200, `{"status":"ok"}`)
			var r = f.run(args...)
			wantFailure(t, r, "WARNING", "without --yes")
			wantNoCalls(t, f)
		})
	}
}

func TestPowerRefusesWithoutYesNeedsNoEnvironment(t *testing.T) {
	t.Parallel()
	var r = runOpn(t, nil, "power", "off")
	wantFailure(t, r, "physical or console", "refusing to power off without --yes")
	wantNotContains(t, "output", r.stderr, "OPN_URL")
}

func TestPowerActions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args    []string
		path    string
		status  int
		answer  string
		wantOk  bool
		wantOut string
	}{
		{[]string{"power", "reboot", "--yes"}, powerRebootPath, 200, `{"status":"ok"}`, true, "Reboot of"},
		{[]string{"power", "reboot", "--yes"}, powerRebootPath, 200, `{"status":"failed"}`, false, `"failed"`},
		{[]string{"power", "reboot", "--yes"}, powerRebootPath, 200, ``, false, "empty response"},
		{[]string{"power", "reboot", "--yes"}, powerRebootPath, 401, `{"status":401,"message":"Authentication Failed"}`, false, "HTTP 401"},
		{[]string{"power", "reboot", "--yes"}, powerRebootPath, 404, `{"errorMessage":"Endpoint not found"}`, false, "HTTP 404: Endpoint not found"},
		{[]string{"power", "off", "--yes"}, powerHaltPath, 200, `{"status":"ok"}`, true, "Power off of"},
		{[]string{"power", "halt", "--yes"}, powerHaltPath, 200, `{"status":"ok"}`, true, "will not come back"},
		{[]string{"power", "poweroff", "--yes"}, powerHaltPath, 200, `{"status":"failed"}`, false, `"failed"`},
		{[]string{"power", "off", "--yes"}, powerHaltPath, 401, `{"status":401,"message":"Authentication Failed"}`, false, "HTTP 401"},
		{[]string{"power", "off", "--yes"}, powerHaltPath, 404, `{"errorMessage":"Endpoint not found"}`, false, "HTTP 404"},
	} {
		t.Run(strings.Join(tc.args, " ")+"/"+tc.answer, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on("POST", tc.path, tc.status, tc.answer)
			var r = f.run(tc.args...)
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
			powerWantOnePost(t, f, tc.path)
		})
	}
}

func TestPowerRebootFlagValidation(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"power", "reboot", "--yes", "--timeout", "1m"},
		{"power", "reboot", "--yes", "--wait", "--timeout", "0s"},
		{"power", "reboot", "--yes", "now"},
		{"power", "off", "--yes", "now"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			wantFailure(t, f.run(args...))
			wantNoCalls(t, f)
		})
	}
}

func TestPowerRebootWaitBinary(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", powerRebootPath, 200, `{"status":"ok"}`)
	powerStatusScript(f, "up", "down", "down", "up")
	var r = f.run("power", "reboot", "--yes", "--wait", "--timeout", "5s", "--poll-interval", "10ms")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "Reboot of", "Waiting up to 5s", "went down", "back up")
	powerWantOnePost(t, f, powerRebootPath)
	var calls = f.calls()
	if len(calls) != 5 || calls[0].Path != powerRebootPath {
		t.Errorf("want the reboot followed by 4 status probes, got %v", calls)
	}
}

func TestPowerRebootWaitBinaryNeverWentDown(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", powerRebootPath, 200, `{"status":"ok"}`)
	powerStatusScript(f, "up")
	var r = f.run("power", "reboot", "--yes", "--wait", "--timeout", "200ms", "--poll-interval", "10ms")
	wantFailure(t, r, "never went down")
	powerWantOnePost(t, f, powerRebootPath)
}

// in-process tests of the wait logic with a fake clock

type powerTestClock struct{ now time.Time }

func (c *powerTestClock) Now() time.Time        { return c.now }
func (c *powerTestClock) Sleep(d time.Duration) { c.now = c.now.Add(d) }

func powerRebootInProcess(t *testing.T, timeout time.Duration, states ...string) (*fakeOPN, string, error) {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("POST", powerRebootPath, 200, `{"status":"ok"}`)
	powerStatusScript(f, states...)
	var clock = &powerTestClock{now: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	var out bytes.Buffer
	var err = powerRebootExecute(powerTestApi(t, f), &out, powerRebootOptions{
		Yes: true, Wait: true,
		WaitOptions: system.PowerWaitOptions{Timeout: timeout, PollInterval: 5 * time.Second, Now: clock.Now, Sleep: clock.Sleep},
	})
	return f, out.String(), err
}

func TestPowerRebootWaitDownThenUp(t *testing.T) {
	t.Parallel()
	var f, out, err = powerRebootInProcess(t, time.Minute, "up", "up", "down", "down", "up")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	wantContains(t, "output", out, "Waiting up to 1m0s", "went down after 10s", "back up after 20s")
	if len(f.calls()) != 6 {
		t.Errorf("want reboot + 5 probes, got %v", f.calls())
	}
}

func TestPowerRebootWaitTimeoutDown(t *testing.T) {
	t.Parallel()
	var _, out, err = powerRebootInProcess(t, 30*time.Second, "up", "down")
	if err == nil || !strings.Contains(err.Error(), "timed out after 30s waiting for the system to come back up") {
		t.Fatalf("want come back timeout, got %v\n%s", err, out)
	}
	wantContains(t, "output", out, "went down after 5s")
	wantNotContains(t, "output", out, "is back up")
}

func TestPowerRebootWaitNeverWentDown(t *testing.T) {
	t.Parallel()
	var f, out, err = powerRebootInProcess(t, 20*time.Second, "up")
	if err == nil || !strings.Contains(err.Error(), "never went down") {
		t.Fatalf("want never went down, got %v\n%s", err, out)
	}
	if len(f.calls()) != 6 { // reboot + probes at 0, 5, 10, 15, 20s
		t.Errorf("want reboot + 5 probes, got %v", f.calls())
	}
}

func TestPowerRebootNoWaitMakesNoProbe(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", powerRebootPath, 200, `{"status":"ok"}`)
	var out bytes.Buffer
	if err := powerRebootExecute(powerTestApi(t, f), &out, powerRebootOptions{Yes: true}); err != nil {
		t.Fatal(err)
	}
	if len(f.calls()) != 1 {
		t.Errorf("want only the reboot call, got %v", f.calls())
	}
}

func TestPowerExecuteRefusesWithoutYes(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var out bytes.Buffer
	if err := powerRebootExecute(powerTestApi(t, f), &out, powerRebootOptions{Wait: true}); err == nil {
		t.Error("reboot without yes did not fail")
	}
	if err := powerOffExecute(powerTestApi(t, f), &out, false); err == nil {
		t.Error("power off without yes did not fail")
	}
	// nil api must not be touched either
	if err := powerRebootExecute(nil, &out, powerRebootOptions{}); err == nil {
		t.Error("reboot without yes did not fail")
	}
	if err := powerOffExecute(nil, &out, false); err == nil {
		t.Error("power off without yes did not fail")
	}
	wantContains(t, "output", out.String(), powerRebootWarning, powerOffWarning)
	wantNoCalls(t, f)
}
