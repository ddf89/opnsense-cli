package system

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"strings"
	"sync"
	"testing"
	"time"
)

const powerTestStatusAnswer = `{"metadata":{"system":{"status":2,"message":"No pending messages","title":"System"},` +
	`"translations":{"dialogTitle":"System Status","dialogCloseButton":"Close"},"subsystems":[]}}`

type powerTestCall struct {
	Method string
	Path   string
	Body   string
}

// powerTestApi returns a SystemApi talking to a test server answering with handler, and the recorded requests
func powerTestApi(t *testing.T, handler http.HandlerFunc) (*SystemApi, func() []powerTestCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []powerTestCall
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, powerTestCall{Method: r.Method, Path: r.URL.Path, Body: string(body)})
		mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(server.Close)

	var serverUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	var api = &SystemApi{OPNsense: &coreapi.OPNsense{BaseUrl: *serverUrl, ApiKey: "key", ApiSecret: "secret"}}
	return api, func() []powerTestCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]powerTestCall(nil), calls...)
	}
}

func powerTestAnswer(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func TestPowerActions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		call    func(*SystemApi) error
		path    string
		status  int
		answer  string
		wantErr string // "" for success
	}{
		{"reboot", (*SystemApi).PowerReboot, "/api/core/system/reboot", 200, `{"status":"ok"}`, ""},
		{"reboot failed", (*SystemApi).PowerReboot, "/api/core/system/reboot", 200, `{"status":"failed"}`, `"failed"`},
		{"reboot no status", (*SystemApi).PowerReboot, "/api/core/system/reboot", 200, `{}`, `status ""`},
		{"reboot empty", (*SystemApi).PowerReboot, "/api/core/system/reboot", 200, ``, "empty response"},
		{"reboot not json", (*SystemApi).PowerReboot, "/api/core/system/reboot", 200, `<html>`, "could not decode"},
		{"reboot 401", (*SystemApi).PowerReboot, "/api/core/system/reboot", 401, `{"status":401,"message":"Authentication Failed"}`, "HTTP 401: Authentication Failed"},
		{"reboot 403", (*SystemApi).PowerReboot, "/api/core/system/reboot", 403, `{"status":403,"message":"Forbidden"}`, "HTTP 403: Forbidden"},
		{"reboot 404", (*SystemApi).PowerReboot, "/api/core/system/reboot", 404, `{"errorMessage":"Endpoint not found"}`, "HTTP 404: Endpoint not found"},
		{"halt", (*SystemApi).PowerOff, "/api/core/system/halt", 200, `{"status":"ok"}`, ""},
		{"halt failed", (*SystemApi).PowerOff, "/api/core/system/halt", 200, `{"status":"failed"}`, `"failed"`},
		{"halt 401", (*SystemApi).PowerOff, "/api/core/system/halt", 401, `{"status":401,"message":"Authentication Failed"}`, "HTTP 401"},
		{"halt 404", (*SystemApi).PowerOff, "/api/core/system/halt", 404, `{"errorMessage":"Endpoint not found"}`, "HTTP 404"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var api, calls = powerTestApi(t, powerTestAnswer(tc.status, tc.answer))
			var err = tc.call(api)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
			var got = calls()
			if len(got) != 1 || got[0].Method != "POST" || got[0].Path != tc.path || got[0].Body != "" {
				t.Errorf("want exactly one POST %s without body, got %+v", tc.path, got)
			}
		})
	}
}

func TestPowerActionsHttpErrorType(t *testing.T) {
	var api, _ = powerTestApi(t, powerTestAnswer(404, `{"errorMessage":"Endpoint not found"}`))
	var httpErr *coreapi.HttpError
	if err := api.PowerOff(); !errors.As(err, &httpErr) || httpErr.StatusCode != 404 {
		t.Fatalf("want *HttpError 404, got %v", err)
	}
}

// powerTestClock is a fake clock, Sleep advances it instantly
type powerTestClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (c *powerTestClock) Now() time.Time { return c.now }
func (c *powerTestClock) Sleep(d time.Duration) {
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
}

// powerTestScript answers the n-th status probe with states[n] ("up", "down" = 503, "drop" = closed connection,
// "garbage" = 200 with an unexpected body), the last state repeats. Note that the HTTP client transparently retries
// a GET once when a reused keep-alive connection is dropped, so "drop" only maps 1:1 to a probe on a fresh connection
func powerTestScript(t *testing.T, states ...string) http.HandlerFunc {
	var mu sync.Mutex
	var n = 0
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/core/system/status" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		mu.Lock()
		var state = states[min(n, len(states)-1)]
		n++
		mu.Unlock()
		switch state {
		case "up":
			powerTestAnswer(200, powerTestStatusAnswer)(w, r)
		case "down":
			powerTestAnswer(503, `<html>Service Unavailable</html>`)(w, r)
		case "garbage":
			powerTestAnswer(200, `{"metadata":null}`)(w, r)
		case "drop":
			var conn, _, err = http.NewResponseController(w).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_ = conn.Close()
		default:
			t.Errorf("unknown state %q", state)
		}
	}
}

func powerTestWait(t *testing.T, timeout time.Duration, states ...string) ([]PowerWaitEvent, *powerTestClock, int, error) {
	t.Helper()
	var api, calls = powerTestApi(t, powerTestScript(t, states...))
	var clock = &powerTestClock{now: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	var events []PowerWaitEvent
	var err = api.PowerWaitUntilUp(PowerWaitOptions{
		Timeout:      timeout,
		PollInterval: 5 * time.Second,
		ProbeTimeout: 2 * time.Second,
		Progress:     func(e PowerWaitEvent) { events = append(events, e) },
		Now:          clock.Now,
		Sleep:        clock.Sleep,
	})
	return events, clock, len(calls()), err
}

func TestPowerWaitDownThenUp(t *testing.T) {
	var events, clock, probes, err = powerTestWait(t, time.Minute, "up", "up", "down", "garbage", "down", "up", "up")
	if err != nil {
		t.Fatal(err)
	}
	if probes != 6 {
		t.Errorf("want 6 probes (stop at the first up after down), got %d", probes)
	}
	if len(events) != 2 || events[0].State != PowerStateDown || events[1].State != PowerStateUp {
		t.Fatalf("want down then up events, got %+v", events)
	}
	if events[0].Err == nil || events[0].Elapsed != 10*time.Second || events[1].Elapsed != 25*time.Second {
		t.Errorf("unexpected events %+v", events)
	}
	if len(clock.sleeps) != 5 {
		t.Errorf("want 5 sleeps, got %v", clock.sleeps)
	}
}

func TestPowerWaitNeverWentDown(t *testing.T) {
	var events, clock, probes, err = powerTestWait(t, 12*time.Second, "up")
	if err == nil || !strings.Contains(err.Error(), "never went down") {
		t.Fatalf("want never went down error, got %v", err)
	}
	if len(events) != 0 {
		t.Errorf("want no events, got %+v", events)
	}
	// probes at 0s, 5s, 10s, 12s: the last sleep is cut to the deadline
	if probes != 4 || clock.now.Sub(time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)) != 12*time.Second {
		t.Errorf("want 4 probes ending at the deadline, got %d probes, sleeps %v", probes, clock.sleeps)
	}
}

func TestPowerWaitNeverCameBack(t *testing.T) {
	var events, _, probes, err = powerTestWait(t, 30*time.Second, "up", "down")
	if err == nil || !strings.Contains(err.Error(), "come back up") || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("want come back up timeout with last error, got %v", err)
	}
	if len(events) != 1 || events[0].State != PowerStateDown {
		t.Errorf("want only a down event, got %+v", events)
	}
	if probes != 7 {
		t.Errorf("want 7 probes (0s..30s every 5s), got %d", probes)
	}
}

func TestPowerWaitAlreadyDown(t *testing.T) {
	// a dropped connection counts as down
	var events, _, probes, err = powerTestWait(t, time.Minute, "drop", "up")
	if err != nil {
		t.Fatal(err)
	}
	if probes != 2 || len(events) != 2 || events[0].Elapsed != 0 {
		t.Errorf("want down on the first probe and up on the second, got %d probes, events %+v", probes, events)
	}
}

func TestPowerWaitUnreachable(t *testing.T) {
	// nothing listens: connection refused counts as down
	var server = httptest.NewServer(http.NotFoundHandler())
	var serverUrl, _ = url.Parse(server.URL)
	server.Close()
	var api = &SystemApi{OPNsense: &coreapi.OPNsense{BaseUrl: *serverUrl, ApiKey: "key", ApiSecret: "secret"}}
	var clock = &powerTestClock{now: time.Now()}
	var events []PowerWaitEvent
	var err = api.PowerWaitUntilUp(PowerWaitOptions{
		Timeout: 10 * time.Second, Now: clock.Now, Sleep: clock.Sleep,
		Progress: func(e PowerWaitEvent) { events = append(events, e) },
	})
	if err == nil || !strings.Contains(err.Error(), "come back up") {
		t.Fatalf("want come back up timeout, got %v", err)
	}
	if len(events) != 1 || events[0].State != PowerStateDown {
		t.Errorf("want a down event, got %+v", events)
	}
}

func TestPowerProbeTimeout(t *testing.T) {
	var release = make(chan struct{})
	var api, _ = powerTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	var start = time.Now()
	if err := api.powerProbe(50 * time.Millisecond); err == nil {
		t.Fatal("want a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("probe did not respect its timeout: %s", elapsed)
	}
}

func TestPowerWaitDefaults(t *testing.T) {
	var options = PowerWaitOptions{}.withDefaults()
	if options.Timeout != PowerDefaultWaitTimeout || options.PollInterval != PowerDefaultPollInterval ||
		options.ProbeTimeout != PowerDefaultProbeTimeout || options.Now == nil || options.Sleep == nil || options.Progress == nil {
		t.Errorf("unexpected defaults %+v", options)
	}
}
