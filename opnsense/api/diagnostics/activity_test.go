package diagnostics

import (
	"net/http"
	"strings"
	"testing"
)

const activityTestAnswer = `{"headers":["last pid: 34390;  load averages:    1.56,    0.82,    0.65  up 0+00:43:41    00:07:37",` +
	`"143 threads:   4 running, 125 sleeping, 14 waiting","CPU: 50.0% user,  0.0% nice, 13.7% system,  2.3% interrupt, 34.0% idle",` +
	`"Mem: 205M Active, 34M Inact, 338M Wired, 174M Buf, 1381M Free"],"details":[` +
	`{"C":"0","PID":"11","THR":"100003","USERNAME":"root","PRI":"199","NICE":"ki31","SIZE":"0B","RES":"16K","STATE":"RUN","TIME":"41:27","WCPU":"33.23%","COMMAND":"[idle]"},` +
	`{"C":"0","PID":"65995","THR":"100369","USERNAME":"root","PRI":"13","NICE":"0","SIZE":"205M","RES":"47M","STATE":"select","TIME":"0:01","WCPU":"14.55%","COMMAND":"/usr/local/bin/php-cgi"}]}`

func TestActivityGet(t *testing.T) {
	var api, calls = trafficTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/activity/get_activity": trafficTestJSON(200, activityTestAnswer),
	})
	var activity, err = api.ActivityGet()
	if err != nil {
		t.Fatal(err)
	}
	if len(activity.Headers) != 4 || !strings.HasPrefix(activity.Headers[2], "CPU:") || len(activity.Threads) != 2 {
		t.Fatalf("unexpected activity %+v", activity)
	}
	var php = activity.Threads[1]
	if php.Pid != "65995" || php.Thread != "100369" || php.User != "root" || php.Priority != "13" || php.Nice != "0" ||
		php.Size != "205M" || php.Resident != "47M" || php.State != "select" || php.Cpu != "0" || php.Time != "0:01" ||
		php.CpuUsage != "14.55%" || php.Command != "/usr/local/bin/php-cgi" {
		t.Errorf("unexpected thread %+v", php)
	}
	if string(activity.Raw) != activityTestAnswer {
		t.Error("raw answer not kept")
	}
	if c := calls(); len(c) != 1 || c[0].Method != "GET" {
		t.Errorf("unexpected requests %+v", c)
	}
}

func TestActivityGetErrors(t *testing.T) {
	for _, tc := range []struct {
		status  int
		answer  string
		wantErr string
	}{
		{200, `{}`, "no headers and no details"},
		{200, ``, "empty response"},
		{200, `{"headers":"x"}`, "unexpected answer"},
		{403, `{"status":403,"message":"Forbidden"}`, "HTTP 403"},
	} {
		var api, _ = trafficTestApi(t, map[string]http.HandlerFunc{
			"GET /api/diagnostics/activity/get_activity": trafficTestJSON(tc.status, tc.answer),
		})
		if _, err := api.ActivityGet(); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%q: want error containing %q, got %v", tc.answer, tc.wantErr, err)
		}
	}
}
