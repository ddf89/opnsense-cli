package cli

import (
	"reflect"
	"strings"
	"testing"
)

func systemNtpFake(t *testing.T, gps string) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search("/api/ntpd/service/status",
		map[string]any{"status": "__pool", "server": "0.opnsense.pool.ntp.org", "refid": ".POOL.", "stratum": "16", "type": "p",
			"when": "-", "poll": "64", "reach": "0", "delay": "0.000", "offset": "+0.000", "jitter": "0.000"},
		map[string]any{"status": "*", "server": "193.203.3.171", "refid": ".GPS.", "stratum": "1", "type": "u",
			"when": "24", "poll": "64", "reach": "377", "delay": "50.195", "offset": "-2.356", "jitter": "9.305"},
		map[string]any{"status": " ", "server": "10.0.0.1", "refid": ".INIT.", "stratum": "16", "type": "u",
			"when": "-", "poll": "64", "reach": "0", "delay": "0.000", "offset": "+0.000", "jitter": "0.000"},
	)
	f.on("GET", "/api/ntpd/service/gps", 200, `{"ntpq_servers":[],"gps":`+gps+`}`)
	return f
}

func TestSystemNtpStatus(t *testing.T) {
	t.Parallel()
	var f = systemNtpFake(t, "[]")
	var r = f.run("/system/ntp", "status")
	wantExit(t, r, 0)
	var want = []string{
		"SERVER|STATUS|REFID|ST|T|WHEN|POLL|REACH|DELAY|OFFSET|JITTER",
		"0.opnsense.pool.ntp.org|pool|.POOL.|16|p|-|64|0|0.000|+0.000|0.000",
		"193.203.3.171|* active peer|.GPS.|1|u|24|64|377|50.195|-2.356|9.305",
		"10.0.0.1|not considered|.INIT.|16|u|-|64|0|0.000|+0.000|0.000",
	}
	if got := firewallGroupLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("status:\n got  %q\n want %q", got, want)
	}

	var detail = f.run("/system/ntp", "status", "detail")
	wantExit(t, detail, 0)
	wantContains(t, "detail", detail.stdout, "server:   193.203.3.171\n", "type:     u (unicast)\n", "status:   * active peer\n")

	var asJSON = f.run("/system/ntp", "status", "json")
	wantExit(t, asJSON, 0)
	if lines := strings.Split(strings.TrimSpace(asJSON.stdout), "\n"); len(lines) != 3 || !strings.Contains(lines[1], `"refid":".GPS."`) {
		t.Errorf("json: %q", asJSON.stdout)
	}
	wantNoMutations(t, f)
}

func TestSystemNtpStatusGps(t *testing.T) {
	t.Parallel()
	var f = systemNtpFake(t, `{"sentence":"$GPRMC","ok":true,"lat":52.5,"lat_dir":"N"}`)
	var r = f.run("/system/ntp", "status")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "gps-lat:       52.5\n", "gps-lat-dir:   N\n", "gps-ok:        true\n", "gps-sentence:  $GPRMC\n")
}

func TestSystemNtpStatusNotRunning(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search("/api/ntpd/service/status")
	f.on("GET", "/api/ntpd/service/gps", 200, `{"ntpq_servers":[],"gps":[]}`)
	var r = f.run("/system/ntp", "status")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "not running")
}
