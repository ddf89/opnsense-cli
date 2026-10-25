package cli

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	systemHealthListPath = "/api/diagnostics/systemhealth/getRRDlist"
	systemHealthDataPath = "/api/diagnostics/systemhealth/getSystemHealth/"
)

// systemHealthTestList is a getRRDlist answer of 26.7 with a few reports
const systemHealthTestList = `{"data":{"packets":["lan"],"system":["processor"],"traffic":["lan","wan"]},` +
	`"files":[{"key":"lan-packets","filename":"lan-packets.rrd"},{"key":"lan-traffic","filename":"lan-traffic.rrd"},` +
	`{"key":"system-processor","filename":"system-processor.rrd"},{"key":"wan-traffic","filename":"wan-traffic.rrd"}],` +
	`"interfaces":{"wan":{"descr":"Uplink"},"lan":{"descr":"lan"}},"result":"ok"}`

// systemHealthTestSeries: 2026-10-25 13:44, 13:45 and 13:46 UTC; user is unknown at 13:44 (leading NaN) and 13:46
const systemHealthTestSeries = `{"step":60,"lastupdate":1792935960,"set":{"count":2,"data":[` +
	`{"key":"user","values":[[1792935900000,1.5],[1792935960000,null]]},` +
	`{"key":"system","values":[[1792935840000,0.25],[1792935900000,0.123456],[1792935960000,1234567.5]]}],"step_size":60},` +
	`"title":"Processor | Processor","y-axis_label":"%"}`

func systemHealthFake(t *testing.T) *fakeOPN {
	var f = newFakeOPN(t)
	f.on("GET", systemHealthListPath, 200, systemHealthTestList)
	f.on("GET", systemHealthDataPath+"processor-system/0", 200, systemHealthTestSeries)
	f.on("GET", systemHealthDataPath+"processor-system/2", 200, strings.ReplaceAll(systemHealthTestSeries, `"step_size":60`, `"step_size":3600`))
	return f
}

func TestSystemHealthPrintReports(t *testing.T) {
	var f = systemHealthFake(t)
	var r = f.run("/system/health", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "METRIC", "TOPIC", "0  lan-packets", "2  processor-system  system   processor",
		"3  wan-traffic       traffic  wan        Uplink")

	r = f.run("/system/health", "print", "topic=traffic")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "lan-traffic", "wan-traffic")
	wantNotContains(t, "stdout", r.stdout, "processor", "packets")

	r = f.run("/system/health", "print", "json")
	wantExit(t, r, 0)
	if lines := strings.Split(strings.TrimSpace(r.stdout), "\n"); len(lines) != 4 ||
		lines[2] != `{"description":"processor","filename":"system-processor.rrd","item":"processor","key":"system-processor","metric":"processor-system","topic":"system"}` {
		t.Errorf("json: %s", r.stdout)
	}

	// the # of the print selects the report in the same session
	r = f.runScript("/system/health\nprint\nprint metric=2 to=1792936000\n")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "TIME              USER  SYSTEM", "2026-10-25 13:44  -     0.25")
	wantNoMutations(t, f)
}

func TestSystemHealthPrintEmpty(t *testing.T) {
	var f = newFakeOPN(t)
	f.on("GET", systemHealthListPath, 200, `{"data":[],"files":[],"interfaces":{"lan":{"descr":"lan"}},"result":"ok"}`)
	var r = f.run("/system/health", "print")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "no health data collected yet")
}

func TestSystemHealthPrintValues(t *testing.T) {
	var f = systemHealthFake(t)
	// default range: the 60 steps before to
	var r = f.run("/system/health", "print", "metric=processor-system", "to=1792936000")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout,
		"TIME              USER  SYSTEM",
		"2026-10-25 13:44  -     0.25",
		"2026-10-25 13:45  1.5   0.123",
		"2026-10-25 13:46  -     1234567.5")
	wantContains(t, "stderr", r.stderr, "Processor | Processor (%), one value per 1m")

	// from/to as times, by file name and topic/item
	for _, metric := range []string{"system-processor", "system/processor", "2"} {
		r = f.run("/system/health", "print", "metric="+metric, "from=2026-10-25T13:45", "to=2026-10-25 13:45:30")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "2026-10-25 13:45  1.5   0.123")
		wantNotContains(t, "stdout", r.stdout, "13:44", "13:46")
	}

	r = f.run("/system/health", "print", "metric=processor-system", "from=1792935900", "to=1792935900", "json")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != `{"system":0.123456,"time":"2026-10-25T13:45:00Z","user":1.5}` {
		t.Errorf("json: %s", r.stdout)
	}

	r = f.run("/system/health", "print", "metric=processor-system", "resolution=1h", "to=1792936000")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "one value per 1h")

	// nothing in range
	r = f.run("/system/health", "print", "metric=processor-system", "from=2020-01-01", "to=2020-01-02")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "no values from 2020-01-01 00:00 to 2020-01-02 00:00")
	wantNoMutations(t, f)
}

func TestSystemHealthPrintErrors(t *testing.T) {
	var f = systemHealthFake(t)
	wantFailure(t, f.run("/system/health", "print", "metric=nope"), "not found", "nope")
	for _, call := range f.calls() {
		if strings.HasPrefix(call.Path, systemHealthDataPath) {
			t.Errorf("an unknown report must not be fetched: %v", call)
		}
	}

	var g = newFakeOPN(t)
	wantFailure(t, g.run("/system/health", "print", "resolution=5m"), "resolution only with metric=")
	wantFailure(t, g.run("/system/health", "print", "metric=x", "topic=system"), "topic=")
	wantFailure(t, g.run("/system/health", "print", "metric=x", "from=yesterday"), "from must be a time")
	wantFailure(t, g.run("/system/health", "print", "metric=x", "resolution=2m"), "resolution")
	wantFailure(t, g.run("/system/health", "print", "metric=x", "from=2026-10-25", "to=2026-10-24"), "is after to")
	wantNoCalls(t, g)
}

func TestSystemHealthParseTime(t *testing.T) {
	var now = time.Date(2026, 10, 25, 12, 0, 0, 0, time.Local)
	for value, want := range map[string]time.Time{
		"now":                  now,
		"1792936000":           time.Unix(1792936000, 0),
		"6h":                   now.Add(-6 * time.Hour),
		"1h30m":                now.Add(-90 * time.Minute),
		"2d":                   now.Add(-48 * time.Hour),
		"1w":                   now.Add(-7 * 24 * time.Hour),
		"2026-10-24":           time.Date(2026, 10, 24, 0, 0, 0, 0, time.Local),
		"2026-10-24T08:30":     time.Date(2026, 10, 24, 8, 30, 0, 0, time.Local),
		"2026-10-24 08:30:15":  time.Date(2026, 10, 24, 8, 30, 15, 0, time.Local),
		"2026-10-24T08:30:00Z": time.Date(2026, 10, 24, 8, 30, 0, 0, time.UTC),
	} {
		var got, err = systemHealthParseTime(value, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("%s: got %v, %v, want %v", value, got, err, want)
		}
	}
	for _, value := range []string{"", "yesterday", "-5m", "2026-13-01", "5x"} {
		if _, err := systemHealthParseTime(value, now); err == nil {
			t.Errorf("%q: want an error", value)
		}
	}
}

func TestSystemHealthExport(t *testing.T) {
	var f = systemHealthFake(t)
	var csv = "iso_time;user;system\n2026-10-25T13:45:00+00:00;1.5;0.123456\n"
	f.onFunc("GET", "/api/diagnostics/systemhealth/exportAsCSV/processor-system/1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		_, _ = io.WriteString(w, csv)
	})
	f.onFunc("GET", "/api/diagnostics/systemhealth/exportAsCSV/wan-traffic/0", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	})

	var dir = t.TempDir()
	var r = runOpnIn(t, dir, f.env(), "/system/health", "export", "metric=processor-system", "resolution=5m", "cpu.csv")
	wantExit(t, r, 0)
	if content, err := os.ReadFile(filepath.Join(dir, "cpu.csv")); err != nil || string(content) != csv {
		t.Errorf("file: %q, %v", content, err)
	}
	wantContains(t, "stderr", r.stderr, "saved cpu.csv")

	r = runOpnIn(t, dir, f.env(), "/system/health", "export", "metric=processor-system", "resolution=5m", "cpu.csv")
	wantFailure(t, r, "already exists", "overwrite")
	r = runOpnIn(t, dir, f.env(), "/system/health", "export", "metric=processor-system", "resolution=5m", "cpu.csv", "overwrite")
	wantExit(t, r, 0)

	r = f.run("/system/health", "export", "metric=processor-system", "resolution=5m", "-")
	wantExit(t, r, 0)
	if r.stdout != csv {
		t.Errorf("stdout: %q", r.stdout)
	}

	r = runOpnIn(t, dir, f.env(), "/system/health", "export", "metric=wan-traffic", "wan.csv")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "no data", "nothing exported")
	if _, err := os.Stat(filepath.Join(dir, "wan.csv")); !os.IsNotExist(err) {
		t.Errorf("no file must be written without data: %v", err)
	}

	wantFailure(t, f.run("/system/health", "export", "metric=nope", "x.csv"), "not found")
	wantFailure(t, f.run("/system/health", "export", "metric=wan-traffic", "-", "overwrite"), "overwrite has no effect")
	wantFailure(t, f.run("/system/health", "export", "x.csv"), "metric")
	wantNoMutations(t, f)
}

func TestSystemHealthResetData(t *testing.T) {
	var f = systemHealthFake(t)
	f.on("POST", "/api/diagnostics/systemhealth/del_rrd", 200, `{"status":"OK"}`)
	f.on("POST", "/api/diagnostics/systemhealth/del_rrd/wan-traffic", 200, `{"status":"OK"}`)

	wantFailure(t, f.run("/system/health", "reset-data"), "deletes the collected health data", "confirm=yes")
	wantNoCalls(t, f)

	wantExit(t, f.run("/system/health", "reset-data", "confirm=yes"), 0)
	wantOneMutation(t, f, "POST", "/api/diagnostics/systemhealth/del_rrd")

	var g = systemHealthFake(t)
	g.on("POST", "/api/diagnostics/systemhealth/del_rrd/wan-traffic", 200, `{"status":"OK"}`)
	wantExit(t, g.run("/system/health", "reset-data", "metric=wan-traffic", "confirm=yes"), 0)
	wantOneMutation(t, g, "POST", "/api/diagnostics/systemhealth/del_rrd/wan-traffic")

	var h = systemHealthFake(t)
	h.on("POST", "/api/diagnostics/systemhealth/del_rrd", 500, `{"errorMessage":"failed to flush RRD data"}`)
	wantFailure(t, h.run("/system/health", "reset-data", "confirm=yes"), "failed to flush RRD data")
	wantFailure(t, h.run("/system/health", "reset-data", "metric=nope", "confirm=yes"), "not found")
}

func TestSystemHealthSettings(t *testing.T) {
	var f = newFakeOPN(t)
	f.on("GET", "/api/diagnostics/systemhealth/get", 200, `{"systemhealth":{"enabled":"0"}}`)
	f.on("POST", "/api/diagnostics/systemhealth/set", 200, answerSaved)
	f.on("POST", "/api/diagnostics/systemhealth/reconfigure", 200, `{"status":"OK"}`)

	var r = f.run("/system/health/settings", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "enabled:  no")
	r = f.run("/system/health/settings", "print", "json")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != `{"systemhealth":{"enabled":"0"}}` {
		t.Errorf("json: %s", r.stdout)
	}

	r = f.run("/system/health/settings", "set", "enabled")
	wantExit(t, r, 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/diagnostics/systemhealth/set"), map[string]any{"systemhealth": map[string]any{"enabled": "1"}})
	if r.stdout != "" {
		t.Errorf("set must be silent: %q", r.stdout)
	}

	var g = newFakeOPN(t)
	g.on("POST", "/api/diagnostics/systemhealth/reconfigure", 200, `{"status":"OK"}`)
	wantExit(t, g.run("/system/health/settings", "apply"), 0)
	wantOneMutation(t, g, "POST", "/api/diagnostics/systemhealth/reconfigure")

	var h = newFakeOPN(t)
	h.on("POST", "/api/diagnostics/systemhealth/reconfigure", 200, `{"status":"error restarting cron"}`)
	wantFailure(t, h.run("/system/health/settings", "reconfigure"), "error restarting cron")
	wantFailure(t, h.run("/system/health/settings", "set"), "enabled")
}
