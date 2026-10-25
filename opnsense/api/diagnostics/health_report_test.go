package diagnostics

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	coreapi "opnsense-cli/opnsense/api"
)

// healthTestCall is one request seen by healthTestApi
type healthTestCall struct {
	Method string
	Path   string // escaped
	Query  url.Values
	Body   string
}

// healthTestApi returns a DiagnosticsApi talking to a test server answering "METHOD /escaped/path" with routes
// (unknown routes get a 404 like OPNsense) and a function reporting the requests so far. Shared by the health,
// memory, netflow and insight tests
func healthTestApi(t *testing.T, routes map[string]http.HandlerFunc) (*DiagnosticsApi, func() []healthTestCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []healthTestCall
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, healthTestCall{Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.Query(), Body: string(body)})
		mu.Unlock()
		if handler, found := routes[r.Method+" "+r.URL.EscapedPath()]; found {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"errorMessage":"Endpoint not found"}`)
	}))
	t.Cleanup(server.Close)
	var serverUrl, _ = url.Parse(server.URL)
	return &DiagnosticsApi{OPNsense: &coreapi.OPNsense{BaseUrl: *serverUrl}}, func() []healthTestCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]healthTestCall(nil), calls...)
	}
}

// healthTestRaw answers with body and content type
func healthTestRaw(status int, contentType string, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func healthTestJSON(body string) http.HandlerFunc {
	return healthTestRaw(200, "application/json", body)
}

const healthTestList = `{"data":{"packets":["lan","wan"],"quality":["WAN_DHCP"],"services":["ntpd"],"system":["mbuf","processor"],` +
	`"traffic":["lan","wan"]},"files":[{"key":"WAN_DHCP-quality","filename":"WAN_DHCP-quality.rrd"},` +
	`{"key":"lan-packets","filename":"lan-packets.rrd"},{"key":"ntpd","filename":"ntpd.rrd"},` +
	`{"key":"system-mbuf","filename":"system-mbuf.rrd"},{"key":"system-processor","filename":"system-processor.rrd"},` +
	`{"key":"wan-traffic","filename":"wan-traffic.rrd"}],` +
	`"interfaces":{"wan":{"descr":"Uplink"},"lan":{"descr":"lan"},"lo0":{"descr":"Loopback"}},"result":"ok"}`

func TestHealthReports(t *testing.T) {
	var api, _ = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/systemhealth/getRRDlist": healthTestJSON(healthTestList),
	})
	var reports, raw, err = api.HealthReports()
	if err != nil {
		t.Fatal(err)
	}
	var want = []HealthReport{
		{"WAN_DHCP-quality", "quality", "WAN_DHCP", "WAN_DHCP-quality", "WAN_DHCP-quality.rrd", "WAN_DHCP"},
		{"lan-packets", "packets", "lan", "lan-packets", "lan-packets.rrd", "lan"},
		{"ntpd-services", "services", "ntpd", "ntpd", "ntpd.rrd", "ntpd"},
		{"mbuf-system", "system", "mbuf", "system-mbuf", "system-mbuf.rrd", "mbuf"},
		{"processor-system", "system", "processor", "system-processor", "system-processor.rrd", "processor"},
		{"wan-traffic", "traffic", "wan", "wan-traffic", "wan-traffic.rrd", "Uplink"},
	}
	if len(reports) != len(want) {
		t.Fatalf("got %+v", reports)
	}
	for i := range want {
		if reports[i] != want[i] {
			t.Errorf("report %d: got %+v, want %+v", i, reports[i], want[i])
		}
	}
	if string(raw) != healthTestList {
		t.Errorf("raw: %s", raw)
	}
}

func TestHealthReportsEmpty(t *testing.T) {
	// 26.7 with the collection disabled
	var api, _ = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/systemhealth/getRRDlist": healthTestJSON(`{"data":[],"files":[],"interfaces":{"wan":{"descr":"wan"}},"result":"ok"}`),
	})
	if reports, _, err := api.HealthReports(); err != nil || len(reports) != 0 {
		t.Errorf("got %v, %v", reports, err)
	}

	var broken, _ = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/systemhealth/getRRDlist": healthTestJSON(`[]`),
	})
	if _, _, err := broken.HealthReports(); err == nil || !strings.Contains(err.Error(), "unexpected answer") {
		t.Errorf("want an error for an unexpected answer, got %v", err)
	}
}

// healthTestSeries is a getSystemHealth answer: "user" starts one step later than "system" (a leading NaN of the
// RRD), and has an unknown value
const healthTestSeries = `{"step":60,"lastupdate":1761400000,"set":{"count":2,"data":[` +
	`{"key":"user","values":[[1761399900000,1.5],[1761399960000,null]]},` +
	`{"key":"system","values":[[1761399840000,0.25],[1761399900000,0.5],[1761399960000,0.75]]}],"step_size":60},` +
	`"title":"Processor | Processor","y-axis_label":"%"}`

func TestHealthFetch(t *testing.T) {
	var api, calls = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/systemhealth/getSystemHealth/processor-system/1": healthTestJSON(healthTestSeries),
	})
	var series, err = api.HealthFetch("processor-system", 1)
	if err != nil {
		t.Fatal(err)
	}
	if series.Title != "Processor | Processor" || series.YAxisLabel != "%" || series.StepSize != 60 ||
		!series.LastUpdate.Equal(time.Unix(1761400000, 0)) || strings.Join(series.Columns, ",") != "user,system" {
		t.Errorf("series: %+v", series)
	}
	if len(series.Rows) != 3 {
		t.Fatalf("rows: %+v", series.Rows)
	}
	var first, second, third = series.Rows[0], series.Rows[1], series.Rows[2]
	if !first.Time.Equal(time.UnixMilli(1761399840000)) || !math.IsNaN(first.Values[0]) || first.Values[1] != 0.25 {
		t.Errorf("first row: %+v", first)
	}
	if second.Values[0] != 1.5 || second.Values[1] != 0.5 {
		t.Errorf("second row: %+v", second)
	}
	if !math.IsNaN(third.Values[0]) || third.Values[1] != 0.75 {
		t.Errorf("third row: %+v", third)
	}
	if string(series.Raw) != healthTestSeries || len(calls()) != 1 || calls()[0].Method != "GET" {
		t.Errorf("raw %s, calls %v", series.Raw, calls())
	}
}

func TestHealthFetchUnknownAndEmpty(t *testing.T) {
	var api, _ = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/systemhealth/getSystemHealth/nope-system/0":      healthTestJSON(`{"set":[],"title":"error","y-axis_label":""}`),
		"GET /api/diagnostics/systemhealth/getSystemHealth/processor-system/7": healthTestJSON(`{"step":60,"lastupdate":1761400000,"set":{"count":0,"data":[],"step_size":0},"title":"Processor","y-axis_label":"%"}`),
		"GET /api/diagnostics/systemhealth/getSystemHealth/odd%2Fname-x/0":     healthTestJSON(`{"set":[],"title":"error","y-axis_label":""}`),
	})
	var _, err = api.HealthFetch("nope-system", 0)
	var notFound *coreapi.NotFoundError
	if !errors.As(err, &notFound) || !strings.Contains(err.Error(), "nope-system") {
		t.Errorf("want not found, got %v", err)
	}
	series, err := api.HealthFetch("processor-system", 7)
	if err != nil || len(series.Rows) != 0 || len(series.Columns) != 0 {
		t.Errorf("want an empty series, got %+v, %v", series, err)
	}
	// the metric is one path element
	if _, err := api.HealthFetch("odd/name-x", 0); !errors.As(err, &notFound) {
		t.Errorf("want not found for the escaped name, got %v", err)
	}
}

func TestHealthExportCsv(t *testing.T) {
	var csv = "iso_time;user;system\n2026-10-25T13:45:00+00:00;1.5;0.5\n"
	var api, _ = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/systemhealth/exportAsCSV/processor-system/0": healthTestRaw(200, "text/csv", csv),
		"GET /api/diagnostics/systemhealth/exportAsCSV/nope-system/0":      healthTestRaw(200, "text/html; charset=UTF-8", ""),
		"GET /api/diagnostics/systemhealth/exportAsCSV/broken-system/0":    healthTestRaw(500, "application/json", `{"errorMessage":"boom"}`),
		"GET /api/diagnostics/systemhealth/exportAsCSV/json-system/0":      healthTestJSON(`{"status":"failed"}`),
	})
	if content, err := api.HealthExportCsv("processor-system", 0); err != nil || string(content) != csv {
		t.Errorf("got %q, %v", content, err)
	}
	if content, err := api.HealthExportCsv("nope-system", 0); err != nil || content != nil {
		t.Errorf("want no content, got %q, %v", content, err)
	}
	var httpErr *coreapi.HttpError
	if _, err := api.HealthExportCsv("broken-system", 0); !errors.As(err, &httpErr) || httpErr.Message != "boom" {
		t.Errorf("want HTTP 500 boom, got %v", err)
	}
	if _, err := api.HealthExportCsv("json-system", 0); err == nil || !strings.Contains(err.Error(), "expected CSV") {
		t.Errorf("want an error for a JSON answer, got %v", err)
	}
}

func TestHealthSettings(t *testing.T) {
	var api, calls = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/systemhealth/get":          healthTestJSON(`{"systemhealth":{"enabled":"1"}}`),
		"POST /api/diagnostics/systemhealth/set":         healthTestJSON(`{"result":"saved"}`),
		"POST /api/diagnostics/systemhealth/reconfigure": healthTestJSON(`{"status":"OK"}`),
	})
	if enabled, _, err := api.HealthSettings(); err != nil || !enabled {
		t.Errorf("got %v, %v", enabled, err)
	}
	if err := api.HealthSetEnabled(false); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	_ = json.Unmarshal([]byte(calls()[1].Body), &body)
	if calls()[1].Method != "POST" || body["systemhealth"].(map[string]any)["enabled"] != "0" {
		t.Errorf("set: %v", calls()[1])
	}
	if err := api.HealthReconfigure(); err != nil {
		t.Error(err)
	}

	var failing, _ = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/systemhealth/get":          healthTestJSON(`[]`),
		"POST /api/diagnostics/systemhealth/set":         healthTestJSON(`{"result":"failed","validations":{"systemhealth.enabled":"bad"}}`),
		"POST /api/diagnostics/systemhealth/reconfigure": healthTestJSON(`{"status":"error restarting cron"}`),
	})
	if _, _, err := failing.HealthSettings(); err == nil {
		t.Error("want an error for an unexpected answer")
	}
	var validation *coreapi.ValidationError
	if err := failing.HealthSetEnabled(true); !errors.As(err, &validation) {
		t.Errorf("want a validation error, got %v", err)
	}
	if err := failing.HealthReconfigure(); err == nil || !strings.Contains(err.Error(), "error restarting cron") {
		t.Errorf("want the status, got %v", err)
	}
}

func TestHealthReset(t *testing.T) {
	var api, calls = healthTestApi(t, map[string]http.HandlerFunc{
		"POST /api/diagnostics/systemhealth/del_rrd":             healthTestJSON(`{"status":"OK"}`),
		"POST /api/diagnostics/systemhealth/del_rrd/wan-traffic": healthTestJSON(`{"status":"OK"}`),
		"POST /api/diagnostics/systemhealth/del_rrd/lan-traffic": healthTestRaw(500, "application/json", `{"errorMessage":"failed to flush RRD data"}`),
	})
	if err := api.HealthReset(""); err != nil {
		t.Error(err)
	}
	if err := api.HealthReset("wan-traffic"); err != nil {
		t.Error(err)
	}
	if err := api.HealthReset("lan-traffic"); err == nil || !strings.Contains(err.Error(), "failed to flush") {
		t.Errorf("want the error message, got %v", err)
	}
	for _, call := range calls() {
		if call.Method != "POST" || call.Body != "" {
			t.Errorf("unexpected %+v", call)
		}
	}
}
