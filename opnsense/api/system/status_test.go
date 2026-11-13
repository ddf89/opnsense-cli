package system

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"strings"
	"testing"
)

// statusTestAnswer is a trimmed copy of the 26.7.9 answer with three notices, in the order OPNsense sorted them
// (not alphabetical, so a map decoding would show)
const statusTestAnswer = `{"metadata":{"system":{"status":"ERROR","message":"No pending messages","title":"System"},` +
	`"translations":{"dialogTitle":"System Status","dialogCloseButton":"Close"},"subsystems":[]},"subsystems":{` +
	`"firewall":{"title":"Firewall","statusCode":-1,"message":"There were error(s) loading the rules","location":"/ui/diagnostics/log/core/firewall","timestamp":1762940000,"persistent":false,"isBanner":false,"priority":20,"status":"ERROR","age":"2 hours ago"},` +
	`"diskspace":{"title":"Disk Space","statusCode":-1,"message":"Disk space on the root filesystem is critically full (2.32G or 90% used, 258M available).","location":null,"timestamp":null,"persistent":true,"isBanner":false,"priority":5,"status":"ERROR"},` +
	`"crashreporter":{"title":"Crash Reporter","statusCode":0,"message":"An issue was detected and can be reviewed using the firmware crash reporter.","location":"/crash_reporter.php","timestamp":"1762900000","persistent":false,"isBanner":false,"priority":10,"status":"WARNING","age":"13 hours ago"}}}`

// statusTestServer answers every request with the answer of its path and records the requests
func statusTestServer(t *testing.T, answers map[string]string, requests *[]*http.Request, bodies *[]string) *SystemApi {
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		*requests = append(*requests, r)
		*bodies = append(*bodies, string(body))
		if answer, found := answers[r.URL.Path]; found {
			_, _ = w.Write([]byte(answer))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &SystemApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}
}

func TestStatusNotices(t *testing.T) {
	var requests []*http.Request
	var bodies []string
	var api = statusTestServer(t, map[string]string{"/api/core/system/status": statusTestAnswer}, &requests, &bodies)

	var notices, err = api.StatusNotices()
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 1 || requests[0].Method != "GET" {
		t.Fatalf("want one GET, got %d requests", len(requests))
	}
	var subjects []string
	for _, notice := range notices {
		subjects = append(subjects, notice.Subject)
	}
	if strings.Join(subjects, ",") != "firewall,diskspace,crashreporter" {
		t.Fatalf("the order of OPNsense must be kept, got %v", subjects)
	}

	var firewall = notices[0]
	if firewall.Title != "Firewall" || firewall.StatusCode != StatusCodeError || firewall.Status != "ERROR" ||
		firewall.Location != "/ui/diagnostics/log/core/firewall" || firewall.Timestamp != 1762940000 ||
		firewall.Age != "2 hours ago" || firewall.Priority != 20 || !firewall.Dismissable() {
		t.Errorf("firewall: %+v", firewall)
	}
	var disk = notices[1]
	if disk.Location != "" || disk.Timestamp != 0 || !disk.Persistent || disk.Dismissable() || !strings.Contains(disk.Message, "90% used") {
		t.Errorf("diskspace: %+v", disk)
	}
	var crash = notices[2]
	if crash.Timestamp != 1762900000 || crash.StatusCode != StatusCodeWarning || !crash.Dismissable() {
		t.Errorf("crashreporter (timestamp as a string): %+v", crash)
	}
	var raw map[string]any
	if err := json.Unmarshal(crash.Raw, &raw); err != nil || raw["title"] != "Crash Reporter" || raw["timestamp"] != "1762900000" {
		t.Errorf("raw: %s (%v)", crash.Raw, err)
	}
}

func TestStatusNoticesEmptyAndInvalid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answer  string
		wantErr string
	}{
		// PHP encodes an empty array as []
		{"no notices", `{"metadata":{"system":{"status":"OK","message":"No pending messages","title":"System"},"subsystems":[]},"subsystems":[]}`, ""},
		{"no subsystems", `{"metadata":{"system":{"status":"OK"}}}`, ""},
		{"not OPNsense", `{"status":"ok"}`, "no metadata"},
		{"non-empty list", `{"metadata":{},"subsystems":[{"title":"x"}]}`, "non-empty list"},
		{"bad timestamp", `{"metadata":{},"subsystems":{"x":{"timestamp":"yesterday"}}}`, "timestamp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests []*http.Request
			var bodies []string
			var api = statusTestServer(t, map[string]string{"/api/core/system/status": tc.answer}, &requests, &bodies)
			var notices, err = api.StatusNotices()
			if tc.wantErr == "" {
				if err != nil || len(notices) != 0 {
					t.Errorf("want no notices, got %+v, %v", notices, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("want an error with %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestStatusDismiss(t *testing.T) {
	var requests []*http.Request
	var bodies []string
	var api = statusTestServer(t, map[string]string{"/api/core/system/dismiss_status": `{"status":"ok"}`}, &requests, &bodies)

	if err := api.StatusDismiss("firewall"); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 1 || requests[0].Method != "POST" {
		t.Fatalf("want one POST, got %d requests", len(requests))
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(bodies[0]), &body); err != nil || len(body) != 1 || body["subject"] != "firewall" {
		t.Errorf("body %q (%v), want {\"subject\":\"firewall\"}", bodies[0], err)
	}

	var failing = statusTestServer(t, map[string]string{"/api/core/system/dismiss_status": `{"status":"failed"}`}, &requests, &bodies)
	if err := failing.StatusDismiss("diskspace"); err == nil || !strings.Contains(err.Error(), "did not dismiss") {
		t.Errorf("want a refusal, got %v", err)
	}

	requests = nil
	if err := api.StatusDismiss(" "); err == nil || len(requests) != 0 {
		t.Errorf("an empty subject must fail without a request: %v, %d requests", err, len(requests))
	}
}
