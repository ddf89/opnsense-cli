package system

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

// defaultsTestRequest is a request received by the test server of defaultsTestApi
type defaultsTestRequest struct {
	Method string
	Path   string
}

// defaultsTestApi starts a test server answering every request with status and body, and records the requests.
// Never point these tests at a real OPNsense: DefaultsFactoryReset wipes it
func defaultsTestApi(t *testing.T, status int, body string) (*SystemApi, *[]defaultsTestRequest) {
	t.Helper()
	var requests = &[]defaultsTestRequest{}
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests = append(*requests, defaultsTestRequest{Method: r.Method, Path: r.URL.Path})
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	var baseUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &SystemApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl, ApiKey: "key", ApiSecret: "secret"}}, requests
}

func TestDefaultsGet(t *testing.T) {
	var api, requests = defaultsTestApi(t, 200, `{"default_ip":"192.168.1.1"}`)

	var defaults, err = api.DefaultsGet()
	if err != nil {
		t.Fatal(err)
	}
	if defaults.DefaultIp != "192.168.1.1" {
		t.Errorf("DefaultIp = %q, want 192.168.1.1", defaults.DefaultIp)
	}
	if got := *requests; len(got) != 1 || got[0].Method != "GET" || got[0].Path != "/api/core/defaults/get" {
		t.Errorf("requests = %v, want GET /api/core/defaults/get", got)
	}
}

func TestDefaultsGetErrors(t *testing.T) {
	var cases = []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"no default_ip", 200, `{}`, "no default_ip"},
		{"empty body", 200, ``, "empty response"},
		{"not found", 404, `{"errorMessage":"Endpoint not found"}`, "HTTP 404: Endpoint not found"},
		{"auth failure", 401, `{"status":401,"message":"Authentication Failed"}`, "HTTP 401: Authentication Failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var api, _ = defaultsTestApi(t, c.status, c.body)
			var _, err = api.DefaultsGet()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want containing %q", err, c.want)
			}
		})
	}
}

func TestDefaultsFactoryReset(t *testing.T) {
	var api, requests = defaultsTestApi(t, 200, `{"status":"ok"}`)

	if err := api.DefaultsFactoryReset(); err != nil {
		t.Fatal(err)
	}
	// must be a POST to factory_defaults, core/defaults/reset is the per-section reset with a different contract
	if got := *requests; len(got) != 1 || got[0].Method != "POST" || got[0].Path != "/api/core/defaults/factory_defaults" {
		t.Errorf("requests = %v, want exactly one POST /api/core/defaults/factory_defaults", got)
	}
}

func TestDefaultsFactoryResetErrors(t *testing.T) {
	var cases = []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"failed", 200, `{"status":"failed"}`, `status: "failed"`},
		{"empty body", 200, ``, "empty response"},
		{"read only key", 403, `{"status":403,"message":"Forbidden"}`, "HTTP 403: Forbidden"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var api, _ = defaultsTestApi(t, c.status, c.body)
			var err = api.DefaultsFactoryReset()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want containing %q", err, c.want)
			}
		})
	}
}
