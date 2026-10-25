package dnsmasq

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

// serviceTestApi starts a test server answering path with status and body, and records the method used
func serviceTestApi(t *testing.T, path string, status int, body string) (*DnsmasqApi, *string) {
	t.Helper()
	var method = new(string)
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			t.Errorf("unexpected request path %s, want %s", r.URL.Path, path)
		}
		*method = r.Method
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	var baseUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &DnsmasqApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl, ApiKey: "key", ApiSecret: "secret"}}, method
}

func TestServiceStatus(t *testing.T) {
	var api, method = serviceTestApi(t, "/api/dnsmasq/service/status", 200,
		`{"status":"running","widget":{"caption_restart":"Restart","caption_start":"Start","caption_stop":"Stop"}}`)

	var status, err = api.ServiceStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status != "running" {
		t.Errorf("status = %q, want running", status)
	}
	if *method != "GET" {
		t.Errorf("method = %s, want GET", *method)
	}
}

func TestServiceStatusErrors(t *testing.T) {
	var cases = []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"no status", 200, `{"widget":{}}`, "no status"},
		{"empty body", 200, ``, "empty response"},
		{"auth failure", 401, `{"status":401,"message":"Authentication Failed"}`, "HTTP 401: Authentication Failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var api, _ = serviceTestApi(t, "/api/dnsmasq/service/status", c.status, c.body)
			var _, err = api.ServiceStatus()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want containing %q", err, c.want)
			}
		})
	}
}

func TestServiceReconfigure(t *testing.T) {
	var cases = []struct {
		name string
		body string
		want string // "" means success
	}{
		{"ok", `{"status":"ok"}`, ""},
		{"failed with message", `{"status":"failed","status_msg":"Service \"dnsmasq\" failed to start."}`, `Service "dnsmasq" failed to start.`},
		{"failed", `{"status":"failed"}`, `status "failed"`},
		{"get no-op answer", `{"response":[]}`, `status ""`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var api, method = serviceTestApi(t, "/api/dnsmasq/service/reconfigure", 200, c.body)
			var err = api.ServiceReconfigure()
			if *method != "POST" {
				t.Errorf("method = %s, want POST", *method)
			}
			if c.want == "" {
				if err != nil {
					t.Errorf("unexpected error %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want containing %q", err, c.want)
			}
		})
	}
}

func TestServiceActions(t *testing.T) {
	var actions = map[string]func(*DnsmasqApi) error{
		"restart": (*DnsmasqApi).ServiceRestart,
		"start":   (*DnsmasqApi).ServiceStart,
		"stop":    (*DnsmasqApi).ServiceStop,
	}
	var cases = []struct {
		name string
		body string
		want string // "" means success
	}{
		{"ok", `{"response":"OK"}`, ""},
		{"configd error", `{"response":"Execute error"}`, "unexpected response Execute error"},
		{"get no-op answer", `{"response":[]}`, "unexpected response []"},
		{"no response", `{}`, "unexpected response <nil>"},
	}
	for action, call := range actions {
		for _, c := range cases {
			t.Run(action+" "+c.name, func(t *testing.T) {
				var api, method = serviceTestApi(t, "/api/dnsmasq/service/"+action, 200, c.body)
				var err = call(api)
				if *method != "POST" {
					t.Errorf("method = %s, want POST", *method)
				}
				if c.want == "" {
					if err != nil {
						t.Errorf("unexpected error %v", err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), action) {
					t.Errorf("err = %v, want containing %q and %q", err, action, c.want)
				}
			})
		}
	}
}

func TestServiceActionHttpError(t *testing.T) {
	var api, _ = serviceTestApi(t, "/api/dnsmasq/service/restart", 401, `{"status":401,"message":"Authentication Failed"}`)
	var err = api.ServiceRestart()
	var httpErr *coreapi.HttpError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != 401 {
		t.Errorf("err = %v, want *HttpError 401", err)
	}
}
