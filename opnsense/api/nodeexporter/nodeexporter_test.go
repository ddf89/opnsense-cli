package nodeexporter

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

type request struct {
	method string
	path   string
	body   string
}

// testApi starts a server answering every request with status and body and records the requests
func testApi(t *testing.T, status int, body string) (*NodeExporterApi, *[]request) {
	t.Helper()
	var requests = &[]request{}
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data, _ = io.ReadAll(r.Body)
		*requests = append(*requests, request{r.Method, r.URL.Path, string(data)})
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	var baseUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &NodeExporterApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl, ApiKey: "key", ApiSecret: "secret"}}, requests
}

const settingsAnswer = `{"general":{"enabled":"1","listenaddress":"192.168.1.1","listenport":"9100","cpu":"1","exec":"0",
"filesystem":"0","loadavg":"1","meminfo":"0","netdev":"0","time":"0","devstat":"0","interrupts":"0","ntp":"1","zfs":"0"}}`

func TestSettingsGet(t *testing.T) {
	var api, requests = testApi(t, 200, settingsAnswer)
	var settings, err = api.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	if settings.Enabled != "1" || settings.ListenAddress != "192.168.1.1" || settings.ListenPort != "9100" {
		t.Errorf("settings %+v", settings)
	}
	if got := settings.Collectors(); !reflect.DeepEqual(got, []string{"cpu", "loadavg", "ntp"}) {
		t.Errorf("collectors %v", got)
	}
	if (*requests)[0] != (request{"GET", "/api/nodeexporter/general/get", ""}) {
		t.Errorf("request %+v", (*requests)[0])
	}
	if got := (Settings{}).Collectors(); got == nil || len(got) != 0 {
		t.Errorf("no collectors: %#v", got)
	}
}

func TestSettingsGetErrors(t *testing.T) {
	var api, _ = testApi(t, 200, `{"other":{}}`)
	if _, err := api.SettingsGet(); err == nil || !strings.Contains(err.Error(), "no settings") {
		t.Errorf("err %v", err)
	}
	var missing, _ = testApi(t, 404, `{"errorMessage":"Endpoint not found"}`)
	var _, err = missing.SettingsGet()
	var httpErr *coreapi.HttpError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != 404 {
		t.Errorf("want the 404 as *HttpError, got %v", err)
	}
}

func TestSettingsSet(t *testing.T) {
	var enabled, address, port = false, "127.0.0.1", 9101
	var cases = []struct {
		name   string
		update SettingsUpdate
		want   map[string]string
	}{
		{"partial", SettingsUpdate{Enabled: &enabled, ListenAddress: &address, ListenPort: &port},
			map[string]string{"enabled": "0", "listenaddress": "127.0.0.1", "listenport": "9101"}},
		{"collectors", SettingsUpdate{Collectors: []string{"zfs", "cpu"}},
			map[string]string{"cpu": "1", "exec": "0", "filesystem": "0", "loadavg": "0", "meminfo": "0", "netdev": "0",
				"time": "0", "devstat": "0", "interrupts": "0", "ntp": "0", "zfs": "1"}},
		{"no collectors", SettingsUpdate{Collectors: []string{}},
			map[string]string{"cpu": "0", "exec": "0", "filesystem": "0", "loadavg": "0", "meminfo": "0", "netdev": "0",
				"time": "0", "devstat": "0", "interrupts": "0", "ntp": "0", "zfs": "0"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var api, requests = testApi(t, 200, `{"result":"saved"}`)
			if err := api.SettingsSet(c.update); err != nil {
				t.Fatal(err)
			}
			var got struct {
				General map[string]string `json:"general"`
			}
			var sent = (*requests)[0]
			if sent.method != "POST" || sent.path != "/api/nodeexporter/general/set" {
				t.Errorf("request %+v", sent)
			}
			if err := json.Unmarshal([]byte(sent.body), &got); err != nil || !reflect.DeepEqual(got.General, c.want) {
				t.Errorf("body %s, want %v", sent.body, c.want)
			}
		})
	}
}

func TestSettingsSetErrors(t *testing.T) {
	var api, requests = testApi(t, 200, `{"result":"failed","validations":{"general.listenport":"Please provide a valid port number between 1 and 65535."}}`)
	if err := api.SettingsSet(SettingsUpdate{}); err == nil || !strings.Contains(err.Error(), "nothing to change") {
		t.Errorf("empty update: %v", err)
	}
	if err := api.SettingsSet(SettingsUpdate{Collectors: []string{"cpu", "nope"}}); err == nil || !strings.Contains(err.Error(), `"nope"`) {
		t.Errorf("unknown collector: %v", err)
	}
	if len(*requests) != 0 {
		t.Errorf("sent %v", *requests)
	}
	var port = 0
	var err = api.SettingsSet(SettingsUpdate{ListenPort: &port})
	var validation *coreapi.ValidationError
	if !errors.As(err, &validation) || !strings.Contains(err.Error(), "general.listenport") {
		t.Errorf("want the validation error, got %v", err)
	}
}

func TestServiceStatus(t *testing.T) {
	var api, requests = testApi(t, 200, `{"status":"disabled","widget":{"caption_restart":"Restart"}}`)
	var status, err = api.ServiceStatus()
	if err != nil || status != StatusDisabled {
		t.Errorf("status %q %v", status, err)
	}
	if (*requests)[0] != (request{"GET", "/api/nodeexporter/service/status", ""}) {
		t.Errorf("request %+v", (*requests)[0])
	}
	var empty, _ = testApi(t, 200, `{"widget":{}}`)
	if _, err := empty.ServiceStatus(); err == nil || !strings.Contains(err.Error(), "no status") {
		t.Errorf("no status: %v", err)
	}
}

func TestServiceActions(t *testing.T) {
	var actions = map[string]func(api *NodeExporterApi) error{
		"start":   (*NodeExporterApi).ServiceStart,
		"stop":    (*NodeExporterApi).ServiceStop,
		"restart": (*NodeExporterApi).ServiceRestart,
	}
	for action, run := range actions {
		var api, requests = testApi(t, 200, `{"response":"OK"}`)
		if err := run(api); err != nil {
			t.Errorf("%s: %v", action, err)
		}
		if (*requests)[0] != (request{"POST", "/api/nodeexporter/service/" + action, ""}) {
			t.Errorf("%s request %+v", action, (*requests)[0])
		}
		var failing, _ = testApi(t, 200, `{"response":"Execute error"}`)
		if err := run(failing); err == nil || !strings.Contains(err.Error(), "Execute error") {
			t.Errorf("%s failure: %v", action, err)
		}
		var ignored, _ = testApi(t, 200, `{"response":[]}`)
		if err := run(ignored); err == nil {
			t.Errorf("%s: want an error for an empty response", action)
		}
	}
}

func TestServiceReconfigure(t *testing.T) {
	var api, requests = testApi(t, 200, `{"status":"ok"}`)
	if err := api.ServiceReconfigure(); err != nil {
		t.Fatal(err)
	}
	if (*requests)[0] != (request{"POST", "/api/nodeexporter/service/reconfigure", ""}) {
		t.Errorf("request %+v", (*requests)[0])
	}
	var failed, _ = testApi(t, 200, `{"status":"failed","status_msg":"Service \"node_exporter\" failed to start."}`)
	if err := failed.ServiceReconfigure(); err == nil || !strings.Contains(err.Error(), "failed to start") {
		t.Errorf("failure: %v", err)
	}
	var bare, _ = testApi(t, 200, `{"status":"failed"}`)
	if err := bare.ServiceReconfigure(); err == nil || !strings.Contains(err.Error(), `"failed"`) {
		t.Errorf("bare failure: %v", err)
	}
}
