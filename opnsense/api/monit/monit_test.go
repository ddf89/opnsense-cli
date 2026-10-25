package monit

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

type testRequest struct {
	Method string
	Path   string
	Body   map[string]any
}

func newTestApi(t *testing.T, answers map[string]string) (*MonitApi, *[]testRequest) {
	t.Helper()
	var requests []testRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var recorded = testRequest{Method: r.Method, Path: r.URL.Path}
		var raw, _ = io.ReadAll(r.Body)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &recorded.Body); err != nil {
				t.Errorf("invalid request body %q: %v", raw, err)
			}
		}
		requests = append(requests, recorded)
		_, _ = io.WriteString(w, answers[r.Method+" "+r.URL.Path])
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &MonitApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, &requests
}

func mutations(requests []testRequest) []testRequest {
	var result []testRequest
	for _, request := range requests {
		if request.Method != "GET" {
			result = append(result, request)
		}
	}
	return result
}

func TestSettings(t *testing.T) {
	var api, requests = newTestApi(t, map[string]string{
		"GET /api/monit/settings/get_general": `{"monit":{"enabled":"0","interval":"120","mailserver":{"127.0.0.1":{"value":"127.0.0.1","selected":1},` +
			`"mx.example.com":{"value":"mx.example.com","selected":1}},"password":"s3cret","sslversion":{"auto":{"value":"AUTO","selected":1},` +
			`"tlsv13":{"value":"TLSV13","selected":0}},"httpdAllow":{"":{"value":"","selected":1}}},"result":"ok"}`,
		"POST /api/monit/settings/set": `{"result":"failed","validations":{"monit.general.interval":"Polling Interval needs to be an integer value between 0 and 86400."}}`,
	})
	var settings, err = api.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"enabled": "0", "interval": "120", "mailserver": "127.0.0.1,mx.example.com",
		"password": "s3cret", "sslversion": "auto", "httpdAllow": ""} {
		if got := settings[path].Value; got != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}
	var setErr = api.SettingsSet(map[string]string{"interval": "-1"})
	if setErr == nil || !strings.Contains(setErr.Error(), "Polling Interval") {
		t.Errorf("want the validation error, got %v", setErr)
	}
	if body := (*requests)[1].Body; !reflect.DeepEqual(body, map[string]any{"monit": map[string]any{"general": map[string]any{"interval": "-1"}}}) {
		t.Errorf("set body %v", body)
	}
}

const (
	testServiceUuid = "69cf0fbc-020c-4cfb-9b86-fdb538de9dea"
	testTestUuid    = "aa7d0e55-f0c0-4653-a59d-a75cf8025311"
)

func TestRecords(t *testing.T) {
	var api, requests = newTestApi(t, map[string]string{
		"GET /api/monit/settings/search_service": `{"rows":[{"uuid":"` + testServiceUuid + `","enabled":"0","name":"probe","type":"process",` +
			`"match":"x","tests":"` + testTestUuid + `","%tests":"cpu","depends":""},` +
			`{"uuid":"s2","enabled":"1","name":"web","type":"process","depends":"` + testServiceUuid + `"}]}`,
		"GET /api/monit/settings/search_test": `{"rows":[{"uuid":"` + testTestUuid + `","name":"cpu","type":"ProcessResource",` +
			`"condition":"cpu is greater than 90%","action":"alert","path":""},{"uuid":"t2","name":"free","type":"Custom"}]}`,
		"POST /api/monit/settings/del_test/t2":                       `{"result":"deleted"}`,
		"POST /api/monit/settings/del_service/s2":                    `{"result":"not found"}`,
		"POST /api/monit/settings/set_service/" + testServiceUuid:    `{"result":"saved"}`,
		"POST /api/monit/settings/add_alert":                         `{"result":"saved","uuid":"a1"}`,
		"GET /api/monit/settings/search_alert":                       `{"rows":[]}`,
		"GET /api/monit/settings/get_service":                        `{"service":{"interface":{"":{"value":"None","selected":1},"lan":{"value":"LAN","selected":0}}}}`,
		"POST /api/monit/settings/set_test/" + testTestUuid:          `{"result":"saved"}`,
		"POST /api/monit/settings/toggle_service/" + testServiceUuid: `{"result":"Enabled","changed":true}`,
	})
	var services, _, err = api.ServiceSearch("")
	if err != nil || len(services) != 2 || services[0].TestNames != "cpu" || services[1].Depends != testServiceUuid {
		t.Fatalf("services %+v %v", services, err)
	}
	// in use: refused before anything is sent
	if err := api.TestRemove(testTestUuid); err == nil || !strings.Contains(err.Error(), "probe") {
		t.Errorf("test in use: %v", err)
	}
	if err := api.ServiceRemove(testServiceUuid); err == nil || !strings.Contains(err.Error(), "web") {
		t.Errorf("service in use: %v", err)
	}
	if got := mutations(*requests); len(got) != 0 {
		t.Errorf("nothing may be sent for items in use: %+v", got)
	}
	if err := api.TestRemove("t2"); err != nil {
		t.Errorf("remove: %v", err)
	}
	if err := api.ServiceRemove("s2"); !coreapi.IsNotFound(err) {
		t.Errorf("not found: %v", err)
	}

	var enabled = "1"
	if err := api.ServiceUpdate(testServiceUuid, ServiceFields{Enabled: &enabled}); err != nil {
		t.Errorf("update: %v", err)
	}
	if err := api.AlertUpdate("a9", AlertFields{Enabled: &enabled}); !coreapi.IsNotFound(err) {
		t.Errorf("unknown alert: %v", err)
	}
	if err := api.ServiceUpdate(testServiceUuid, ServiceFields{}); err == nil {
		t.Error("an empty update must fail")
	}
	var recipient = "a@example.com"
	if uuid, err := api.AlertCreate(AlertFields{Recipient: &recipient}); err != nil || uuid != "a1" {
		t.Errorf("create: %q %v", uuid, err)
	}
	var condition = "cpu is greater than 95%"
	if err := api.TestUpdate(testTestUuid, TestFields{Condition: &condition}); err != nil {
		t.Errorf("test update: %v", err)
	}
	var got = mutations(*requests)
	var want = []string{"/api/monit/settings/del_test/t2", "/api/monit/settings/del_service/s2",
		"/api/monit/settings/set_service/" + testServiceUuid, "/api/monit/settings/add_alert", "/api/monit/settings/set_test/" + testTestUuid}
	var paths []string
	for _, request := range got {
		paths = append(paths, request.Path)
	}
	if !reflect.DeepEqual(paths, want) {
		t.Errorf("mutations %v", paths)
	}
	if !reflect.DeepEqual(got[3].Body, map[string]any{"alert": map[string]any{"recipient": "a@example.com"}}) {
		t.Errorf("alert body %v", got[3].Body)
	}
	if interfaces, err := api.ServiceInterfaces(); err != nil || len(interfaces) != 1 || interfaces[0].Key != "lan" {
		t.Errorf("interfaces %+v %v", interfaces, err)
	}
}

func TestStatusAndDaemon(t *testing.T) {
	var api, _ = newTestApi(t, map[string]string{
		"GET /api/monit/status/get/text": `{"result":"ok","status":"<div class=\"alert\"><pre>Monit 5.34 uptime: 1m\n\n` +
			`System 'fw'\n  status                       <span class=\"text-success\">OK</span>\n  load &amp; more</pre></div>"}`,
		"GET /api/monit/status/get/xml":       `{"result":"failed","status":"\nEither the file \/var\/run\/monit.sock does not exists"}`,
		"GET /api/monit/service/status":       `{"status":"running"}`,
		"POST /api/monit/service/reconfigure": `{"status":"failed","status_msg":"Service \"monit\" failed to start."}`,
		"POST /api/monit/service/restart":     `{"response":"OK"}`,
	})
	var text, err = api.StatusText()
	if err != nil || text != "Monit 5.34 uptime: 1m\n\nSystem 'fw'\n  status                       OK\n  load & more" {
		t.Errorf("text %q %v", text, err)
	}
	if _, err := api.StatusXml(); err == nil || !strings.Contains(err.Error(), "monit.sock does not exists") {
		t.Errorf("xml: %v", err)
	}
	if status, err := api.DaemonStatus(); err != nil || status != DaemonRunning {
		t.Errorf("status %q %v", status, err)
	}
	if err := api.DaemonReconfigure(); err == nil || !strings.Contains(err.Error(), "failed to start") {
		t.Errorf("reconfigure: %v", err)
	}
	if err := api.DaemonRestart(); err != nil {
		t.Errorf("restart: %v", err)
	}
}
