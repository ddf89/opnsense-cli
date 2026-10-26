package ddclient

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

type testCall struct {
	method string
	path   string
	body   string
}

type testServer struct {
	mu      sync.Mutex
	answers map[string]string // "METHOD /path" → body, "!404" answers 404
	calls   []testCall
}

func newTestApi(t *testing.T, answers map[string]string) (*DdclientApi, *testServer) {
	t.Helper()
	var ts = &testServer{answers: answers}
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		ts.mu.Lock()
		ts.calls = append(ts.calls, testCall{r.Method, r.URL.Path, string(body)})
		var answer, found = ts.answers[r.Method+" "+r.URL.Path]
		ts.mu.Unlock()
		switch {
		case !found:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		case answer == "!404":
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errorMessage":"Endpoint not found"}`)
		default:
			_, _ = io.WriteString(w, answer)
		}
	}))
	t.Cleanup(server.Close)
	var baseUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &DdclientApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl, ApiKey: "key", ApiSecret: "secret"}}, ts
}

func (ts *testServer) mutations() []testCall {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	var result []testCall
	for _, call := range ts.calls {
		if call.method != "GET" {
			result = append(result, call)
		}
	}
	return result
}

const (
	testUuid   = "17a38f84-c8e2-4d2e-8b23-1798774db7ea"
	searchPath = "GET /api/dyndns/accounts/search_item"
	searchRows = `{"rows":[{"uuid":"17a38f84-c8e2-4d2e-8b23-1798774db7ea","enabled":"0","service":"dyndns2","server":"",
"username":"user","password":"s3cret","%password":"","resourceId":"","hostnames":"a.example.com,b.example.org",
"wildcard":"0","zone":"","checkip":"if","%checkip":"Interface [IPv4]","dynipv6host":"","checkip_timeout":"10",
"force_ssl":"1","ttl":"300","interface":"wan","%interface":"WAN","description":"home","current_ip":"192.0.2.7",
"current_mtime":"2026-10-26T10:00:00+00:00"},{"uuid":"27a38f84-c8e2-4d2e-8b23-1798774db7eb","enabled":"1",
"service":"custom","password":"","hostnames":"c.example.net","checkip":"web_icanhazip","description":"office"}],
"rowCount":2,"total":2,"current":1}`
)

func TestAccountListHidesPasswords(t *testing.T) {
	var api, _ = newTestApi(t, map[string]string{searchPath: searchRows})
	var accounts, raws, err = api.AccountList("")
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 2 || accounts[0].Description != "home" || !accounts[0].PasswordSet || accounts[1].PasswordSet ||
		accounts[0].CurrentIp != "192.0.2.7" || accounts[0].InterfaceName != "WAN" || accounts[0].CheckipName != "Interface [IPv4]" {
		t.Errorf("accounts %+v", accounts)
	}
	for _, raw := range raws {
		if strings.Contains(string(raw), "s3cret") || strings.Contains(string(raw), "password") {
			t.Errorf("raw row with password: %s", raw)
		}
	}
	var row map[string]any
	if err := json.Unmarshal(raws[0], &row); err != nil || row["hostnames"] != "a.example.com,b.example.org" {
		t.Errorf("raw row %s %v", raws[0], err)
	}
}

func TestAccountGetWithProtocol(t *testing.T) {
	var api, _ = newTestApi(t, map[string]string{searchPath: searchRows,
		"GET /api/dyndns/accounts/get_item/" + testUuid: `{"account":{"protocol":{"":{"value":"None","selected":0},` +
			`"dyndns2":{"value":"DynDNS 2","selected":1}},"password":""}}`})
	var account, err = api.AccountGet(testUuid)
	if err != nil || account.Protocol != "dyndns2" || account.Description != "home" {
		t.Errorf("account %+v %v", account, err)
	}
	if _, err := api.AccountGet("00000000-0000-4000-8000-000000000000"); !coreapi.IsNotFound(err) {
		t.Errorf("unknown uuid: %v", err)
	}
	if _, err := api.AccountGet("a,b"); err == nil {
		t.Error("uuid list accepted")
	}
}

func TestAccountOptions(t *testing.T) {
	var api, _ = newTestApi(t, map[string]string{"GET /api/dyndns/accounts/get_item": `{"account":{"enabled":"1",
"service":{"dyndns2":{"value":"dyndns2","selected":0},"cloudflare":{"value":"Cloudflare","selected":0}},
"protocol":{"":{"value":"None","selected":1},"get":{"value":"Custom GET","selected":0}},
"checkip":{"if":{"value":"Interface [IPv4]","selected":0}},"interface":{"":{"value":"None","selected":1},"lan":{"value":"LAN","selected":0}}}}`})
	var options, err = api.AccountOptions()
	if err != nil {
		t.Fatal(err)
	}
	if want := []Option{{Key: "cloudflare", Name: "Cloudflare"}, {Key: "dyndns2", Name: "dyndns2"}}; !reflect.DeepEqual(options["service"], want) {
		t.Errorf("services %+v", options["service"])
	}
	if len(options["interface"]) != 2 || !options["interface"][0].Selected || len(options["checkip"]) != 1 {
		t.Errorf("options %+v", options)
	}
}

func TestAccountMutations(t *testing.T) {
	var api, ts = newTestApi(t, map[string]string{searchPath: searchRows,
		"POST /api/dyndns/accounts/add_item":                  `{"result":"saved","uuid":"new-uuid"}`,
		"POST /api/dyndns/accounts/set_item/" + testUuid:      `{"result":"saved"}`,
		"POST /api/dyndns/accounts/del_item/" + testUuid:      `{"result":"deleted"}`,
		"POST /api/dyndns/accounts/del_item/gone":             `{"result":"not found"}`,
		"POST /api/dyndns/accounts/force_refresh/" + testUuid: `{"status":"ok"}`,
	})
	var uuid, err = api.AccountCreate(AccountFields{"description": "x", "enabled": "0"})
	if err != nil || uuid != "new-uuid" {
		t.Errorf("create %q %v", uuid, err)
	}
	if err := api.AccountUpdate(testUuid, AccountFields{"ttl": "60"}); err != nil {
		t.Error(err)
	}
	if err := api.AccountSetEnabled(testUuid, false); err != nil {
		t.Error(err)
	}
	if err := api.AccountUpdate("00000000-0000-4000-8000-000000000000", AccountFields{"ttl": "60"}); !coreapi.IsNotFound(err) {
		t.Errorf("update of an unknown uuid: %v", err)
	}
	if err := api.AccountUpdate(testUuid, AccountFields{}); err == nil {
		t.Error("empty update accepted")
	}
	if err := api.AccountRemove(testUuid); err != nil {
		t.Error(err)
	}
	if err := api.AccountRemove("gone"); !coreapi.IsNotFound(err) {
		t.Errorf("remove unknown: %v", err)
	}
	if err := api.AccountForceRefresh(testUuid); err != nil {
		t.Error(err)
	}
	if err := api.AccountForceRefresh(); err == nil {
		t.Error("force refresh without accounts accepted")
	}
	var want = []testCall{
		{"POST", "/api/dyndns/accounts/add_item", `{"account":{"description":"x","enabled":"0"}}` + "\n"},
		{"POST", "/api/dyndns/accounts/set_item/" + testUuid, `{"account":{"ttl":"60"}}` + "\n"},
		{"POST", "/api/dyndns/accounts/set_item/" + testUuid, `{"account":{"enabled":"0"}}` + "\n"},
		{"POST", "/api/dyndns/accounts/del_item/" + testUuid, ""},
		{"POST", "/api/dyndns/accounts/del_item/gone", ""},
		{"POST", "/api/dyndns/accounts/force_refresh/" + testUuid, ""},
	}
	if got := ts.mutations(); !reflect.DeepEqual(got, want) {
		t.Errorf("mutations\n got  %q\n want %q", got, want)
	}
}

func TestAccountValidationAndRefreshErrors(t *testing.T) {
	var api, _ = newTestApi(t, map[string]string{
		"POST /api/dyndns/accounts/add_item":                  `{"result":"failed","validations":{"account.checkip":"An IP service type is required."}}`,
		"POST /api/dyndns/accounts/force_refresh/" + testUuid: `{"status":"failed"}`,
	})
	var _, err = api.AccountCreate(AccountFields{"description": "x"})
	var validation *coreapi.ValidationError
	if !errors.As(err, &validation) || !strings.Contains(err.Error(), "An IP service type is required.") {
		t.Errorf("validation: %v", err)
	}
	if err := api.AccountForceRefresh(testUuid); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Errorf("failed refresh: %v", err)
	}
}

func TestSettings(t *testing.T) {
	var api, ts = newTestApi(t, map[string]string{
		"GET /api/dyndns/settings/get": `{"ddclient":{"general":{"enabled":"1","verbose":"0","allowipv6":"0","daemon_delay":"300",` +
			`"backend":{"ddclient":{"value":"ddclient","selected":0},"opnsense":{"value":"native","selected":1}}}}}`,
		"POST /api/dyndns/settings/set": `{"result":"saved"}`,
	})
	var settings, err = api.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	if settings.Backend != "opnsense" || settings.DaemonDelay != "300" || settings.Enabled != "1" || len(settings.BackendOptions) != 2 ||
		settings.BackendOptions[1].Name != "native" {
		t.Errorf("settings %+v", settings)
	}
	if fields := settings.SettingsFields(); fields["daemon_delay"] != "300" || fields["backend"] != "opnsense" {
		t.Errorf("fields %v", fields)
	}
	if err := api.SettingsSet(map[string]string{"daemon_delay": "60", "backend": "ddclient"}); err != nil {
		t.Error(err)
	}
	if err := api.SettingsSet(map[string]string{"nope": "1"}); err == nil {
		t.Error("unknown setting accepted")
	}
	if err := api.SettingsSet(nil); err == nil {
		t.Error("empty set accepted")
	}
	var calls = ts.mutations()
	if len(calls) != 1 || calls[0].body != `{"ddclient":{"general":{"backend":"ddclient","daemon_delay":"60"}}}`+"\n" {
		t.Errorf("set calls %q", calls)
	}
}

func TestService(t *testing.T) {
	var api, ts = newTestApi(t, map[string]string{
		"GET /api/dyndns/service/status":       `{"status":"stopped","widget":{}}`,
		"POST /api/dyndns/service/start":       `{"response":"OK"}`,
		"POST /api/dyndns/service/stop":        `{"response":"OK"}`,
		"POST /api/dyndns/service/restart":     `{"response":"Execute error"}`,
		"POST /api/dyndns/service/reconfigure": `{"status":"ok"}`,
	})
	if status, err := api.ServiceStatus(); err != nil || status != "stopped" {
		t.Errorf("status %q %v", status, err)
	}
	if err := api.ServiceStart(); err != nil {
		t.Error(err)
	}
	if err := api.ServiceStop(); err != nil {
		t.Error(err)
	}
	if err := api.ServiceRestart(); err == nil || !strings.Contains(err.Error(), "Execute error") {
		t.Errorf("restart: %v", err)
	}
	if err := api.ServiceReconfigure(); err != nil {
		t.Error(err)
	}
	if got := len(ts.mutations()); got != 4 {
		t.Errorf("mutations %d", got)
	}
}

func TestIsNotInstalled(t *testing.T) {
	var api, _ = newTestApi(t, map[string]string{"GET /api/dyndns/service/status": "!404", searchPath: "!404"})
	var _, err = api.ServiceStatus()
	if !IsNotInstalled(err) {
		t.Errorf("404 not detected: %v", err)
	}
	if _, _, err := api.AccountList(""); !IsNotInstalled(err) {
		t.Errorf("404 of search not detected: %v", err)
	}
	if IsNotInstalled(&coreapi.HttpError{StatusCode: 500}) || IsNotInstalled(errors.New("x")) || IsNotInstalled(nil) {
		t.Error("false positive")
	}
}
