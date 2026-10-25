package dnsmodel

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

var testKind = Kind{Module: "dnsmasq", Controller: "settings", Method: "range", Container: "range", Name: "DHCP range"}

type request struct {
	method, path, body string
}

// testServer answers "METHOD /path" from answers (status 200 unless the answer starts with "500 ")
func testServer(t *testing.T, answers map[string]string) (*coreapi.OPNsense, *[]request) {
	t.Helper()
	var requests []request
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		requests = append(requests, request{r.Method, r.URL.Path, string(body)})
		var answer, found = answers[r.Method+" "+r.URL.Path]
		if !found {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			answer = `{}`
		}
		w.Header().Set("Content-Type", "application/json")
		if rest, isError := strings.CutPrefix(answer, "500 "); isError {
			w.WriteHeader(500)
			answer = rest
		}
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(server.Close)
	var base, _ = url.Parse(server.URL)
	return &coreapi.OPNsense{BaseUrl: *base, ApiKey: "k", ApiSecret: "s"}, &requests
}

const searchPath = "GET /api/dnsmasq/settings/search_range"

func TestGetFiltersBySearch(t *testing.T) {
	var opn, _ = testServer(t, map[string]string{
		searchPath: `{"rows":[{"uuid":"a","start_addr":"192.0.2.1"},{"uuid":"b","start_addr":"192.0.2.2"}]}`,
	})
	type row struct {
		Uuid  string `json:"uuid"`
		Start string `json:"start_addr"`
	}
	var found, err = Get[row](opn, testKind, "b")
	if err != nil || found.Start != "192.0.2.2" {
		t.Errorf("Get b: %+v, %v", found, err)
	}
	if _, err := Get[row](opn, testKind, "c"); !coreapi.IsNotFound(err) {
		t.Errorf("Get c: want not found, got %v", err)
	}
	if _, err := Get[row](opn, testKind, ""); err == nil {
		t.Error("Get without uuid: want an error")
	}
}

func TestUpdateChecksExistenceFirst(t *testing.T) {
	var opn, requests = testServer(t, map[string]string{
		searchPath: `{"rows":[{"uuid":"a"}]}`,
		"POST /api/dnsmasq/settings/set_range/a": `{"result":"saved"}`,
	})
	if err := Update(opn, testKind, "a", Patch{"lease_time": "60"}); err != nil {
		t.Fatal(err)
	}
	var last = (*requests)[len(*requests)-1]
	if last.path != "/api/dnsmasq/settings/set_range/a" || strings.TrimSpace(last.body) != `{"range":{"lease_time":"60"}}` {
		t.Errorf("unexpected update %+v", last)
	}

	// set_* would create an unknown uuid: nothing may be posted
	*requests = nil
	if err := Update(opn, testKind, "0b3c6a1e-2f4d-4e5a-9b7c-8d9e0f1a2b3c", Patch{"lease_time": "60"}); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	for _, r := range *requests {
		if r.method != "GET" {
			t.Errorf("an unknown uuid must not be written: %+v", r)
		}
	}
}

func TestUpdateBareFailureIsNotFound(t *testing.T) {
	var opn, _ = testServer(t, map[string]string{
		searchPath: `{"rows":[{"uuid":"a"}]}`,
		"POST /api/dnsmasq/settings/set_range/a": `{"result":"failed"}`,
	})
	if err := Update(opn, testKind, "a", Patch{"x": "1"}); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
}

func TestUpdateValidationError(t *testing.T) {
	var opn, _ = testServer(t, map[string]string{
		searchPath: `{"rows":[{"uuid":"a"}]}`,
		"POST /api/dnsmasq/settings/set_range/a": `{"result":"failed","validations":{"range.end_addr":["Static only accepts a starting address."]}}`,
	})
	var err = Update(opn, testKind, "a", Patch{"mode": "static"})
	var validationErr *coreapi.ValidationError
	if !errors.As(err, &validationErr) || validationErr.Validations["range.end_addr"] == "" {
		t.Errorf("want the validation error, got %v", err)
	}
}

func TestCreate(t *testing.T) {
	var opn, requests = testServer(t, map[string]string{
		"POST /api/dnsmasq/settings/add_range": `{"result":"saved","uuid":"new"}`,
	})
	var uuid, err = Create(opn, testKind, map[string]string{"start_addr": "192.0.2.1"})
	if err != nil || uuid != "new" {
		t.Fatalf("Create: %q, %v", uuid, err)
	}
	if strings.TrimSpace((*requests)[0].body) != `{"range":{"start_addr":"192.0.2.1"}}` {
		t.Errorf("unexpected body %s", (*requests)[0].body)
	}

	opn, _ = testServer(t, map[string]string{"POST /api/dnsmasq/settings/add_range": `{"result":"saved"}`})
	if _, err := Create(opn, testKind, Patch{}); err == nil {
		t.Error("want an error for an answer without uuid")
	}
}

func TestRemove(t *testing.T) {
	var opn, _ = testServer(t, map[string]string{
		"POST /api/dnsmasq/settings/del_range/a": `{"result":"deleted"}`,
		"POST /api/dnsmasq/settings/del_range/b": `{"result":"not found"}`,
		"POST /api/dnsmasq/settings/del_range/c": `500 {"errorMessage":"dnsmasq - lab {dnsmasq.dhcp_ranges.x}\ndnsmasq - pxe {dnsmasq.dhcp_boot.y}\n","errorTitle":"Item in use by:"}`,
	})
	if err := Remove(opn, testKind, "a"); err != nil {
		t.Errorf("remove a: %v", err)
	}
	if err := Remove(opn, testKind, "b"); !coreapi.IsNotFound(err) {
		t.Errorf("remove b: want not found, got %v", err)
	}
	var err = Remove(opn, testKind, "c")
	if err == nil || !strings.Contains(err.Error(), "in use by: dnsmasq - lab {dnsmasq.dhcp_ranges.x}; dnsmasq - pxe") {
		t.Errorf("remove c: want the users, got %v", err)
	}
	for _, uuid := range []string{"", "a,b", "a/b"} {
		if err := Remove(opn, testKind, uuid); err == nil {
			t.Errorf("remove %q: want an error", uuid)
		}
	}
}

func TestGetSettingsFlattens(t *testing.T) {
	var opn, _ = testServer(t, map[string]string{"GET /api/m/settings/get": `{"m":{
		"enable":"1",
		"interface":{"lan":{"value":"LAN","selected":1},"wan":{"value":"WAN","selected":0},"opt1":{"value":"DMZ","selected":1}},
		"add_mac":{"":{"value":"None","selected":1},"text":{"value":"text","selected":0}},
		"level":[{"value":"Level 0","selected":0},{"value":"Level 1","selected":1}],
		"csv":{"":{"value":"","selected":1}},
		"dhcp":{"domain":"lan","%domain":"internal","no_interface":{"wan":{"value":"WAN","selected":1}}},
		"hosts":{"u1":{"host":"a"}},
		"ranges":[],
		"codes":{"":{"value":"None","selected":1},"10":{"optgroup":"Common","value":"ten [10]","selected":0},"9":{"optgroup":"Common","value":"nine [9]","selected":0}}
	}}`})
	var settings, err = GetSettings(opn, opn.EndpointForPluginControllerMethod("m", "settings", "get"), "m", "hosts")
	if err != nil {
		t.Fatal(err)
	}
	var want = map[string]string{
		"enable": "1", "interface": "lan,opt1", "add_mac": "", "level": "1", "csv": "", "dhcp.domain": "lan",
		"dhcp.no_interface": "wan", "codes": "",
	}
	if !reflect.DeepEqual(settings.Values, want) {
		t.Errorf("values:\n got  %v\n want %v", settings.Values, want)
	}
	var keys []string
	for _, option := range settings.Options["codes"] {
		keys = append(keys, option.Key)
	}
	if !reflect.DeepEqual(keys, []string{"", "9", "10"}) || settings.Options["codes"][1].Group != "Common" {
		t.Errorf("codes are not sorted numerically or lost the group: %+v", settings.Options["codes"])
	}
	if len(settings.Options["level"]) != 2 || settings.Options["level"][1].Key != "1" || !settings.Options["level"][1].Selected {
		t.Errorf("a list option field is keyed by index: %+v", settings.Options["level"])
	}

	if _, err := GetSettings(opn, opn.EndpointForPluginControllerMethod("m", "settings", "get"), "m.nothing"); err == nil {
		t.Error("want an error for a missing section")
	}
}

func TestSetSettingsNests(t *testing.T) {
	var opn, requests = testServer(t, map[string]string{"POST /api/m/settings/set": `{"result":"saved"}`})
	var endpoint = opn.EndpointForPluginControllerMethod("m", "settings", "set")
	if err := SetSettings(opn, endpoint, "m", Patch{"port": "53", "dhcp.domain": "lan", "dhcp.fqdn": "1"}); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte((*requests)[0].body), &body); err != nil {
		t.Fatal(err)
	}
	var want = map[string]any{"m": map[string]any{"port": "53", "dhcp": map[string]any{"domain": "lan", "fqdn": "1"}}}
	if !reflect.DeepEqual(body, want) {
		t.Errorf("body %v, want %v", body, want)
	}
	if err := SetSettings(opn, endpoint, "m", Patch{}); err == nil {
		t.Error("an empty patch must fail without a request")
	}
	if len(*requests) != 1 {
		t.Errorf("want 1 request, got %d", len(*requests))
	}
}

func TestSetSettingsValidation(t *testing.T) {
	var opn, _ = testServer(t, map[string]string{"POST /api/m/settings/set": `{"result":"failed","validations":{"m.dhcp.reply_delay":"Maximum value is 60."}}`})
	var err = SetSettings(opn, opn.EndpointForPluginControllerMethod("m", "settings", "set"), "m", Patch{"dhcp.reply_delay": "61"})
	var validationErr *coreapi.ValidationError
	if !errors.As(err, &validationErr) {
		t.Errorf("want a validation error, got %v", err)
	}
}
