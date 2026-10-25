package openvpn

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

type instanceTestRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   map[string]any
}

// instanceTestApi starts a fake OPNsense answering "METHOD /path" with the JSON in answers (any value is encoded,
// a string is sent as it is), unknown endpoints with an empty 200 like OPNsense. All requests are recorded
func instanceTestApi(t *testing.T, answers map[string]any) (*OpenVPNApi, func() []instanceTestRequest) {
	t.Helper()
	var mu sync.Mutex
	var requests []instanceTestRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var recorded = instanceTestRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query()}
		var raw, _ = io.ReadAll(r.Body)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &recorded.Body); err != nil {
				t.Errorf("invalid request body %q: %v", raw, err)
			}
		}
		mu.Lock()
		requests = append(requests, recorded)
		mu.Unlock()
		var answer, found = answers[r.Method+" "+r.URL.Path]
		if !found {
			return
		}
		if text, isText := answer.(string); isText {
			_, _ = io.WriteString(w, text)
			return
		}
		_ = json.NewEncoder(w).Encode(answer)
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &OpenVPNApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, func() []instanceTestRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]instanceTestRequest(nil), requests...)
	}
}

func instanceTestRows(items ...any) map[string]any {
	return map[string]any{"rows": items, "rowCount": len(items), "total": len(items), "current": 1}
}

// mutations returns the non GET requests
func instanceTestMutations(requests []instanceTestRequest) []instanceTestRequest {
	var result []instanceTestRequest
	for _, request := range requests {
		if request.Method != "GET" {
			result = append(result, request)
		}
	}
	return result
}

const (
	instanceTestSearchPath = "/api/openvpn/instances/search"
	instanceTestGetPath    = "/api/openvpn/instances/get"
)

var instanceTestInstances = []Instance{
	{Uuid: "u-office", Vpnid: "1", Enabled: "1", Role: "server", Description: "office", Password: "pw", TlsKey: "k-1"},
	{Uuid: "u-office-2", Vpnid: "2", Enabled: "0", Role: "server", Description: "office 2"},
	{Uuid: "u-dup-1", Vpnid: "3", Role: "client", Description: "dup"},
	{Uuid: "u-dup-2", Vpnid: "4", Role: "client", Description: "DUP", TlsKey: "k-1"},
}

// instanceTestGetAnswer is a trimmed get answer of OPNsense 26.7: option objects, an option list (verb) and plain values
const instanceTestGetAnswer = `{"instance":{"vpnid":"7","enabled":"0",` +
	`"dev_type":{"tun":{"value":"TUN","selected":1},"tap":{"value":"TAP","selected":0},"ovpn":{"value":"DCO","selected":0}},` +
	`"verb":[{"value":"0 (No output except fatal errors.)","selected":0},{"value":"1 (Normal)","selected":0},{"value":"2 (Normal)","selected":1}],` +
	`"cert":{"":{"value":"None","selected":0},"6ade0cb9a8269":{"value":"Web GUI TLS certificate","selected":1}},` +
	`"ca":{"":{"value":" - Use from certificate","selected":1}},` +
	`"data-ciphers":{"AES-256-GCM":{"value":"AES-256-GCM","optgroup":"Recommended","selected":1},"AES-128-GCM":{"value":"AES-128-GCM","optgroup":"Recommended","selected":0},"CHACHA20-POLY1305":{"value":"CHACHA20-POLY1305","optgroup":"Recommended","selected":1}},` +
	`"push_route":{"":{"value":"","selected":1}},"dns_servers":{"10.0.0.53":{"value":"10.0.0.53","selected":1}},` +
	`"password":"secret","description":"office"}}`

func TestInstanceForm(t *testing.T) {
	var api, requests = instanceTestApi(t, map[string]any{"GET " + instanceTestGetPath + "/u-office": instanceTestGetAnswer, "GET " + instanceTestGetPath + "/u-nope": "[]"})
	var form, err = api.InstanceForm("u-office")
	if err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]string{
		"vpnid": "7", "dev_type": "tun", "verb": "2", "cert": "6ade0cb9a8269", "ca": "", "data-ciphers": "AES-256-GCM,CHACHA20-POLY1305",
		"push_route": "", "dns_servers": "10.0.0.53", "password": "secret", "unknown": "",
	} {
		if got := form.Value(field); got != want {
			t.Errorf("%s: got %q, want %q", field, got, want)
		}
	}
	if form["vpnid"].IsOption() || !form["ca"].IsOption() || !form["verb"].IsOption() {
		t.Errorf("IsOption wrong: %+v", form)
	}
	var wantCiphers = []Option{{"AES-256-GCM", "AES-256-GCM", true}, {"AES-128-GCM", "AES-128-GCM", false}, {"CHACHA20-POLY1305", "CHACHA20-POLY1305", true}}
	if got := form["data-ciphers"].Options; !reflect.DeepEqual(got, wantCiphers) {
		t.Errorf("options keep the API order: got %+v", got)
	}
	if got := form["verb"].Options; len(got) != 3 || got[2] != (Option{"2", "2 (Normal)", true}) {
		t.Errorf("option lists are keyed by index: %+v", got)
	}
	if got := form["cert"].Options[1]; got != (Option{"6ade0cb9a8269", "Web GUI TLS certificate", true}) {
		t.Errorf("cert option: %+v", got)
	}

	// an unknown uuid is answered with []
	if _, err := api.InstanceForm("u-nope"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if got := requests(); len(got) != 2 || got[0].Path != instanceTestGetPath+"/u-office" || got[0].Method != "GET" {
		t.Errorf("requests: %+v", got)
	}
}

func TestInstanceFormDefaults(t *testing.T) {
	var api, requests = instanceTestApi(t, map[string]any{"GET " + instanceTestGetPath: instanceTestGetAnswer})
	if _, err := api.InstanceForm(""); err != nil {
		t.Fatal(err)
	}
	if got := requests(); got[0].Path != instanceTestGetPath {
		t.Errorf("want get without uuid, got %s", got[0].Path)
	}
}

func TestInstanceListAndLookups(t *testing.T) {
	var api, requests = instanceTestApi(t, map[string]any{"GET " + instanceTestSearchPath: instanceTestRows(instanceTestInstances[0], instanceTestInstances[1], instanceTestInstances[2], instanceTestInstances[3])})

	var all, err = api.InstanceList("")
	if err != nil || len(all) != 4 || all[0].Password != "pw" || all[0].Vpnid != "1" {
		t.Fatalf("InstanceList: %+v, %v", all, err)
	}

	instance, err := api.InstanceGet("U-OFFICE-2")
	if err != nil || instance.Uuid != "u-office-2" {
		t.Errorf("InstanceGet: %+v %v", instance, err)
	}
	if _, err := api.InstanceGet("u-nope"); !coreapi.IsNotFound(err) {
		t.Errorf("InstanceGet unknown: %v", err)
	}

	// the search is a substring match, the description must match exactly (case-insensitive)
	instance, err = api.InstanceGetByDescription("Office")
	if err != nil || instance.Uuid != "u-office" {
		t.Errorf("InstanceGetByDescription: %+v %v", instance, err)
	}
	var tooMany *coreapi.TooManyFoundError
	if _, err := api.InstanceGetByDescription("dup"); !errors.As(err, &tooMany) || !strings.Contains(err.Error(), "u-dup-1, u-dup-2") {
		t.Errorf("duplicates: %v", err)
	}
	if _, err := api.InstanceGetByDescription("offic"); !coreapi.IsNotFound(err) {
		t.Errorf("substring: %v", err)
	}
	if _, err := api.InstanceGetByDescription(""); err == nil {
		t.Errorf("empty description must fail")
	}
	var phrases []string
	for _, request := range requests() {
		phrases = append(phrases, request.Query.Get("searchPhrase"))
	}
	if strings.Join(phrases, "|") != "|||Office|dup|offic" {
		t.Errorf("search phrases %q", phrases)
	}
}

func TestInstanceCreate(t *testing.T) {
	var api, requests = instanceTestApi(t, map[string]any{"POST /api/openvpn/instances/add": `{"result":"saved","uuid":"u-new"}`})

	var uuid, err = api.InstanceCreate(InstanceFields{"role": "server", "server": "10.8.0.0/24", "enabled": "0"})
	if err != nil || uuid != "u-new" {
		t.Fatalf("InstanceCreate: %q %v", uuid, err)
	}
	// without vpnid OPNsense fails with "A value is required.", an empty one makes it assign the next free id
	var want = map[string]any{"instance": map[string]any{"vpnid": "", "role": "server", "server": "10.8.0.0/24", "enabled": "0"}}
	if got := requests()[0].Body; !reflect.DeepEqual(got, want) {
		t.Errorf("body %v, want %v", got, want)
	}

	if _, err := api.InstanceCreate(InstanceFields{"vpnid": "12"}); err != nil {
		t.Fatal(err)
	}
	if got := requests()[1].Body["instance"].(map[string]any)["vpnid"]; got != "12" {
		t.Errorf("a given vpnid is sent, got %v", got)
	}

	if _, err := api.InstanceCreate(InstanceFields{"bogus": "1"}); err == nil || len(requests()) != 2 {
		t.Errorf("unknown fields must fail without request: %v", err)
	}
}

func TestInstanceCreateValidation(t *testing.T) {
	var api, _ = instanceTestApi(t, map[string]any{
		"POST /api/openvpn/instances/add": `{"result":"failed","validations":{"instance.server":"At least one IPv4 or IPv6 tunnel network is required."}}`,
	})
	var _, err = api.InstanceCreate(InstanceFields{"role": "server"})
	var validation *coreapi.ValidationError
	if !errors.As(err, &validation) || validation.Validations["instance.server"] == "" {
		t.Errorf("want ValidationError, got %v", err)
	}
}

func TestInstanceUpdate(t *testing.T) {
	var api, requests = instanceTestApi(t, map[string]any{
		"GET " + instanceTestSearchPath:              instanceTestRows(instanceTestInstances[0]),
		"POST /api/openvpn/instances/set/u-office":   `{"result":"saved"}`,
		"POST /api/openvpn/instances/set/u-gone":     `{"result":"failed"}`,
		"POST /api/openvpn/instances/set/u-invalid":  `{"result":"failed","validations":{"instance.port":"invalid"}}`,
		"POST /api/openvpn/instances/set/u-whatever": `{"result":"saved"}`,
	})

	if err := api.InstanceUpdate("u-office", InstanceFields{"port": "1195", "description": ""}); err != nil {
		t.Fatal(err)
	}
	var sets = instanceTestMutations(requests())
	var want = map[string]any{"instance": map[string]any{"port": "1195", "description": ""}}
	if len(sets) != 1 || sets[0].Path != "/api/openvpn/instances/set/u-office" || !reflect.DeepEqual(sets[0].Body, want) {
		t.Errorf("set: %+v", sets)
	}

	// set on a well-formed unknown uuid would create the instance, so the existence is checked first
	if err := api.InstanceUpdate("u-whatever", InstanceFields{"port": "1"}); !coreapi.IsNotFound(err) {
		t.Errorf("unknown uuid: %v", err)
	}
	if err := api.InstanceUpdate("u-office", InstanceFields{"vpnid": ""}); err == nil || !strings.Contains(err.Error(), "vpnid") {
		t.Errorf("empty vpnid must be refused: %v", err)
	}
	if err := api.InstanceUpdate("u-office", InstanceFields{"nope": ""}); err == nil {
		t.Errorf("unknown field must be refused")
	}
	if err := api.InstanceUpdate("", InstanceFields{"port": "1"}); err == nil {
		t.Errorf("empty uuid must be refused")
	}
	if got := instanceTestMutations(requests()); len(got) != 1 {
		t.Errorf("refused updates must not post: %+v", got)
	}

	// instanceSet: a bare failed is not found, validation messages are a ValidationError
	if err := api.instanceSet("u-gone", InstanceFields{"port": "1"}); !coreapi.IsNotFound(err) {
		t.Errorf("bare failed: %v", err)
	}
	var validation *coreapi.ValidationError
	if err := api.instanceSet("u-invalid", InstanceFields{"port": "x"}); !errors.As(err, &validation) {
		t.Errorf("validation: %v", err)
	}
}

func TestInstanceRemove(t *testing.T) {
	var api, requests = instanceTestApi(t, map[string]any{
		"POST /api/openvpn/instances/del/u-office": `{"result":"deleted"}`,
		"POST /api/openvpn/instances/del/u-nope":   `{"result":"not found"}`,
	})
	if err := api.InstanceRemove("u-office"); err != nil {
		t.Fatal(err)
	}
	if err := api.InstanceRemove("u-nope"); !coreapi.IsNotFound(err) || !strings.Contains(err.Error(), "openvpn instance u-nope") {
		t.Errorf("unknown: %v", err)
	}
	if err := api.InstanceRemove(""); err == nil {
		t.Errorf("empty uuid must fail")
	}
	if got := requests(); len(got) != 2 || got[0].Method != "POST" || got[0].Body != nil {
		t.Errorf("requests: %+v", got)
	}
}

func TestInstanceSetEnabled(t *testing.T) {
	var api, requests = instanceTestApi(t, map[string]any{
		"POST /api/openvpn/instances/toggle/u-office/1": `{"result":"Enabled","changed":true}`,
		"POST /api/openvpn/instances/toggle/u-office/0": `{"result":"Disabled","changed":false}`,
		"POST /api/openvpn/instances/toggle/u-nope/0":   `{"result":"failed"}`,
	})
	if changed, err := api.InstanceSetEnabled("u-office", true); err != nil || !changed {
		t.Errorf("enable: %v %v", changed, err)
	}
	if changed, err := api.InstanceSetEnabled("u-office", false); err != nil || changed {
		t.Errorf("disable: %v %v", changed, err)
	}
	if _, err := api.InstanceSetEnabled("u-nope", false); !coreapi.IsNotFound(err) {
		t.Errorf("unknown: %v", err)
	}
	if got := requests(); len(got) != 3 || got[0].Method != "POST" {
		t.Errorf("requests: %+v", got)
	}
}

func TestInstanceServiceActions(t *testing.T) {
	var api, requests = instanceTestApi(t, map[string]any{
		"POST /api/openvpn/service/reconfigure":           `{"result":"ok"}`,
		"POST /api/openvpn/service/start_service/u-a":     `{"result":"ok"}`,
		"POST /api/openvpn/service/stop_service/u-a":      `{"result":"ok"}`,
		"POST /api/openvpn/service/restart_service/u-a":   `{"result":"ok"}`,
		"POST /api/openvpn/service/restart_service/u-bad": `{"result":"failed"}`,
	})
	for name, action := range map[string]func() error{
		"reconfigure": api.InstancesReconfigure,
		"start":       func() error { return api.InstanceStart("u-a") },
		"stop":        func() error { return api.InstanceStop("u-a") },
		"restart":     func() error { return api.InstanceRestart("u-a") },
	} {
		if err := action(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := api.InstanceRestart("u-bad"); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Errorf("failed result: %v", err)
	}
	if err := api.InstanceStart(""); err == nil {
		t.Errorf("empty uuid must fail")
	}
	for _, request := range requests() {
		if request.Method != "POST" || request.Body != nil {
			t.Errorf("actions must be bodiless POSTs: %+v", request)
		}
	}
	if got := len(requests()); got != 5 {
		t.Errorf("want 5 requests, got %d", got)
	}
}

func TestInstanceServiceActionEmptyAnswer(t *testing.T) {
	var api, _ = instanceTestApi(t, nil)
	if err := api.InstancesReconfigure(); err == nil {
		t.Errorf("an empty answer must be an error")
	}
}
