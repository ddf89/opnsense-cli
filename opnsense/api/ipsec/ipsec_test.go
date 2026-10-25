package ipsec

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

type testRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   map[string]any
}

// testApi starts a fake OPNsense answering "METHOD /path" with the JSON in answers (a string is sent as it is,
// other values are encoded), unknown endpoints with an empty 200 like OPNsense. All requests are recorded
func testApi(t *testing.T, answers map[string]any) (*IPsecApi, func() []testRequest) {
	t.Helper()
	var mu sync.Mutex
	var requests []testRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var recorded = testRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query()}
		var raw, _ = io.ReadAll(r.Body)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &recorded.Body); err != nil {
				t.Errorf("invalid request body %q: %v", raw, err)
			}
		}
		mu.Lock()
		requests = append(requests, recorded)
		var answer, found = answers[r.Method+" "+r.URL.Path]
		mu.Unlock()
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
	return &IPsecApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, func() []testRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]testRequest(nil), requests...)
	}
}

func testRows(items ...any) map[string]any {
	return map[string]any{"rows": items, "rowCount": len(items), "total": len(items), "current": 1}
}

func testMutations(requests []testRequest) []testRequest {
	var result []testRequest
	for _, request := range requests {
		if request.Method != "GET" {
			result = append(result, request)
		}
	}
	return result
}

const (
	testConnUuid  = "b43d742c-043a-4991-9e1f-8536d364c35b"
	testOtherUuid = "14443ac8-49fc-4f53-80d1-1165a30102b9"
	testUnknown   = "00000000-0000-4000-8000-000000000000"
	testConnPath  = "/api/ipsec/connections/"
)

// testConnectionRow is a search_connection row of OPNsense 26.7
func testConnectionRow(uuid string, description string) map[string]any {
	return map[string]any{"uuid": uuid, "enabled": "0", "proposals": "default", "unique": "no", "%unique": "No (default)",
		"aggressive": "0", "version": "2", "%version": "IKEv2", "mobike": "1", "local_addrs": "198.51.100.7", "local_port": "",
		"remote_addrs": "192.0.2.7", "remote_port": "", "encap": "0", "reauth_time": "", "rekey_time": "", "over_time": "",
		"dpd_delay": "", "dpd_timeout": "", "pools": "", "send_certreq": "1", "send_cert": "", "keyingtries": "",
		"description": description, "local_ts": "", "remote_ts": ""}
}

func TestRecordValues(t *testing.T) {
	var record Record
	if err := json.Unmarshal([]byte(`{"uuid":"u1","name":"x","n":42,"f":1.5,"t":true,"no":false,"nil":null,`+
		`"list":["a",1,null],"obj":{"a":1},"%name":"X name"}`), &record); err != nil {
		t.Fatal(err)
	}
	var want = map[string]string{"uuid": "u1", "name": "x", "n": "42", "f": "1.5", "t": "1", "no": "0", "nil": "", "list": "a,1,",
		"obj": `{"a":1}`, "%name": "X name"}
	if !reflect.DeepEqual(record.Values(), want) {
		t.Errorf("got %v\nwant %v", record.Values(), want)
	}
	if record.Uuid() != "u1" || record.Display("name") != "X name" || record.Display("n") != "42" || record.Value("missing") != "" ||
		!record.Has("nil") || record.Has("missing") || record.Enabled() {
		t.Errorf("accessors: %+v", record)
	}
	var encoded, _ = json.Marshal(record)
	if !strings.Contains(string(encoded), `"obj":{"a":1}`) {
		t.Errorf("raw not kept: %s", encoded)
	}
	if NewRecord(map[string]string{"enabled": "1"}).Enabled() != true {
		t.Error("NewRecord")
	}
}

func TestConnectionListGet(t *testing.T) {
	var api, requests = testApi(t, map[string]any{
		"GET " + testConnPath + "search_connection": testRows(testConnectionRow(testConnUuid, "Site B"), testConnectionRow(testOtherUuid, "site b")),
	})
	var connections, err = api.ConnectionList("site")
	if err != nil || len(connections) != 2 || connections[0].Display("version") != "IKEv2" {
		t.Fatalf("ConnectionList: %v %v", connections, err)
	}
	if got := requests()[0]; got.Query.Get("searchPhrase") != "site" {
		t.Errorf("searchPhrase not sent: %+v", got)
	}
	if connection, err := api.ConnectionGet(strings.ToUpper(testConnUuid)); err != nil || connection.Value("description") != "Site B" {
		t.Errorf("ConnectionGet: %v %v", connection, err)
	}
	if _, err := api.ConnectionGet(testUnknown); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if _, err := api.ConnectionGet(""); err == nil {
		t.Error("want an error for an empty uuid")
	}
	var tooMany *coreapi.TooManyFoundError
	if _, err := api.ConnectionGetByDescription("SITE B"); !errors.As(err, &tooMany) || !strings.Contains(err.Error(), testOtherUuid) {
		t.Errorf("want TooManyFoundError, got %v", err)
	}
	if _, err := api.ConnectionGetByDescription("nope"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
}

func TestRoundListFilter(t *testing.T) {
	var api, requests = testApi(t, map[string]any{"GET " + testConnPath + "search_local": testRows(), "GET " + testConnPath + "search_remote": testRows()})
	if records, err := api.LocalList(testConnUuid); err != nil || len(records) != 0 || records == nil {
		t.Fatalf("LocalList: %v %v", records, err)
	}
	if got := requests()[0]; got.Query.Get("connection") != testConnUuid {
		t.Errorf("connection filter not sent: %+v", got)
	}
	if _, err := api.RemoteList(""); err != nil {
		t.Fatal(err)
	}
	if got := requests()[1]; got.Path != testConnPath+"search_remote" || len(got.Query) != 0 {
		t.Errorf("unexpected request %+v", got)
	}
}

func TestConnectionCreateUpdateRemove(t *testing.T) {
	var answers = map[string]any{
		"GET " + testConnPath + "search_connection":                         testRows(testConnectionRow(testConnUuid, "Site B")),
		"POST " + testConnPath + "add_connection":                           `{"result":"saved","uuid":"` + testConnUuid + `"}`,
		"POST " + testConnPath + "set_connection/" + testConnUuid:           `{"result":"saved"}`,
		"POST " + testConnPath + "del_connection/" + testConnUuid:           `{"result":"deleted"}`,
		"POST " + testConnPath + "del_connection/" + testUnknown:            `{"result":"not found"}`,
		"POST " + testConnPath + "toggle_connection/" + testConnUuid + "/0": `{"result":"Disabled","changed":true}`,
		"POST " + testConnPath + "toggle_connection/" + testConnUuid + "/1": `{"result":"Enabled","changed":false}`,
		"POST " + testConnPath + "toggle_connection/" + testUnknown + "/1":  `{"result":"failed"}`,
	}
	var api, requests = testApi(t, answers)

	var uuid, err = api.ConnectionCreate(Fields{"description": "Site B", "enabled": "0", "version": "2"})
	if err != nil || uuid != testConnUuid {
		t.Fatalf("ConnectionCreate: %q %v", uuid, err)
	}
	var want = map[string]any{"connection": map[string]any{"description": "Site B", "enabled": "0", "version": "2"}}
	if got := testMutations(requests())[0]; got.Path != testConnPath+"add_connection" || !reflect.DeepEqual(got.Body, want) {
		t.Errorf("unexpected request %+v", got)
	}
	if _, err := api.ConnectionCreate(Fields{"descr": "x"}); err == nil || !strings.Contains(err.Error(), `unknown ipsec connection field "descr"`) {
		t.Errorf("want an unknown field error, got %v", err)
	}

	if err := api.ConnectionUpdate(testConnUuid, Fields{"rekey_time": "3600"}); err != nil {
		t.Fatal(err)
	}
	var mutations = testMutations(requests())
	if got := mutations[len(mutations)-1]; got.Path != testConnPath+"set_connection/"+testConnUuid ||
		!reflect.DeepEqual(got.Body, map[string]any{"connection": map[string]any{"rekey_time": "3600"}}) {
		t.Errorf("unexpected request %+v", got)
	}
	// set_connection would create an unknown uuid: checked first, nothing is sent
	var before = len(testMutations(requests()))
	if err := api.ConnectionUpdate(testUnknown, Fields{"rekey_time": "1"}); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if err := api.ConnectionUpdate("", Fields{}); err == nil {
		t.Error("want an error for an empty uuid")
	}
	if after := len(testMutations(requests())); after != before {
		t.Errorf("unknown uuids must not be sent: %v", requests())
	}

	answers["POST "+testConnPath+"set_connection/"+testConnUuid] = `{"result":"failed","validations":{"connection.rekey_time":["Invalid integer value."]}}`
	var validation *coreapi.ValidationError
	if err := api.ConnectionUpdate(testConnUuid, Fields{"rekey_time": "x"}); !errors.As(err, &validation) ||
		validation.Validations["connection.rekey_time"] != "Invalid integer value." {
		t.Errorf("want the validation error, got %v", err)
	}
	answers["POST "+testConnPath+"set_connection/"+testConnUuid] = `{"result":"failed"}`
	if err := api.ConnectionUpdate(testConnUuid, Fields{"rekey_time": "1"}); !coreapi.IsNotFound(err) {
		t.Errorf("a bare failed is a not found, got %v", err)
	}

	if err := api.ConnectionRemove(testConnUuid); err != nil {
		t.Fatal(err)
	}
	if err := api.ConnectionRemove(testUnknown); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	before = len(requests())
	for _, bad := range []string{"", "a,b", "a/b"} {
		if err := api.ConnectionRemove(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
	if len(requests()) != before {
		t.Errorf("invalid uuids must not be sent")
	}

	if changed, err := api.ConnectionSetEnabled(testConnUuid, false); err != nil || !changed {
		t.Errorf("disable: %v %v", changed, err)
	}
	if changed, err := api.ConnectionSetEnabled(testConnUuid, true); err != nil || changed {
		t.Errorf("enable: %v %v", changed, err)
	}
	if _, err := api.ConnectionSetEnabled(testUnknown, true); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if _, err := api.setEnabled(preSharedKeyResource, testConnUuid, true); err == nil {
		t.Error("pre-shared keys have no toggle")
	}
}

func TestConnectionExists(t *testing.T) {
	var api, _ = testApi(t, map[string]any{"GET " + testConnPath + "connection_exists/" + testConnUuid: `{"exists":true}`})
	if exists, err := api.ConnectionExists(testConnUuid); err != nil || !exists {
		t.Errorf("%v %v", exists, err)
	}
	if _, err := api.ConnectionExists("a/b"); err == nil {
		t.Error("want an error")
	}
}

func TestForms(t *testing.T) {
	var api, _ = testApi(t, map[string]any{
		"GET " + testConnPath + "get_connection": `{"connection":{"enabled":"1",` +
			`"proposals":{"default":{"value":"default","optgroup":"Internal","selected":1},"aes256-sha256-modp2048":{"value":"aes256-sha256-modp2048 [DH14]","selected":0}},` +
			`"version":[{"value":"IKEv1+IKEv2","selected":1},{"value":"IKEv1","selected":0},{"value":"IKEv2","selected":0}],` +
			`"local_addrs":{"":{"value":"","selected":1}},"pools":{"radius":{"value":"radius","selected":0}},"org_uuid":null,"uuid":"x"}}`,
		"GET " + testConnPath + "get_local": `{"local":{"pubkeys":[],"certs":{"6ade1fe2418b9":{"value":"Web GUI TLS certificate","selected":0}},"connection":{}}}`,
		"GET /api/ipsec/pools/get":          `[]`,
		"GET /api/ipsec/settings/get": `{"ipsec":{"general":{"enabled":"","passthrough_networks":{"192.0.2.0/24":{"value":"192.0.2.0/24","selected":1}}},` +
			`"charon":{"threads":"16","syslog":{"daemon":{"ike_name":"1","ike":{"-1":{"value":"Absolutely silent","selected":0},"1":{"value":"default","selected":1}}}},` +
			`"plugins":{"eap-radius":{"servers":[]}}}}}`,
	})
	var form, err = api.ConnectionForm()
	if err != nil {
		t.Fatal(err)
	}
	if form.Value("proposals") != "default" || form.Value("version") != "0" || form.Value("local_addrs") != "" ||
		form.Value("enabled") != "1" || form.Value("org_uuid") != "" || !form["pools"].IsOption() || form["enabled"].IsOption() {
		t.Errorf("unexpected form %+v", form)
	}
	if options := form.Options("proposals"); len(options) != 2 || options[1].Key != "aes256-sha256-modp2048" || options[1].Description != "aes256-sha256-modp2048 [DH14]" {
		t.Errorf("options in API order: %+v", options)
	}
	if options := form.Options("local_addrs"); len(options) != 0 {
		t.Errorf("the empty key is no choice: %+v", options)
	}
	if values := form.Values(); values["version"] != "0" || values["proposals"] != "default" {
		t.Errorf("Values: %v", values)
	}

	local, err := api.LocalForm()
	if err != nil || !local["pubkeys"].IsOption() || len(local["pubkeys"].Options) != 0 || !local["connection"].IsOption() ||
		local.Options("certs")[0].Description != "Web GUI TLS certificate" {
		t.Errorf("LocalForm: %+v %v", local, err)
	}
	if _, err := api.PoolForm(); !coreapi.IsNotFound(err) {
		t.Errorf("[] is not found, got %v", err)
	}

	settings, err := api.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	var want = map[string]string{"general.enabled": "", "general.passthrough_networks": "192.0.2.0/24", "charon.threads": "16",
		"charon.syslog.daemon.ike_name": "1", "charon.syslog.daemon.ike": "1", "charon.plugins.eap-radius.servers": ""}
	if !reflect.DeepEqual(settings.Values(), want) {
		t.Errorf("settings: got %v\nwant %v", settings.Values(), want)
	}
	if !settings["charon.plugins.eap-radius.servers"].IsOption() || len(settings.Options("charon.syslog.daemon.ike")) != 2 {
		t.Errorf("settings options: %+v", settings)
	}
}

func TestSettingsUpdate(t *testing.T) {
	var answers = map[string]any{"POST /api/ipsec/settings/set": `{"result":"saved"}`}
	var api, requests = testApi(t, answers)
	if err := api.SettingsUpdate(Fields{"charon.threads": "17", "charon.syslog.daemon.ike": "2", "general.preferred_oldsa": "1",
		"charon.plugins.eap-radius.servers": ""}); err != nil {
		t.Fatal(err)
	}
	var want = map[string]any{"ipsec": map[string]any{
		"general": map[string]any{"preferred_oldsa": "1"},
		"charon": map[string]any{"threads": "17", "syslog": map[string]any{"daemon": map[string]any{"ike": "2"}},
			"plugins": map[string]any{"eap-radius": map[string]any{"servers": ""}}},
	}}
	if got := requests()[0]; got.Method != "POST" || !reflect.DeepEqual(got.Body, want) {
		t.Errorf("got %+v\nwant %+v", got.Body, want)
	}
	for _, bad := range []Fields{{}, {"general.enabled": "1"}, {"charon.nope": "1"}} {
		if err := api.SettingsUpdate(bad); err == nil {
			t.Errorf("%v: want an error", bad)
		}
	}
	if len(requests()) != 1 {
		t.Errorf("refused settings must not be sent: %v", requests())
	}
	answers["POST /api/ipsec/settings/set"] = `{"result":"failed","validations":{"ipsec.charon.threads":"Invalid integer value."}}`
	var validation *coreapi.ValidationError
	if err := api.SettingsUpdate(Fields{"charon.threads": "0"}); !errors.As(err, &validation) {
		t.Errorf("want a validation error, got %v", err)
	}
}

func TestKeyPairGenerate(t *testing.T) {
	var answers = map[string]any{
		"GET /api/ipsec/key_pairs/gen_key_pair/ecdsa/256": `{"pubkey":"-----BEGIN PUBLIC KEY-----\nPUB\n","privkey":"-----BEGIN PRIVATE KEY-----\nPRIV\n","status":"ok"}`,
		"GET /api/ipsec/key_pairs/gen_key_pair/rsa":       `{"status":"failed","message":"unable to generate key"}`,
	}
	var api, requests = testApi(t, answers)
	var keys, err = api.KeyPairGenerate("ecdsa", "256")
	if err != nil || !strings.Contains(keys.PublicKey, "PUB") || !strings.Contains(keys.PrivateKey, "PRIV") {
		t.Fatalf("%+v %v", keys, err)
	}
	if _, err := api.KeyPairGenerate("rsa", ""); err == nil || !strings.Contains(err.Error(), "unable to generate key") {
		t.Errorf("want the message, got %v", err)
	}
	var before = len(requests())
	for _, bad := range [][2]string{{"dsa", ""}, {"rsa", "99"}, {"ecdsa", "2048"}} {
		if _, err := api.KeyPairGenerate(bad[0], bad[1]); err == nil {
			t.Errorf("%v: want an error", bad)
		}
	}
	if len(requests()) != before {
		t.Error("invalid types and sizes must not be sent")
	}
}

func TestService(t *testing.T) {
	var answers = map[string]any{
		"GET /api/ipsec/service/status":                 `{"status":"disabled","widget":{}}`,
		"POST /api/ipsec/service/reconfigure":           `{"status":"ok"}`,
		"POST /api/ipsec/service/start":                 `{"response":"OK"}`,
		"POST /api/ipsec/service/stop":                  `{"response":"Execute error"}`,
		"POST /api/ipsec/service/restart":               `{"response":"OK"}`,
		"GET /api/ipsec/connections/is_enabled":         `{"enabled":false}`,
		"POST /api/ipsec/connections/toggle/1":          `{"status":"ok"}`,
		"POST /api/ipsec/connections/toggle/0":          `{"status":"failed"}`,
		"GET /api/ipsec/legacy_subsystem/status":        `{"enabled":true,"isDirty":true}`,
		"POST /api/ipsec/legacy_subsystem/apply_config": `{"status":"ok","message":"The changes have been applied successfully."}`,
	}
	var api, requests = testApi(t, answers)
	if status, err := api.ServiceStatus(); err != nil || status != "disabled" {
		t.Errorf("status: %q %v", status, err)
	}
	if err := api.ServiceReconfigure(); err != nil {
		t.Error(err)
	}
	if err := api.ServiceStart(); err != nil {
		t.Error(err)
	}
	if err := api.ServiceRestart(); err != nil {
		t.Error(err)
	}
	if err := api.ServiceStop(); err == nil || !strings.Contains(err.Error(), "Execute error") {
		t.Errorf("want the configd error, got %v", err)
	}
	if enabled, err := api.IsEnabled(); err != nil || enabled {
		t.Errorf("IsEnabled: %v %v", enabled, err)
	}
	if err := api.SetEnabled(true); err != nil {
		t.Error(err)
	}
	if err := api.SetEnabled(false); err == nil {
		t.Error("want an error for status failed")
	}
	if status, err := api.LegacyStatus(); err != nil || !status.Enabled || !status.Pending {
		t.Errorf("LegacyStatus: %+v %v", status, err)
	}
	if err := api.ApplyLegacy(); err != nil {
		t.Error(err)
	}
	answers["POST /api/ipsec/service/reconfigure"] = `{"status":"failed","status_msg":"Service \"ipsec\" failed to start."}`
	if err := api.ServiceReconfigure(); err == nil || !strings.Contains(err.Error(), "failed to start") {
		t.Errorf("want the status_msg, got %v", err)
	}
	answers["GET /api/ipsec/service/status"] = `{}`
	if _, err := api.ServiceStatus(); err == nil {
		t.Error("want an error without status")
	}
	for _, request := range requests() {
		var action = !strings.HasSuffix(request.Path, "status") && !strings.HasSuffix(request.Path, "is_enabled")
		if action && request.Method != "POST" {
			t.Errorf("actions must be POSTed: %+v", request)
		}
	}
}

func TestStatus(t *testing.T) {
	var answers = map[string]any{
		"GET /api/ipsec/sessions/search_phase1": testRows(map[string]any{"name": testConnUuid, "phase1desc": "Site B", "connected": true,
			"routed": true, "version": "IKEv2", "bytes-in": 10, "install-time": nil}),
		"POST /api/ipsec/sessions/search_phase2":           testRows(map[string]any{"name": "c1", "local-ts": "198.51.100.0/24 , 2001:db8::/64"}),
		"POST /api/ipsec/sessions/connect/" + testConnUuid: `{"result":"ok"}`,
		"POST /api/ipsec/sessions/disconnect/con 1":        `{"result":"ok"}`,
		"GET /api/ipsec/sad/search": testRows(map[string]any{"src": "No", "dst": "SAD", "satype": nil, "spi": nil, "nat": "ntries",
			"id": "910a25ff497965ab5bed6120daa20baa"}, map[string]any{"src": "192.0.2.7", "dst": "198.51.100.7", "satype": "esp", "spi": "c1f0aa01",
			"id": "0123456789abcdef0123456789abcdef", "reqid": 5}),
		"POST /api/ipsec/sad/delete/0123456789abcdef0123456789abcdef": `{"status":"found","items":[{}],"result":"ok"}`,
		"POST /api/ipsec/spd/delete/0123456789abcdef0123456789abcdef": `{"status":"not_found","items":[],"result":"ok"}`,
		"GET /api/ipsec/spd/search":                                   testRows(),
		"GET /api/ipsec/leases/search":                                testRows(map[string]any{"pool": "mobile", "address": "198.51.100.130", "online": true, "user": "alice"}),
		"GET /api/ipsec/leases/pools":                                 `{"pools":{"v6":{"name":"v6","net":"2001:db8::1","online":0,"offline":0,"size":256},"mobile":{"name":"mobile","net":"198.51.100.128","online":1,"offline":0,"size":126}}}`,
	}
	var api, requests = testApi(t, answers)
	var sessions, err = api.SessionList()
	if err != nil || len(sessions) != 1 || sessions[0].Value("connected") != "1" || sessions[0].Value("bytes-in") != "10" ||
		sessions[0].Value("install-time") != "" {
		t.Fatalf("SessionList: %v %v", sessions, err)
	}
	children, err := api.SessionChildren(testConnUuid)
	if err != nil || len(children) != 1 {
		t.Fatalf("SessionChildren: %v %v", children, err)
	}
	if got := requests()[1]; got.Method != "POST" || !reflect.DeepEqual(got.Body, map[string]any{"id": testConnUuid}) {
		t.Errorf("phase 2 must POST the connection name: %+v", got)
	}
	if err := api.SessionConnect(testConnUuid); err != nil {
		t.Error(err)
	}
	if err := api.SessionDisconnect("con 1"); err != nil {
		t.Error(err)
	}
	if err := api.SessionDisconnect("con2"); err == nil { // unregistered: empty answer
		t.Error("want an error without result ok")
	}
	var before = len(requests())
	for _, bad := range []string{"", "a/b", "a?b"} {
		if err := api.SessionConnect(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
	if _, err := api.SessionChildren(""); err == nil {
		t.Error("want an error for an empty name")
	}
	if len(requests()) != before {
		t.Error("invalid names must not be sent")
	}

	sad, err := api.SadList()
	if err != nil || len(sad) != 1 || sad[0].Value("spi") != "c1f0aa01" || sad[0].Value("reqid") != "5" {
		t.Errorf("the \"No SAD entries.\" row must be dropped: %v %v", sad, err)
	}
	if err := api.SadRemove("0123456789abcdef0123456789abcdef"); err != nil {
		t.Error(err)
	}
	if err := api.SpdRemove("0123456789abcdef0123456789abcdef"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if err := api.SpdRemove("ffffffffffffffffffffffffffffffff"); err == nil { // unregistered: empty answer
		t.Error("want an error")
	}
	before = len(requests())
	for _, bad := range []string{"", "x", "0123456789ABCDEF0123456789ABCDEF", "0123456789abcdef0123456789abcdef/x"} {
		if err := api.SadRemove(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
	if len(requests()) != before {
		t.Error("invalid ids must not be sent")
	}
	if spd, err := api.SpdList(); err != nil || len(spd) != 0 {
		t.Errorf("SpdList: %v %v", spd, err)
	}

	leases, err := api.LeaseList()
	if err != nil || len(leases) != 1 || leases[0].Value("online") != "1" {
		t.Errorf("LeaseList: %v %v", leases, err)
	}
	pools, err := api.LeasePools()
	if err != nil || len(pools) != 2 || pools[0].Value("name") != "mobile" || pools[0].Value("size") != "126" {
		t.Errorf("LeasePools sorted by name: %v %v", pools, err)
	}
	answers["GET /api/ipsec/leases/pools"] = `{"pools":[]}`
	if pools, err := api.LeasePools(); err != nil || len(pools) != 0 {
		t.Errorf("empty pools: %v %v", pools, err)
	}
}

func TestIsUuid(t *testing.T) {
	if !IsUuid(testConnUuid) || IsUuid("con1") || IsUuid(testConnUuid+"x") {
		t.Error("IsUuid")
	}
}
