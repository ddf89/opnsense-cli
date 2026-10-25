package captiveportal

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
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
	Method  string
	Path    string
	RawPath string
	Query   url.Values
	Body    map[string]any
}

// testApi starts a fake OPNsense answering "METHOD /path" with the answer: a string is sent as JSON text, a
// []byte as application/octet-stream, anything else JSON encoded; unknown endpoints get an empty 200
func testApi(t *testing.T, answers map[string]any) (*CaptivePortalApi, func() []testRequest) {
	t.Helper()
	var mu sync.Mutex
	var requests []testRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var recorded = testRequest{Method: r.Method, Path: r.URL.Path, RawPath: r.URL.EscapedPath(), Query: r.URL.Query()}
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
		switch answer := answer.(type) {
		case string:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, answer)
		case []byte:
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(answer)
		default:
			_ = json.NewEncoder(w).Encode(answer)
		}
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &CaptivePortalApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, func() []testRequest {
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

func testZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	var writer = zip.NewWriter(&buffer)
	for name, content := range files {
		var file, err = writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(file, content)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

const testZoneSearch = "/api/captiveportal/settings/search_zones"

func testZoneRow(overrides map[string]any) map[string]any {
	var row = map[string]any{
		"uuid": "z-1", "enabled": "1", "zoneid": "0", "interfaces": "lan", "%interfaces": "LAN", "disableRules": "0",
		"authservers": "Local Database", "roaming": "1", "alwaysSendAccountingReqs": "0", "authEnforceGroup": "",
		"idletimeout": "0", "hardtimeout": "0", "concurrentlogins": "1", "certificate": "", "servername": "",
		"allowedAddresses": "", "allowedMACAddresses": "", "extendedPreAuthData": "0", "template": "", "description": "guests",
	}
	for key, value := range overrides {
		row[key] = value
	}
	return row
}

func TestValue(t *testing.T) {
	var decoded struct {
		A, B, C, D, E Value
	}
	if err := json.Unmarshal([]byte(`{"A":"text","B":12,"C":1761400000.75,"D":null,"E":true}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.A != "text" || decoded.B != "12" || decoded.C != "1761400000.75" || decoded.D != "" || decoded.E != "true" {
		t.Errorf("decoded %+v", decoded)
	}
	if decoded.B.Int() != 12 || decoded.C.Int() != 1761400000 || decoded.A.Int() != 0 {
		t.Errorf("Int: %d %d %d", decoded.B.Int(), decoded.C.Int(), decoded.A.Int())
	}
	var bad Value
	if err := json.Unmarshal([]byte(`[1]`), &bad); err == nil {
		t.Error("a list is no value")
	}
}

func TestZones(t *testing.T) {
	var api, requests = testApi(t, map[string]any{
		"GET " + testZoneSearch: testRows(testZoneRow(nil), testZoneRow(map[string]any{"uuid": "z-2", "description": "dup", "enabled": "0"}),
			testZoneRow(map[string]any{"uuid": "z-3", "description": "DUP"})),
		"POST /api/captiveportal/settings/add_zone":          `{"result":"saved","uuid":"z-new"}`,
		"POST /api/captiveportal/settings/set_zone/z-1":      `{"result":"failed","validations":{"zone.interfaces":"At least one interface must be selected."}}`,
		"POST /api/captiveportal/settings/set_zone/z-2":      `{"result":"saved"}`,
		"POST /api/captiveportal/settings/del_zone/z-x":      `{"result":"not found"}`,
		"POST /api/captiveportal/settings/toggle_zone/z-2/1": `{"result":"Enabled","changed":true}`,
		"POST /api/captiveportal/settings/toggle_zone/z-1/1": `{"result":"Enabled","changed":false}`,
		"POST /api/captiveportal/settings/toggle_zone/z-x/0": `{"result":"failed"}`,
	})
	var raw, zones, err = api.ZoneListRaw("")
	if err != nil || len(raw) != 3 || zones[0].InterfaceNames != "LAN" || zones[0].AuthServers != "Local Database" {
		t.Fatalf("ZoneListRaw: %+v %v", zones, err)
	}
	if zone, err := api.ZoneGetByDescription("Guests"); err != nil || zone.Uuid != "z-1" {
		t.Errorf("by description: %+v %v", zone, err)
	}
	var tooMany *coreapi.TooManyFoundError
	if _, err := api.ZoneGetByDescription("dup"); !errors.As(err, &tooMany) || !strings.Contains(err.Error(), "z-2, z-3") {
		t.Errorf("duplicates: %v", err)
	}
	if uuid, err := api.ZoneCreate(ZoneFields{"enabled": "0", "interfaces": "lan", "description": "new"}); err != nil || uuid != "z-new" {
		t.Errorf("create %q %v", uuid, err)
	}
	if _, err := api.ZoneCreate(ZoneFields{"zoneid": "3"}); err == nil {
		t.Error("zoneid is not writable")
	}
	var validation *coreapi.ValidationError
	if err := api.ZoneUpdate("z-1", ZoneFields{"interfaces": ""}); !errors.As(err, &validation) || validation.Validations["zone.interfaces"] == "" {
		t.Errorf("validation: %v", err)
	}
	if err := api.ZoneUpdate("z-2", ZoneFields{"idletimeout": "5"}); err != nil {
		t.Error(err)
	}
	if err := api.ZoneUpdate("z-ghost", ZoneFields{"idletimeout": "5"}); !coreapi.IsNotFound(err) {
		t.Errorf("unknown: %v", err)
	}
	if err := api.ZoneRemove("z-x"); !coreapi.IsNotFound(err) {
		t.Errorf("remove unknown: %v", err)
	}
	if changed, err := api.ZoneSetEnabled("z-2", true); err != nil || !changed {
		t.Errorf("enable %v %v", changed, err)
	}
	if changed, err := api.ZoneSetEnabled("z-1", true); err != nil || changed {
		t.Errorf("enable enabled %v %v", changed, err)
	}
	if _, err := api.ZoneSetEnabled("z-x", false); !coreapi.IsNotFound(err) {
		t.Errorf("toggle unknown: %v", err)
	}
	var posted = testMutations(requests())
	if len(posted) != 7 || !reflect.DeepEqual(posted[0].Body, map[string]any{"zone": map[string]any{"enabled": "0", "interfaces": "lan", "description": "new"}}) ||
		!reflect.DeepEqual(posted[2].Body, map[string]any{"zone": map[string]any{"idletimeout": "5"}}) {
		t.Errorf("posted %+v", posted)
	}
}

func TestZoneOptions(t *testing.T) {
	var api, _ = testApi(t, map[string]any{
		"GET /api/captiveportal/settings/get_zone": `{"zone":{"enabled":"1","interfaces":{"lan":{"value":"LAN","selected":1},"opt2":{"value":"GUEST","selected":0}},` +
			`"authEnforceGroup":{"":{"value":"None","selected":1},"1999":{"value":"admins","selected":0}},"description":""}}`,
	})
	var options, err = api.ZoneOptions()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(options["interfaces"], []Option{{Key: "lan", Description: "LAN", Selected: true}, {Key: "opt2", Description: "GUEST"}}) ||
		len(options["authEnforceGroup"]) != 2 || options["description"] != nil {
		t.Errorf("options %+v", options)
	}
}

func TestTemplates(t *testing.T) {
	var zipped = testZip(t, map[string]string{"index.html": "<html>portal</html>"})
	var api, requests = testApi(t, map[string]any{
		"GET /api/captiveportal/template/search_templates": testRows(
			map[string]string{"uuid": "t-1", "fileid": "6ade2378b8019", "name": "guest page", "content": "UEsDBA=="},
		),
		"GET /api/captiveportal/template/get_template":               zipped,
		"GET /api/captiveportal/template/get_template/6ade2378b8019": zipped,
		"GET /api/captiveportal/template/get_template/broken":        `{"errorMessage":"Unexpected error"}`,
		"POST /api/captiveportal/template/del_template/t-1":          `{"result":"deleted"}`,
	})
	if template, err := api.TemplateGetByName("guest page"); err != nil || template.FileId != "6ade2378b8019" {
		t.Errorf("by name: %+v %v", template, err)
	}
	if _, err := api.TemplateGetByName("Guest Page"); !coreapi.IsNotFound(err) {
		t.Errorf("names are case-sensitive: %v", err)
	}
	if content, err := api.TemplateDownload(""); err != nil || !bytes.Equal(content, zipped) {
		t.Errorf("default download: %v", err)
	}
	if content, err := api.TemplateDownload("6ade2378b8019"); err != nil || !bytes.Equal(content, zipped) {
		t.Errorf("download: %v", err)
	}
	if _, err := api.TemplateDownload("broken"); err == nil || !strings.Contains(err.Error(), "Unexpected error") {
		t.Errorf("a JSON answer is an error: %v", err)
	}
	if err := api.TemplateRemove("t-1"); err != nil {
		t.Error(err)
	}
	if got := requests()[2].Path; got != "/api/captiveportal/template/get_template" {
		t.Errorf("default template path %q", got)
	}
}

func TestTemplateSave(t *testing.T) {
	var zipped = testZip(t, map[string]string{"index.html": "<html>portal</html>"})
	var answer = `{"name":"guest page"}`
	var api, requests = testApi(t, map[string]any{"POST /api/captiveportal/template/save_template": answer})
	if err := api.TemplateSave("", "guest page", zipped); err != nil {
		t.Fatal(err)
	}
	if err := api.TemplateSave("t-1", "guest page", nil); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		name    string
		content []byte
	}{{"bad-name", zipped}, {"new", nil}, {"new", []byte("not a zip")}, {"", zipped}} {
		if err := api.TemplateSave("", bad.name, bad.content); err == nil {
			t.Errorf("save %q %q must fail", bad.name, bad.content)
		}
	}
	var posted = testMutations(requests())
	if len(posted) != 2 || posted[0].Body["content"] != base64.StdEncoding.EncodeToString(zipped) || posted[0].Body["uuid"] != nil ||
		!reflect.DeepEqual(posted[1].Body, map[string]any{"name": "guest page", "uuid": "t-1"}) {
		t.Errorf("posted %+v", posted)
	}

	for refusal, want := range map[string]string{
		`{"name":"x","error":null}`:                      "could not process",
		`{"error":"node not found"}`:                     "not found",
		`{"name":"x","error":"Template name should be"}`: "Template name should be",
		`[]`: "could not decode",
	} {
		var failing, _ = testApi(t, map[string]any{"POST /api/captiveportal/template/save_template": refusal})
		if err := failing.TemplateSave("t-1", "x", zipped); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("answer %s: %v", refusal, err)
		}
	}
}

func TestSessions(t *testing.T) {
	var api, requests = testApi(t, map[string]any{
		"GET /api/captiveportal/session/search": `{"total":1,"rowCount":1,"current":1,"rows":[{"zoneid":0,"sessionId":"s-1",` +
			`"authenticated_via":"Local Database","userName":"alice","startTime":1761400000.5,"ipAddress":"192.168.1.50",` +
			`"macAddress":"02:00:00:00:00:01","packets_in":10,"packets_out":20,"bytes_in":1000,"bytes_out":2000,` +
			`"last_accessed":1761400100,"acc_session_timeout":null,"ipAddresses":["192.168.1.50"]}]}`,
		"GET /api/captiveportal/session/zones":       `["guests"]`,
		"POST /api/captiveportal/session/disconnect": `{"zoneid":0,"sessionid":"s-1","username":"alice","ip_address":"192.168.1.50","terminateCause":"Admin-Reset"}`,
	})
	var sessions, err = api.SessionList("ali", "0", "2")
	if err != nil || len(sessions) != 1 {
		t.Fatalf("SessionList %+v %v", sessions, err)
	}
	var session = sessions[0]
	if session.ZoneId != "0" || session.UserName != "alice" || session.StartTime.Int() != 1761400000 || session.BytesOut != "2000" ||
		session.AccSessionTimeout != "" || len(session.IpAddresses) != 1 || !strings.Contains(string(session.Raw), "s-1") {
		t.Errorf("session %+v", session)
	}
	if query := requests()[0].Query; !reflect.DeepEqual(query["selected_zones[]"], []string{"0", "2"}) || query.Get("searchPhrase") != "ali" {
		t.Errorf("query %v", query)
	}
	if zones, err := api.ZoneDescriptions(); err != nil || !reflect.DeepEqual(zones, map[string]string{"0": "guests"}) {
		t.Errorf("zones %v %v", zones, err)
	}
	disconnected, err := api.SessionDisconnect("s-1")
	if err != nil || disconnected.Username != "alice" || disconnected.TerminateCause != "Admin-Reset" {
		t.Errorf("disconnect %+v %v", disconnected, err)
	}
	if body := testMutations(requests())[0].Body; !reflect.DeepEqual(body, map[string]any{"sessionId": "s-1"}) {
		t.Errorf("disconnect body %v", body)
	}

	var objects, _ = testApi(t, map[string]any{
		"GET /api/captiveportal/session/zones":       `{"0":"guests","3":"staff"}`,
		"POST /api/captiveportal/session/disconnect": `{"terminateCause":"UNKNOWN"}`,
	})
	if zones, err := objects.ZoneDescriptions(); err != nil || zones["3"] != "staff" {
		t.Errorf("zones as object %v %v", zones, err)
	}
	if _, err := objects.SessionDisconnect("s-x"); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("unknown session: %v", err)
	}
	var illegal, _ = testApi(t, map[string]any{"POST /api/captiveportal/session/disconnect": `{"status":"Illegal response"}`})
	if _, err := illegal.SessionDisconnect("s-x"); err == nil || !strings.Contains(err.Error(), "Illegal response") {
		t.Errorf("illegal response: %v", err)
	}
}

func TestVouchers(t *testing.T) {
	var api, requests = testApi(t, map[string]any{
		"GET /api/captiveportal/voucher/list_providers":                                `["Voucher Server"]`,
		"GET /api/captiveportal/voucher/list_voucher_groups/Voucher Server/":           `["guests","event"]`,
		"GET /api/captiveportal/voucher/list_vouchers/Voucher Server/guests/":          `[{"username":"abc","validity":3600,"expirytime":0,"starttime":1761400000,"endtime":1761403600,"state":"unused","vouchergroup":"guests"}]`,
		"POST /api/captiveportal/voucher/generate_vouchers/Voucher Server/":            `[{"username":"u1","password":"p1","vouchergroup":"guests","validity":"3600","expirytime":0,"starttime":null}]`,
		"POST /api/captiveportal/voucher/expire_voucher/Voucher Server/":               `{"status":"ok"}`,
		"POST /api/captiveportal/voucher/drop_expired_vouchers/Voucher Server/guests/": `{"status":"drop","count":3}`,
		"POST /api/captiveportal/voucher/drop_voucher_group/Voucher Server/guests/":    `{"status":"drop"}`,
	})
	if providers, err := api.VoucherProviders(); err != nil || !reflect.DeepEqual(providers, []string{"Voucher Server"}) {
		t.Errorf("providers %v %v", providers, err)
	}
	if groups, err := api.VoucherGroups("Voucher Server"); err != nil || len(groups) != 2 {
		t.Errorf("groups %v %v", groups, err)
	}
	vouchers, err := api.VoucherList("Voucher Server", "guests")
	if err != nil || len(vouchers) != 1 || vouchers[0].Validity != "3600" || vouchers[0].State != "unused" {
		t.Errorf("vouchers %+v %v", vouchers, err)
	}
	generated, err := api.VoucherGenerate("Voucher Server", "guests", 1, 3600, 0)
	if err != nil || len(generated) != 1 || generated[0].Password != "p1" || generated[0].StartTime != "" {
		t.Errorf("generated %+v %v", generated, err)
	}
	if err := api.VoucherExpire("Voucher Server", "u1"); err != nil {
		t.Error(err)
	}
	if count, err := api.VoucherDropExpired("Voucher Server", "guests"); err != nil || count != 3 {
		t.Errorf("drop expired %d %v", count, err)
	}
	if err := api.VoucherDropGroup("Voucher Server", "guests"); err != nil {
		t.Error(err)
	}
	for _, bad := range []func() error{
		func() error { _, err := api.VoucherGenerate("Voucher Server", "guests", 0, 3600, 0); return err },
		func() error { _, err := api.VoucherGenerate("Voucher Server", "guests", 10001, 3600, 0); return err },
		func() error { _, err := api.VoucherGenerate("Voucher Server", "guests", 1, 0, 0); return err },
		func() error { _, err := api.VoucherGenerate("Voucher Server", "a/b", 1, 60, 0); return err },
		func() error { _, err := api.VoucherGenerate("", "guests", 1, 60, 0); return err },
		func() error { return api.VoucherExpire("Voucher Server", "") },
	} {
		if bad() == nil {
			t.Error("invalid input must fail without request")
		}
	}

	var posted = testMutations(requests())
	if len(posted) != 4 || posted[0].RawPath != "/api/captiveportal/voucher/generate_vouchers/Voucher%20Server/" ||
		!reflect.DeepEqual(posted[0].Body, map[string]any{"count": "1", "validity": "3600", "expirytime": "0", "vouchergroup": "guests"}) ||
		!reflect.DeepEqual(posted[1].Body, map[string]any{"username": "u1"}) {
		t.Errorf("posted %+v", posted)
	}

	var failing, _ = testApi(t, map[string]any{
		"POST /api/captiveportal/voucher/generate_vouchers/nope/":       `{"status":"error"}`,
		"POST /api/captiveportal/voucher/drop_voucher_group/nope/g/":    `{"status":"error"}`,
		"POST /api/captiveportal/voucher/drop_expired_vouchers/nope/g/": `{"status":"error"}`,
		"POST /api/captiveportal/voucher/expire_voucher/nope/":          `{"status":"error"}`,
	})
	if _, err := failing.VoucherGenerate("nope", "g", 1, 60, 0); err == nil || !strings.Contains(err.Error(), "unknown voucher provider") {
		t.Errorf("generate: %v", err)
	}
	if err := failing.VoucherDropGroup("nope", "g"); err == nil {
		t.Error("drop group must fail")
	}
	if _, err := failing.VoucherDropExpired("nope", "g"); err == nil {
		t.Error("drop expired must fail")
	}
	if err := failing.VoucherExpire("nope", "u"); err == nil {
		t.Error("expire must fail")
	}
}

func TestService(t *testing.T) {
	var api, _ = testApi(t, map[string]any{
		"GET /api/captiveportal/service/status":       `{"status":"disabled","widget":{}}`,
		"POST /api/captiveportal/service/reconfigure": `{"status":"error reloading ipfw (Execute error)"}`,
		"POST /api/captiveportal/service/start":       `{"response":"OK"}`,
	})
	if status, err := api.ServiceStatus(); err != nil || status != "disabled" {
		t.Errorf("status %q %v", status, err)
	}
	if err := api.ServiceReconfigure(); err == nil || !strings.Contains(err.Error(), "error reloading ipfw") {
		t.Errorf("reconfigure: %v", err)
	}
	if err := api.ServiceStart(); err != nil {
		t.Error(err)
	}
	if err := api.ServiceStop(); err == nil {
		t.Error("an empty answer must fail")
	}
}
