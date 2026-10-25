package openvpn

import (
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

// Answers are shaped like OPNsense 26.7 (ExportController), see the comment at the top of export.go

type exportTestCall struct {
	Method string
	Path   string // escaped path as sent
	Body   string
}

// exportTestApi starts a test server answering with routes[METHOD + " " + escaped path] or an OPNsense like 404,
// and records all calls
func exportTestApi(t *testing.T, routes map[string]string) (*OpenVPNApi, func() []exportTestCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []exportTestCall
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		var path = r.URL.EscapedPath()
		mu.Lock()
		calls = append(calls, exportTestCall{r.Method, path, string(body)})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if answer, ok := routes[r.Method+" "+path]; ok {
			var status = 200
			if strings.HasPrefix(answer, "400 ") {
				status, answer = 400, strings.TrimPrefix(answer, "400 ")
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, answer)
			return
		}
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"errorMessage":"Endpoint not found"}`)
	}))
	t.Cleanup(server.Close)

	var baseUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &OpenVPNApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl, ApiKey: "k", ApiSecret: "s"}}, func() []exportTestCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]exportTestCall(nil), calls...)
	}
}

const (
	exportTestUuid   = "3f0c6a2e-9b1d-4c8e-a7f5-0d2b6e4c1a90"
	exportTestLegacy = "2"

	// exportTestProviders: an instance with presets (vpnid is the uuid) before a legacy server without any
	// (null booleans are stored "0"s)
	exportTestProviders = `{"` + exportTestUuid + `":{"name":"Road Warrior udp:1194","mode":"server_tls_user","vpnid":"` + exportTestUuid + `",` +
		`"hostname":"vpn.example.com,198.51.100.7","template":"ArchiveOpenVPN","local_port":"11194","random_local_port":"1",` +
		`"validate_server_cn":"1","cryptoapi":null,"auth_nocache":"1","static_challenge":null,"plain_config":"verb 4\nmute 10"},` +
		`"` + exportTestLegacy + `":{"name":"server tcp:443","mode":"server_tls","vpnid":"2","hostname":null,"template":null,` +
		`"local_port":"443","random_local_port":null,"validate_server_cn":"1","cryptoapi":null,"auth_nocache":null,` +
		`"static_challenge":null,"plain_config":null}}`

	exportTestAccounts = `{"":{"description":"(none) Exclude certificate from export","users":[]},` +
		`"6ade13f1bff83":{"description":"alice laptop","users":["alice"]},` +
		`"6ade13f1aaa01":{"description":"shared","users":[]}}`

	exportTestTemplates = `{"ArchiveOpenVPN":{"name":"Archive","supportedOptions":["plain_config","p12_password","random_local_port","auth_nocache","cryptoapi","static_challenge"]},` +
		`"PlainOpenVPN":{"name":"File Only","supportedOptions":["plain_config","random_local_port","auth_nocache","cryptoapi","static_challenge"]},` +
		`"ViscosityVisz":{"name":"Viscosity (visz)","supportedOptions":["plain_config","p12_password","random_local_port","auth_nocache","cryptoapi","static_challenge"]}}`

	exportTestNoneOnly = `{"":{"description":"(none) Exclude certificate from export","users":[]}}`

	exportTestProvidersPath = "GET /api/openvpn/export/providers"
)

func exportTestOvpn() string {
	return "dev tun\npersist-tun\npersist-key\nclient\nremote vpn.example.com 11194 udp\n<ca>\n-----BEGIN CERTIFICATE-----\n</ca>"
}

func exportTestDownloadAnswer(changed bool, filename string, filetype string, content string) string {
	var answer, _ = json.Marshal(map[string]any{
		"result": "ok", "changed": changed, "filename": filename, "filetype": filetype,
		"content": base64.StdEncoding.EncodeToString([]byte(content)),
	})
	return string(answer)
}

func exportTestBody(t *testing.T, call exportTestCall) map[string]string {
	t.Helper()
	var body map[string]map[string]string
	if err := json.Unmarshal([]byte(call.Body), &body); err != nil {
		t.Fatalf("body of %s %s: %v %q", call.Method, call.Path, err, call.Body)
	}
	if len(body) != 1 || body["openvpn_export"] == nil {
		t.Fatalf("body of %s %s is not {\"openvpn_export\":{...}}: %q", call.Method, call.Path, call.Body)
	}
	return body["openvpn_export"]
}

func exportTestPosts(calls []exportTestCall) []exportTestCall {
	var posts []exportTestCall
	for _, call := range calls {
		if call.Method != "GET" {
			posts = append(posts, call)
		}
	}
	return posts
}

func TestExportServers(t *testing.T) {
	var api, _ = exportTestApi(t, map[string]string{exportTestProvidersPath: exportTestProviders})
	var servers, err = api.ExportServers()
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 {
		t.Fatalf("want 2 servers in API order, got %+v", servers)
	}
	var warrior, legacy = servers[0], servers[1]
	if warrior.Vpnid != exportTestUuid || warrior.Name != "Road Warrior udp:1194" || warrior.Mode != "server_tls_user" ||
		warrior.Description() != "Road Warrior" || warrior.Listen() != "udp:1194" {
		t.Errorf("first server: %+v", warrior)
	}
	var wantPresets = ExportOptions{
		"hostname": "vpn.example.com,198.51.100.7", "template": "ArchiveOpenVPN", "local_port": "11194",
		"random_local_port": "1", "validate_server_cn": "1", "cryptoapi": "0", "auth_nocache": "1",
		"static_challenge": "0", "plain_config": "verb 4\nmute 10",
	}
	if !reflect.DeepEqual(warrior.Presets, wantPresets) {
		t.Errorf("presets\n got  %v\n want %v", warrior.Presets, wantPresets)
	}
	if legacy.Vpnid != "2" || legacy.Presets["hostname"] != "" || legacy.Presets["random_local_port"] != "0" ||
		legacy.Presets["template"] != "" || legacy.Presets["local_port"] != "443" || legacy.Description() != "server" {
		t.Errorf("legacy server: %+v", legacy)
	}
	var raw map[string]any
	if err := json.Unmarshal(warrior.Raw, &raw); err != nil || raw["name"] != "Road Warrior udp:1194" || raw["cryptoapi"] != nil {
		t.Errorf("raw: %v %s", err, warrior.Raw)
	}

	t.Run("none is an empty PHP array", func(t *testing.T) {
		var api, _ = exportTestApi(t, map[string]string{exportTestProvidersPath: `[]`})
		var servers, err = api.ExportServers()
		if err != nil || len(servers) != 0 {
			t.Errorf("servers %v, err %v", servers, err)
		}
	})
	t.Run("garbage", func(t *testing.T) {
		var api, _ = exportTestApi(t, map[string]string{exportTestProvidersPath: `["x"]`})
		if _, err := api.ExportServers(); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("get", func(t *testing.T) {
		var api, _ = exportTestApi(t, map[string]string{exportTestProvidersPath: exportTestProviders})
		if server, err := api.ExportServerGet("2"); err != nil || server.Name != "server tcp:443" {
			t.Errorf("server %+v, err %v", server, err)
		}
		var _, err = api.ExportServerGet("9")
		if !coreapi.IsNotFound(err) || !strings.Contains(err.Error(), "only enabled servers") {
			t.Errorf("want not found, got %v", err)
		}
	})
}

func TestExportAccounts(t *testing.T) {
	var api, calls = exportTestApi(t, map[string]string{
		exportTestProvidersPath:                              exportTestProviders,
		"GET /api/openvpn/export/accounts/" + exportTestUuid: exportTestAccounts,
		"GET /api/openvpn/export/accounts/2":                 exportTestNoneOnly,
		"GET /api/openvpn/export/accounts/9":                 exportTestNoneOnly,
		"GET /api/openvpn/export/accounts/a%2Fb":             exportTestNoneOnly,
	})

	var accounts, err = api.ExportAccounts(exportTestUuid)
	if err != nil {
		t.Fatal(err)
	}
	var want = []ExportAccount{
		{Certref: "6ade13f1bff83", Description: "alice laptop", Users: []string{"alice"}},
		{Certref: "6ade13f1aaa01", Description: "shared", Users: []string{}},
	}
	if !reflect.DeepEqual(accounts, want) {
		t.Errorf("accounts\n got  %+v\n want %+v", accounts, want)
	}
	if len(calls()) != 1 {
		t.Errorf("accounts of a server with certificates need one call, got %v", calls())
	}

	// a known server without client certificates
	if accounts, err := api.ExportAccounts("2"); err != nil || len(accounts) != 0 {
		t.Errorf("legacy: %v %v", accounts, err)
	}
	// unknown (or disabled) servers get the (none) entry only from OPNsense
	if _, err := api.ExportAccounts("9"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if _, err := api.ExportAccounts("a/b"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found for an escaped vpnid, got %v", err)
	}
	if _, err := api.ExportAccounts(""); err == nil {
		t.Error("want an error without vpnid")
	}
}

func TestExportTemplates(t *testing.T) {
	var api, _ = exportTestApi(t, map[string]string{"GET /api/openvpn/export/templates": exportTestTemplates})
	var templates, err = api.ExportTemplates()
	if err != nil {
		t.Fatal(err)
	}
	if len(templates) != 3 || templates[0].Name != "ArchiveOpenVPN" || templates[1].Name != "PlainOpenVPN" ||
		templates[1].Description != "File Only" || templates[2].Description != "Viscosity (visz)" {
		t.Fatalf("templates: %+v", templates)
	}
	if !templates[0].Supports(ExportOptionP12Password) || templates[1].Supports(ExportOptionP12Password) ||
		!templates[1].Supports(ExportOptionPlainConfig) {
		t.Errorf("supported options: %+v", templates)
	}
}

func TestExportStorePresets(t *testing.T) {
	const storePath = "POST /api/openvpn/export/store_presets/" + exportTestUuid

	t.Run("only the given options are sent", func(t *testing.T) {
		var api, calls = exportTestApi(t, map[string]string{
			exportTestProvidersPath: exportTestProviders,
			storePath:               `{"result":"ok","changed":true}`,
		})
		var changed, err = api.ExportStorePresets(exportTestUuid, ExportOptions{"template": "PlainOpenVPN", "local_port": ""})
		if err != nil || !changed {
			t.Fatalf("changed %v, err %v", changed, err)
		}
		var posts = exportTestPosts(calls())
		if len(posts) != 1 || posts[0].Path != strings.TrimPrefix(storePath, "POST ") {
			t.Fatalf("posts: %v", posts)
		}
		if body := exportTestBody(t, posts[0]); !reflect.DeepEqual(body, map[string]string{"template": "PlainOpenVPN", "local_port": ""}) {
			t.Errorf("body %v", body)
		}
	})
	t.Run("unchanged", func(t *testing.T) {
		var api, _ = exportTestApi(t, map[string]string{
			exportTestProvidersPath: exportTestProviders,
			storePath:               `{"result":"ok","changed":false}`,
		})
		if changed, err := api.ExportStorePresets(exportTestUuid, ExportOptions{"hostname": "vpn.example.com"}); err != nil || changed {
			t.Errorf("changed %v, err %v", changed, err)
		}
	})
	t.Run("validation", func(t *testing.T) {
		var api, _ = exportTestApi(t, map[string]string{
			exportTestProvidersPath: exportTestProviders,
			storePath: `{"result":"failed","changed":true,"validations":{"openvpn_export.local_port":"Port needs to be an integer value between 1 and 65535.",` +
				`"openvpn_export.hostname":["A value is required."]}}`,
		})
		var _, err = api.ExportStorePresets(exportTestUuid, ExportOptions{"local_port": "70000"})
		var validation *coreapi.ValidationError
		if !errors.As(err, &validation) || validation.Validations["local_port"] == "" || validation.Validations["hostname"] != "A value is required." {
			t.Errorf("want a validation error keyed by option names, got %v", err)
		}
	})
	t.Run("unknown server is not stored", func(t *testing.T) {
		var api, calls = exportTestApi(t, map[string]string{exportTestProvidersPath: exportTestProviders})
		var _, err = api.ExportStorePresets("9", ExportOptions{"hostname": "vpn.example.com"})
		if !coreapi.IsNotFound(err) {
			t.Errorf("want not found, got %v", err)
		}
		if posts := exportTestPosts(calls()); len(posts) != 0 {
			t.Errorf("OPNsense creates presets for unknown servers, posts: %v", posts)
		}
	})
	t.Run("unknown option", func(t *testing.T) {
		var api, calls = exportTestApi(t, map[string]string{exportTestProvidersPath: exportTestProviders})
		if _, err := api.ExportStorePresets(exportTestUuid, ExportOptions{"p12_password": "secret"}); err == nil {
			t.Error("the p12 password can not be stored")
		}
		if posts := exportTestPosts(calls()); len(posts) != 0 {
			t.Errorf("posts: %v", posts)
		}
	})
}

func TestExportValidatePresets(t *testing.T) {
	var api, calls = exportTestApi(t, map[string]string{
		"POST /api/openvpn/export/validate_presets/9": `{"result":"failed","changed":false,"validations":{"openvpn_export.hostname":"A value is required."}}`,
		"POST /api/openvpn/export/validate_presets/2": `{"result":"ok","changed":true}`,
	})
	var _, err = api.ExportValidatePresets("9", nil)
	var validation *coreapi.ValidationError
	if !errors.As(err, &validation) || validation.Validations["hostname"] == "" {
		t.Errorf("want a validation error, got %v", err)
	}
	if changed, err := api.ExportValidatePresets("2", ExportOptions{"hostname": "h.example"}); err != nil || !changed {
		t.Errorf("changed %v, err %v", changed, err)
	}
	// validation never needs the server list
	for _, call := range calls() {
		if call.Method == "GET" {
			t.Errorf("unexpected call %v", call)
		}
	}
	if body := exportTestBody(t, calls()[0]); len(body) != 0 {
		t.Errorf("nil options must be sent as {}: %v", body)
	}
}

func TestExportDownload(t *testing.T) {
	const downloadPath = "POST /api/openvpn/export/download/" + exportTestUuid + "/6ade13f1bff83"

	t.Run("effective presets and overrides are sent", func(t *testing.T) {
		var api, calls = exportTestApi(t, map[string]string{
			exportTestProvidersPath: exportTestProviders,
			downloadPath:            exportTestDownloadAnswer(true, "Road_Warrior_alice.ovpn", "text/ovpn", exportTestOvpn()),
		})
		var file, err = api.ExportDownload(exportTestUuid, "6ade13f1bff83", ExportOptions{"template": "PlainOpenVPN", "p12_password": "pw"})
		if err != nil {
			t.Fatal(err)
		}
		if file.Filename != "Road_Warrior_alice.ovpn" || file.Filetype != "text/ovpn" || string(file.Content) != exportTestOvpn() || !file.PresetsChanged {
			t.Errorf("file: %+v", file)
		}
		var posts = exportTestPosts(calls())
		if len(posts) != 1 {
			t.Fatalf("posts: %v", posts)
		}
		var want = map[string]string{
			"hostname": "vpn.example.com,198.51.100.7", "template": "PlainOpenVPN", "local_port": "11194",
			"random_local_port": "1", "validate_server_cn": "1", "cryptoapi": "0", "auth_nocache": "1",
			"static_challenge": "0", "plain_config": "verb 4\nmute 10", "p12_password": "pw",
		}
		if body := exportTestBody(t, posts[0]); !reflect.DeepEqual(body, want) {
			t.Errorf("body\n got  %v\n want %v", body, want)
		}
	})
	t.Run("without certificate and template preset", func(t *testing.T) {
		var api, calls = exportTestApi(t, map[string]string{
			exportTestProvidersPath:               exportTestProviders,
			"POST /api/openvpn/export/download/2": exportTestDownloadAnswer(false, "server.ovpn", "text/ovpn", "client\n"),
		})
		var file, err = api.ExportDownload("2", "", ExportOptions{"hostname": "vpn.example.org"})
		if err != nil || string(file.Content) != "client\n" || file.PresetsChanged {
			t.Fatalf("file %+v, err %v", file, err)
		}
		var body = exportTestBody(t, exportTestPosts(calls())[0])
		if body["template"] != ExportDefaultTemplate || body["hostname"] != "vpn.example.org" || body["local_port"] != "443" || body["random_local_port"] != "0" {
			t.Errorf("body %v", body)
		}
	})
	t.Run("unknown server", func(t *testing.T) {
		var api, calls = exportTestApi(t, map[string]string{exportTestProvidersPath: exportTestProviders})
		var _, err = api.ExportDownload("9", "", nil)
		if !coreapi.IsNotFound(err) {
			t.Errorf("want not found, got %v", err)
		}
		if posts := exportTestPosts(calls()); len(posts) != 0 {
			t.Errorf("posts: %v", posts)
		}
	})
	for _, tc := range []struct {
		name   string
		answer string
		check  func(error) bool
		want   string
	}{
		{"failed without validations (server disabled meanwhile)", `{"result":"failed"}`, coreapi.IsNotFound, "only enabled servers"},
		{"validation", `{"result":"failed","changed":true,"validations":{"openvpn_export.hostname":"A value is required."}}`,
			func(err error) bool { var v *coreapi.ValidationError; return errors.As(err, &v) }, "hostname: A value is required."},
		{"unknown template", `{"result":"ok","changed":true}`, coreapi.IsNotFound, "export template ArchiveOpenVPN"},
		{"certificate of another CA", `400 {"errorMessage":"Certificate does not belong to server CA","errorTitle":"OpenVPN export"}`,
			func(err error) bool { var h *coreapi.HttpError; return errors.As(err, &h) }, "Certificate does not belong to server CA"},
		{"broken content", `{"result":"ok","filename":"x.ovpn","content":"%%%"}`, func(err error) bool { return err != nil }, "decode"},
		{"unexpected", `{"result":""}`, func(err error) bool { return err != nil }, "unexpected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var api, _ = exportTestApi(t, map[string]string{exportTestProvidersPath: exportTestProviders, downloadPath: tc.answer})
			var _, err = api.ExportDownload(exportTestUuid, "6ade13f1bff83", nil)
			if err == nil || !tc.check(err) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want %q, got %T %v", tc.want, err, err)
			}
		})
	}
	t.Run("a path in the file name is dropped", func(t *testing.T) {
		for name, want := range map[string]string{"../../etc/x.ovpn": "x.ovpn", `..\a.zip`: "a.zip", "..": "openvpn.ovpn", "": "openvpn.ovpn"} {
			var api, _ = exportTestApi(t, map[string]string{
				exportTestProvidersPath: exportTestProviders,
				downloadPath:            exportTestDownloadAnswer(false, name, "text/ovpn", "x"),
			})
			if file, err := api.ExportDownload(exportTestUuid, "6ade13f1bff83", nil); err != nil || file.Filename != want {
				t.Errorf("%q: got %q, %v", name, file.Filename, err)
			}
		}
	})
	t.Run("unknown option", func(t *testing.T) {
		var api, calls = exportTestApi(t, nil)
		if _, err := api.ExportDownload(exportTestUuid, "", ExportOptions{"bogus": "1"}); err == nil {
			t.Error("want an error")
		}
		if len(calls()) != 0 {
			t.Errorf("calls: %v", calls())
		}
	})
}
