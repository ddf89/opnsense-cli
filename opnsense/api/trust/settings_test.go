package trust

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"reflect"
	"strings"
	"testing"
)

// settingsTestGet is a trimmed trust/settings/get answer of OPNsense 26.7 (with a few options selected)
const settingsTestGet = `{"trust":{"store_intermediate_certs":"0","install_crls":"1","fetch_crls":"0","enable_legacy_sect":"1",` +
	`"enable_config_constraints":"1",` +
	`"CipherString":{"DHE-PSK-AES128-CBC-SHA":{"value":"TLS_DHE_PSK_WITH_AES_128_CBC_SHA","selected":0},` +
	`"ECDHE-RSA-AES256-GCM-SHA384":{"value":"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","selected":1},` +
	`"AES128-SHA":{"value":"TLS_RSA_WITH_AES_128_CBC_SHA","selected":1}},` +
	`"Ciphersuites":{"TLS_AES_128_GCM_SHA256":{"value":"TLS_AES_128_GCM_SHA256","selected":0},"TLS_AES_256_GCM_SHA384":{"value":"TLS_AES_256_GCM_SHA384","selected":0}},` +
	`"SignatureAlgorithms":{"ECDSA+SHA256":{"value":"ECDSA+SHA256","selected":1},"RSA+SHA256":{"value":"RSA+SHA256","selected":0}},` +
	`"groups":{"X25519":{"value":"X25519","selected":1},"prime256v1":{"value":"prime256v1","selected":1}},` +
	`"MinProtocol":{"":{"value":"None","selected":0},"TLSv1.2":{"value":"TLSv1.2","selected":1},"TLSv1.3":{"value":"TLSv1.3","selected":0}},` +
	`"MinProtocol_DTLS":{"":{"value":"None","selected":1},"DTLSv1":{"value":"DTLSv1","selected":0}}}}`

type settingsTestRequest struct {
	Method string
	Path   string
	Body   string
}

func settingsTestServer(t *testing.T, responses map[string]string) (*TrustApi, *[]settingsTestRequest) {
	t.Helper()
	var requests []settingsTestRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		requests = append(requests, settingsTestRequest{Method: r.Method, Path: r.URL.Path, Body: string(body)})
		if response, found := responses[r.URL.Path]; found {
			_, _ = io.WriteString(w, response)
		}
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &TrustApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, &requests
}

func TestSettingsGet(t *testing.T) {
	var api, _ = settingsTestServer(t, map[string]string{"/api/trust/settings/get": settingsTestGet})
	var settings, err = api.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	var options = settings.Options
	settings.Options = nil
	var want = Settings{
		StoreIntermediateCerts: "0", InstallCrls: "1", FetchCrls: "0", EnableLegacySect: "1", EnableConfigConstraints: "1",
		CipherString: "ECDHE-RSA-AES256-GCM-SHA384,AES128-SHA", Ciphersuites: "", SignatureAlgorithms: "ECDSA+SHA256",
		Groups: "X25519,prime256v1", MinProtocol: "TLSv1.2", MinProtocolDTLS: "",
	}
	if !reflect.DeepEqual(settings, want) {
		t.Errorf("got  %+v\nwant %+v", settings, want)
	}
	if len(options) != 6 {
		t.Errorf("want the options of 6 fields, got %v", options)
	}
	var wantMin = []SettingsOption{{"", "None", false}, {"TLSv1.2", "TLSv1.2", true}, {"TLSv1.3", "TLSv1.3", false}}
	if !reflect.DeepEqual(options["MinProtocol"], wantMin) {
		t.Errorf("MinProtocol options in API order: got %+v, want %+v", options["MinProtocol"], wantMin)
	}
	if len(options["CipherString"]) != 3 || options["CipherString"][0].Key != "DHE-PSK-AES128-CBC-SHA" ||
		options["CipherString"][0].Value != "TLS_DHE_PSK_WITH_AES_128_CBC_SHA" {
		t.Errorf("CipherString options: %+v", options["CipherString"])
	}

	// the JSON form uses the API names and leaves the options out
	var encoded, _ = json.Marshal(settings)
	if !strings.Contains(string(encoded), `"MinProtocol_DTLS":""`) || !strings.Contains(string(encoded), `"groups":"X25519,prime256v1"`) ||
		strings.Contains(string(encoded), "Options") {
		t.Errorf("unexpected JSON %s", encoded)
	}
}

func TestSettingsGetErrors(t *testing.T) {
	for _, answer := range []string{`{}`, ``, `[]`} {
		var api, _ = settingsTestServer(t, map[string]string{"/api/trust/settings/get": answer})
		if settings, err := api.SettingsGet(); err == nil {
			t.Errorf("answer %q: want an error, got %+v", answer, settings)
		}
	}
}

func TestSettingsSetSendsOnlyGivenFields(t *testing.T) {
	var api, requests = settingsTestServer(t, map[string]string{"/api/trust/settings/set": `{"result":"saved"}`})
	var yes, none, groups = "1", "", "X25519,prime256v1"
	if err := api.SettingsSet(SettingsFields{FetchCrls: &yes, MinProtocol: &none, Groups: &groups}); err != nil {
		t.Fatal(err)
	}
	var request = (*requests)[0]
	if request.Method != "POST" || request.Path != "/api/trust/settings/set" ||
		strings.TrimSpace(request.Body) != `{"trust":{"fetch_crls":"1","groups":"X25519,prime256v1","MinProtocol":""}}` {
		t.Errorf("unexpected request %+v", request)
	}
}

func TestSettingsSetValidation(t *testing.T) {
	var api, _ = settingsTestServer(t, map[string]string{
		"/api/trust/settings/set": `{"result":"failed","validations":{"trust.MinProtocol":"Option not in list."}}`,
	})
	var value = "SSLv3"
	var err = api.SettingsSet(SettingsFields{MinProtocol: &value})
	if _, isValidation := err.(*coreapi.ValidationError); !isValidation || !strings.Contains(err.Error(), "Option not in list") {
		t.Errorf("want the validation error, got %v", err)
	}
}

func TestSettingsReconfigure(t *testing.T) {
	var api, requests = settingsTestServer(t, map[string]string{"/api/trust/settings/reconfigure": `{"status":"ok"}`})
	if err := api.SettingsReconfigure(); err != nil {
		t.Fatal(err)
	}
	if (*requests)[0].Method != "POST" || strings.TrimSpace((*requests)[0].Body) != `{}` {
		t.Errorf("want a POST with {}, got %+v", (*requests)[0])
	}

	for _, answer := range []string{`{"status":"failed"}`, ``} {
		var failing, _ = settingsTestServer(t, map[string]string{"/api/trust/settings/reconfigure": answer})
		if err := failing.SettingsReconfigure(); err == nil {
			t.Errorf("answer %q: want an error", answer)
		}
	}
}
