package hostdiscovery

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
	Body   string
}

func newTestApi(t *testing.T, answers map[string]string) (*HostDiscoveryApi, *[]testRequest) {
	t.Helper()
	var requests []testRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		requests = append(requests, testRequest{Method: r.Method, Path: r.URL.Path, Body: string(body)})
		var answer, found = answers[r.Method+" "+r.URL.Path]
		if !found {
			return // empty 200 like OPNsense
		}
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &HostDiscoveryApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, &requests
}

const settingsTestGet = `{"hostdiscovery":{"general":{"enabled":"1","promisc":"0","verbose":"1",` +
	`"skip_nets":{"10.99.0.0/16":{"value":"10.99.0.0/16","selected":1}},"expire4_interval":"7200","expire6_interval":"",` +
	`"interface":{"lan":{"value":"LAN","selected":1},"wan":{"value":"WAN","selected":0},"opt1":{"value":"DMZ","selected":1}}}}}`

func TestSettingsGet(t *testing.T) {
	var api, _ = newTestApi(t, map[string]string{"GET /api/hostdiscovery/settings/get": settingsTestGet})
	var settings, err = api.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	var want = Settings{Enabled: "1", Promisc: "0", Verbose: "1", SkipNets: "10.99.0.0/16", Expire4Interval: "7200",
		Interfaces: "lan,opt1", InterfaceOptions: []InterfaceOption{{"lan", "LAN", true}, {"wan", "WAN", false}, {"opt1", "DMZ", true}}}
	if !reflect.DeepEqual(settings, want) {
		t.Errorf("got  %+v\nwant %+v", settings, want)
	}

	// the 26.7 defaults: an empty skip_nets map and nothing selected
	api, _ = newTestApi(t, map[string]string{"GET /api/hostdiscovery/settings/get": `{"hostdiscovery":{"general":{"enabled":"1",` +
		`"skip_nets":{"":{"value":"","selected":1}},"interface":[]}}}`})
	if settings, err = api.SettingsGet(); err != nil || settings.SkipNets != "" || settings.Interfaces != "" || len(settings.InterfaceOptions) != 0 {
		t.Errorf("defaults: %+v / %v", settings, err)
	}

	api, _ = newTestApi(t, map[string]string{"GET /api/hostdiscovery/settings/get": `{"other":{}}`})
	if _, err := api.SettingsGet(); err == nil {
		t.Error("want an error without a general section")
	}
}

func TestSettingsSet(t *testing.T) {
	var api, requests = newTestApi(t, map[string]string{"POST /api/hostdiscovery/settings/set": `{"result":"saved"}`})
	var interfaces, expire = "lan", ""
	if err := api.SettingsSet(SettingsFields{Interfaces: &interfaces, Expire4Interval: &expire}); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	_ = json.Unmarshal([]byte((*requests)[0].Body), &body)
	var want = map[string]any{"hostdiscovery": map[string]any{"general": map[string]any{"interface": "lan", "expire4_interval": ""}}}
	if !reflect.DeepEqual(body, want) {
		t.Errorf("body %s", (*requests)[0].Body)
	}

	api, _ = newTestApi(t, map[string]string{"POST /api/hostdiscovery/settings/set": `{"result":"failed","validations":` +
		`{"hostdiscovery.general.interface":"Option [nosuch0] not in list."}}`})
	if err := api.SettingsSet(SettingsFields{Interfaces: &interfaces}); err == nil || !strings.Contains(err.Error(), "not in list") {
		t.Errorf("want the validation, got %v", err)
	}
}

func TestHostListAndService(t *testing.T) {
	var api, requests = newTestApi(t, map[string]string{
		"GET /api/hostdiscovery/service/search": `{"total":1,"rowCount":1,"current":1,"rows":[{"source":"arp-ndp",` +
			`"interface_name":"LAN","ether_address":"52:54:00:12:34:56","ip_address":"192.168.1.1","organization_name":"",` +
			`"first_seen":"","last_seen":""}]}`,
		"GET /api/hostdiscovery/service/status":       `{"status":"stopped","widget":{}}`,
		"POST /api/hostdiscovery/service/reconfigure": `{"status":"ok"}`,
		"POST /api/hostdiscovery/service/start":       `{"response":"OK"}`,
		"POST /api/hostdiscovery/service/stop":        `{"response":"Execute error"}`,
	})
	var hosts, err = api.HostList()
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0] != (Host{Source: "arp-ndp", Interface: "LAN", MAC: "52:54:00:12:34:56", IP: "192.168.1.1"}) {
		t.Errorf("unexpected %+v", hosts)
	}
	if status, err := api.ServiceStatus(); err != nil || status != "stopped" {
		t.Errorf("status %q / %v", status, err)
	}
	if err := api.ServiceReconfigure(); err != nil {
		t.Error(err)
	}
	if err := api.ServiceStart(); err != nil {
		t.Error(err)
	}
	if err := api.ServiceStop(); err == nil {
		t.Error("want an error for Execute error")
	}
	if err := api.ServiceRestart(); err == nil {
		t.Error("want an error for an empty answer")
	}
	for _, request := range *requests {
		if strings.Contains(request.Path, "/service/") && !strings.HasSuffix(request.Path, "/search") &&
			!strings.HasSuffix(request.Path, "/status") && request.Method != "POST" {
			t.Errorf("actions must be POSTed: %+v", request)
		}
	}
}
