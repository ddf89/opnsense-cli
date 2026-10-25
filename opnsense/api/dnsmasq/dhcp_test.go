package dnsmasq

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

// newDhcpTestApi answers "METHOD /path" from answers and records the request bodies
func newDhcpTestApi(t *testing.T, answers map[string]string) (*DnsmasqApi, *[]string) {
	t.Helper()
	var requests []string
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		requests = append(requests, strings.TrimSpace(r.Method+" "+r.URL.Path+" "+string(body)))
		var answer, found = answers[r.Method+" "+r.URL.Path]
		if !found {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &DnsmasqApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, &requests
}

func TestRangeCreateSendsOnlyGivenFields(t *testing.T) {
	var api, requests = newDhcpTestApi(t, map[string]string{"POST /api/dnsmasq/settings/add_range": `{"result":"saved","uuid":"r1"}`})
	var uuid, err = api.RangeCreate(Range{StartAddr: "192.0.2.10", EndAddr: "192.0.2.20", SetTag: "t1"})
	if err != nil || uuid != "r1" {
		t.Fatalf("RangeCreate: %q, %v", uuid, err)
	}
	var want = `POST /api/dnsmasq/settings/add_range {"range":{"set_tag":"t1","start_addr":"192.0.2.10","end_addr":"192.0.2.20"}}`
	if (*requests)[0] != want {
		t.Errorf("got  %s\nwant %s", (*requests)[0], want)
	}
}

func TestOptionUpdateUnknownUuid(t *testing.T) {
	var api, requests = newDhcpTestApi(t, map[string]string{"GET /api/dnsmasq/settings/search_option": `{"rows":[{"uuid":"o1"}]}`})
	if err := api.OptionUpdate("0b3c6a1e-2f4d-4e5a-9b7c-8d9e0f1a2b3c", Patch{"value": "x"}); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if len(*requests) != 1 {
		t.Errorf("only the existence check may be sent: %v", *requests)
	}
}

func TestTagGetByName(t *testing.T) {
	var api, _ = newDhcpTestApi(t, map[string]string{"GET /api/dnsmasq/settings/search_tag": `{"rows":[{"uuid":"t1","tag":"Lab"},{"uuid":"t2","tag":"lab2"}]}`})
	var tag, err = api.TagGetByName("lab")
	if err != nil || tag.Uuid != "t1" {
		t.Errorf("TagGetByName lab: %+v, %v", tag, err)
	}
	if _, err := api.TagGetByName("la"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found for a prefix, got %v", err)
	}
}

func TestOptionCodes(t *testing.T) {
	var api, _ = newDhcpTestApi(t, map[string]string{"GET /api/dnsmasq/settings/get_option": `{"option":{
		"type":{"set":{"value":"Set","selected":1}},
		"option":{"":{"value":"None","selected":1},"6":{"optgroup":"Common","value":"dns-server [6]","selected":0},"3":{"optgroup":"Common","value":"router [3]","selected":0}},
		"option6":{"":{"value":"None","selected":1},"23":{"optgroup":"Common","value":"dns-server [23]","selected":0}}}}`})
	var codes, err = api.OptionCodes(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 2 || codes[0].Key != "3" || codes[1].Value != "dns-server [6]" || codes[1].Group != "Common" {
		t.Errorf("unexpected codes %+v", codes)
	}
	codes, err = api.OptionCodes(true)
	if err != nil || len(codes) != 1 || codes[0].Key != "23" {
		t.Errorf("unexpected v6 codes %+v, %v", codes, err)
	}
}

func TestDhcpInterfaces(t *testing.T) {
	var api, _ = newDhcpTestApi(t, map[string]string{"GET /api/dnsmasq/settings/get_tag_list": `{"tags":{"items":[]},"interfaces":{"items":[{"value":"lan","label":"LAN"},{"value":"opt1","label":"DMZ"}]}}`})
	var interfaces, err = api.DhcpInterfaces()
	if err != nil || !reflect.DeepEqual(interfaces, []Interface{{"lan", "LAN"}, {"opt1", "DMZ"}}) {
		t.Errorf("DhcpInterfaces: %+v, %v", interfaces, err)
	}
}

func TestSettingsGetSkipsRecordLists(t *testing.T) {
	var api, _ = newDhcpTestApi(t, map[string]string{"GET /api/dnsmasq/settings/get": `{"dnsmasq":{"enable":"1","port":"53053",
		"interface":{"lan":{"value":"LAN","selected":1}},"dhcp":{"domain":"","%domain":"internal","fqdn":"1"},
		"hosts":{"h1":{"host":"a","ip":"10.0.0.1"}},"dhcp_ranges":{"r1":{"start_addr":"10.0.0.1","interface":{"lan":{"value":"LAN","selected":1}}}},
		"dhcp_tags":[],"domainoverrides":[],"dhcp_options":[],"dhcp_boot":[]}}`})
	var settings, err = api.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	var want = map[string]string{"enable": "1", "port": "53053", "interface": "lan", "dhcp.domain": "", "dhcp.fqdn": "1"}
	if !reflect.DeepEqual(settings.Values, want) {
		t.Errorf("values %v, want %v", settings.Values, want)
	}
}

func TestSettingsSet(t *testing.T) {
	var api, requests = newDhcpTestApi(t, map[string]string{"POST /api/dnsmasq/settings/set": `{"result":"saved"}`})
	if err := api.SettingsSet(Patch{"dhcp.domain": "lan.example"}); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	var _, raw, _ = strings.Cut((*requests)[0], "set ")
	if err := json.Unmarshal([]byte(raw), &body); err != nil || !reflect.DeepEqual(body, map[string]any{"dnsmasq": map[string]any{"dhcp": map[string]any{"domain": "lan.example"}}}) {
		t.Errorf("unexpected request %s", (*requests)[0])
	}
}
