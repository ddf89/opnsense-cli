package unbound

import (
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

// newRecordTestApi answers "METHOD /path" from answers and records "METHOD /path body"
func newRecordTestApi(t *testing.T, answers map[string]string) (*UnboundApi, *[]string) {
	t.Helper()
	var requests []string
	var api = newTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		requests = append(requests, strings.TrimSpace(r.Method+" "+r.URL.Path+" "+string(body)))
		var answer, found = answers[r.Method+" "+r.URL.Path]
		if !found {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, answer)
	})
	return api, &requests
}

const (
	forwardSearch = "GET /api/unbound/settings/search_forward"
	dotSearch     = "GET /api/unbound/settings/search_dot"
)

func TestForwardListMergesBothTypes(t *testing.T) {
	var api, _ = newRecordTestApi(t, map[string]string{
		forwardSearch: `{"rows":[{"uuid":"f1","type":"forward","server":"192.0.2.53"}]}`,
		dotSearch:     `{"rows":[{"uuid":"d1","type":"dot","server":"192.0.2.54","verify":"dns.example"}]}`,
	})
	var forwards, err = api.ForwardList("")
	if err != nil || len(forwards) != 2 || forwards[0].Uuid != "f1" || forwards[1].Verify != "dns.example" {
		t.Errorf("ForwardList: %+v, %v", forwards, err)
	}
	if forward, err := api.ForwardGet("d1"); err != nil || forward.Type != "dot" {
		t.Errorf("ForwardGet d1: %+v, %v", forward, err)
	}
	if _, err := api.ForwardGet("x"); !coreapi.IsNotFound(err) {
		t.Errorf("ForwardGet x: want not found, got %v", err)
	}
}

func TestForwardCreateUsesTheEndpointOfTheType(t *testing.T) {
	var api, requests = newRecordTestApi(t, map[string]string{
		"POST /api/unbound/settings/add_dot":     `{"result":"saved","uuid":"d1"}`,
		"POST /api/unbound/settings/add_forward": `{"result":"saved","uuid":"f1"}`,
	})
	if uuid, err := api.ForwardCreate(Forward{Type: "dot", Server: "192.0.2.54", Enabled: "0"}); err != nil || uuid != "d1" {
		t.Errorf("create dot: %q, %v", uuid, err)
	}
	if uuid, err := api.ForwardCreate(Forward{Type: "forward", Server: "192.0.2.53"}); err != nil || uuid != "f1" {
		t.Errorf("create forward: %q, %v", uuid, err)
	}
	var want = []string{
		`POST /api/unbound/settings/add_dot {"dot":{"enabled":"0","server":"192.0.2.54"}}`,
		`POST /api/unbound/settings/add_forward {"dot":{"server":"192.0.2.53"}}`,
	}
	if !reflect.DeepEqual(*requests, want) {
		t.Errorf("requests:\n got  %q\n want %q", *requests, want)
	}
	if _, err := api.ForwardCreate(Forward{Type: "tls"}); err == nil {
		t.Error("want an error for an unknown type")
	}
}

func TestForwardUpdateConvertsTheType(t *testing.T) {
	var api, requests = newRecordTestApi(t, map[string]string{
		forwardSearch:                           `{"rows":[{"uuid":"f1","type":"forward"}]}`,
		dotSearch:                               `{"rows":[]}`,
		"POST /api/unbound/settings/set_dot/f1": `{"result":"saved"}`,
	})
	if err := api.ForwardUpdate("f1", "dot", Patch{"type": "dot", "port": "853"}); err != nil {
		t.Fatal(err)
	}
	if last := (*requests)[len(*requests)-1]; last != `POST /api/unbound/settings/set_dot/f1 {"dot":{"port":"853"}}` {
		t.Errorf("unexpected update %s", last)
	}
	*requests = nil
	if err := api.ForwardUpdate("0b3c6a1e-2f4d-4e5a-9b7c-8d9e0f1a2b3c", "forward", Patch{"port": "53"}); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	for _, request := range *requests {
		if !strings.HasPrefix(request, "GET ") {
			t.Errorf("an unknown uuid must not be written: %s", request)
		}
	}
}

func TestAclDefaultAction(t *testing.T) {
	var api, requests = newRecordTestApi(t, map[string]string{
		"GET /api/unbound/settings/get":  `{"unbound":{"general":{"port":"53"},"acls":{"default_action":{"allow":{"value":"Allow","selected":0},"refuse":{"value":"Refuse","selected":1}},"acl":{"a1":{"name":"x"}}}}}`,
		"POST /api/unbound/settings/set": `{"result":"saved"}`,
	})
	if action, err := api.AclDefaultAction(); err != nil || action != "refuse" {
		t.Errorf("AclDefaultAction: %q, %v", action, err)
	}
	if err := api.AclSetDefaultAction("deny"); err != nil {
		t.Fatal(err)
	}
	if last := (*requests)[len(*requests)-1]; last != `POST /api/unbound/settings/set {"unbound":{"acls":{"default_action":"deny"}}}` {
		t.Errorf("unexpected request %s", last)
	}
}

func TestSettingsGetSkipsRecordLists(t *testing.T) {
	var api, _ = newRecordTestApi(t, map[string]string{
		"GET /api/unbound/settings/get": `{"unbound":{"general":{"port":"53","active_interface":{"lan":{"value":"LAN","selected":0}}},
			"advanced":{"logverbosity":[{"value":"Level 0","selected":0},{"value":"Level 1","selected":1}]},
			"acls":{"default_action":{"allow":{"value":"Allow","selected":1}},"acl":{"a1":{"name":"x","enabled":"1"}}},
			"dnsbl":{"blocklist":{"b1":{"description":"x"}}},"forwarding":{"enabled":"0"},"dots":{"dot":[]},
			"hosts":{"host":{"h1":{"hostname":"x"}}},"aliases":{"alias":[]}}}`,
	})
	var settings, err = api.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	var want = map[string]string{"general.port": "53", "general.active_interface": "", "advanced.logverbosity": "1",
		"acls.default_action": "allow", "forwarding.enabled": "0"}
	if !reflect.DeepEqual(settings.Values, want) {
		t.Errorf("values:\n got  %v\n want %v", settings.Values, want)
	}
}

func TestSystemNameservers(t *testing.T) {
	var api, _ = newRecordTestApi(t, map[string]string{"GET /api/unbound/settings/get_nameservers": `["10.0.2.3","2001:db8::53"]`})
	if nameservers, err := api.SystemNameservers(); err != nil || !reflect.DeepEqual(nameservers, []string{"10.0.2.3", "2001:db8::53"}) {
		t.Errorf("SystemNameservers: %v, %v", nameservers, err)
	}
	api, _ = newRecordTestApi(t, map[string]string{"GET /api/unbound/settings/get_nameservers": `{"message":"Unable to run configd action"}`})
	if _, err := api.SystemNameservers(); err == nil || !strings.Contains(err.Error(), "Unable to run configd action") {
		t.Errorf("want the configd failure, got %v", err)
	}
}

func TestBlocklistAddDomain(t *testing.T) {
	var api, requests = newRecordTestApi(t, map[string]string{
		"GET /api/unbound/settings/search_dnsbl":      `{"rows":[{"uuid":"b1","description":"ads"}]}`,
		"POST /api/unbound/settings/update_blocklist": `{"status":"OK"}`,
	})
	if err := api.BlocklistAddDomain("b1", "ads.example", true); err != nil {
		t.Fatal(err)
	}
	if last := (*requests)[len(*requests)-1]; last != `POST /api/unbound/settings/update_blocklist {"domain":"ads.example","type":"allowlists","uuid":"b1"}` {
		t.Errorf("unexpected request %s", last)
	}
	if err := api.BlocklistAddDomain("b2", "ads.example", false); !coreapi.IsNotFound(err) {
		t.Errorf("unknown policy: want not found, got %v", err)
	}

	api, _ = newRecordTestApi(t, map[string]string{
		"GET /api/unbound/settings/search_dnsbl":      `{"rows":[{"uuid":"b1"}]}`,
		"POST /api/unbound/settings/update_blocklist": `{"status":"failed"}`,
	})
	if err := api.BlocklistAddDomain("b1", "ads.example", false); err == nil || !strings.Contains(err.Error(), "already") {
		t.Errorf("want the failure, got %v", err)
	}
}

func TestBlocklistTypes(t *testing.T) {
	var api, _ = newRecordTestApi(t, map[string]string{"GET /api/unbound/settings/get_dnsbl": `{"blocklist":{"enabled":"1","type":{
		"ag":{"value":"AdGuard List","optgroup":"General Blocklists","selected":0},"hgz002":{"value":"NORMAL","optgroup":"Hagezi","selected":0}}}}`})
	var types, err = api.BlocklistTypes()
	if err != nil || len(types) != 2 || types[0].Key != "ag" || types[0].Group != "General Blocklists" {
		t.Errorf("BlocklistTypes: %+v, %v", types, err)
	}
}

func TestBlocklistTest(t *testing.T) {
	var api, requests = newRecordTestApi(t, map[string]string{"POST /api/unbound/diagnostics/test_blocklist": `{"status":"OK","action":"Block","policy":{"description":"ads","source_nets":[]}}`})
	var result, err = api.BlocklistTest("ads.example", "192.0.2.1")
	if err != nil || result.Action != "Block" || result.Policy["description"] != "ads" {
		t.Errorf("BlocklistTest: %+v, %v", result, err)
	}
	if (*requests)[0] != `POST /api/unbound/diagnostics/test_blocklist {"domain":"ads.example","src":"192.0.2.1"}` {
		t.Errorf("unexpected request %s", (*requests)[0])
	}
	api, _ = newRecordTestApi(t, map[string]string{"POST /api/unbound/diagnostics/test_blocklist": `{"status":"error"}`})
	if _, err := api.BlocklistTest("ads.example", ""); err == nil {
		t.Error("want an error without loaded blocklists")
	}
}

func TestHostAliasFQDN(t *testing.T) {
	if fqdn := (HostAlias{Hostname: "www", Domain: "example.lan."}).FQDN(); fqdn != "www.example.lan" {
		t.Errorf("got %q", fqdn)
	}
	if fqdn := (HostAlias{Domain: "example.lan"}).FQDN(); fqdn != "example.lan" {
		t.Errorf("got %q", fqdn)
	}
}

func TestServiceControl(t *testing.T) {
	var api, requests = newRecordTestApi(t, map[string]string{
		"POST /api/unbound/service/start":               `{"response":"OK\n\n"}`,
		"POST /api/unbound/service/stop":                `{"response":"Execute error"}`,
		"POST /api/unbound/service/reconfigure_general": `{"status":"ok"}`,
		"POST /api/unbound/service/dnsbl":               `{"status":"OK\n\n"}`,
	})
	if err := api.ServiceStart(); err != nil {
		t.Errorf("start: %v", err)
	}
	if err := api.ServiceStop(); err == nil {
		t.Error("stop: want the configd error")
	}
	if err := api.ServiceReconfigureGeneral(); err != nil {
		t.Errorf("reconfigure general: %v", err)
	}
	if err := api.ServiceDnsbl(); err != nil {
		t.Errorf("dnsbl: %v", err)
	}
	if len(*requests) != 4 {
		t.Errorf("want 4 POSTs, got %v", *requests)
	}
}
