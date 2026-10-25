package system

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

type gatewayTestRequest struct {
	Method string
	Path   string
	Body   map[string]map[string]string
}

// gatewayTestAnswer is what the fake answers: Status 0 means 200, Body is JSON encoded
type gatewayTestAnswer struct {
	Status int
	Body   any
}

// newGatewayTestApi starts a fake OPNsense answering every request with handler, all requests are recorded
func newGatewayTestApi(t *testing.T, handler func(r gatewayTestRequest) gatewayTestAnswer) (*SystemApi, *[]gatewayTestRequest) {
	t.Helper()
	var requests []gatewayTestRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var recorded = gatewayTestRequest{Method: r.Method, Path: r.URL.Path}
		var raw, _ = io.ReadAll(r.Body)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &recorded.Body); err != nil {
				t.Errorf("invalid request body %q: %v", raw, err)
			}
		}
		requests = append(requests, recorded)
		var answer = handler(recorded)
		if answer.Status != 0 {
			w.WriteHeader(answer.Status)
		}
		_ = json.NewEncoder(w).Encode(answer.Body)
	}))
	t.Cleanup(server.Close)

	var baseUrl, _ = url.Parse(server.URL)
	return &SystemApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, &requests
}

func gatewayOk(body any) gatewayTestAnswer {
	return gatewayTestAnswer{Body: body}
}

const (
	gatewayTestUuid         = "3afca08c-7f2a-48b9-a6a6-d70f6b65c762"
	gatewayTestOverrideUuid = "9d6e1c1a-1111-4222-8333-444455556666"

	gatewayTestSearchPath = "/api/routing/settings/search_gateway"
	gatewayTestGetPath    = "/api/routing/settings/get_gateway"
	gatewayTestSetPath    = "/api/routing/settings/set_gateway/"
)

// gatewayTestDynamicRow is a generated gateway of a dynamic interface as search_gateway returns it in 26.7
const gatewayTestDynamicRow = `{"interface":"wan","weight":"1","ipprotocol":"inet","name":"WAN_DHCP","descr":"Interface WAN_DHCP Gateway",` +
	`"monitor_disable":"1","monitor_noroute":"0","gateway_interface":false,"if":"vtnet1","dynamic":true,"virtual":true,` +
	`"priority":254,"gateway":"10.0.2.2","uuid":"WAN_DHCP","disabled":false,"upstream":false,"defaultgw":true,` +
	`"interface_descr":"WAN","status":"Online","delay":"~","stddev":"~","loss":"~","label_class":"fa fa-plug text-success"}`

// gatewayTestConfiguredRow is a configured gateway as search_gateway returns it in 26.7
const gatewayTestConfiguredRow = `{"disabled":false,"name":"a8gw_probe1","descr":"probe","interface":"lan","ipprotocol":"inet",` +
	`"gateway":"192.168.1.240","defaultgw":false,"fargw":"0","monitor_disable":"1","monitor_noroute":"0","monitor_killstates":"0",` +
	`"monitor_killstates_priority":"1","monitor":"","force_down":"0","nosync":"0","priority":"255","weight":"1",` +
	`"latencylow":"","current_latencylow":"200","latencyhigh":"","current_latencyhigh":"500","losslow":"","current_losslow":"10",` +
	`"losshigh":"","current_losshigh":"20","interval":"","current_interval":"1","time_period":"","current_time_period":"60",` +
	`"loss_interval":"","current_loss_interval":"4","data_length":"","current_data_length":"1",` +
	`"uuid":"3afca08c-7f2a-48b9-a6a6-d70f6b65c762","if":"vtnet0","attribute":0,"virtual":false,"upstream":true,` +
	`"interface_descr":"LAN","status":"Online","delay":"~","stddev":"~","loss":"~","label_class":"fa fa-plug text-success"}`

// gatewayTestGetDynamic is get_gateway/WAN_DHCP in 26.7
const gatewayTestGetDynamic = `{"gateway_item":{"disabled":"0","name":"WAN_DHCP","descr":"Interface WAN_DHCP Gateway",` +
	`"interface":{"lan":{"value":"LAN","selected":0},"wan":{"value":"WAN","selected":1}},` +
	`"ipprotocol":{"inet":{"value":"IPv4","selected":1},"inet6":{"value":"IPv6","selected":0}},"gateway":"","defaultgw":"0",` +
	`"fargw":"0","monitor_disable":"1","monitor_noroute":"0","monitor_killstates":"0","monitor_killstates_priority":"0",` +
	`"monitor":"","force_down":"0","nosync":"0","priority":"254","weight":"1","latencylow":"","latencyhigh":"","losslow":"",` +
	`"losshigh":"","interval":"","time_period":"","loss_interval":"","data_length":""}}`

func gatewayTestSearch(rows ...string) any {
	var decoded = make([]json.RawMessage, len(rows))
	for i, row := range rows {
		decoded[i] = json.RawMessage(row)
	}
	return map[string]any{"rows": decoded, "rowCount": len(rows), "total": len(rows), "current": 1}
}

func gatewayTestRaw(body string) any {
	return json.RawMessage(body)
}

func TestGatewayListMixedTypes(t *testing.T) {
	var api, requests = newGatewayTestApi(t, func(r gatewayTestRequest) gatewayTestAnswer {
		return gatewayOk(gatewayTestSearch(gatewayTestDynamicRow, gatewayTestConfiguredRow))
	})

	var gateways, err = api.GatewayList()
	if err != nil || len(gateways) != 2 {
		t.Fatalf("want 2 gateways, got %+v / %v", gateways, err)
	}
	if got := (*requests)[0]; got.Method != "GET" || got.Path != gatewayTestSearchPath {
		t.Errorf("unexpected request %+v", got)
	}

	var dynamic, configured = gateways[0], gateways[1]
	if dynamic.Priority != "254" || dynamic.Uuid != "WAN_DHCP" || !dynamic.Dynamic || !dynamic.Virtual || !dynamic.Default ||
		dynamic.Upstream || dynamic.IsConfigured() || dynamic.Device != "vtnet1" || dynamic.Address != "10.0.2.2" ||
		!dynamic.MonitorDisable || dynamic.InterfaceDescription != "WAN" || dynamic.Status != "Online" {
		t.Errorf("dynamic row not decoded right: %+v", dynamic)
	}
	if configured.Priority != "255" || !configured.IsConfigured() || configured.Default || !configured.Upstream ||
		configured.Dynamic || !configured.MonitorKillStatesPriority || configured.MonitorKillStates ||
		configured.Current["latencyhigh"] != "500" || configured.Current["time_period"] != "60" || configured.LatencyHigh != "" {
		t.Errorf("configured row not decoded right: %+v", configured)
	}
	if string(configured.Raw) != gatewayTestConfiguredRow {
		t.Errorf("Raw must be the row as returned: %s", configured.Raw)
	}
}

func TestGatewayGet(t *testing.T) {
	var api, _ = newGatewayTestApi(t, func(r gatewayTestRequest) gatewayTestAnswer {
		return gatewayOk(gatewayTestSearch(gatewayTestDynamicRow, gatewayTestConfiguredRow))
	})
	for id, want := range map[string]string{gatewayTestUuid: "a8gw_probe1", "a8gw_probe1": "a8gw_probe1", "WAN_DHCP": "WAN_DHCP"} {
		if gateway, err := api.GatewayGet(id); err != nil || gateway.Name != want {
			t.Errorf("%s: want %s, got %+v / %v", id, want, gateway, err)
		}
	}
	for _, id := range []string{"wan_dhcp", "a8gw", "00000000-0000-4000-8000-000000000000"} {
		if _, err := api.GatewayGet(id); !coreapi.IsNotFound(err) {
			t.Errorf("%s: want NotFoundError, got %v", id, err)
		}
	}
}

func TestGatewayCreate(t *testing.T) {
	var api, requests = newGatewayTestApi(t, func(r gatewayTestRequest) gatewayTestAnswer {
		return gatewayOk(map[string]string{"result": "saved", "uuid": gatewayTestUuid})
	})
	var fields = GatewayFields{"name": "a8gw_x", "interface": "lan", "gateway": "192.168.1.241", "descr": "d", "priority": "10"}
	var uuid, err = api.GatewayCreate(fields)
	if err != nil || uuid != gatewayTestUuid {
		t.Fatalf("want %s, got %s / %v", gatewayTestUuid, uuid, err)
	}
	var add = (*requests)[0]
	if add.Method != "POST" || add.Path != "/api/routing/settings/add_gateway" || len(add.Body["gateway_item"]) != 5 ||
		add.Body["gateway_item"]["gateway"] != "192.168.1.241" {
		t.Errorf("unexpected request %+v", add)
	}

	for _, invalid := range []GatewayFields{
		{"interface": "lan"},
		{"name": "a8gw_x"},
		{"name": "bad name", "interface": "lan"},
		{"name": strings.Repeat("a", 33), "interface": "lan"},
		{"name": "a8gw_x", "interface": "lan", "gateway": "fe80::1"},
		{"name": "a8gw_x", "interface": "lan", "ipprotocol": "inet6", "gateway": "192.168.1.1"},
		{"name": "a8gw_x", "interface": "lan", "ipprotocol": "ipv4"},
		{"name": "a8gw_x", "interface": "lan", "monitor": "dynamic"},
		{"name": "a8gw_x", "interface": "lan", "weight": "11"},
		{"name": "a8gw_x", "interface": "lan", "priority": ""},
		{"name": "a8gw_x", "interface": "lan", "losslow": "100"},
		{"name": "a8gw_x", "interface": "lan", "latencylow": "500", "latencyhigh": "100"},
		{"name": "a8gw_x", "interface": "lan", "losslow": "20", "losshigh": "20"},
		{"name": "a8gw_x", "interface": "lan", "defaultgw": "yes"},
		{"name": "a8gw_x", "interface": "lan", "descr": "a\nb"},
		{"name": "a8gw_x", "interface": "lan", "unknown": "1"},
	} {
		if _, err := api.GatewayCreate(invalid); err == nil {
			t.Errorf("%v: want a validation error", invalid)
		}
	}
	if len(*requests) != 1 {
		t.Errorf("invalid input must not be sent, got %d requests", len(*requests))
	}

	for _, valid := range []GatewayFields{
		{"name": "a8gw-X_1", "interface": "opt1", "gateway": "dynamic"},
		{"name": "a8gw_x", "interface": "lan", "ipprotocol": "inet6", "gateway": "fe80::1", "monitor": "2001:db8::1"},
		{"name": "a8gw_x", "interface": "lan", "latencylow": "100", "latencyhigh": "", "data_length": "0", "priority": "0"},
	} {
		if err := GatewayValidateFields(valid, "inet"); err != nil {
			t.Errorf("%v: unexpected error %v", valid, err)
		}
	}
}

func TestGatewayUpdateConfiguredPartially(t *testing.T) {
	var answer = gatewayOk(map[string]string{"result": "saved"})
	var api, requests = newGatewayTestApi(t, func(r gatewayTestRequest) gatewayTestAnswer {
		if r.Path == gatewayTestSearchPath {
			return gatewayOk(gatewayTestSearch(gatewayTestDynamicRow, gatewayTestConfiguredRow))
		}
		return answer
	})

	var uuid, err = api.GatewayUpdate("a8gw_probe1", GatewayFields{"priority": "100", "name": "a8gw_probe1"})
	if err != nil || uuid != gatewayTestUuid {
		t.Fatalf("want %s, got %s / %v", gatewayTestUuid, uuid, err)
	}
	var set = (*requests)[1]
	if set.Method != "POST" || set.Path != gatewayTestSetPath+gatewayTestUuid {
		t.Errorf("unexpected request %s %s", set.Method, set.Path)
	}
	if sent := set.Body["gateway_item"]; len(sent) != 2 || sent["priority"] != "100" {
		t.Errorf("want only the given fields to be sent, got %v", sent)
	}

	// deleted between the existence check and the write: bare failure
	answer = gatewayOk(map[string]string{"result": "failed"})
	if _, err := api.GatewayUpdate(gatewayTestUuid, GatewayFields{"descr": "x"}); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	answer = gatewayOk(map[string]any{"result": "failed", "validations": map[string]any{"gateway_item.gateway": "This gateway IP address already exists."}})
	if _, err := api.GatewayUpdate(gatewayTestUuid, GatewayFields{"gateway": "192.168.1.1"}); err == nil ||
		!strings.Contains(err.Error(), "gateway_item.gateway: This gateway IP address already exists.") {
		t.Errorf("want the validation message, got %v", err)
	}
}

func TestGatewayUpdateRefusals(t *testing.T) {
	var api, requests = newGatewayTestApi(t, func(r gatewayTestRequest) gatewayTestAnswer {
		return gatewayOk(gatewayTestSearch(gatewayTestDynamicRow, gatewayTestConfiguredRow))
	})

	if _, err := api.GatewayUpdate(gatewayTestUuid, GatewayFields{"name": "other"}); err == nil || !strings.Contains(err.Error(), "can not be renamed") {
		t.Errorf("want rename error, got %v", err)
	}
	if _, err := api.GatewayUpdate(gatewayTestUuid, GatewayFields{"gateway": "fe80::1"}); err == nil || !strings.Contains(err.Error(), "IPv4") {
		t.Errorf("want address family error, got %v", err)
	}
	if _, err := api.GatewayUpdate("00000000-0000-4000-8000-000000000000", GatewayFields{"descr": "x"}); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if _, err := api.GatewayUpdate(gatewayTestUuid, GatewayFields{}); err == nil {
		t.Errorf("want an error for no fields")
	}
	for _, request := range *requests {
		if request.Method != "GET" {
			t.Errorf("nothing must be written: %s %s", request.Method, request.Path)
		}
	}
}

// overriding a generated gateway sends its complete record merged with the change to set_gateway/<name>
func TestGatewayUpdateOverridesDynamic(t *testing.T) {
	var overridden = false
	var api, requests = newGatewayTestApi(t, func(r gatewayTestRequest) gatewayTestAnswer {
		switch {
		case r.Path == gatewayTestSearchPath && overridden:
			var row = strings.Replace(gatewayTestDynamicRow, `"uuid":"WAN_DHCP"`, `"uuid":"`+gatewayTestOverrideUuid+`"`, 1)
			return gatewayOk(gatewayTestSearch(row, gatewayTestConfiguredRow))
		case r.Path == gatewayTestSearchPath:
			return gatewayOk(gatewayTestSearch(gatewayTestDynamicRow, gatewayTestConfiguredRow))
		case r.Path == gatewayTestGetPath+"/WAN_DHCP":
			return gatewayOk(gatewayTestRaw(gatewayTestGetDynamic))
		case r.Path == gatewayTestSetPath+"WAN_DHCP":
			overridden = true
			return gatewayOk(map[string]string{"result": "saved"})
		}
		return gatewayTestAnswer{Status: 404, Body: map[string]string{"errorMessage": "Endpoint not found"}}
	})

	var uuid, err = api.GatewayUpdate("WAN_DHCP", GatewayFields{"priority": "10", "descr": "mine"})
	if err != nil || uuid != gatewayTestOverrideUuid {
		t.Fatalf("want the new uuid %s, got %q / %v", gatewayTestOverrideUuid, uuid, err)
	}
	var set = (*requests)[2]
	if set.Method != "POST" || set.Path != gatewayTestSetPath+"WAN_DHCP" {
		t.Fatalf("unexpected request %s %s", set.Method, set.Path)
	}
	var sent = set.Body["gateway_item"]
	if len(sent) != len(GatewayFieldNames) || sent["name"] != "WAN_DHCP" || sent["interface"] != "wan" ||
		sent["ipprotocol"] != "inet" || sent["gateway"] != "" || sent["priority"] != "10" || sent["descr"] != "mine" ||
		sent["monitor_disable"] != "1" || sent["weight"] != "1" {
		t.Errorf("want the complete merged record, got %v", sent)
	}
}

func TestGatewaySetEnabled(t *testing.T) {
	var toggleAnswer = map[string]any{"result": "Disabled", "changed": true}
	var api, requests = newGatewayTestApi(t, func(r gatewayTestRequest) gatewayTestAnswer {
		switch {
		case r.Path == gatewayTestSearchPath:
			return gatewayOk(gatewayTestSearch(gatewayTestDynamicRow, gatewayTestConfiguredRow))
		case r.Path == gatewayTestGetPath+"/WAN_DHCP":
			return gatewayOk(gatewayTestRaw(gatewayTestGetDynamic))
		case strings.HasPrefix(r.Path, "/api/routing/settings/toggle_gateway/"):
			return gatewayOk(toggleAnswer)
		}
		return gatewayOk(map[string]string{"result": "saved"})
	})

	var changed, err = api.GatewaySetEnabled("a8gw_probe1", false)
	if err != nil || !changed {
		t.Fatalf("want changed, got %v / %v", changed, err)
	}
	if got := (*requests)[1]; got.Method != "POST" || got.Path != "/api/routing/settings/toggle_gateway/"+gatewayTestUuid+"/0" {
		t.Errorf("unexpected request %s %s", got.Method, got.Path)
	}
	toggleAnswer = map[string]any{"result": "Enabled", "changed": false}
	if changed, err = api.GatewaySetEnabled(gatewayTestUuid, true); err != nil || changed {
		t.Errorf("want unchanged, got %v / %v", changed, err)
	}
	toggleAnswer = map[string]any{"result": "failed"}
	if _, err = api.GatewaySetEnabled(gatewayTestUuid, true); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}

	// a generated gateway which is enabled already: nothing to do
	*requests = nil
	if changed, err = api.GatewaySetEnabled("WAN_DHCP", true); err != nil || changed || len(*requests) != 1 {
		t.Errorf("want unchanged without writes, got %v / %v / %v", changed, err, *requests)
	}
	// disabling it stores an override (the final lookup of the new uuid finds none in this fake)
	*requests = nil
	_, err = api.GatewaySetEnabled("WAN_DHCP", false)
	if err == nil || !strings.Contains(err.Error(), "override of WAN_DHCP was stored") {
		t.Errorf("want the missing override to be reported, got %v", err)
	}
	if set := (*requests)[2]; set.Path != gatewayTestSetPath+"WAN_DHCP" || set.Body["gateway_item"]["disabled"] != "1" ||
		set.Body["gateway_item"]["name"] != "WAN_DHCP" {
		t.Errorf("want an override with disabled=1, got %+v", set)
	}
}

func TestGatewayRemove(t *testing.T) {
	var api, requests = newGatewayTestApi(t, func(r gatewayTestRequest) gatewayTestAnswer {
		switch r.Path {
		case "/api/routing/settings/del_gateway/" + gatewayTestUuid:
			return gatewayOk(map[string]string{"result": "deleted"})
		case "/api/routing/settings/del_gateway/" + gatewayTestOverrideUuid:
			return gatewayTestAnswer{Status: 500, Body: map[string]string{
				"errorMessage": "Gateway a8gw cannot be deleted because it is in use on Gateway Group(s) 'grp'", "errorTitle": ""}}
		}
		return gatewayOk(map[string]string{"result": "failed"})
	})

	if err := api.GatewayRemove(gatewayTestUuid); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got := (*requests)[0]; got.Method != "POST" || got.Path != "/api/routing/settings/del_gateway/"+gatewayTestUuid {
		t.Errorf("unexpected request %s %s", got.Method, got.Path)
	}
	if err := api.GatewayRemove("00000000-0000-4000-8000-000000000000"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	var err = api.GatewayRemove(gatewayTestOverrideUuid)
	if err == nil || err.Error() != "Gateway a8gw cannot be deleted because it is in use on Gateway Group(s) 'grp'" {
		t.Errorf("want the in use message, got %v", err)
	}
	if err := api.GatewayRemove("WAN_DHCP"); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Errorf("want refusal for a generated gateway, got %v", err)
	}
	if len(*requests) != 3 {
		t.Errorf("removing a generated gateway must not be sent, got %d requests", len(*requests))
	}
}

func TestGatewayRecordAndInterfaces(t *testing.T) {
	var api, requests = newGatewayTestApi(t, func(r gatewayTestRequest) gatewayTestAnswer {
		return gatewayOk(gatewayTestRaw(gatewayTestGetDynamic))
	})
	var record, err = api.GatewayRecord("WAN_DHCP")
	if err != nil || record["interface"] != "wan" || record["ipprotocol"] != "inet" || record["priority"] != "254" || len(record) != len(GatewayFieldNames) {
		t.Errorf("unexpected record %v / %v", record, err)
	}
	var interfaces, listErr = api.GatewayInterfaces()
	if listErr != nil || len(interfaces) != 2 || interfaces[0] != (GatewayInterface{"lan", "LAN"}) || interfaces[1] != (GatewayInterface{"wan", "WAN"}) {
		t.Errorf("unexpected interfaces %v / %v", interfaces, listErr)
	}
	if (*requests)[0].Path != gatewayTestGetPath+"/WAN_DHCP" || (*requests)[1].Path != gatewayTestGetPath {
		t.Errorf("unexpected requests %+v", *requests)
	}
}

func TestGatewayReconfigure(t *testing.T) {
	var status = "ok"
	var api, requests = newGatewayTestApi(t, func(r gatewayTestRequest) gatewayTestAnswer {
		return gatewayOk(map[string]string{"status": status})
	})
	if err := api.GatewayReconfigure(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got := (*requests)[0]; got.Method != "POST" || got.Path != "/api/routing/settings/reconfigure" {
		t.Errorf("unexpected request %s %s", got.Method, got.Path)
	}
	status = "failed"
	if err := api.GatewayReconfigure(); err == nil {
		t.Errorf("want an error for status failed")
	}
}

func TestGatewayStatuses(t *testing.T) {
	var answer = gatewayTestRaw(`{"items":[{"name":"WAN_DHCP","address":"10.0.2.2","status":"loss","loss":"12.0 %","delay":"1.2 ms",` +
		`"stddev":"0.3 ms","monitor":"10.0.2.2","status_translated":"Packetloss"}],"status":"ok"}`)
	var api, requests = newGatewayTestApi(t, func(r gatewayTestRequest) gatewayTestAnswer {
		return gatewayOk(answer)
	})
	var statuses, err = api.GatewayStatuses()
	if err != nil || len(statuses) != 1 {
		t.Fatalf("want 1 status, got %+v / %v", statuses, err)
	}
	var status = statuses[0]
	if status.Name != "WAN_DHCP" || status.Loss != "12.0 %" || status.Delay != "1.2 ms" || status.StdDev != "0.3 ms" ||
		status.Status != "loss" || status.StatusTranslated != "Packetloss" || !strings.HasPrefix(string(status.Raw), `{"name":"WAN_DHCP"`) {
		t.Errorf("unexpected status %+v", status)
	}
	if got := (*requests)[0]; got.Method != "GET" || got.Path != "/api/routes/gateway/status" {
		t.Errorf("unexpected request %s %s", got.Method, got.Path)
	}

	answer = map[string]any{"items": []any{}, "status": "failed"}
	if statuses, err = api.GatewayStatuses(); err != nil || len(statuses) != 0 {
		t.Errorf("want an empty list, got %v / %v", statuses, err)
	}
	var api2, _ = newGatewayTestApi(t, func(r gatewayTestRequest) gatewayTestAnswer {
		return gatewayTestAnswer{Status: 403, Body: map[string]any{"status": 403, "message": "Forbidden"}}
	})
	var httpErr *coreapi.HttpError
	if _, err = api2.GatewayStatuses(); !errors.As(err, &httpErr) {
		t.Errorf("want HttpError, got %v", err)
	}
}
