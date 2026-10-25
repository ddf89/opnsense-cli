package interfaces

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

type testRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   map[string]any
}

// newTestApi starts a fake OPNsense answering with handler and recording the requests
func newTestApi(t *testing.T, handler func(r testRequest) (int, string)) (*InterfacesApi, *[]testRequest) {
	t.Helper()
	var requests []testRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var recorded = testRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query()}
		var raw, _ = io.ReadAll(r.Body)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &recorded.Body); err != nil {
				t.Errorf("invalid request body %q: %v", raw, err)
			}
		}
		requests = append(requests, recorded)
		var status, body = handler(recorded)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &InterfacesApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, &requests
}

const testVlanUuid = "c39ae86f-2284-43b1-86c6-a29b168114ef"

// testVlanSearch is a vlan_settings/search_item answer of OPNsense 26.7: an unassigned VLAN and an assigned QinQ
const testVlanSearch = `{"rows":[` +
	`{"uuid":"c39ae86f-2284-43b1-86c6-a29b168114ef","if":"vtnet0","%if":"vtnet0 (52:54:00:12:34:56) [LAN]","tag":"4091",` +
	`"pcp":"3","%pcp":"Critical Applications (3)","proto":"","descr":"guests","vlanif":"vlan01"},` +
	`{"uuid":"7a1d1b6e-0c55-4d4e-9b0c-4f6f2b8e2b11","if":"vlan01","%if":"vlan01 (Tag: 4091, Parent: vtnet0)","tag":"7",` +
	`"pcp":"0","%pcp":"Best Effort (0, default)","proto":"802.1ad","descr":"","vlanif":"qinq01 [OPT2]"}` +
	`],"rowCount":2,"total":2,"current":1}`

// testVlanGet is get_item without uuid: the defaults and the parent options
const testVlanGet = `{"vlan":{"if":{"vtnet0":{"value":"vtnet0 (52:54:00:12:34:56) [LAN]","selected":0},` +
	`"vtnet1":{"value":"vtnet1 (52:54:00:12:34:57) [WAN]","selected":0}},"tag":"",` +
	`"pcp":{"1":{"value":"Background (1, lowest)","selected":0},"0":{"value":"Best Effort (0, default)","selected":1}},` +
	`"proto":{"":{"value":"Automatic","selected":1},"802.1q":{"value":"802.1q","selected":0}},"descr":"","vlanif":""}}`

func testHandler(mutation *string) func(r testRequest) (int, string) {
	return func(r testRequest) (int, string) {
		switch {
		case strings.HasSuffix(r.Path, "/vlan_settings/search_item"):
			return 200, testVlanSearch
		case strings.HasSuffix(r.Path, "/vlan_settings/get_item"):
			return 200, testVlanGet
		case strings.HasPrefix(*mutation, "500 "):
			return 500, strings.TrimPrefix(*mutation, "500 ")
		}
		return 200, *mutation
	}
}

func TestItemSearchAndDevice(t *testing.T) {
	var api, requests = newTestApi(t, testHandler(new(string)))
	var items, err = api.Search(Vlans, "guest")
	if err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Method != "GET" || got.Path != "/api/interfaces/vlan_settings/search_item" || got.Query.Get("searchPhrase") != "guest" {
		t.Errorf("unexpected request %+v", got)
	}
	if len(items) != 2 || items[0].Uuid != testVlanUuid || items[0].Get("tag") != "4091" || items[0].Display["if"] != "vtnet0 (52:54:00:12:34:56) [LAN]" {
		t.Fatalf("unexpected items %+v", items)
	}
	if items[0].Has("uuid") || !items[0].Has("proto") || items[0].Has("noclamp") {
		t.Errorf("Has: %v", items[0].Fields)
	}
	// the assigned marker of the search is not part of the device name
	if got := []string{Vlans.Device(items[0]), Vlans.Device(items[1])}; !reflect.DeepEqual(got, []string{"vlan01", "qinq01"}) {
		t.Errorf("devices %q", got)
	}
	var loopback, vip Item
	_ = json.Unmarshal([]byte(`{"uuid":"u","deviceId":"3","description":"x"}`), &loopback)
	_ = json.Unmarshal([]byte(`{"uuid":"v","subnet":"192.0.2.1","subnet_bits":"32"}`), &vip)
	if Loopbacks.Device(loopback) != "lo3" || Vxlans.Device(loopback) != "vxlan3" || Vips.Device(vip) != "" || Vips.HasDevice() || !Gifs.HasDevice() {
		t.Errorf("device names: %q %q", Loopbacks.Device(loopback), Vxlans.Device(loopback))
	}
	if VipNetwork(vip) != "192.0.2.1/32" || VipNetwork(loopback) != "" {
		t.Errorf("VipNetwork %q", VipNetwork(vip))
	}

	if item, err := api.Get(Vlans, testVlanUuid); err != nil || item.Get("descr") != "guests" {
		t.Errorf("Get: %+v / %v", item, err)
	}
	if _, err := api.Get(Vlans, "00000000-0000-4000-8000-000000000000"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if _, err := api.Get(Vlans, ""); err == nil {
		t.Error("want an error for an empty uuid")
	}
}

func TestItemValues(t *testing.T) {
	var item Item
	if err := json.Unmarshal([]byte(`{"uuid":"u","list":["a","b"],"flag":true,"off":false,"number":5,"none":null,"%list":"A, B"}`), &item); err != nil {
		t.Fatal(err)
	}
	var want = map[string]string{"list": "a,b", "flag": "1", "off": "0", "number": "5", "none": ""}
	if !reflect.DeepEqual(item.Fields, want) || item.Display["list"] != "A, B" || item.Uuid != "u" {
		t.Errorf("got %v / %v", item.Fields, item.Display)
	}
}

func TestItemCreate(t *testing.T) {
	var mutation = `{"result":"saved","uuid":"new-uuid"}`
	var api, requests = newTestApi(t, testHandler(&mutation))
	var uuid, err = api.Create(Vlans, map[string]string{"if": "vtnet0", "tag": "10"})
	if err != nil || uuid != "new-uuid" {
		t.Fatalf("Create: %q / %v", uuid, err)
	}
	var got = (*requests)[0]
	if got.Method != "POST" || got.Path != "/api/interfaces/vlan_settings/add_item" ||
		!reflect.DeepEqual(got.Body, map[string]any{"vlan": map[string]any{"if": "vtnet0", "tag": "10"}}) {
		t.Errorf("unexpected request %+v", got)
	}

	mutation = `{"result":"failed","validations":{"vlan.tag":"Tag for this device must be unique."}}`
	var validation *coreapi.ValidationError
	if _, err := api.Create(Vlans, map[string]string{}); !errors.As(err, &validation) || validation.Validations["vlan.tag"] == "" {
		t.Errorf("want a ValidationError, got %v", err)
	}
	mutation = `{"result":"saved"}`
	if _, err := api.Create(Vlans, map[string]string{}); err == nil {
		t.Error("want an error without uuid")
	}
}

func TestItemUpdate(t *testing.T) {
	var mutation = `{"result":"saved"}`
	var api, requests = newTestApi(t, testHandler(&mutation))
	// VLANs repeat parent, tag and device name (without the assigned marker) unless given
	if err := api.Update(Vlans, "7a1d1b6e-0c55-4d4e-9b0c-4f6f2b8e2b11", map[string]string{"descr": "inner", "tag": "8"}); err != nil {
		t.Fatal(err)
	}
	var got = (*requests)[len(*requests)-1]
	var want = map[string]any{"vlan": map[string]any{"if": "vlan01", "tag": "8", "vlanif": "qinq01", "descr": "inner"}}
	if got.Path != "/api/interfaces/vlan_settings/set_item/7a1d1b6e-0c55-4d4e-9b0c-4f6f2b8e2b11" || !reflect.DeepEqual(got.Body, want) {
		t.Errorf("unexpected request %+v", got)
	}

	// unknown uuids are not sent (set_item would create them)
	var before = len(*requests)
	if err := api.Update(Vlans, "00000000-0000-4000-8000-000000000000", map[string]string{"descr": "x"}); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	for _, request := range (*requests)[before:] {
		if request.Method != "GET" {
			t.Errorf("unexpected mutation %+v", request)
		}
	}
}

func TestItemUpdateVip(t *testing.T) {
	var api, requests = newTestApi(t, func(r testRequest) (int, string) {
		if strings.HasSuffix(r.Path, "/search_item") {
			return 200, `{"rows":[{"uuid":"v1","interface":"lan","mode":"carp","subnet":"192.168.1.10","subnet_bits":"24",` +
				`"password":"secret","vhid":"3","descr":"x"}]}`
		}
		return 200, `{"result":"saved"}`
	})
	if err := api.Update(Vips, "v1", map[string]string{"descr": "y"}); err != nil {
		t.Fatal(err)
	}
	var want = map[string]any{"vip": map[string]any{"interface": "lan", "network": "192.168.1.10/24", "descr": "y"}}
	if got := (*requests)[1]; got.Path != "/api/interfaces/vip_settings/set_item/v1" || !reflect.DeepEqual(got.Body, want) {
		t.Errorf("unexpected request %+v", got)
	}
}

func TestItemRemove(t *testing.T) {
	var mutation = `{"result":"deleted"}`
	var api, requests = newTestApi(t, testHandler(&mutation))
	if err := api.Remove(Vlans, testVlanUuid); err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Method != "POST" || got.Path != "/api/interfaces/vlan_settings/del_item/"+testVlanUuid {
		t.Errorf("unexpected request %+v", got)
	}
	mutation = `{"result":"not found"}`
	if err := api.Remove(Laggs, "x"); !coreapi.IsNotFound(err) || !strings.Contains(err.Error(), "LAGG x") {
		t.Errorf("want NotFoundError, got %v", err)
	}
	mutation = `500 {"errorMessage":"This VLAN cannot be deleted because it is assigned as an interface.","errorTitle":"Error"}`
	if err := api.Remove(Vlans, testVlanUuid); err == nil || !strings.Contains(err.Error(), "assigned as an interface") {
		t.Errorf("want the in use message, got %v", err)
	}
	for _, uuid := range []string{"", "a,b"} {
		if err := api.Remove(Vlans, uuid); err == nil {
			t.Errorf("Remove(%q): want an error", uuid)
		}
	}
}

func TestNeighborGenerated(t *testing.T) {
	var api, requests = newTestApi(t, func(r testRequest) (int, string) {
		if strings.HasSuffix(r.Path, "/search_item") {
			return 200, `{"rows":[{"uuid":"dhcpd-1","etheraddr":"00:11:22:33:44:55","ipaddress":"192.168.1.5","descr":"","origin":"dhcpd"},` +
				`{"uuid":"m1","etheraddr":"00:11:22:33:44:66","ipaddress":"192.168.1.6","descr":"","origin":"manual"}]}`
		}
		return 200, `{"result":"deleted"}`
	})
	if err := api.Update(Neighbors, "dhcpd-1", map[string]string{"descr": "x"}); err == nil || !strings.Contains(err.Error(), "generated by dhcpd") {
		t.Errorf("want a refusal, got %v", err)
	}
	if err := api.Remove(Neighbors, "dhcpd-1"); err == nil || !strings.Contains(err.Error(), "generated by dhcpd") {
		t.Errorf("want a refusal, got %v", err)
	}
	if err := api.Remove(Neighbors, "m1"); err != nil {
		t.Errorf("manual neighbor: %v", err)
	}
	var mutations = 0
	for _, request := range *requests {
		if request.Method != "GET" {
			mutations++
		}
	}
	if mutations != 1 {
		t.Errorf("want only the manual neighbor removed, got %+v", *requests)
	}
}

func TestReconfigure(t *testing.T) {
	var status = `{"status":"ok"}`
	var api, requests = newTestApi(t, func(r testRequest) (int, string) { return 200, status })
	for _, kind := range Kinds {
		if err := api.Reconfigure(kind); err != nil {
			t.Errorf("%s: %v", kind.Name, err)
		}
	}
	for i, request := range *requests {
		if request.Method != "POST" || !strings.HasSuffix(request.Path, "_settings/reconfigure") || request.Body == nil {
			t.Errorf("request %d: %+v", i, request)
		}
	}
	if (*requests)[0].Path != "/api/interfaces/vlan_settings/reconfigure" {
		t.Errorf("unexpected path %s", (*requests)[0].Path)
	}
	status = `{"status":"failed"}`
	if err := api.Reconfigure(Vips); err == nil || !strings.Contains(err.Error(), "virtual IP reconfigure failed") {
		t.Errorf("want an error, got %v", err)
	}
	if err := api.Reconfigure(Kind{}); err == nil {
		t.Error("want an error for an unknown kind")
	}
}

func TestForm(t *testing.T) {
	var api, _ = newTestApi(t, func(r testRequest) (int, string) {
		if strings.HasSuffix(r.Path, "/lagg_settings/get_item") {
			return 200, `{"lagg":{"laggif":"","members":[],"proto":{"none":{"value":"none","selected":0},"lacp":{"value":"lacp","selected":1}},"mtu":""}}`
		}
		return 200, testVlanGet
	})
	var form, err = api.Form(Vlans)
	if err != nil {
		t.Fatal(err)
	}
	if form.Defaults["pcp"] != "0" || form.Defaults["proto"] != "" || form.Defaults["tag"] != "" {
		t.Errorf("defaults %v", form.Defaults)
	}
	var keys []string
	for _, option := range form.Options["if"] {
		keys = append(keys, option.Key)
	}
	if !reflect.DeepEqual(keys, []string{"vtnet0", "vtnet1"}) || form.Options["if"][0].Value != "vtnet0 (52:54:00:12:34:56) [LAN]" {
		t.Errorf("options %+v", form.Options["if"])
	}

	var lagg, laggErr = api.Form(Laggs)
	if laggErr != nil || lagg.Defaults["proto"] != "lacp" || lagg.Defaults["members"] != "" || len(lagg.Options["members"]) != 0 {
		t.Errorf("lagg form %+v / %v", lagg, laggErr)
	}
	if _, err := api.Form(Gifs); err == nil {
		t.Error("want an error for a missing record")
	}
}

func TestUnusedVhid(t *testing.T) {
	var answer = `{"vhid":4,"status":"ok"}`
	var api, _ = newTestApi(t, func(r testRequest) (int, string) { return 200, answer })
	if vhid, err := api.UnusedVhid(); err != nil || vhid != 4 {
		t.Errorf("UnusedVhid: %d / %v", vhid, err)
	}
	answer = `{"status":"not_found"}`
	if _, err := api.UnusedVhid(); err == nil {
		t.Error("want an error")
	}
}
