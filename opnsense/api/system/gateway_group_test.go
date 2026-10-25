package system

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

type gatewayGroupTestRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   map[string]map[string]string
}

// newGatewayGroupTestApi starts a fake OPNsense answering every request with the raw JSON of handler,
// all requests are recorded
func newGatewayGroupTestApi(t *testing.T, handler func(r gatewayGroupTestRequest) (int, string)) (*SystemApi, *[]gatewayGroupTestRequest) {
	t.Helper()
	var requests []gatewayGroupTestRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var recorded = gatewayGroupTestRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query()}
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
	return &SystemApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, &requests
}

const (
	gatewayGroupTestUuid = "949865b0-9635-4ec7-a359-292f5c5e5784"
	gatewayGroupTestPath = "/api/routing/group_settings/"
)

// gatewayGroupTestSearch is a search answer of OPNsense 26.7 (two groups, the second with a disabled member)
const gatewayGroupTestSearch = `{"rows":[` +
	`{"uuid":"949865b0-9635-4ec7-a359-292f5c5e5784","name":"multiwan","item2":"","item3":"GW_B","%item3":"GW_B - 192.168.1.251",` +
	`"item4":"","item5":"","item":"GW_A,GW_B","%item":"GW_A - 192.168.1.250, GW_B - 192.168.1.251","trigger":"downloss",` +
	`"%trigger":"Packet Loss","poolopts":"round-robin sticky-address","%poolopts":"Round Robin with Sticky Address","descr":"main",` +
	`"gateways":{"1":[{"name":"GW_A","address":"192.168.1.250","status":"none","loss":"0.0 %","delay":"1.2 ms","stddev":"0.1 ms",` +
	`"monitor":"192.168.1.250","status_translated":"Online","label":"success"},{"name":"GW_B","address":"192.168.1.251","status":"down",` +
	`"loss":"100.0 %","delay":"~","stddev":"~","monitor":"~","status_translated":"Offline","label":"danger"}],"2":[],` +
	`"3":[{"name":"GW_B","address":"192.168.1.251","status":"down","loss":"100.0 %","delay":"~","stddev":"~","monitor":"~",` +
	`"status_translated":"Offline","label":"danger"}],"4":[],"5":[]}},` +
	`{"uuid":"11111111-2222-4333-8444-555555555555","name":"multiwan2","item2":"GW_OLD","item3":"","item4":"","item5":"","item":"",` +
	`"trigger":"down","poolopts":"","descr":"","gateways":{"1":[],"2":[{"name":"GW_OLD","label":"danger",` +
	`"status_translated":"Disabled or inactive"}],"3":[],"4":[],"5":[]}}` +
	`],"rowCount":2,"total":2,"current":1}`

// gatewayGroupTestGet is get without uuid: the defaults with the option maps
const gatewayGroupTestGet = `{"gateway_group":{"name":"",` +
	`"item2":{"WAN_DHCP":{"value":"WAN_DHCP - 10.0.2.2","selected":0}},` +
	`"item":{"WAN_DHCP6":{"value":"WAN_DHCP6 - fe80::2","selected":0},"WAN_DHCP":{"value":"WAN_DHCP - 10.0.2.2","selected":0},` +
	`"GW_A":{"value":"GW_A - 192.168.1.250","selected":0}},` +
	`"trigger":{"down":{"value":"Member Down","selected":1}},"poolopts":{"":{"value":"Default","selected":1}},"descr":""}}`

func TestGatewayGroupSearchDecodes(t *testing.T) {
	var api, requests = newGatewayGroupTestApi(t, func(r gatewayGroupTestRequest) (int, string) {
		return 200, gatewayGroupTestSearch
	})
	var groups, err = api.GatewayGroupSearch("multi")
	if err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Method != "GET" || got.Path != gatewayGroupTestPath+"search" || got.Query.Get("searchPhrase") != "multi" {
		t.Errorf("unexpected request %+v", got)
	}
	if len(groups) != 2 {
		t.Fatalf("want 2 groups, got %+v", groups)
	}

	var group = groups[0]
	if group.Uuid != gatewayGroupTestUuid || group.Name != "multiwan" || group.Trigger != GatewayGroupTriggerLoss ||
		group.PoolOptions != GatewayGroupPoolRoundRobinSticky || group.Description != "main" {
		t.Errorf("unexpected fields %+v", group)
	}
	var wantTiers = [GatewayGroupTierCount][]string{{"GW_A", "GW_B"}, nil, {"GW_B"}, nil, nil}
	if !reflect.DeepEqual(group.Tiers, wantTiers) {
		t.Errorf("tiers %q, want %q", group.Tiers, wantTiers)
	}
	if len(group.Status[0]) != 2 || group.Status[0][1].Name != "GW_B" || group.Status[0][1].StatusText != "Offline" ||
		group.Status[0][0].Delay != "1.2 ms" || len(group.Status[2]) != 1 || len(group.Status[1]) != 0 {
		t.Errorf("unexpected status %+v", group.Status)
	}
	if got := group.Members(); !reflect.DeepEqual(got, []string{"GW_A", "GW_B"}) {
		t.Errorf("members %q", got)
	}

	var second = groups[1]
	if len(second.Tiers[0]) != 0 || !reflect.DeepEqual(second.Tiers[1], []string{"GW_OLD"}) ||
		len(second.Status[1]) != 1 || second.Status[1][0].StatusText != "Disabled or inactive" {
		t.Errorf("unexpected second group %+v", second)
	}
}

func TestGatewayGroupStatusShapes(t *testing.T) {
	for name, raw := range map[string]string{
		"list":    `{"name":"g","item":"A","gateways":[[{"name":"A","status":"none"}],[],[],[],[]]}`,
		"missing": `{"name":"g","item":"A"}`,
		"null":    `{"name":"g","item":"A","gateways":null}`,
	} {
		var group GatewayGroup
		if err := json.Unmarshal([]byte(raw), &group); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if group.Name != "g" || !reflect.DeepEqual(group.Tiers[0], []string{"A"}) {
			t.Errorf("%s: %+v", name, group)
		}
		if name == "list" && (len(group.Status[0]) != 1 || group.Status[0][0].Status != "none") {
			t.Errorf("list status: %+v", group.Status)
		}
	}
	var group GatewayGroup
	if err := json.Unmarshal([]byte(`{"name":"g","gateways":"x"}`), &group); err == nil {
		t.Error("want an error for an unexpected status shape")
	}
}

func TestGatewayGroupGet(t *testing.T) {
	var api, requests = newGatewayGroupTestApi(t, func(r gatewayGroupTestRequest) (int, string) {
		return 200, gatewayGroupTestSearch
	})

	var group, err = api.GatewayGroupGet(gatewayGroupTestUuid)
	if err != nil || group.Name != "multiwan" {
		t.Fatalf("got %+v / %v", group, err)
	}
	if got := (*requests)[0]; got.Path != gatewayGroupTestPath+"search" || got.Query.Get("searchPhrase") != "" {
		t.Errorf("unexpected request %+v", got)
	}
	if _, err = api.GatewayGroupGet("00000000-0000-4000-8000-000000000000"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if _, err = api.GatewayGroupGet(""); err == nil {
		t.Error("want an error for an empty uuid")
	}

	// names are matched exactly, the search is a substring match
	group, err = api.GatewayGroupGetByName("multiwan2")
	if err != nil || group.Uuid != "11111111-2222-4333-8444-555555555555" {
		t.Errorf("by name: %+v / %v", group, err)
	}
	if got := (*requests)[len(*requests)-1]; got.Query.Get("searchPhrase") != "multiwan2" {
		t.Errorf("unexpected request %+v", got)
	}
	for _, name := range []string{"multi", "MULTIWAN", "GW_A"} {
		if _, err = api.GatewayGroupGetByName(name); !coreapi.IsNotFound(err) {
			t.Errorf("%s: want NotFoundError, got %v", name, err)
		}
	}
	if _, err = api.GatewayGroupGetByName(""); err == nil {
		t.Error("want an error for an empty name")
	}
}

func TestGatewayGroupCreate(t *testing.T) {
	var api, requests = newGatewayGroupTestApi(t, func(r gatewayGroupTestRequest) (int, string) {
		return 200, `{"result":"saved","uuid":"` + gatewayGroupTestUuid + `"}`
	})

	var uuid, err = api.GatewayGroupCreate(GatewayGroup{
		Name:  "multiwan",
		Tiers: [GatewayGroupTierCount][]string{{"GW_A", "GW_B"}, nil, {"GW_C"}},
	})
	if err != nil || uuid != gatewayGroupTestUuid {
		t.Fatalf("got %q / %v", uuid, err)
	}
	var want = map[string]map[string]string{"gateway_group": {
		"name": "multiwan", "item": "GW_A,GW_B", "item2": "", "item3": "GW_C", "item4": "", "item5": "",
		"trigger": "down", "poolopts": "", "descr": "",
	}}
	if got := (*requests)[0]; got.Method != "POST" || got.Path != gatewayGroupTestPath+"add" || !reflect.DeepEqual(got.Body, want) {
		t.Errorf("unexpected request %+v", got)
	}

	for name, group := range map[string]GatewayGroup{
		"no member":       {Name: "g"},
		"bad name":        {Name: "a b", Tiers: [GatewayGroupTierCount][]string{{"GW_A"}}},
		"long name":       {Name: strings.Repeat("a", 33), Tiers: [GatewayGroupTierCount][]string{{"GW_A"}}},
		"bad member":      {Name: "g", Tiers: [GatewayGroupTierCount][]string{{"GW A"}}},
		"duplicate":       {Name: "g", Tiers: [GatewayGroupTierCount][]string{nil, {"GW_A", "GW_A"}}},
		"bad trigger":     {Name: "g", Tiers: [GatewayGroupTierCount][]string{{"GW_A"}}, Trigger: "loss"},
		"bad pool option": {Name: "g", Tiers: [GatewayGroupTierCount][]string{{"GW_A"}}, PoolOptions: "sticky"},
	} {
		if _, err := api.GatewayGroupCreate(group); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if len(*requests) != 1 {
		t.Errorf("invalid groups must not be sent: %+v", (*requests)[1:])
	}
}

func TestGatewayGroupCreateValidation(t *testing.T) {
	var api, _ = newGatewayGroupTestApi(t, func(r gatewayGroupTestRequest) (int, string) {
		return 200, `{"result":"failed","validations":{"gateway_group.item":"Option [GW_X] not in list."}}`
	})
	var _, err = api.GatewayGroupCreate(GatewayGroup{Name: "g", Tiers: [GatewayGroupTierCount][]string{{"GW_X"}}})
	var validationErr *coreapi.ValidationError
	if !errors.As(err, &validationErr) || !strings.Contains(err.Error(), "not in list") {
		t.Errorf("want the validation error, got %v", err)
	}
}

func TestGatewayGroupUpdate(t *testing.T) {
	var setAnswer = `{"result":"saved"}`
	var api, requests = newGatewayGroupTestApi(t, func(r gatewayGroupTestRequest) (int, string) {
		if strings.HasSuffix(r.Path, "/search") {
			return 200, gatewayGroupTestSearch
		}
		return 200, setAnswer
	})
	var reset = func() { *requests = nil }

	var tier2 = []string{"GW_B", "GW_A"}
	var description = "changed"
	if err := api.GatewayGroupUpdate(gatewayGroupTestUuid, GatewayGroupPatch{
		Tiers: [GatewayGroupTierCount]*[]string{nil, &tier2}, Description: &description,
	}); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 2 || (*requests)[0].Path != gatewayGroupTestPath+"search" {
		t.Fatalf("want an existence check and the set, got %+v", *requests)
	}
	var want = map[string]map[string]string{"gateway_group": {"item2": "GW_B,GW_A", "descr": "changed"}}
	if got := (*requests)[1]; got.Method != "POST" || got.Path != gatewayGroupTestPath+"set/"+gatewayGroupTestUuid || !reflect.DeepEqual(got.Body, want) {
		t.Errorf("unexpected set %+v", got)
	}

	t.Run("unknown uuid is not sent", func(t *testing.T) {
		reset()
		var err = api.GatewayGroupUpdate("00000000-0000-4000-8000-000000000000", GatewayGroupPatch{Description: &description})
		if !coreapi.IsNotFound(err) || len(*requests) != 1 {
			t.Errorf("want NotFoundError without set, got %v / %+v", err, *requests)
		}
	})

	t.Run("clearing tier 1 is refused", func(t *testing.T) {
		reset()
		var empty []string
		var err = api.GatewayGroupUpdate(gatewayGroupTestUuid, GatewayGroupPatch{Tiers: [GatewayGroupTierCount]*[]string{&empty}})
		if err == nil || !strings.Contains(err.Error(), "tier 1") || len(*requests) != 1 {
			t.Errorf("want a refusal without set, got %v / %+v", err, *requests)
		}
	})

	t.Run("an empty tier 1 can stay empty", func(t *testing.T) {
		reset()
		var empty []string
		var err = api.GatewayGroupUpdate("11111111-2222-4333-8444-555555555555", GatewayGroupPatch{Tiers: [GatewayGroupTierCount]*[]string{&empty}})
		if err != nil || len(*requests) != 2 {
			t.Errorf("got %v / %+v", err, *requests)
		}
	})

	t.Run("no member left is refused", func(t *testing.T) {
		reset()
		var empty []string
		var err = api.GatewayGroupUpdate("11111111-2222-4333-8444-555555555555", GatewayGroupPatch{Tiers: [GatewayGroupTierCount]*[]string{nil, &empty}})
		if err == nil || !strings.Contains(err.Error(), "at least one gateway") || len(*requests) != 1 {
			t.Errorf("want a refusal without set, got %v / %+v", err, *requests)
		}
	})

	t.Run("invalid values are not sent", func(t *testing.T) {
		reset()
		var trigger = "never"
		var bad = []string{"a,b"}
		for _, patch := range []GatewayGroupPatch{{Trigger: &trigger}, {Tiers: [GatewayGroupTierCount]*[]string{nil, nil, &bad}}} {
			if err := api.GatewayGroupUpdate(gatewayGroupTestUuid, patch); err == nil {
				t.Errorf("want an error for %+v", patch)
			}
		}
		if err := api.GatewayGroupUpdate("", GatewayGroupPatch{}); err == nil {
			t.Error("want an error for an empty uuid")
		}
		if len(*requests) != 0 {
			t.Errorf("want no requests, got %+v", *requests)
		}
	})

	t.Run("validation error", func(t *testing.T) {
		reset()
		setAnswer = `{"result":"failed","validations":{"gateway_group.name":"Changing name on a gateway group is not allowed."}}`
		var err = api.GatewayGroupUpdate(gatewayGroupTestUuid, GatewayGroupPatch{Description: &description})
		if err == nil || !strings.Contains(err.Error(), "Changing name") {
			t.Errorf("want the validation error, got %v", err)
		}
	})
}

func TestGatewayGroupRemove(t *testing.T) {
	var status, answer = 200, `{"result":"deleted"}`
	var api, requests = newGatewayGroupTestApi(t, func(r gatewayGroupTestRequest) (int, string) {
		return status, answer
	})

	if err := api.GatewayGroupRemove(gatewayGroupTestUuid); err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Method != "POST" || got.Path != gatewayGroupTestPath+"del/"+gatewayGroupTestUuid || got.Body != nil {
		t.Errorf("unexpected request %+v", got)
	}

	answer = `{"result":"not found"}`
	if err := api.GatewayGroupRemove(gatewayGroupTestUuid); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}

	// a group used by a firewall rule: UserException
	status, answer = 500, `{"errorMessage":"Gateway group multiwan in use by rule lan out (4b0b1f5c)","errorTitle":""}`
	var err = api.GatewayGroupRemove(gatewayGroupTestUuid)
	if err == nil || !strings.Contains(err.Error(), "in use by rule lan out") {
		t.Errorf("want the in use message, got %v", err)
	}

	*requests = nil
	for _, uuid := range []string{"", "a,b"} {
		if err := api.GatewayGroupRemove(uuid); err == nil {
			t.Errorf("%q: want an error", uuid)
		}
	}
	if len(*requests) != 0 {
		t.Errorf("want no requests, got %+v", *requests)
	}
}

func TestGatewayGroupCandidates(t *testing.T) {
	var api, requests = newGatewayGroupTestApi(t, func(r gatewayGroupTestRequest) (int, string) {
		return 200, gatewayGroupTestGet
	})
	var candidates, err = api.GatewayGroupCandidates()
	if err != nil {
		t.Fatal(err)
	}
	var want = []GatewayGroupCandidate{
		{Name: "GW_A", Description: "GW_A - 192.168.1.250"},
		{Name: "WAN_DHCP", Description: "WAN_DHCP - 10.0.2.2"},
		{Name: "WAN_DHCP6", Description: "WAN_DHCP6 - fe80::2"},
	}
	if !reflect.DeepEqual(candidates, want) {
		t.Errorf("got %+v", candidates)
	}
	if got := (*requests)[0]; got.Method != "GET" || got.Path != gatewayGroupTestPath+"get" {
		t.Errorf("unexpected request %+v", got)
	}
}

func TestGatewayGroupReconfigure(t *testing.T) {
	var answer = `{"status":"ok"}`
	var api, requests = newGatewayGroupTestApi(t, func(r gatewayGroupTestRequest) (int, string) {
		return 200, answer
	})
	if err := api.GatewayGroupReconfigure(); err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Method != "POST" || got.Path != gatewayGroupTestPath+"reconfigure" {
		t.Errorf("unexpected request %+v", got)
	}
	answer = `{"status":"failed"}`
	if err := api.GatewayGroupReconfigure(); err == nil {
		t.Error("want an error for status failed")
	}
}
