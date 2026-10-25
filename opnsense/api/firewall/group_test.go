package firewall

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

type groupTestRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   map[string]map[string]string
}

// newGroupTestApi starts a fake OPNsense answering every request with the status and raw JSON of handler (also
// used by the category tests), all requests are recorded
func newGroupTestApi(t *testing.T, handler func(r groupTestRequest) (int, string)) (*FirewallApi, *[]groupTestRequest) {
	t.Helper()
	var requests []groupTestRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var recorded = groupTestRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query()}
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
	return &FirewallApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, &requests
}

const (
	groupTestUuid = "cc70dc4d-1c2a-4f29-810a-632d0d87e395"
	groupTestPath = "/api/firewall/group/"
)

// groupTestSearch is a search_item answer of OPNsense 26.7: a custom group and the built-in groups
const groupTestSearch = `{"rows":[` +
	`{"uuid":"cc70dc4d-1c2a-4f29-810a-632d0d87e395","ifname":"office","members":"lan,opt1","%members":"LAN, OFFICE",` +
	`"nogroup":"1","sequence":"5","descr":"office nets"},` +
	`{"uuid":"enc0","ifname":"enc0","members":"","nogroup":"","sequence":"10","descr":"IPsec encapsulation"},` +
	`{"uuid":"openvpn","ifname":"openvpn","members":"","nogroup":"","sequence":"10","descr":"OpenVPN (Group)"}` +
	`],"rowCount":3,"total":3,"current":1}`

// groupTestGet is get_item without uuid: the defaults with the member options
const groupTestGet = `{"group":{"ifname":"","members":{"lan":{"value":"LAN","selected":0},"lo0":{"value":"Loopback","selected":0},` +
	`"wan":{"value":"WAN","selected":0},"opt1":{"value":"OFFICE","selected":0}},"nogroup":"0","sequence":"0","descr":""}}`

// groupTestHandler answers search_item, get_item and with mutation for everything else
func groupTestHandler(mutation *string) func(r groupTestRequest) (int, string) {
	return func(r groupTestRequest) (int, string) {
		switch {
		case strings.HasSuffix(r.Path, "/search_item"):
			return 200, groupTestSearch
		case strings.HasSuffix(r.Path, "/get_item"):
			return 200, groupTestGet
		}
		if strings.HasPrefix(*mutation, "500 ") {
			return 500, strings.TrimPrefix(*mutation, "500 ")
		}
		return 200, *mutation
	}
}

// groupTestMutations returns the POST requests
func groupTestMutations(requests []groupTestRequest) []groupTestRequest {
	var result []groupTestRequest
	for _, request := range requests {
		if request.Method != "GET" {
			result = append(result, request)
		}
	}
	return result
}

func TestGroupSearchDecodes(t *testing.T) {
	var api, requests = newGroupTestApi(t, func(r groupTestRequest) (int, string) { return 200, groupTestSearch })
	var groups, err = api.GroupSearch("off")
	if err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Method != "GET" || got.Path != groupTestPath+"search_item" || got.Query.Get("searchPhrase") != "off" {
		t.Errorf("unexpected request %+v", got)
	}
	var want = []Group{
		{Uuid: groupTestUuid, Name: "office", Members: []string{"lan", "opt1"}, MembersText: "LAN, OFFICE", NoGroup: true, Sequence: 5,
			Description: "office nets"},
		{Uuid: "enc0", Name: "enc0", Sequence: 10, Description: "IPsec encapsulation"},
		{Uuid: "openvpn", Name: "openvpn", Sequence: 10, Description: "OpenVPN (Group)"},
	}
	if !reflect.DeepEqual(groups, want) {
		t.Errorf("got  %+v\nwant %+v", groups, want)
	}
	if groups[0].IsBuiltin() || !groups[1].IsBuiltin() {
		t.Error("IsBuiltin")
	}

	var bad Group
	if err := json.Unmarshal([]byte(`{"ifname":"x","sequence":"ten"}`), &bad); err == nil {
		t.Error("want an error for a non numeric sequence")
	}
}

func TestGroupGet(t *testing.T) {
	var api, requests = newGroupTestApi(t, func(r groupTestRequest) (int, string) { return 200, groupTestSearch })
	if group, err := api.GroupGet(groupTestUuid); err != nil || group.Name != "office" {
		t.Errorf("GroupGet: %+v / %v", group, err)
	}
	if group, err := api.GroupGet("openvpn"); err != nil || !group.IsBuiltin() {
		t.Errorf("GroupGet(openvpn): %+v / %v", group, err)
	}
	if _, err := api.GroupGet("00000000-0000-4000-8000-000000000000"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if group, err := api.GroupGetByName("office"); err != nil || group.Uuid != groupTestUuid {
		t.Errorf("GroupGetByName: %+v / %v", group, err)
	}
	if got := (*requests)[len(*requests)-1]; got.Query.Get("searchPhrase") != "office" {
		t.Errorf("unexpected request %+v", got)
	}
	for _, name := range []string{"off", "OFFICE", "LAN"} {
		if _, err := api.GroupGetByName(name); !coreapi.IsNotFound(err) {
			t.Errorf("%s: want NotFoundError, got %v", name, err)
		}
	}
	for _, err := range []error{func() error { _, err := api.GroupGet(""); return err }(), func() error { _, err := api.GroupGetByName(""); return err }()} {
		if err == nil {
			t.Error("want an error for an empty key")
		}
	}
}

func TestGroupValidateName(t *testing.T) {
	for _, name := range []string{"a", "office", "Office_Nets", "a1b", "_x_", "abcdefghijklmno"} {
		if err := GroupValidateName(name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	for _, name := range []string{"", "1abc", "abc1", "a-b", "a b", "abcdefghijklmnop", "ä"} {
		if err := GroupValidateName(name); err == nil {
			t.Errorf("%q: want an error", name)
		}
	}
}

func TestGroupInterfaces(t *testing.T) {
	var api, _ = newGroupTestApi(t, func(r groupTestRequest) (int, string) { return 200, groupTestGet })
	var interfaces, err = api.GroupInterfaces()
	var want = []GroupInterface{{"lan", "LAN"}, {"lo0", "Loopback"}, {"opt1", "OFFICE"}, {"wan", "WAN"}}
	if err != nil || !reflect.DeepEqual(interfaces, want) {
		t.Errorf("got %+v / %v", interfaces, err)
	}
}

func TestGroupCreate(t *testing.T) {
	var answer = `{"result":"saved","uuid":"` + groupTestUuid + `"}`
	var api, requests = newGroupTestApi(t, groupTestHandler(&answer))
	var uuid, err = api.GroupCreate(Group{Name: "office", Members: []string{"lan", "opt1"}, Sequence: 3, Description: "x"})
	if err != nil || uuid != groupTestUuid {
		t.Fatalf("got %q / %v", uuid, err)
	}
	var mutations = groupTestMutations(*requests)
	var want = map[string]map[string]string{"group": {"ifname": "office", "members": "lan,opt1", "nogroup": "0", "sequence": "3", "descr": "x"}}
	if len(mutations) != 1 || mutations[0].Path != groupTestPath+"add_item" || !reflect.DeepEqual(mutations[0].Body, want) {
		t.Errorf("unexpected mutations %+v", mutations)
	}

	*requests = nil
	for name, group := range map[string]Group{
		"bad name":        {Name: "1x", Members: []string{"lan"}},
		"interface name":  {Name: "LAN", Members: []string{"lan"}},
		"no members":      {Name: "g"},
		"twice":           {Name: "g", Members: []string{"lan", "lan"}},
		"bad member":      {Name: "g", Members: []string{"lan,wan"}},
		"sequence high":   {Name: "g", Members: []string{"lan"}, Sequence: 10000},
		"sequence below0": {Name: "g", Members: []string{"lan"}, Sequence: -1},
	} {
		if _, err := api.GroupCreate(group); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if got := groupTestMutations(*requests); len(got) != 0 {
		t.Errorf("invalid groups must not be sent: %+v", got)
	}
}

func TestGroupCreateRefusesInterfaceNamesNotOffered(t *testing.T) {
	// a box whose lan interface entry is broken (it was overwritten by a group named lan) does not offer lan as a
	// member: the name must still be refused, without asking the API
	var answer = `{"result":"saved","uuid":"` + groupTestUuid + `"}`
	var api, requests = newGroupTestApi(t, groupTestHandler(&answer))
	for _, name := range []string{"lan", "WAN"} {
		if _, err := api.GroupCreate(Group{Name: name, Members: []string{"wan"}}); err == nil ||
			!strings.Contains(err.Error(), "is the name of an interface") {
			t.Errorf("%s: want the interface name refused, got %v", name, err)
		}
	}
	if len(*requests) != 0 {
		t.Errorf("want no requests, got %+v", *requests)
	}
}

func TestGroupUpdate(t *testing.T) {
	var answer = `{"result":"saved"}`
	var api, requests = newGroupTestApi(t, groupTestHandler(&answer))
	var reset = func() { *requests = nil }

	var members = []string{"wan"}
	var sequence = 0
	if err := api.GroupUpdate(groupTestUuid, GroupPatch{Members: &members, Sequence: &sequence}); err != nil {
		t.Fatal(err)
	}
	// the current name is always sent, a missing ifname is a rename to "" for OPNsense
	var want = map[string]map[string]string{"group": {"ifname": "office", "members": "wan", "sequence": "0"}}
	if got := groupTestMutations(*requests); len(got) != 1 || got[0].Path != groupTestPath+"set_item/"+groupTestUuid || !reflect.DeepEqual(got[0].Body, want) {
		t.Errorf("unexpected mutations %+v", got)
	}

	t.Run("rename", func(t *testing.T) {
		reset()
		var name = "branch"
		if err := api.GroupUpdate(groupTestUuid, GroupPatch{Name: &name}); err != nil {
			t.Fatal(err)
		}
		if got := groupTestMutations(*requests); len(got) != 1 || !reflect.DeepEqual(got[0].Body, map[string]map[string]string{"group": {"ifname": "branch"}}) {
			t.Errorf("unexpected mutations %+v", got)
		}
	})

	t.Run("refused without set", func(t *testing.T) {
		var wan, bad, empty = "wan", "9x", []string{}
		for name, call := range map[string]func() error{
			"unknown": func() error {
				return api.GroupUpdate("00000000-0000-4000-8000-000000000000", GroupPatch{Members: &members})
			},
			"built-in":       func() error { return api.GroupUpdate("openvpn", GroupPatch{Members: &members}) },
			"interface name": func() error { return api.GroupUpdate(groupTestUuid, GroupPatch{Name: &wan}) },
			"bad name":       func() error { return api.GroupUpdate(groupTestUuid, GroupPatch{Name: &bad}) },
			"no members":     func() error { return api.GroupUpdate(groupTestUuid, GroupPatch{Members: &empty}) },
			"no uuid":        func() error { return api.GroupUpdate("", GroupPatch{}) },
		} {
			reset()
			if err := call(); err == nil {
				t.Errorf("%s: want an error", name)
			}
			if got := groupTestMutations(*requests); len(got) != 0 {
				t.Errorf("%s: want no mutation, got %+v", name, got)
			}
		}
		reset()
		if err := api.GroupUpdate("00000000-0000-4000-8000-000000000000", GroupPatch{Members: &members}); !coreapi.IsNotFound(err) {
			t.Errorf("want NotFoundError, got %v", err)
		}
	})

	t.Run("validation error", func(t *testing.T) {
		reset()
		answer = `{"result":"failed","validations":{"group.members":"Option [opt9] not in list."}}`
		var unknown = []string{"opt9"}
		if err := api.GroupUpdate(groupTestUuid, GroupPatch{Members: &unknown}); err == nil || !strings.Contains(err.Error(), "not in list") {
			t.Errorf("want the validation error, got %v", err)
		}
	})
}

func TestGroupRemove(t *testing.T) {
	var answer = `{"result":"deleted"}`
	var api, requests = newGroupTestApi(t, groupTestHandler(&answer))
	if err := api.GroupRemove(groupTestUuid); err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Method != "POST" || got.Path != groupTestPath+"del_item/"+groupTestUuid || got.Body != nil {
		t.Errorf("unexpected request %+v", got)
	}

	answer = `{"result":"not found"}`
	if err := api.GroupRemove(groupTestUuid); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}

	answer = "500 " + `{"errorMessage":"Cannot delete group. Currently in use by \n[OPNsense.Firewall.Filter.rules.rule.d621e174] allow office ","errorTitle":"Group in use"}`
	var err = api.GroupRemove(groupTestUuid)
	if err == nil || err.Error() != "cannot remove group "+groupTestUuid+": Cannot delete group. Currently in use by [OPNsense.Firewall.Filter.rules.rule.d621e174] allow office" {
		t.Errorf("want the in use message, got %v", err)
	}

	*requests = nil
	for _, uuid := range []string{"", "a,b", "openvpn"} {
		if err := api.GroupRemove(uuid); err == nil {
			t.Errorf("%q: want an error", uuid)
		}
	}
	if len(*requests) != 0 {
		t.Errorf("want no requests, got %+v", *requests)
	}
}

func TestGroupReconfigure(t *testing.T) {
	var answer = `{"status":"ok"}`
	var api, requests = newGroupTestApi(t, func(r groupTestRequest) (int, string) { return 200, answer })
	if err := api.GroupReconfigure(); err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Method != "POST" || got.Path != groupTestPath+"reconfigure" {
		t.Errorf("unexpected request %+v", got)
	}
	answer = `{"status":"failed"}`
	if err := api.GroupReconfigure(); err == nil {
		t.Error("want an error for status failed")
	}
}
