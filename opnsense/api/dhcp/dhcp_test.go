package dhcp

import (
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

// testRequest is one request the fake OPNsense received
type testRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   any // decoded JSON, nil without body
	Raw    string
}

// testServer answers with handler and records every request
type testServer struct {
	mu       sync.Mutex
	requests []testRequest
}

func (s *testServer) recorded() []testRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]testRequest(nil), s.requests...)
}

func (s *testServer) mutations() []testRequest {
	var result []testRequest
	for _, request := range s.recorded() {
		if request.Method != "GET" {
			result = append(result, request)
		}
	}
	return result
}

func (s *testServer) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = nil
}

// newTestApi starts a fake OPNsense: answers maps "METHOD /path" to "<status> <body>" or "<body>" (status 200);
// unknown endpoints answer 404 like OPNsense
func newTestApi(t *testing.T, answers map[string]string) (*DhcpApi, *testServer) {
	t.Helper()
	var server = &testServer{}
	var srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw, _ = io.ReadAll(r.Body)
		var request = testRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Raw: string(raw)}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &request.Body)
		}
		server.mu.Lock()
		server.requests = append(server.requests, request)
		server.mu.Unlock()

		var answer, found = answers[r.Method+" "+r.URL.Path]
		if !found {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"errorMessage":"Endpoint not found"}`)
			return
		}
		var status = 200
		if strings.HasPrefix(answer, "500 ") {
			status, answer = 500, strings.TrimPrefix(answer, "500 ")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(srv.Close)
	var base, err = url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &DhcpApi{OPNsense: &coreapi.OPNsense{BaseUrl: *base, ApiKey: "k", ApiSecret: "s"}}, server
}

func wantBody(t *testing.T, request testRequest, want string) {
	t.Helper()
	var wanted any
	if err := json.Unmarshal([]byte(want), &wanted); err != nil {
		t.Fatalf("bad test JSON %s: %v", want, err)
	}
	if !reflect.DeepEqual(request.Body, wanted) {
		t.Errorf("body of %s %s:\n got  %s\n want %s", request.Method, request.Path, request.Raw, want)
	}
}

func TestFieldsNested(t *testing.T) {
	var nested = Fields{"subnet": "198.51.100.0/24", "option_data.routers": "198.51.100.1", "option_data.domain_name": "x"}.nested()
	var want = map[string]any{"subnet": "198.51.100.0/24", "option_data": map[string]any{"routers": "198.51.100.1", "domain_name": "x"}}
	if !reflect.DeepEqual(nested, want) {
		t.Errorf("got %v, want %v", nested, want)
	}
}

func TestFlexText(t *testing.T) {
	for raw, want := range map[string]string{
		`"a"`: "a", `12`: "12", `null`: "", `true`: "1", `false`: "0", `["hwaddr","duid"]`: "hwaddr,duid", `[]`: "",
		`[{"a":1}]`: `[{"a":1}]`, `{"a":1}`: `{"a":1}`,
	} {
		if got := flexText(json.RawMessage(raw)); got != want {
			t.Errorf("flexText(%s) = %q, want %q", raw, got, want)
		}
	}
}

// keaSubnetGet is a get_subnet answer of 26.7 for a new subnet (shortened)
const keaSubnetGet = `{"subnet4":{"subnet":"","valid_lifetime":"","option_data_autocollect":"1",` +
	`"option_data":{"domain_name_servers":{"":{"value":"","selected":1}},"routers":{"":{"value":"","selected":1}},"domain_name":""},` +
	`"option":[],"match-client-id":"1",` +
	`"allocator":{"":{"value":"Default","selected":1},"iterative":{"value":"Iterative","selected":0},"random":{"value":"Random","selected":0}},` +
	`"pools":"","description":""}}`

func TestParseForm(t *testing.T) {
	var api, _ = newTestApi(t, map[string]string{"GET /api/kea/dhcpv4/get_subnet": keaSubnetGet})
	var form, err = api.KeaSubnets4().Form("")
	if err != nil {
		t.Fatal(err)
	}
	var want = Fields{
		"subnet": "", "valid_lifetime": "", "option_data_autocollect": "1", "option_data.domain_name_servers": "",
		"option_data.routers": "", "option_data.domain_name": "", "option": "", "match-client-id": "1", "allocator": "",
		"pools": "", "description": "",
	}
	if got := form.Fields(); !reflect.DeepEqual(got, want) {
		t.Errorf("fields:\n got  %v\n want %v", got, want)
	}
	if !form["allocator"].IsOption() || len(form["allocator"].Options) != 3 || form["allocator"].Options[2] != (Option{Key: "random", Description: "Random"}) {
		t.Errorf("allocator options: %+v", form["allocator"])
	}
	if !form["option"].IsOption() || form["subnet"].IsOption() {
		t.Errorf("option must be an option field without choices, subnet a plain one: %+v", form)
	}

	// option lists PHP renders as arrays (keys 0..n)
	var listForm, listErr = parseForm(json.RawMessage(`{"verb":[{"value":"zero","selected":0},{"value":"one","selected":1}],"x":{"a":{"b":"c"}}}`))
	if listErr != nil || listForm.Value("verb") != "1" || listForm.Value("x.a.b") != "c" {
		t.Errorf("got %+v / %v", listForm, listErr)
	}
}

func TestSettings(t *testing.T) {
	var api, server = newTestApi(t, map[string]string{
		"GET /api/kea/dhcpv4/get": `{"dhcpv4":{"general":{"enabled":"0","interfaces":{"lan":{"value":"LAN","selected":1},"wan":{"value":"WAN","selected":0}},` +
			`"valid_lifetime":"4000"},"lexpire":{"max_reclaim_time":""},"ha":{"enabled":"0","%this_server_name":"OPNsense"}}}`,
		"POST /api/kea/dhcpv4/set": `{"result":"saved"}`,
		"POST /api/kea/ddns/set":   `{"result":"failed","validations":{"ddns.general.server_port":["Please provide a valid port number."]}}`,
	})
	var form, err = api.SettingsGet(KeaDhcp4Settings)
	if err != nil {
		t.Fatal(err)
	}
	if form.Value("general.interfaces") != "lan" || form.Value("general.valid_lifetime") != "4000" || form.Value("ha.%this_server_name") != "OPNsense" {
		t.Errorf("form %+v", form)
	}
	if _, writable := form.Fields()["ha.%this_server_name"]; writable {
		t.Error("display fields must not be written back")
	}

	if err := api.SettingsSet(KeaDhcp4Settings, Fields{"general.valid_lifetime": "3600", "ha.enabled": "1"}); err != nil {
		t.Fatal(err)
	}
	wantBody(t, server.mutations()[0], `{"dhcpv4":{"general":{"valid_lifetime":"3600"},"ha":{"enabled":"1"}}}`)

	var setErr = api.SettingsSet(KeaDdnsSettings, Fields{"general.server_port": "x"})
	var validation *coreapi.ValidationError
	if !errors.As(setErr, &validation) || !strings.Contains(setErr.Error(), "valid port") {
		t.Errorf("want the validation error, got %v", setErr)
	}
	server.reset()
	if err := api.SettingsSet(KeaDhcp4Settings, nil); err == nil || len(server.recorded()) != 0 {
		t.Errorf("an empty set must not be sent: %v", err)
	}
}
