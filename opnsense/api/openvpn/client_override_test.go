package openvpn

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

type clientOverrideTestRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   string
}

// newClientOverrideTestApi starts a fake OPNsense answering every request with handler (a value encoded as JSON, or
// a string sent as is), all requests are recorded
func newClientOverrideTestApi(t *testing.T, handler func(r clientOverrideTestRequest) any) (*OpenVPNApi, func() []clientOverrideTestRequest) {
	t.Helper()
	var mu sync.Mutex
	var requests []clientOverrideTestRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw, _ = io.ReadAll(r.Body)
		var recorded = clientOverrideTestRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Body: string(raw)}
		mu.Lock()
		requests = append(requests, recorded)
		mu.Unlock()
		switch answer := handler(recorded).(type) {
		case string:
			_, _ = io.WriteString(w, answer)
		default:
			_ = json.NewEncoder(w).Encode(answer)
		}
	}))
	t.Cleanup(server.Close)

	var baseUrl, _ = url.Parse(server.URL)
	return &OpenVPNApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, func() []clientOverrideTestRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]clientOverrideTestRequest(nil), requests...)
	}
}

func clientOverrideTestSearch(rows ...ClientOverride) any {
	return map[string]any{"rows": rows, "rowCount": len(rows), "total": len(rows), "current": 1}
}

var clientOverrideTestRows = []ClientOverride{
	{Uuid: "u-alice", Enabled: "1", CommonName: "alice", TunnelNetwork: "10.8.0.8/30"},
	{Uuid: "u-alice-office", Enabled: "1", CommonName: "alice", Servers: "s-office", ServersLabel: "office (1194 / UDP)"},
	{Uuid: "u-alice2", Enabled: "1", CommonName: "alice2"},
	{Uuid: "u-Alice", Enabled: "0", CommonName: "Alice", Servers: "s-home,s-office"},
}

const (
	clientOverrideTestSearchPath = "/api/openvpn/client_overwrites/search"
	clientOverrideTestAddPath    = "/api/openvpn/client_overwrites/add"
	clientOverrideTestSetPath    = "/api/openvpn/client_overwrites/set/"
)

func clientOverrideTestBody(t *testing.T, r clientOverrideTestRequest) map[string]string {
	t.Helper()
	var body map[string]map[string]string
	if err := json.Unmarshal([]byte(r.Body), &body); err != nil {
		t.Fatalf("invalid body %q: %v", r.Body, err)
	}
	return body["cso"]
}

func TestClientOverrideFindByKeyIsExact(t *testing.T) {
	var api, requests = newClientOverrideTestApi(t, func(r clientOverrideTestRequest) any {
		return clientOverrideTestSearch(clientOverrideTestRows...)
	})

	for _, tc := range []struct {
		commonName, servers string
		want                []string
	}{
		{"alice", "", []string{"u-alice"}},
		{"alice", "s-office", []string{"u-alice-office"}},
		{"alice", "S-OFFICE", []string{"u-alice-office"}},
		{"Alice", "s-office,s-home", []string{"u-Alice"}},
		{"Alice", " s-home , s-office,s-home", []string{"u-Alice"}},
		{"Alice", "s-home", nil},
		{"alic", "", nil},
	} {
		var found, err = api.ClientOverrideFindByKey(tc.commonName, tc.servers)
		if err != nil {
			t.Fatalf("%s/%s: %v", tc.commonName, tc.servers, err)
		}
		var uuids []string
		for _, o := range found {
			uuids = append(uuids, o.Uuid)
		}
		if !reflect.DeepEqual(uuids, tc.want) {
			t.Errorf("%s/%s: got %v, want %v", tc.commonName, tc.servers, uuids, tc.want)
		}
	}
	if got := requests()[0]; got.Path != clientOverrideTestSearchPath || got.Query.Get("searchPhrase") != "alice" {
		t.Errorf("unexpected search request %+v", got)
	}
}

func TestClientOverrideCreateSendsAllFields(t *testing.T) {
	var api, requests = newClientOverrideTestApi(t, func(r clientOverrideTestRequest) any {
		return map[string]string{"result": "saved", "uuid": "u-new"}
	})
	var uuid, err = api.ClientOverrideCreate(ClientOverride{CommonName: "bob", TunnelNetwork: "10.8.0.4/30", Description: "x"})
	if err != nil || uuid != "u-new" {
		t.Fatalf("got %q / %v", uuid, err)
	}
	var request = requests()[0]
	if request.Method != "POST" || request.Path != clientOverrideTestAddPath {
		t.Fatalf("unexpected request %+v", request)
	}
	var body = clientOverrideTestBody(t, request)
	if len(body) != len(ClientOverrideFieldNames) {
		t.Errorf("want all %d fields, got %v", len(ClientOverrideFieldNames), body)
	}
	for field, want := range map[string]string{"enabled": "1", "block": "0", "push_reset": "0", "register_dns": "0",
		"common_name": "bob", "tunnel_network": "10.8.0.4/30", "description": "x", "servers": ""} {
		if body[field] != want {
			t.Errorf("%s: got %q, want %q", field, body[field], want)
		}
	}
}

func TestClientOverrideUpdateChecksExistence(t *testing.T) {
	var api, requests = newClientOverrideTestApi(t, func(r clientOverrideTestRequest) any {
		if r.Path == clientOverrideTestSearchPath {
			return clientOverrideTestSearch(clientOverrideTestRows...)
		}
		return map[string]string{"result": "saved"}
	})

	// set/<unknown uuid> would create the override, so nothing must be sent
	var err = api.ClientOverrideUpdate("0f0f0f0f-1111-4222-8333-444455556666", ClientOverrideFields{"description": "x"})
	if !coreapi.IsNotFound(err) {
		t.Fatalf("want NotFoundError, got %v", err)
	}
	if len(requests()) != 1 {
		t.Errorf("want only the search, got %+v", requests())
	}

	if err = api.ClientOverrideUpdate("u-alice2", ClientOverrideFields{"description": "only this"}); err != nil {
		t.Fatal(err)
	}
	var set = requests()[2]
	if set.Path != clientOverrideTestSetPath+"u-alice2" || !reflect.DeepEqual(clientOverrideTestBody(t, set), map[string]string{"description": "only this"}) {
		t.Errorf("unexpected set %+v", set)
	}

	if err = api.ClientOverrideUpdate("u-alice2", ClientOverrideFields{"bogus": "x"}); err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Errorf("want an unknown field error, got %v", err)
	}
}

func TestClientOverrideUpdateValidation(t *testing.T) {
	var api, _ = newClientOverrideTestApi(t, func(r clientOverrideTestRequest) any {
		if r.Path == clientOverrideTestSearchPath {
			return clientOverrideTestSearch(clientOverrideTestRows...)
		}
		return `{"result":"failed","validations":{"cso.tunnel_network":"Please specify a valid network segment or IP address."}}`
	})
	var err = api.ClientOverrideUpdate("u-alice", ClientOverrideFields{"tunnel_network": "10.0.0.1"})
	var validation *coreapi.ValidationError
	if !errors.As(err, &validation) || !strings.Contains(err.Error(), "cso.tunnel_network") {
		t.Errorf("want a ValidationError, got %v", err)
	}
}

func TestClientOverrideCreateOrUpdate(t *testing.T) {
	var rows = append(append([]ClientOverride(nil), clientOverrideTestRows...),
		ClientOverride{Uuid: "u-dup1", CommonName: "dup"}, ClientOverride{Uuid: "u-dup2", CommonName: "dup"})
	var api, requests = newClientOverrideTestApi(t, func(r clientOverrideTestRequest) any {
		switch r.Path {
		case clientOverrideTestSearchPath:
			return clientOverrideTestSearch(rows...)
		case clientOverrideTestAddPath:
			return map[string]string{"result": "saved", "uuid": "u-new"}
		default:
			return map[string]string{"result": "saved"}
		}
	})

	var uuid, replaced, err = api.ClientOverrideCreateOrUpdate(ClientOverride{CommonName: "alice", Servers: "s-office", Block: "1"})
	if err != nil || uuid != "u-alice-office" || !replaced {
		t.Fatalf("got %q %v %v", uuid, replaced, err)
	}
	var last = requests()[len(requests())-1]
	if last.Path != clientOverrideTestSetPath+"u-alice-office" || clientOverrideTestBody(t, last)["block"] != "1" ||
		clientOverrideTestBody(t, last)["tunnel_network"] != "" {
		t.Errorf("want a complete set of u-alice-office, got %+v", last)
	}

	uuid, replaced, err = api.ClientOverrideCreateOrUpdate(ClientOverride{CommonName: "alice", Servers: "s-home"})
	if err != nil || uuid != "u-new" || replaced {
		t.Fatalf("other servers must add: got %q %v %v", uuid, replaced, err)
	}

	_, _, err = api.ClientOverrideCreateOrUpdate(ClientOverride{CommonName: "dup"})
	var tooMany *coreapi.TooManyFoundError
	if !errors.As(err, &tooMany) || !strings.Contains(err.Error(), "u-dup1, u-dup2") {
		t.Errorf("want TooManyFoundError naming the uuids, got %v", err)
	}
}

func TestClientOverrideRemove(t *testing.T) {
	var api, requests = newClientOverrideTestApi(t, func(r clientOverrideTestRequest) any {
		if strings.HasSuffix(r.Path, "/u-gone") {
			return map[string]string{"result": "not found"}
		}
		return map[string]string{"result": "deleted"}
	})
	if err := api.ClientOverrideRemove("u-alice"); err != nil {
		t.Fatal(err)
	}
	if got := requests()[0]; got.Method != "POST" || got.Path != "/api/openvpn/client_overwrites/del/u-alice" {
		t.Errorf("unexpected request %+v", got)
	}
	if err := api.ClientOverrideRemove("u-gone"); !coreapi.IsNotFound(err) || !strings.Contains(err.Error(), "u-gone") {
		t.Errorf("want NotFoundError, got %v", err)
	}
}

func TestClientOverrideSetEnabled(t *testing.T) {
	var api, requests = newClientOverrideTestApi(t, func(r clientOverrideTestRequest) any {
		switch {
		case strings.Contains(r.Path, "/u-gone/"):
			return map[string]string{"result": "failed"}
		case strings.HasSuffix(r.Path, "/1"):
			return map[string]any{"result": "Enabled", "changed": true}
		default:
			return map[string]any{"result": "Disabled", "changed": false}
		}
	})
	if changed, err := api.ClientOverrideSetEnabled("u-alice", true); err != nil || !changed {
		t.Errorf("enable: %v %v", changed, err)
	}
	if changed, err := api.ClientOverrideSetEnabled("u-alice", false); err != nil || changed {
		t.Errorf("disable: %v %v", changed, err)
	}
	if got := requests()[1]; got.Method != "POST" || got.Path != "/api/openvpn/client_overwrites/toggle/u-alice/0" || got.Body == "" {
		t.Errorf("unexpected request %+v (toggle needs a POST with a body)", got)
	}
	if _, err := api.ClientOverrideSetEnabled("u-gone", true); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
}

func TestClientOverrideServers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer string
		want   []ClientOverrideServer
		desc   []string
		err    string
	}{
		{name: "no servers", answer: `{"cso":{"servers":[],"common_name":""}}`},
		{name: "option map", answer: `{"cso":{"servers":{` +
			`"u-2":{"value":"office (1194 / UDP)","selected":0},` +
			`"u-1":{"value":" (1195 / TCP)","selected":1},` +
			`"3":{"value":"Legacy (srv) (1196 / UDP4)","selected":0}}}}`,
			want: []ClientOverrideServer{{"u-1", " (1195 / TCP)"}, {"3", "Legacy (srv) (1196 / UDP4)"}, {"u-2", "office (1194 / UDP)"}},
			desc: []string{"", "Legacy (srv)", "office"}},
		{name: "no cso", answer: `{}`, err: "no servers option list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var api, requests = newClientOverrideTestApi(t, func(r clientOverrideTestRequest) any { return tc.answer })
			var servers, err = api.ClientOverrideServers()
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Errorf("want error %q, got %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(servers, tc.want) {
				t.Errorf("got %+v, want %+v", servers, tc.want)
			}
			for i, server := range servers {
				if server.Description() != tc.desc[i] {
					t.Errorf("description of %q: got %q, want %q", server.Label, server.Description(), tc.desc[i])
				}
			}
			if got := requests()[0]; got.Method != "GET" || got.Path != "/api/openvpn/client_overwrites/get" {
				t.Errorf("unexpected request %+v", got)
			}
		})
	}
}

func TestClientOverridesForServer(t *testing.T) {
	var api, requests = newClientOverrideTestApi(t, func(r clientOverrideTestRequest) any {
		return clientOverrideTestSearch(clientOverrideTestRows...)
	})
	for id, want := range map[string][]string{
		"s-office": {"u-alice-office", "u-Alice"},
		"S-HOME":   {"u-Alice"},
		"s-none":   nil,
	} {
		var found, err = api.ClientOverridesForServer(id)
		if err != nil {
			t.Fatal(err)
		}
		var uuids []string
		for _, o := range found {
			uuids = append(uuids, o.Uuid)
		}
		if !reflect.DeepEqual(uuids, want) {
			t.Errorf("%s: got %v, want %v (overrides for all servers do not count)", id, uuids, want)
		}
	}
	if _, err := api.ClientOverridesForServer(""); err == nil {
		t.Errorf("an empty id must be refused")
	}
	if got := requests()[0]; got.Path != clientOverrideTestSearchPath || got.Query.Get("searchPhrase") != "" {
		t.Errorf("unexpected search request %+v", got)
	}
}
