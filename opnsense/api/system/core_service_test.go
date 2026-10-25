package system

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

// coreTestCall is one request received by the core test server
type coreTestCall struct {
	Method string
	Path   string
	Body   string
}

// coreTestServer answers "METHOD /path" with canned answers ("<status> <body>" or just a JSON body), unknown
// routes with an empty 200 like OPNsense. It records all requests
type coreTestServer struct {
	mu     sync.Mutex
	routes map[string]string
	// sequences answer the n-th request of a route with the n-th answer, the last one repeats
	sequences map[string][]string
	counts    map[string]int
	calls     []coreTestCall
}

func newCoreTestApi(t *testing.T, routes map[string]string) (*SystemApi, *coreTestServer) {
	t.Helper()
	var server = &coreTestServer{routes: routes, sequences: map[string][]string{}, counts: map[string]int{}}
	var srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		server.mu.Lock()
		server.calls = append(server.calls, coreTestCall{Method: r.Method, Path: r.URL.Path, Body: string(body)})
		var route = r.Method + " " + r.URL.Path
		var answer, found = server.routes[route]
		if sequence := server.sequences[route]; len(sequence) > 0 {
			answer, found = sequence[min(server.counts[route], len(sequence)-1)], true
			server.counts[route]++
		}
		server.mu.Unlock()
		if !found {
			return
		}
		var status = 200
		if code, err := strconv.Atoi(answer[:min(3, len(answer))]); err == nil && len(answer) > 3 && answer[3] == ' ' {
			status, answer = code, answer[4:]
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(srv.Close)
	var serverUrl, err = url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &SystemApi{OPNsense: &coreapi.OPNsense{BaseUrl: *serverUrl, ApiKey: "key", ApiSecret: "secret"}}, server
}

func (s *coreTestServer) set(route string, answer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes[route] = answer
}

func (s *coreTestServer) sequence(route string, answers ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sequences[route] = answers
	s.counts[route] = 0
}

func (s *coreTestServer) recorded() []coreTestCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]coreTestCall(nil), s.calls...)
}

// posts returns the non GET requests
func (s *coreTestServer) posts() []coreTestCall {
	var result []coreTestCall
	for _, call := range s.recorded() {
		if call.Method != "GET" {
			result = append(result, call)
		}
	}
	return result
}

func coreTestWantError(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want error containing %q, got %v", want, err)
	}
}

// coreServiceTestSearch is a core/service/search answer of OPNsense 26.7 (with an instance service added)
const coreServiceTestSearch = `{"total":4,"rowCount":4,"current":1,"rows":[` +
	`{"id":"configd","locked":1,"running":1,"description":"Configd","name":"configd"},` +
	`{"id":"hostwatch","locked":0,"running":0,"description":"Hostwatch","name":"hostwatch"},` +
	`{"id":"openvpn\/1","locked":0,"running":"1","description":"OpenVPN server: road","name":"openvpn"},` +
	`{"locked":0,"running":true,"description":"No id","name":"noid"}]}`

func TestCoreServiceList(t *testing.T) {
	var api, server = newCoreTestApi(t, map[string]string{"GET /api/core/service/search": coreServiceTestSearch})
	var services, err = api.CoreServiceList()
	if err != nil {
		t.Fatal(err)
	}
	var want = []CoreService{
		{Id: "configd", Name: "configd", Description: "Configd", Running: true, Locked: true},
		{Id: "hostwatch", Name: "hostwatch", Description: "Hostwatch"},
		{Id: "openvpn/1", Name: "openvpn", Description: "OpenVPN server: road", Running: true},
		{Id: "noid", Name: "noid", Description: "No id", Running: true},
	}
	if !reflect.DeepEqual(services, want) {
		t.Errorf("got  %+v\nwant %+v", services, want)
	}
	if service, err := api.CoreServiceGet("openvpn/1"); err != nil || service.Description != "OpenVPN server: road" {
		t.Errorf("CoreServiceGet: %+v %v", service, err)
	}
	if _, err := api.CoreServiceGet("openvpn"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError for a name with instances, got %v", err)
	}
	if len(server.posts()) != 0 {
		t.Errorf("listing must not post: %v", server.posts())
	}
}

func TestCoreServiceActions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		call    func(*SystemApi, string) error
		id      string
		path    string
		answer  string
		wantErr string
	}{
		{"start", (*SystemApi).CoreServiceStart, "hostwatch", "/api/core/service/start/hostwatch", `{"result":"ok"}`, ""},
		{"stop", (*SystemApi).CoreServiceStop, "hostwatch", "/api/core/service/stop/hostwatch", `{"result":"ok"}`, ""},
		{"restart instance", (*SystemApi).CoreServiceRestart, "openvpn/1", "/api/core/service/restart/openvpn/1", `{"result":"ok"}`, ""},
		{"escaped", (*SystemApi).CoreServiceRestart, "a b/x?y", "/api/core/service/restart/a b/x?y", `{"result":"ok"}`, ""},
		{"failed", (*SystemApi).CoreServiceStart, "x", "/api/core/service/start/x", `{"result":"failed"}`, `result "failed"`},
		{"empty", (*SystemApi).CoreServiceStart, "x", "/api/core/service/start/x", ``, "empty response"},
		{"401", (*SystemApi).CoreServiceStop, "x", "/api/core/service/stop/x", `401 {"status":401,"message":"Authentication Failed"}`, "HTTP 401"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var api, server = newCoreTestApi(t, map[string]string{"POST " + tc.path: tc.answer})
			coreTestWantError(t, tc.call(api, tc.id), tc.wantErr)
			var calls = server.recorded()
			if len(calls) != 1 || calls[0].Method != "POST" || calls[0].Path != tc.path || calls[0].Body != "" {
				t.Errorf("want one POST %s without body, got %+v", tc.path, calls)
			}
		})
	}
}

func TestCoreServiceInvalidIds(t *testing.T) {
	var api, server = newCoreTestApi(t, map[string]string{})
	for _, id := range []string{"", " ", "a/b/c", "/x", "x/", "..", "a/.."} {
		if err := api.CoreServiceStop(id); err == nil {
			t.Errorf("%q: want an error", id)
		}
	}
	if len(server.recorded()) != 0 {
		t.Errorf("invalid ids must not be sent: %v", server.recorded())
	}
}
