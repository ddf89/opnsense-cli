package system

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

// staticRouteTestSearchAnswer is searchroute as OPNsense 26.7 answers it
const staticRouteTestSearchAnswer = `{"rows":[
 {"uuid":"r1","network":"198.51.100.0\/24","gateway":"LAN_GW","%gateway":"LAN_GW - 192.168.1.230","descr":"doc net","enabled":"0"},
 {"uuid":"r2","network":"2001:db8::\/32","gateway":"Null6","%gateway":"Null6 - ::1","descr":"","enabled":"1"}
],"rowCount":2,"total":2,"current":1}`

// staticRouteTestGetAnswer is getroute without uuid: the defaults of a new route with the gateway options
const staticRouteTestGetAnswer = `{"route":{"network":"","gateway":{
 "Null4":{"value":"Null4 - 127.0.0.1","selected":0},"Null6":{"value":"Null6 - ::1","selected":0},
 "WAN_DHCP":{"value":"WAN_DHCP - 10.0.2.2","selected":0},"WAN_DHCP6":{"value":"WAN_DHCP6 - inet6","selected":0},
 "my-gw":{"value":"my-gw - 192.168.1.230","selected":0},"NOADDR":{"value":"NOADDR","selected":0}},
 "descr":"","enabled":"1"}}`

type staticRouteTestCall struct {
	Method string
	Path   string
	Query  string
	Body   string
}

// staticRouteTestServer answers searchroute and getroute with the canned answers and the other paths from
// answers, recording every call
func staticRouteTestServer(t *testing.T, answers map[string]string) (*SystemApi, func() []staticRouteTestCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []staticRouteTestCall
	var api = cronTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, staticRouteTestCall{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Body: strings.TrimSpace(string(body))})
		mu.Unlock()

		var key = r.Method + " " + r.URL.Path
		if answer, ok := answers[key]; ok {
			_, _ = io.WriteString(w, answer)
			return
		}
		switch key {
		case "GET /api/routes/routes/searchroute":
			_, _ = io.WriteString(w, staticRouteTestSearchAnswer)
		case "GET /api/routes/routes/getroute":
			_, _ = io.WriteString(w, staticRouteTestGetAnswer)
		default:
			t.Errorf("unexpected request %s", key)
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errorMessage":"Endpoint not found"}`)
		}
	})
	return api, func() []staticRouteTestCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]staticRouteTestCall(nil), calls...)
	}
}

// staticRouteTestMutations returns the non GET calls
func staticRouteTestMutations(calls []staticRouteTestCall) []staticRouteTestCall {
	var mutations []staticRouteTestCall
	for _, call := range calls {
		if call.Method != "GET" {
			mutations = append(mutations, call)
		}
	}
	return mutations
}

func staticRouteTestWantBody(t *testing.T, call staticRouteTestCall, want string) {
	t.Helper()
	var got, wanted any
	if err := json.Unmarshal([]byte(call.Body), &got); err != nil {
		t.Fatalf("body of %s %s is not JSON: %q", call.Method, call.Path, call.Body)
	}
	if err := json.Unmarshal([]byte(want), &wanted); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, wanted) {
		t.Errorf("body of %s %s: got %s, want %s", call.Method, call.Path, call.Body, want)
	}
}

func TestStaticRouteListDecodesRows(t *testing.T) {
	var api, _ = staticRouteTestServer(t, nil)
	var routes, err = api.StaticRouteList()
	if err != nil {
		t.Fatal(err)
	}
	var want = []StaticRoute{
		{Uuid: "r1", Network: "198.51.100.0/24", Gateway: "LAN_GW", GatewayDescription: "LAN_GW - 192.168.1.230", Description: "doc net", Enabled: "0"},
		{Uuid: "r2", Network: "2001:db8::/32", Gateway: "Null6", GatewayDescription: "Null6 - ::1", Enabled: "1"},
	}
	if !reflect.DeepEqual(routes, want) {
		t.Errorf("got %+v\nwant %+v", routes, want)
	}
	if routes[0].GatewayAddress() != "192.168.1.230" || routes[1].GatewayAddress() != "::1" {
		t.Errorf("gateway addresses %q, %q", routes[0].GatewayAddress(), routes[1].GatewayAddress())
	}
}

func TestStaticRouteSearchSendsPhrase(t *testing.T) {
	var api, calls = staticRouteTestServer(t, nil)
	if _, err := api.StaticRouteSearch("doc net&x"); err != nil {
		t.Fatal(err)
	}
	if got := calls(); len(got) != 1 || got[0].Query != "searchPhrase=doc+net%26x" {
		t.Errorf("calls %+v", got)
	}
}

func TestStaticRouteGet(t *testing.T) {
	var api, _ = staticRouteTestServer(t, nil)
	var route, err = api.StaticRouteGet("R2")
	if err != nil {
		t.Fatal(err)
	}
	if route.Uuid != "r2" || route.Network != "2001:db8::/32" {
		t.Errorf("got %+v", route)
	}
	if _, err := api.StaticRouteGet("r3"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found for an unknown uuid, got %v", err)
	}
}

func TestStaticRouteCreate(t *testing.T) {
	var api, calls = staticRouteTestServer(t, map[string]string{
		"POST /api/routes/routes/addroute": `{"result":"saved","uuid":"new-uuid"}`,
	})
	var uuid, err = api.StaticRouteCreate(StaticRoute{Uuid: "ignored", Network: "203.0.113.0/24", Gateway: "my-gw", Enabled: "0",
		GatewayDescription: "ignored"})
	if err != nil {
		t.Fatal(err)
	}
	if uuid != "new-uuid" {
		t.Errorf("uuid %q", uuid)
	}
	var mutations = staticRouteTestMutations(calls())
	if len(mutations) != 1 {
		t.Fatalf("mutations %+v", mutations)
	}
	staticRouteTestWantBody(t, mutations[0], `{"route":{"network":"203.0.113.0/24","gateway":"my-gw","enabled":"0"}}`)

	t.Run("validation failure", func(t *testing.T) {
		var api, _ = staticRouteTestServer(t, map[string]string{
			"POST /api/routes/routes/addroute": `{"result":"failed","validations":{"route.gateway":"Specify a valid gateway from the list matching the networks ip protocol."}}`,
		})
		var _, err = api.StaticRouteCreate(StaticRoute{Network: "2001:db8::/48", Gateway: "my-gw"})
		var validationErr *coreapi.ValidationError
		if !errors.As(err, &validationErr) || !strings.Contains(err.Error(), "route.gateway") {
			t.Errorf("want a validation error, got %v", err)
		}
	})
}

func TestStaticRouteUpdate(t *testing.T) {
	var description = "renamed"
	var network = "203.0.113.0/24"
	for _, tc := range []struct {
		name  string
		patch StaticRoutePatch
		want  string
	}{
		{"the current network is always sent", StaticRoutePatch{Description: &description},
			`{"route":{"network":"198.51.100.0/24","descr":"renamed"}}`},
		{"a new network", StaticRoutePatch{Network: &network}, `{"route":{"network":"203.0.113.0/24"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var api, calls = staticRouteTestServer(t, map[string]string{
				"POST /api/routes/routes/setroute/r1": `{"result":"saved"}`,
			})
			if err := api.StaticRouteUpdate("r1", tc.patch); err != nil {
				t.Fatal(err)
			}
			var mutations = staticRouteTestMutations(calls())
			if len(mutations) != 1 {
				t.Fatalf("mutations %+v", mutations)
			}
			staticRouteTestWantBody(t, mutations[0], tc.want)
		})
	}

	t.Run("unknown uuid is not sent, OPNsense would create it", func(t *testing.T) {
		var api, calls = staticRouteTestServer(t, nil)
		if err := api.StaticRouteUpdate("00000000-0000-4000-8000-000000000001", StaticRoutePatch{Description: &description}); !coreapi.IsNotFound(err) {
			t.Errorf("want not found, got %v", err)
		}
		if mutations := staticRouteTestMutations(calls()); len(mutations) != 0 {
			t.Errorf("mutations %+v", mutations)
		}
	})
	t.Run("removed meanwhile", func(t *testing.T) {
		var api, _ = staticRouteTestServer(t, map[string]string{"POST /api/routes/routes/setroute/r1": `{"result":"failed"}`})
		if err := api.StaticRouteUpdate("r1", StaticRoutePatch{Description: &description}); !coreapi.IsNotFound(err) {
			t.Errorf("want not found, got %v", err)
		}
	})
	t.Run("validation failure", func(t *testing.T) {
		var api, _ = staticRouteTestServer(t, map[string]string{
			"POST /api/routes/routes/setroute/r1": `{"result":"failed","validations":{"route.enabled":"Value should be a boolean (0,1)."}}`,
		})
		var err = api.StaticRouteUpdate("r1", StaticRoutePatch{Description: &description})
		if err == nil || coreapi.IsNotFound(err) || !strings.Contains(err.Error(), "route.enabled") {
			t.Errorf("want a validation error, got %v", err)
		}
	})
	t.Run("empty uuid", func(t *testing.T) {
		var api, calls = staticRouteTestServer(t, nil)
		if err := api.StaticRouteUpdate("", StaticRoutePatch{}); err == nil {
			t.Error("want an error")
		}
		if len(calls()) != 0 {
			t.Errorf("calls %+v", calls())
		}
	})
}

func TestStaticRouteRemove(t *testing.T) {
	var api, calls = staticRouteTestServer(t, map[string]string{
		"POST /api/routes/routes/delroute/r1":   `{"result":"deleted"}`,
		"POST /api/routes/routes/delroute/nope": `{"result":"not found"}`,
	})
	if err := api.StaticRouteRemove("r1"); err != nil {
		t.Fatal(err)
	}
	if err := api.StaticRouteRemove("nope"); !coreapi.IsNotFound(err) || !strings.Contains(err.Error(), "static route nope") {
		t.Errorf("want not found, got %v", err)
	}
	if err := api.StaticRouteRemove(""); err == nil {
		t.Error("want an error for an empty uuid")
	}
	if got := len(calls()); got != 2 {
		t.Errorf("want 2 calls, got %d", got)
	}
}

func TestStaticRouteSetEnabled(t *testing.T) {
	for _, tc := range []struct {
		enabled bool
		answer  string
		path    string
		changed bool
	}{
		{true, `{"result":"Enabled","changed":true}`, "/api/routes/routes/toggleroute/r1/1", true},
		{false, `{"result":"Disabled","changed":false}`, "/api/routes/routes/toggleroute/r1/0", false},
	} {
		var api, calls = staticRouteTestServer(t, map[string]string{"POST " + tc.path: tc.answer})
		var changed, err = api.StaticRouteSetEnabled("r1", tc.enabled)
		if err != nil {
			t.Fatal(err)
		}
		if changed != tc.changed {
			t.Errorf("%s: changed %v", tc.path, changed)
		}
		if got := calls(); len(got) != 1 || got[0].Method != "POST" {
			t.Errorf("calls %+v", got)
		}
	}

	var api, _ = staticRouteTestServer(t, map[string]string{
		"POST /api/routes/routes/toggleroute/nope/0": `{"result":"failed"}`,
		"POST /api/routes/routes/toggleroute/odd/0":  `{"result":"what"}`,
	})
	if _, err := api.StaticRouteSetEnabled("nope", false); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if _, err := api.StaticRouteSetEnabled("odd", false); err == nil || coreapi.IsNotFound(err) {
		t.Errorf("want an unexpected result error, got %v", err)
	}
}

func TestStaticRouteGateways(t *testing.T) {
	var api, _ = staticRouteTestServer(t, nil)
	var gateways, err = api.StaticRouteGateways()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, gateway := range gateways {
		got = append(got, gateway.Name+"|"+gateway.Address+"|"+gateway.Protocol())
	}
	var want = []string{"NOADDR||", "Null4|127.0.0.1|inet", "Null6|::1|inet6", "WAN_DHCP|10.0.2.2|inet", "WAN_DHCP6|inet6|inet6",
		"my-gw|192.168.1.230|inet"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}

	t.Run("no gateways", func(t *testing.T) {
		var api, _ = staticRouteTestServer(t, map[string]string{
			"GET /api/routes/routes/getroute": `{"route":{"network":"","gateway":[],"descr":"","enabled":"1"}}`,
		})
		var gateways, err = api.StaticRouteGateways()
		if err != nil || len(gateways) != 0 {
			t.Errorf("got %+v, %v", gateways, err)
		}
	})
}

func TestStaticRouteReconfigure(t *testing.T) {
	var api, calls = staticRouteTestServer(t, map[string]string{"POST /api/routes/routes/reconfigure": `{"status":"ok"}`})
	if err := api.StaticRouteReconfigure(); err != nil {
		t.Fatal(err)
	}
	if got := calls(); len(got) != 1 || got[0].Method != "POST" {
		t.Errorf("calls %+v", got)
	}

	var failing, _ = staticRouteTestServer(t, map[string]string{
		"POST /api/routes/routes/reconfigure": `{"status":"error reloading routes (failed)"}`,
	})
	if err := failing.StaticRouteReconfigure(); err == nil || !strings.Contains(err.Error(), "error reloading routes") {
		t.Errorf("want the status in the error, got %v", err)
	}
}
