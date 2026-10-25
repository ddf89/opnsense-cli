package system

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"strings"
	"testing"
)

// routeTableTestRoutes is a trimmed get_routes answer of OPNsense 26.7
const routeTableTestRoutes = `[` +
	`{"proto":"ipv4","destination":"default","gateway":"10.0.2.2","flags":"UGS","nhop#":"6","mtu":"1500","netif":"vtnet1","expire":"","intf_description":"WAN","id":"default,10.0.2.2"},` +
	`{"proto":"ipv4","destination":"10.0.2.0\/24","gateway":"link#2","flags":"U","nhop#":"4","mtu":"1500","netif":"vtnet1","expire":"","intf_description":"WAN","id":"10.0.2.0\/24,link#2"},` +
	`{"proto":"ipv6","destination":"default","gateway":"fe80::2%vtnet1","flags":"UG","nhop#":"8","mtu":"1500","netif":"vtnet1","expire":"","intf_description":"WAN","id":"default,fe80::2%vtnet1"}]`

type routeTableTestRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   string
}

// routeTableTestServer answers every path with responses[path] (unknown paths get an empty 200 like OPNsense)
func routeTableTestServer(t *testing.T, responses map[string]string) (*SystemApi, *[]routeTableTestRequest) {
	t.Helper()
	var requests []routeTableTestRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		requests = append(requests, routeTableTestRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Body: string(body)})
		if response, found := responses[r.URL.Path]; found {
			_, _ = io.WriteString(w, response)
		}
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &SystemApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, &requests
}

func TestRouteTableList(t *testing.T) {
	var api, requests = routeTableTestServer(t, map[string]string{"/api/diagnostics/interface/get_routes": routeTableTestRoutes})

	var routes, err = api.RouteTableList(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 3 {
		t.Fatalf("want 3 routes, got %d: %+v", len(routes), routes)
	}
	var subnet = routes[1]
	if subnet.Proto != "ipv4" || subnet.Destination != "10.0.2.0/24" || subnet.Gateway != "link#2" || subnet.Flags != "U" ||
		subnet.Nhop != "4" || subnet.Mtu != "1500" || subnet.Netif != "vtnet1" || subnet.IntfDescription != "WAN" ||
		subnet.Id != "10.0.2.0/24,link#2" {
		t.Errorf("unexpected route %+v", subnet)
	}
	if !strings.HasPrefix(string(subnet.Raw), `{"proto":"ipv4","destination":"10.0.2.0\/24"`) {
		t.Errorf("Raw must be the route as sent, got %s", subnet.Raw)
	}
	if subnet.Key() != "ipv4,10.0.2.0/24,link#2" || routes[2].Key() != "ipv6,default,fe80::2%vtnet1" {
		t.Errorf("unexpected keys %q %q", subnet.Key(), routes[2].Key())
	}
	if !routes[0].IsDefault() || subnet.IsDefault() || !routes[2].IsDefault() {
		t.Errorf("IsDefault wrong")
	}
	if (*requests)[0].Method != "GET" || len((*requests)[0].Query) != 0 {
		t.Errorf("want a GET without resolve, got %+v", (*requests)[0])
	}

	if _, err := api.RouteTableList(true); err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[1].Query.Get("resolve"); got != "yes" {
		t.Errorf("resolve: want resolve=yes, got %q", got)
	}
}

func TestRouteTableListErrors(t *testing.T) {
	for _, answer := range []string{`null`, `{"status":"failed"}`, ``} {
		var api, _ = routeTableTestServer(t, map[string]string{"/api/diagnostics/interface/get_routes": answer})
		if routes, err := api.RouteTableList(false); err == nil {
			t.Errorf("answer %q: want an error, got %+v", answer, routes)
		}
	}
	var api, _ = routeTableTestServer(t, map[string]string{"/api/diagnostics/interface/get_routes": `[]`})
	if routes, err := api.RouteTableList(false); err != nil || len(routes) != 0 {
		t.Errorf("empty table: got %+v, %v", routes, err)
	}
}

func TestRouteTableRemove(t *testing.T) {
	var api, requests = routeTableTestServer(t, map[string]string{"/api/diagnostics/interface/del_route": `{"message":"found"}`})
	if err := api.RouteTableRemove("ipv4", "10.99.0.0/24", "10.0.2.2"); err != nil {
		t.Fatal(err)
	}
	var request = (*requests)[0]
	if request.Method != "POST" || request.Path != "/api/diagnostics/interface/del_route" ||
		strings.TrimSpace(request.Body) != `{"destination":"10.99.0.0/24","family":"ipv4","gateway":"10.0.2.2"}` {
		t.Errorf("unexpected request %+v", request)
	}
}

func TestRouteTableRemoveErrors(t *testing.T) {
	for _, tc := range []struct {
		answer   string
		notFound bool
	}{
		{`{"message":"not_found"}`, true},
		{`{"message":"error"}`, false},
		{`{}`, false},
	} {
		var api, _ = routeTableTestServer(t, map[string]string{"/api/diagnostics/interface/del_route": tc.answer})
		var err = api.RouteTableRemove("ipv6", "fd00::/64", "link#2")
		var notFound *coreapi.NotFoundError
		if err == nil || errors.As(err, &notFound) != tc.notFound {
			t.Errorf("answer %s: got %v, want not found %v", tc.answer, err, tc.notFound)
		}
	}

	// invalid input is refused without a request
	var api, requests = routeTableTestServer(t, nil)
	for _, args := range [][3]string{{"inet", "10.0.0.0/8", "10.0.2.2"}, {"ipv4", "", "10.0.2.2"}} {
		if err := api.RouteTableRemove(args[0], args[1], args[2]); err == nil {
			t.Errorf("%q: want an error", args)
		}
	}
	if len(*requests) != 0 {
		t.Errorf("want no requests, got %+v", *requests)
	}
}
