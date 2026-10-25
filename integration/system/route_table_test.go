//go:build integration

package integrationsystem

import (
	"testing"
)

// The kernel routing table is only read live: del_route is never called against the shared instance (it would
// cut it off), RouteTableRemove is covered by the unit tests in opnsense/api/system and cli

func TestRouteTableList(t *testing.T) {
	var sys = systemApi(t)
	var routes, err = sys.RouteTableList(false)
	if err != nil {
		t.Fatalf("RouteTableList: %v", err)
	}
	if len(routes) == 0 {
		t.Fatal("empty routing table")
	}

	var keys = map[string]bool{}
	var loopback, ipv4Default bool
	for _, route := range routes {
		if route.Proto != "ipv4" && route.Proto != "ipv6" {
			t.Errorf("unexpected protocol in %+v", route)
		}
		if route.Destination == "" || route.Gateway == "" || route.Netif == "" || route.Flags == "" || len(route.Raw) == 0 {
			t.Errorf("incomplete route %+v", route)
		}
		if keys[route.Key()] {
			t.Errorf("duplicate route key %q", route.Key())
		}
		keys[route.Key()] = true
		if route.Proto == "ipv4" && route.Destination == "127.0.0.1" {
			loopback = route.Netif == "lo0" && route.IntfDescription == "Loopback"
		}
		ipv4Default = ipv4Default || route.Proto == "ipv4" && route.IsDefault()
	}
	if !loopback {
		t.Errorf("no IPv4 loopback route over lo0 (Loopback): %+v", routes)
	}
	if !ipv4Default {
		t.Errorf("no IPv4 default route: %+v", routes)
	}
	// netstat lists IPv4 first
	for i := 1; i < len(routes); i++ {
		if routes[i-1].Proto == "ipv6" && routes[i].Proto == "ipv4" {
			t.Errorf("IPv4 route after IPv6: %+v", routes[i])
		}
	}
}

func TestRouteTableListResolve(t *testing.T) {
	var sys = systemApi(t)
	var routes, err = sys.RouteTableList(false)
	if err != nil {
		t.Fatalf("RouteTableList: %v", err)
	}
	var resolved, resolveErr = sys.RouteTableList(true)
	if resolveErr != nil {
		t.Fatalf("RouteTableList(resolve): %v", resolveErr)
	}
	// same table, only names instead of addresses (it may change in between, so only roughly)
	if len(resolved) == 0 || len(resolved) < len(routes)-2 || len(resolved) > len(routes)+2 {
		t.Errorf("resolved table has %d routes, the numeric one %d", len(resolved), len(routes))
	}
	var localhost bool
	for _, route := range resolved {
		localhost = localhost || route.Destination == "localhost"
	}
	if !localhost {
		t.Errorf("resolve did not name 127.0.0.1 localhost: %+v", resolved)
	}
}

func TestRouteTableRemoveRefusesInvalidInput(t *testing.T) {
	var sys = systemApi(t)
	// refused locally, nothing is sent
	for _, args := range [][3]string{{"inet", "192.0.2.0/24", "192.0.2.1"}, {"ipv4", "", "192.0.2.1"}} {
		if err := sys.RouteTableRemove(args[0], args[1], args[2]); err == nil {
			t.Errorf("RouteTableRemove%q: want an error", args)
		}
	}
}
