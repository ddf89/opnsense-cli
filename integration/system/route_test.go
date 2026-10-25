//go:build integration

package integrationsystem

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
)

// Static routes (System > Routes > Configuration). Safety: every route is created disabled, to a random /29 of
// the documentation networks 198.51.100.0/24 and 203.0.113.0/24, via a LAN gateway created here (192.168.1.230-239,
// never the default, not monitored). The routes are never applied (no reconfigure), routes are removed before
// their gateway. The system gateways (WAN_DHCP, WAN_DHCP6, Null4, Null6) are never used or changed

// routeTestGateway is a LAN gateway created for one test
type routeTestGateway struct {
	Uuid    string
	Name    string
	Address string
}

func routeTestRandom(t *testing.T, n int64) int64 {
	t.Helper()
	var value, err = rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		t.Fatal(err)
	}
	return value.Int64()
}

// routeTestNetwork returns a random /29 of the documentation network base (198.51.100 or 203.0.113)
func routeTestNetwork(t *testing.T, base string) string {
	t.Helper()
	return fmt.Sprintf("%s.%d/29", base, routeTestRandom(t, 32)*8)
}

// createRouteTestGateway creates a LAN gateway owned by this run, registers its removal (registered first, so it
// runs after the removal of the routes) and waits until OPNsense offers it for routes (configd caches the list 20s)
func createRouteTestGateway(t *testing.T, sys *system.SystemApi, label string) routeTestGateway {
	t.Helper()
	var core = sys.OPNsense
	var random = make([]byte, 3)
	_, _ = rand.Read(random)
	var gateway = routeTestGateway{Name: "a8rt_" + hex.EncodeToString(random)}

	var lastErr error
	for attempt := 0; attempt < 5 && gateway.Uuid == ""; attempt++ {
		gateway.Address = fmt.Sprintf("192.168.1.%d", 230+routeTestRandom(t, 10))
		var body = map[string]any{"gateway_item": map[string]string{
			"name": gateway.Name, "interface": "lan", "ipprotocol": "inet", "gateway": gateway.Address,
			"defaultgw": "0", "monitor_disable": "1", "descr": testDescription(label),
		}}
		gateway.Uuid, lastErr = core.Mutate(core.EndpointForModule("routing/settings/add_gateway"), body)
	}
	if gateway.Uuid == "" {
		t.Fatalf("creating the test gateway %s failed: %v", gateway.Name, lastErr)
	}
	t.Cleanup(func() {
		if _, err := core.Mutate(core.EndpointForModule("routing/settings/del_gateway/"+gateway.Uuid), nil); err != nil {
			t.Errorf("cleanup of the test gateway %s (%s) failed: %v", gateway.Name, gateway.Uuid, err)
		}
		// nothing of this test may remain
		if routes, err := sys.StaticRouteList(); err == nil {
			for _, route := range routes {
				if route.Gateway == gateway.Name {
					t.Errorf("a route via the test gateway remains: %+v", route)
				}
			}
		}
		if rows, err := rawSearch(core, "routing/settings/search_gateway", ""); err == nil {
			for _, row := range rows {
				if row.Uuid == gateway.Uuid {
					t.Errorf("the test gateway %s remains", gateway.Name)
				}
			}
		}
	})

	var deadline = time.Now().Add(60 * time.Second)
	for {
		var gateways, err = sys.StaticRouteGateways()
		if err != nil {
			t.Fatal(err)
		}
		for _, offered := range gateways {
			if offered.Name == gateway.Name {
				return gateway
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the test gateway %s is not offered for routes after 60s", gateway.Name)
		}
		time.Sleep(2 * time.Second)
	}
}

// cleanupStaticRoute removes the route when the test ends
func cleanupStaticRoute(t *testing.T, sys *system.SystemApi, uuid string) {
	t.Helper()
	t.Cleanup(func() {
		if err := sys.StaticRouteRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of static route %s failed: %v", uuid, err)
		}
	})
}

// createStaticRoute creates a disabled route owned by this run and registers its removal
func createStaticRoute(t *testing.T, sys *system.SystemApi, route system.StaticRoute) string {
	t.Helper()
	route.Enabled = "0"
	var uuid, err = sys.StaticRouteCreate(route)
	if uuid != "" {
		cleanupStaticRoute(t, sys, uuid)
	}
	if err != nil {
		t.Fatalf("StaticRouteCreate(%+v): %v", route, err)
	}
	return uuid
}

func TestStaticRouteLifecycle(t *testing.T) {
	var sys = systemApi(t)
	var gateway = createRouteTestGateway(t, sys, "route-gw")
	var description = testDescription("route-lifecycle")
	var network = routeTestNetwork(t, "198.51.100")
	var uuid = createStaticRoute(t, sys, system.StaticRoute{Network: network, Gateway: gateway.Name, Description: description})

	t.Run("the gateway is offered as IPv4", func(t *testing.T) {
		var gateways, err = sys.StaticRouteGateways()
		if err != nil {
			t.Fatal(err)
		}
		for _, offered := range gateways {
			if offered.Name == gateway.Name {
				if offered.Address != gateway.Address || offered.Protocol() != "inet" {
					t.Errorf("offered as %+v (%s)", offered, offered.Protocol())
				}
				return
			}
		}
		t.Errorf("%s is not offered", gateway.Name)
	})

	t.Run("get returns the created fields", func(t *testing.T) {
		var route, err = sys.StaticRouteGet(uuid)
		if err != nil {
			t.Fatal(err)
		}
		var want = system.StaticRoute{Uuid: uuid, Network: network, Gateway: gateway.Name,
			GatewayDescription: gateway.Name + " - " + gateway.Address, Description: description, Enabled: "0"}
		if route != want {
			t.Errorf("got %+v\nwant %+v", route, want)
		}
		if route.GatewayAddress() != gateway.Address {
			t.Errorf("gateway address %q", route.GatewayAddress())
		}
	})

	t.Run("search", func(t *testing.T) {
		var routes, err = sys.StaticRouteSearch(description)
		if err != nil {
			t.Fatal(err)
		}
		if len(routes) != 1 || routes[0].Uuid != uuid {
			t.Errorf("search %q returned %+v", description, routes)
		}
	})

	t.Run("update changes only the given fields", func(t *testing.T) {
		var renamed = description + " renamed"
		if err := sys.StaticRouteUpdate(uuid, system.StaticRoutePatch{Description: &renamed}); err != nil {
			t.Fatal(err)
		}
		var route, err = sys.StaticRouteGet(uuid)
		if err != nil {
			t.Fatal(err)
		}
		if route.Description != renamed || route.Network != network || route.Gateway != gateway.Name || route.Enabled != "0" {
			t.Errorf("after update: %+v", route)
		}

		var moved = strings.TrimSuffix(network, "/29") + "/30"
		if err := sys.StaticRouteUpdate(uuid, system.StaticRoutePatch{Network: &moved, Description: &description}); err != nil {
			t.Fatal(err)
		}
		if route, err = sys.StaticRouteGet(uuid); err != nil || route.Network != moved || route.Description != description || route.Enabled != "0" {
			t.Errorf("after moving: %+v, %v", route, err)
		}
		network = moved
	})

	t.Run("disable an already disabled route changes nothing", func(t *testing.T) {
		// the routes are never enabled live, enabling is covered by the unit tests
		var changed, err = sys.StaticRouteSetEnabled(uuid, false)
		if err != nil || changed {
			t.Errorf("SetEnabled(false): changed %v, %v", changed, err)
		}
	})

	t.Run("OPNsense validates the network and the protocol of the gateway", func(t *testing.T) {
		for _, route := range []system.StaticRoute{
			{Network: "2001:db8:a8::/48", Gateway: gateway.Name, Description: description + " v6"},         // IPv6 via IPv4
			{Network: strings.TrimSuffix(network, "/30"), Gateway: gateway.Name, Description: description}, // no mask
			{Network: network, Gateway: gateway.Name + "_missing", Description: description},               // unknown gateway
		} {
			route.Enabled = "0"
			var created, err = sys.StaticRouteCreate(route)
			if created != "" {
				cleanupStaticRoute(t, sys, created)
			}
			var validationErr *api.ValidationError
			if !errors.As(err, &validationErr) || len(validationErr.Validations) == 0 {
				t.Errorf("create %+v: want a validation error, got %v", route, err)
			}
		}
	})

	t.Run("OPNsense accepts a second route for the same network", func(t *testing.T) {
		var second = createStaticRoute(t, sys, system.StaticRoute{Network: network, Gateway: gateway.Name, Description: description + " dup"})
		if err := sys.StaticRouteRemove(second); err != nil {
			t.Error(err)
		}
	})

	t.Run("unknown uuids are not found and not created", func(t *testing.T) {
		var unknown = "00000000-0000-4000-8000-" + strings.Repeat("a8", 6)
		var renamed = description + " ghost"
		var patch = system.StaticRoutePatch{Network: &network, Gateway: &gateway.Name, Description: &renamed, Enabled: strPtr("0")}
		if err := sys.StaticRouteUpdate(unknown, patch); !api.IsNotFound(err) {
			t.Errorf("update: want *NotFoundError, got %v", err)
		}
		if _, err := sys.StaticRouteGet(unknown); !api.IsNotFound(err) {
			cleanupStaticRoute(t, sys, unknown)
			t.Errorf("the update created %s: %v", unknown, err)
		}
		if err := sys.StaticRouteRemove(unknown); !api.IsNotFound(err) {
			t.Errorf("remove: want *NotFoundError, got %v", err)
		}
		if _, err := sys.StaticRouteSetEnabled(unknown, false); !api.IsNotFound(err) {
			t.Errorf("set enabled: want *NotFoundError, got %v", err)
		}
	})

	t.Run("remove", func(t *testing.T) {
		if err := sys.StaticRouteRemove(uuid); err != nil {
			t.Fatal(err)
		}
		if _, err := sys.StaticRouteGet(uuid); !api.IsNotFound(err) {
			t.Errorf("the route still exists after remove: %v", err)
		}
		if err := sys.StaticRouteRemove(uuid); !api.IsNotFound(err) {
			t.Errorf("second remove: want *NotFoundError, got %v", err)
		}
	})
}
