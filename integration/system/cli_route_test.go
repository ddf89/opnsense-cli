//go:build integration

package integrationsystem

import (
	"net/netip"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
)

// TestCliStaticRoute runs /system/route against the live instance. The routes are always disabled, go to a
// documentation network via a LAN gateway created here and are never applied (see route_test.go)
func TestCliStaticRoute(t *testing.T) {
	var sys = systemApi(t)
	var gateway = createRouteTestGateway(t, sys, "cli-route-gw")
	var description = testDescription("cli-route")
	var network = routeTestNetwork(t, "203.0.113")

	var created = mustOpn(t, "/system/route", "add", "network="+network, "gateway="+gateway.Name, "description="+description, "disabled")
	var uuid = uuidFrom(t, created)
	cleanupStaticRoute(t, sys, uuid)
	if strings.TrimSpace(created.stdout) != uuid {
		t.Errorf("add should print only the uuid:\n%s", created)
	}
	if route, err := sys.StaticRouteGet(uuid); err != nil || route.Enabled != "0" || route.Network != network ||
		route.Gateway != gateway.Name || route.Description != description {
		t.Fatalf("the route is not as added: %+v, %v", route, err)
	}

	var printed = mustOpn(t, "/system/route", "print", "search="+description)
	requireContains(t, printed, printed.stdout, "#", "DISABLED", "GATEWAY-IP", network, gateway.Name, gateway.Address, description, "yes")
	var detail = mustOpn(t, "/system/route", "print", "search="+description, "detail")
	requireContains(t, detail, detail.stdout, uuid, "gateway-ip:")
	var asJSON = mustOpn(t, "/system/route", "print", "search="+description, "json")
	requireContains(t, asJSON, asJSON.stdout, `"uuid":"`+uuid+`"`, `"enabled":"0"`)

	var show = mustOpn(t, "/system/route", "show", network)
	requireContains(t, show, show.stdout, uuid, "disabled:     yes", gateway.Name)

	requireNoStdout(t, mustOpn(t, "/system/route", "set", network, "description="+description+" changed"))
	if route, err := sys.StaticRouteGet(uuid); err != nil || route.Description != description+" changed" || route.Network != network || route.Enabled != "0" {
		t.Errorf("after set: %+v, %v", route, err)
	}

	var disable = mustOpn(t, "/system/route", "disable", uuid)
	requireContains(t, disable, disable.stderr, "already disabled")

	// the network names the route: add refuses a duplicate (also with host bits) unless replace is given
	var prefix = netip.MustParsePrefix(network)
	var withHostBits = netip.PrefixFrom(prefix.Addr().Next().Next().Next(), prefix.Bits()).String()
	var duplicate = mustFailOpn(t, "/system/route", "add", "network="+withHostBits, "gateway="+gateway.Name, "disabled")
	requireContains(t, duplicate, duplicate.stderr, "exists already", uuid)
	var replaced = mustOpn(t, "/system/route", "add", "network="+network, "gateway="+gateway.Name, "description="+description, "disabled", "replace")
	if replacedUuid := uuidFrom(t, replaced); replacedUuid != uuid {
		cleanupStaticRoute(t, sys, replacedUuid)
		t.Errorf("add replace created %s instead of replacing %s", replacedUuid, uuid)
	}
	if route, err := sys.StaticRouteGet(uuid); err != nil || route.Description != description || route.Enabled != "0" {
		t.Errorf("after add replace: %+v, %v", route, err)
	}

	// refused before anything is sent
	var v6 = mustFailOpn(t, "/system/route", "add", "network=2001:db8:a8::/48", "gateway="+gateway.Name, "description="+description, "disabled")
	requireContains(t, v6, v6.stderr, "needs an IPv6 gateway")
	var v6Set = mustFailOpn(t, "/system/route", "set", uuid, "network=2001:db8:a8::/48")
	requireContains(t, v6Set, v6Set.stderr, "needs an IPv6 gateway")
	var unknownGateway = mustFailOpn(t, "/system/route", "add", "network=198.51.100.0/24", "gateway="+gateway.Name+"_missing", "disabled")
	requireContains(t, unknownGateway, unknownGateway.stderr, "unknown gateway")
	if routes, err := sys.StaticRouteSearch(runPrefix); err != nil {
		t.Error(err)
	} else {
		for _, route := range routes {
			if route.Gateway == gateway.Name && route.Uuid != uuid {
				cleanupStaticRoute(t, sys, route.Uuid)
				t.Errorf("a refused command created %+v", route)
			}
		}
	}

	// move the route: host bits are cleared
	var moved = strings.TrimSuffix(network, "/29") + "/30"
	requireNoStdout(t, mustOpn(t, "/system/route", "set", uuid, "network="+moved))
	var showMoved = mustOpn(t, "/system/route", "show", moved)
	requireContains(t, showMoved, showMoved.stdout, uuid, "network:      "+moved)

	var missing = mustFailOpn(t, "/system/route", "show", "198.51.100.255/32")
	requireContains(t, missing, missing.stderr, "not found")

	requireNoStdout(t, mustOpn(t, "/system/route", "remove", moved))
	if _, err := sys.StaticRouteGet(uuid); !api.IsNotFound(err) {
		t.Errorf("the route still exists after remove: %v", err)
	}
	// apply is never run live: it would change the routing table of the shared instance
}
