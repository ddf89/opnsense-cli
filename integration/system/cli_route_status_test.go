//go:build integration

package integrationsystem

import (
	"encoding/json"
	"strings"
	"testing"
)

// /system/route/status is only read live. remove is never confirmed against the shared instance, only its
// refusals (which send nothing) are checked; the deletion itself is covered by cli/system_route_status_test.go

func TestCliRouteStatusPrint(t *testing.T) {
	var printed = mustOpn(t, "/system/route/status", "print")
	requireContains(t, printed, printed.stdout, "#", "PROTOCOL", "DESTINATION", "GATEWAY", "FLAGS", "INTERFACE", "MTU", "EXPIRE",
		"127.0.0.1", "Loopback (lo0)", "default", "ipv6")

	var ipv6 = mustOpn(t, "/system/route", "status", "print", "protocol=ipv6")
	requireContains(t, ipv6, ipv6.stdout, "ipv6")
	if strings.Contains(ipv6.stdout, "ipv4") {
		t.Errorf("protocol=ipv6 shows IPv4 routes:\n%s", ipv6)
	}

	var loopback = mustOpn(t, "/system/route/status", "print", "interface=lo0", "detail")
	requireContains(t, loopback, loopback.stdout, "device:", "lo0", "nhop:")
	if strings.Contains(loopback.stdout, "vtnet") {
		t.Errorf("interface=lo0 shows other interfaces:\n%s", loopback)
	}

	var resolved = mustOpn(t, "/system/route/status", "print", "resolve", "search=localhost")
	requireContains(t, resolved, resolved.stdout, "localhost")

	var asJSON = mustOpn(t, "/system/route/status", "print", "json", "protocol=ipv4")
	var lines = strings.Split(strings.TrimSpace(asJSON.stdout), "\n")
	for _, line := range lines {
		var route map[string]any
		if err := json.Unmarshal([]byte(line), &route); err != nil || route["proto"] != "ipv4" || route["netif"] == nil {
			t.Errorf("not a raw IPv4 route: %q (%v)", line, err)
		}
	}
	if len(lines) < 2 {
		t.Errorf("want several IPv4 routes:\n%s", asJSON)
	}
}

func TestCliRouteStatusRemoveRefused(t *testing.T) {
	// a default route is refused by name before the confirmation, and there is no confirm=yes anyway
	var refused = mustFailOpn(t, "/system/route/status", "remove", "default")
	requireContains(t, refused, refused.stderr, "refusing to delete a default route", "allow-default")

	// without confirm=yes nothing is run
	refused = mustFailOpn(t, "/system/route/status", "remove", "127.0.0.1")
	requireContains(t, refused, refused.stderr, "connectivity can be lost", "confirm=yes")

	// the route is still there
	var printed = mustOpn(t, "/system/route/status", "print", "search=127.0.0.1")
	requireContains(t, printed, printed.stdout, "127.0.0.1")
}
