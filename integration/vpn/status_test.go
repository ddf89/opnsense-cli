//go:build integration

package integrationvpn

import (
	"encoding/json"
	"strings"
	"testing"

	"opnsense-cli/opnsense/api/openvpn"
)

// The shared box has no running OpenVPN instance, so the session and route lists hold at most enabled instances that
// are not running. Sessions are never killed live: remove is only run where it can not reach kill_session

func TestSessionAndRouteList(t *testing.T) {
	var core = coreApi(t)
	var vpn = &openvpn.OpenVPNApi{OPNsense: core}
	// a disabled instance is not listed (only enabled ones that are not running are)
	var instance = csoCreateServerInstance(t, core, "session-server")

	var sessions, err = vpn.SessionList("")
	if err != nil {
		t.Fatalf("SessionList: %v", err)
	}
	for _, session := range sessions {
		if session.InstanceId() == instance {
			t.Errorf("the disabled instance is listed: %+v", session)
		}
		if session.IsClient {
			t.Logf("unexpected connected client on the dev box: %s %s", session.CommonName, session.RealAddress)
		}
	}
	if _, err := vpn.SessionList("", "server", "client"); err != nil {
		t.Errorf("SessionList with types: %v", err)
	}
	if _, err := vpn.RouteList(""); err != nil {
		t.Errorf("RouteList: %v", err)
	}
	if _, err := vpn.RouteList(runPrefix, "server"); err != nil {
		t.Errorf("RouteList with search and type: %v", err)
	}
}

func TestCliSessionRoutePrint(t *testing.T) {
	requireLive(t)

	var sessions = mustOpn(t, "/vpn/openvpn/session", "print")
	requireContains(t, sessions, sessions.stdout, "#", "INSTANCE", "COMMON-NAME", "REAL-ADDRESS", "CONNECTED-SINCE", "STATUS")
	for _, args := range [][]string{
		{"/vpn/openvpn/session", "print", "json"},
		{"/vpn/openvpn/session", "print", "json", "type=server"},
		{"/vpn/openvpn/route", "print", "json"},
	} {
		var result = mustOpn(t, args...)
		for _, line := range strings.Split(strings.TrimSpace(result.stdout), "\n") {
			if line != "" && !json.Valid([]byte(line)) {
				t.Errorf("not a JSON line %q:\n%s", line, result)
			}
		}
	}
	mustOpn(t, "/vpn/openvpn/session", "print", "detail")

	var routes = mustOpn(t, "/vpn/openvpn/route", "print")
	requireContains(t, routes, routes.stdout, "#", "INSTANCE", "TARGET", "COMMON-NAME", "LAST-REF")

	// no session carries this run's prefix: remove fails while selecting, before kill_session is called
	var unknown = mustFailOpn(t, "/vpn/openvpn/session", "remove", runPrefix+"-nobody", "confirm=yes")
	requireContains(t, unknown, unknown.stderr, "not found")
	// without confirmation nothing is even queried
	var refused = mustFailOpn(t, "/vpn/openvpn/session", "kill", runPrefix+"-nobody")
	requireContains(t, refused, refused.stderr, "confirm=yes")
}
