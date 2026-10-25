package cli

import (
	"net/http"
	"strings"
	"testing"
)

const (
	systemRouteStatusListPath = "/api/diagnostics/interface/get_routes"
	systemRouteStatusDelPath  = "/api/diagnostics/interface/del_route"
)

// systemRouteStatusRoutes is a trimmed get_routes answer of OPNsense 26.7 (plus a static route 10.99.0.0/24)
const systemRouteStatusRoutes = `[` +
	`{"proto":"ipv4","destination":"default","gateway":"10.0.2.2","flags":"UGS","nhop#":"6","mtu":"1500","netif":"vtnet1","expire":"","intf_description":"WAN","id":"default,10.0.2.2"},` +
	`{"proto":"ipv4","destination":"10.0.2.0\/24","gateway":"link#2","flags":"U","nhop#":"4","mtu":"1500","netif":"vtnet1","expire":"","intf_description":"WAN","id":"10.0.2.0\/24,link#2"},` +
	`{"proto":"ipv4","destination":"10.99.0.0\/24","gateway":"192.168.1.254","flags":"UGS","nhop#":"9","mtu":"1500","netif":"vtnet0","expire":"","intf_description":"LAN","id":"10.99.0.0\/24,192.168.1.254"},` +
	`{"proto":"ipv4","destination":"127.0.0.1","gateway":"link#3","flags":"UH","nhop#":"2","mtu":"16384","netif":"lo0","expire":"","intf_description":"Loopback","id":"127.0.0.1,link#3"},` +
	`{"proto":"ipv6","destination":"default","gateway":"fe80::2%vtnet1","flags":"UG","nhop#":"8","mtu":"1500","netif":"vtnet1","expire":"","intf_description":"WAN","id":"default,fe80::2%vtnet1"},` +
	`{"proto":"ipv6","destination":"fd00:99::\/64","gateway":"fd00::254","flags":"UGS","nhop#":"10","mtu":"1500","netif":"ovpns1","expire":"","intf_description":"","id":"fd00:99::\/64,fd00::254"}]`

// systemRouteStatusResolved is the same table with resolve=yes
const systemRouteStatusResolved = `[` +
	`{"proto":"ipv4","destination":"default","gateway":"10.0.2.2","flags":"UGS","nhop#":"6","mtu":"1500","netif":"vtnet1","expire":"","intf_description":"WAN","id":"default,10.0.2.2"},` +
	`{"proto":"ipv4","destination":"10.0.2.0\/24","gateway":"link#2","flags":"U","nhop#":"4","mtu":"1500","netif":"vtnet1","expire":"","intf_description":"WAN","id":"10.0.2.0\/24,link#2"},` +
	`{"proto":"ipv4","destination":"branch-net","gateway":"branch-gw","flags":"UGS","nhop#":"9","mtu":"1500","netif":"vtnet0","expire":"","intf_description":"LAN","id":"branch-net,branch-gw"},` +
	`{"proto":"ipv4","destination":"localhost","gateway":"link#3","flags":"UH","nhop#":"2","mtu":"16384","netif":"lo0","expire":"","intf_description":"Loopback","id":"localhost,link#3"},` +
	`{"proto":"ipv6","destination":"default","gateway":"fe80::2%vtnet1","flags":"UG","nhop#":"8","mtu":"1500","netif":"vtnet1","expire":"","intf_description":"WAN","id":"default,fe80::2%vtnet1"},` +
	`{"proto":"ipv6","destination":"fd00:99::\/64","gateway":"fd00::254","flags":"UGS","nhop#":"10","mtu":"1500","netif":"ovpns1","expire":"","intf_description":"","id":"fd00:99::\/64,fd00::254"}]`

var systemRouteStatusHeader = []string{"#", "PROTOCOL", "DESTINATION", "GATEWAY", "FLAGS", "INTERFACE", "MTU", "EXPIRE"}

// systemRouteStatusFake serves get_routes (resolved with ?resolve=yes) and answers del_route with delAnswer
func systemRouteStatusFake(t *testing.T, delAnswer string) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.onFunc("GET", systemRouteStatusListPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("resolve") != "" {
			_, _ = w.Write([]byte(systemRouteStatusResolved))
			return
		}
		_, _ = w.Write([]byte(systemRouteStatusRoutes))
	})
	f.on("POST", systemRouteStatusDelPath, 200, delAnswer)
	return f
}

func systemRouteStatus(args ...string) []string {
	return append([]string{"/system/route/status"}, args...)
}

func TestSystemRouteStatusPrint(t *testing.T) {
	t.Parallel()
	var f = systemRouteStatusFake(t, `{"message":"found"}`)
	var r = f.run(systemRouteStatus("print")...)
	wantExit(t, r, 0)
	var rows = systemLoggingWantTable(t, r.stdout, systemRouteStatusHeader, 2,
		"default", "10.0.2.0/24", "10.99.0.0/24", "127.0.0.1", "default", "fd00:99::/64")
	if got := strings.Join(rows[3], "|"); got != "2|ipv4|10.99.0.0/24|192.168.1.254|UGS|LAN (vtnet0)|1500|-" {
		t.Errorf("row 2: %s", got)
	}
	if got := rows[6][5]; got != "ovpns1" {
		t.Errorf("an interface without description shows the device, got %q", got)
	}
	if len(f.calls()) != 1 || len(f.calls()[0].Query) != 0 {
		t.Errorf("want one GET without resolve, got %v", f.calls())
	}

	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"protocol=ipv6"}, []string{"default", "fd00:99::/64"}},
		{[]string{"interface=wan"}, []string{"default", "10.0.2.0/24", "default"}},
		{[]string{"interface=vtnet0,OVPNS1"}, []string{"10.99.0.0/24", "fd00:99::/64"}},
		{[]string{"protocol=ipv4", "interface=WAN"}, []string{"default", "10.0.2.0/24"}},
		{[]string{"search=UGS"}, []string{"default", "10.99.0.0/24", "fd00:99::/64"}},
		{[]string{"search=loopback"}, []string{"127.0.0.1"}},
		{[]string{"search=nothing-matches"}, nil},
	} {
		var r = f.run(systemRouteStatus(append([]string{"print"}, tc.args...)...)...)
		wantExit(t, r, 0)
		systemLoggingWantTable(t, r.stdout, systemRouteStatusHeader, 2, tc.want...)
	}
	wantFailure(t, f.run(systemRouteStatus("print", "protocol=inet")...), "protocol", "ipv4, ipv6")
	wantNoMutations(t, f)
}

func TestSystemRouteStatusPrintResolve(t *testing.T) {
	t.Parallel()
	var f = systemRouteStatusFake(t, `{"message":"found"}`)
	var r = f.run(systemRouteStatus("print", "resolve")...)
	wantExit(t, r, 0)
	systemLoggingWantTable(t, r.stdout, systemRouteStatusHeader, 2,
		"default", "10.0.2.0/24", "branch-net", "localhost", "default", "fd00:99::/64")
	if got := f.calls()[0].Query.Get("resolve"); got != "yes" {
		t.Errorf("want resolve=yes, got %v", f.calls())
	}
}

func TestSystemRouteStatusPrintJSONAndDetail(t *testing.T) {
	t.Parallel()
	var f = systemRouteStatusFake(t, `{"message":"found"}`)
	var r = f.run(systemRouteStatus("print", "json", "protocol=ipv6")...)
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 2 || lines[1] != `{"proto":"ipv6","destination":"fd00:99::\/64","gateway":"fd00::254","flags":"UGS","nhop#":"10","mtu":"1500","netif":"ovpns1","expire":"","intf_description":"","id":"fd00:99::\/64,fd00::254"}` {
		t.Errorf("want the raw routes, one per line:\n%s", r.stdout)
	}

	r = f.run(systemRouteStatus("print", "detail", "search=10.99")...)
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "0\n", "protocol:", "destination:  10.99.0.0/24", "gateway:      192.168.1.254",
		"interface:    LAN", "device:       vtnet0", "nhop:         9")
}

func TestSystemRouteStatusFollow(t *testing.T) {
	t.Parallel()
	var f = systemRouteStatusFake(t, `{"message":"found"}`)
	var p = f.start(systemRouteStatus("print", "follow", "interval=20ms", "protocol=ipv6")...)
	f.waitForConnections(systemRouteStatusListPath, 3)
	p.waitFor("fd00:99::/64")
	var r = p.interrupt()
	wantExit(t, r, 0)
	var refreshes = strings.Count(r.stdout, "fd00:99::/64")
	if refreshes < 2 || strings.Count(r.stdout, "--- ") != refreshes || strings.Contains(r.stdout, "10.99.0.0") {
		t.Errorf("want several filtered refreshes, each with a separator:\n%s", r.stdout)
	}
	wantNoMutations(t, f)
}

func TestSystemRouteStatusRemove(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		want map[string]any
	}{
		{"by destination", []string{"10.99.0.0/24"}, map[string]any{"family": "ipv4", "destination": "10.99.0.0/24", "gateway": "192.168.1.254"}},
		{"by #", []string{"5"}, map[string]any{"family": "ipv6", "destination": "fd00:99::/64", "gateway": "fd00::254"}},
		{"connected", []string{"item=10.0.2.0/24"}, map[string]any{"family": "ipv4", "destination": "10.0.2.0/24", "gateway": "link#2"}},
		{"by key", []string{"ipv6,fd00:99::/64,fd00::254"}, map[string]any{"family": "ipv6", "destination": "fd00:99::/64", "gateway": "fd00::254"}},
		{"default by # with allow-default", []string{"0", "allow-default"}, map[string]any{"family": "ipv4", "destination": "default", "gateway": "10.0.2.2"}},
		{"default by key with allow-default", []string{"ipv6,default,fe80::2%vtnet1", "allow-default"},
			map[string]any{"family": "ipv6", "destination": "default", "gateway": "fe80::2%vtnet1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = systemRouteStatusFake(t, `{"message":"found"}`)
			var r = f.run(systemRouteStatus(append(append([]string{"remove"}, tc.args...), "confirm=yes")...)...)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("remove must be silent, got %q", r.stdout)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", systemRouteStatusDelPath), tc.want)
		})
	}
}

func TestSystemRouteStatusRemoveNeedsConfirmation(t *testing.T) {
	t.Parallel()
	var f = systemRouteStatusFake(t, `{"message":"found"}`)
	var r = f.run(systemRouteStatus("remove", "10.99.0.0/24")...)
	wantFailure(t, r, systemRouteStatusRemoveConfirm, "confirm=yes")
	r = f.run(systemRouteStatus("remove", "10.99.0.0/24", "confirm=no")...)
	wantFailure(t, r, "confirm=yes")
	wantNoCalls(t, f)
}

func TestSystemRouteStatusRemoveRefusesDefault(t *testing.T) {
	t.Parallel()
	var f = systemRouteStatusFake(t, `{"message":"found"}`)
	// by name: refused before the confirmation, nothing is sent
	for _, item := range []string{"default", "DEFAULT", "0.0.0.0/0", "::/0", "ipv6,default,fe80::2%vtnet1"} {
		wantFailure(t, f.run(systemRouteStatus("remove", item)...), "refusing to delete a default route", "allow-default")
	}
	wantNoCalls(t, f)
	// by #: refused once resolved
	wantFailure(t, f.run(systemRouteStatus("remove", "4", "confirm=yes")...), "refusing to delete a default route")
	wantFailure(t, f.runScript("/system/route/status\nprint\nremove 0 confirm=yes\n"), "refusing to delete a default route")
	wantNoMutations(t, f)
}

func TestSystemRouteStatusRemoveErrors(t *testing.T) {
	t.Parallel()
	var f = systemRouteStatusFake(t, `{"message":"found"}`)
	wantFailure(t, f.run(systemRouteStatus("remove", "10.1.2.0/24", "confirm=yes")...), "not found", "10.1.2.0/24")
	wantFailure(t, f.run(systemRouteStatus("remove", "17", "confirm=yes")...), "not found", "#17")
	// default exists for both families
	wantFailure(t, f.run(systemRouteStatus("remove", "default", "allow-default", "confirm=yes")...), "too many found", "ipv4,default,10.0.2.2", "ipv6,default,fe80::2%vtnet1")
	wantFailure(t, f.run(systemRouteStatus("remove")...), "item")
	wantNoMutations(t, f)

	for _, tc := range []struct{ answer, want string }{
		{`{"message":"not_found"}`, "not found: ipv4 route 10.99.0.0/24 via 192.168.1.254"},
		{`{"message":"error"}`, `unexpected answer`},
	} {
		var f = systemRouteStatusFake(t, tc.answer)
		wantFailure(t, f.run(systemRouteStatus("remove", "10.99.0.0/24", "confirm=yes")...), tc.want)
	}
}

func TestSystemRouteStatusRemoveAfterFilteredPrint(t *testing.T) {
	t.Parallel()
	var f = systemRouteStatusFake(t, `{"message":"found"}`)
	var r = f.runScript("/system/route/status\nprint protocol=ipv6\nremove 1 confirm=yes\n")
	wantExit(t, r, 0)
	wantJSON(t, wantOneMutation(t, f, "POST", systemRouteStatusDelPath),
		map[string]any{"family": "ipv6", "destination": "fd00:99::/64", "gateway": "fd00::254"})
}

func TestSystemRouteStatusRemoveAfterResolvedPrint(t *testing.T) {
	t.Parallel()
	for _, item := range []string{"2", "branch-net"} {
		var f = systemRouteStatusFake(t, `{"message":"found"}`)
		var r = f.runScript("/system/route/status\nprint resolve\nremove " + item + " confirm=yes\n")
		wantExit(t, r, 0)
		// the address is sent, not the name
		wantJSON(t, wantOneMutation(t, f, "POST", systemRouteStatusDelPath),
			map[string]any{"family": "ipv4", "destination": "10.99.0.0/24", "gateway": "192.168.1.254"})
	}
}

func TestSystemRouteStatusComplete(t *testing.T) {
	t.Parallel()
	var f = systemRouteStatusFake(t, `{"message":"found"}`)
	var session = fakeSession(t, f)
	var candidates, _ = session.Complete("/system/route/status remove 10.")
	if strings.Join(candidates, " ") != "10.0.2.0/24 10.99.0.0/24" {
		t.Errorf("item completion: %q", candidates)
	}
	candidates, _ = session.Complete("/system/route/status print interface=vt")
	if strings.Join(candidates, " ") != "interface=vtnet0 interface=vtnet1" {
		t.Errorf("interface completion: %q", candidates)
	}
}
