package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	openvpnSessionSearchPath = "/api/openvpn/service/search_sessions"
	openvpnRouteSearchPath   = "/api/openvpn/service/search_routes"
	openvpnSessionKillPath   = "/api/openvpn/service/kill_session"
)

// openvpnSessionRow is a 26.7 shaped search_sessions row: all rows carry the same keys, missing ones are null
func openvpnSessionRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"socket": nil, "status": nil, "type": "server", "id": "", "description": "", "connected_since": nil,
		"timestamp": nil, "common_name": nil, "real_address": nil, "virtual_address": nil, "virtual_ipv6_address": nil,
		"bytes_received": nil, "bytes_sent": nil, "connected_since__time_t_": nil, "username": nil, "client_id": nil,
		"peer_id": nil, "data_channel_cipher": nil, "is_client": nil, "service_id": nil,
	}, overrides)
}

func openvpnSessionClient(id string, commonName string, realAddress string, overrides map[string]any) map[string]any {
	return openvpnSessionRow(withFields(map[string]any{
		"socket": "/var/etc/openvpn/instance-u-srv.sock", "status": "ok", "id": "u-srv_" + realAddress, "description": "office",
		"common_name": commonName, "real_address": realAddress, "virtual_address": "10.8.0." + id,
		"bytes_received": "1234567", "bytes_sent": "999", "connected_since": "2026-10-25 14:03:12",
		"connected_since__time_t_": "1761401000", "username": "UNDEF", "client_id": id, "peer_id": id,
		"data_channel_cipher": "AES-256-GCM", "is_client": true,
	}, overrides))
}

var openvpnSessionRows = []map[string]any{
	openvpnSessionClient("2", "alice", "203.0.113.7:51820", map[string]any{"virtual_ipv6_address": "fd00:8::2"}),
	openvpnSessionClient("3", "bob", "198.51.100.9:40000", nil),
	openvpnSessionRow(map[string]any{"socket": "/var/etc/openvpn/instance-u-cli.sock", "status": "connected", "type": "client",
		"id": "u-cli", "description": "uplink", "timestamp": 1761397200, "real_address": "192.0.2.1:1194",
		"virtual_address": "10.9.0.6", "bytes_received": "100", "bytes_sent": "200"}),
	openvpnSessionRow(map[string]any{"id": "u-down", "description": "down", "service_id": "openvpn/u-down"}),
}

func newOpenvpnSessionFake(t *testing.T) *fakeOPN {
	var f = newFakeOPN(t)
	f.search(openvpnSessionSearchPath, openvpnSessionRows...)
	return f
}

func TestOpenvpnSessionPrint(t *testing.T) {
	t.Parallel()
	var f = newOpenvpnSessionFake(t)
	var r = f.run("/vpn/openvpn/session", "print")
	wantExit(t, r, 0)
	var rows = dnsmasqTableRows(r.stdout)
	var since = time.Unix(1761401000, 0).UTC().Format(time.DateTime) // the tests run with TZ=UTC
	var want = [][]string{
		{"#", "INSTANCE", "TYPE", "COMMON-NAME", "REAL-ADDRESS", "VIRTUAL-ADDRESS", "CONNECTED-SINCE", "BYTES-IN", "BYTES-OUT", "STATUS"},
		{"0", "office", "server", "alice", "203.0.113.7:51820", "10.8.0.2, fd00:8::2", since, "1.2 MB", "999 B", "connected"},
		{"1", "office", "server", "bob", "198.51.100.9:40000", "10.8.0.3", since, "1.2 MB", "999 B", "connected"},
		{"2", "uplink", "client", "-", "192.0.2.1:1194", "10.9.0.6", time.Unix(1761397200, 0).UTC().Format(time.DateTime), "100 B", "200 B", "connected"},
		{"3", "down", "server", "-", "-", "-", "-", "-", "-", "stopped"},
	}
	if len(rows) != len(want) {
		t.Fatalf("want %d lines:\n%s", len(want), r.stdout)
	}
	for i := range want {
		if strings.Join(rows[i], "|") != strings.Join(want[i], "|") {
			t.Errorf("line %d: got %q, want %q", i, rows[i], want[i])
		}
	}

	r = f.run("/vpn/openvpn/session", "print", "json")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 4 {
		t.Fatalf("want 4 JSON lines:\n%s", r.stdout)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil || first["is_client"] != true || first["id"] != "u-srv_203.0.113.7:51820" {
		t.Errorf("want the raw row, got %s (%v)", lines[0], err)
	}

	r = f.run("/vpn/openvpn/session", "print", "detail", "search=alice")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "instance:", "office", "instance-id:", "u-srv", "common-name:", "alice",
		"virtual-address6:", "fd00:8::2", "cipher:", "AES-256-GCM", "bytes-in:", "1.2 MB")
	wantNotContains(t, "stdout", r.stdout, "bob")
	wantNoMutations(t, f)
}

func TestOpenvpnSessionPrintType(t *testing.T) {
	t.Parallel()
	var f = newOpenvpnSessionFake(t)
	wantExit(t, f.run("/vpn/openvpn/session", "print", "type=client"), 0)
	wantFailure(t, f.run("/vpn/openvpn/session", "print", "type=both"), "type", "both")
	var calls = f.calls()
	if len(calls) != 1 || strings.Join(calls[0].Query["type[]"], ",") != "client" {
		t.Errorf("want one query with type[]=client, got %v", calls)
	}
}

func TestOpenvpnSessionPrintEmpty(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search(openvpnSessionSearchPath)
	var r = f.run("/vpn/openvpn/session", "print")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) == "" || len(dnsmasqTableRows(r.stdout)) != 1 {
		t.Errorf("want only the header:\n%s", r.stdout)
	}
	r = f.run("/vpn/openvpn/session", "print", "json")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("want no JSON lines, got %q", r.stdout)
	}
}

func TestOpenvpnSessionFollow(t *testing.T) {
	t.Parallel()
	var f = newOpenvpnSessionFake(t)
	var p = f.start("/vpn/openvpn/session", "print", "follow", "interval=20ms")
	f.waitForConnections(openvpnSessionSearchPath, 4)
	p.waitFor("alice")
	var r = p.interrupt()
	wantExit(t, r, 0)
	var refreshes = strings.Count(r.stdout, "alice")
	if refreshes < 3 || strings.Count(r.stdout, "--- ") != refreshes {
		t.Errorf("want at least 3 refreshes, each with a separator (not a terminal):\n%s", r.stdout)
	}
}

func TestOpenvpnSessionFollowStopsOnError(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", openvpnSessionSearchPath, 500, `{"status":500,"message":"Internal Error"}`)
	var r = f.start("/vpn/openvpn/session", "print", "follow", "interval=20ms").wait()
	wantFailure(t, r, "HTTP 500")
	if n := f.streamConnections(openvpnSessionSearchPath); n != 1 {
		t.Errorf("want no polling after an error, got %d queries", n)
	}
}

func TestOpenvpnSessionRemove(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		args     []string
		wantBody map[string]any
	}{
		{name: "by common name", args: []string{"remove", "alice", "confirm=yes"},
			wantBody: map[string]any{"server_id": "u-srv", "session_id": "203.0.113.7:51820"}},
		{name: "kill by real address", args: []string{"kill", "198.51.100.9:40000", "confirm"},
			wantBody: map[string]any{"server_id": "u-srv", "session_id": "198.51.100.9:40000"}},
		{name: "by #", args: []string{"remove", "1", "confirm"},
			wantBody: map[string]any{"server_id": "u-srv", "session_id": "198.51.100.9:40000"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newOpenvpnSessionFake(t)
			f.on("POST", openvpnSessionKillPath, 200, `{"status":"killed","clients":1}`)
			var r = f.run(append([]string{"/vpn/openvpn/session"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("remove must be silent, got %q", r.stdout)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", openvpnSessionKillPath), tc.wantBody)
		})
	}
}

// like the GUI: when the address is unknown (the client reconnected) the common name is killed
func TestOpenvpnSessionRemoveFallsBackToCommonName(t *testing.T) {
	t.Parallel()
	var f = newOpenvpnSessionFake(t)
	f.onFunc("POST", openvpnSessionKillPath, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["session_id"] == "alice" {
			_, _ = w.Write([]byte(`{"status":"killed","clients":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"not_found"}`))
	})
	wantExit(t, f.run("/vpn/openvpn/session", "remove", "alice", "confirm"), 0)
	var calls = f.mutations()
	if len(calls) != 2 {
		t.Fatalf("want two kill attempts, got %v", calls)
	}
	wantJSON(t, calls[0], map[string]any{"server_id": "u-srv", "session_id": "203.0.113.7:51820"})
	wantJSON(t, calls[1], map[string]any{"server_id": "u-srv", "session_id": "alice"})

	f = newOpenvpnSessionFake(t)
	f.on("POST", openvpnSessionKillPath, 200, `{"status":"not_found"}`)
	wantFailure(t, f.run("/vpn/openvpn/session", "remove", "bob", "confirm"), "not found", "198.51.100.9:40000", "bob")
}

func TestOpenvpnSessionRemoveErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		args      []string
		wantErr   []string
		wantCalls bool
	}{
		{name: "not confirmed", args: []string{"remove", "alice"}, wantErr: []string{"disconnects the client", "confirm=yes"}},
		{name: "declined", args: []string{"kill", "alice", "confirm=no"}, wantErr: []string{"confirm"}},
		{name: "no item", args: []string{"remove", "confirm"}, wantErr: []string{"item"}},
		{name: "unknown client", args: []string{"remove", "carol", "confirm"}, wantErr: []string{"carol", "not found"}, wantCalls: true},
		{name: "a client instance is no session", args: []string{"remove", "2", "confirm"},
			wantErr: []string{"client instance uplink", "not a client session"}, wantCalls: true},
		{name: "a stopped server is no session", args: []string{"remove", "u-down", "confirm"},
			wantErr: []string{"server instance down", "stopped"}, wantCalls: true},
		{name: "names of instances do not match", args: []string{"remove", "192.0.2.1:1194", "confirm"},
			wantErr: []string{"not found"}, wantCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newOpenvpnSessionFake(t)
			wantFailure(t, f.run(append([]string{"/vpn/openvpn/session"}, tc.args...)...), tc.wantErr...)
			if !tc.wantCalls {
				wantNoCalls(t, f)
			}
			wantNoMutations(t, f)
		})
	}

	// a server that is not running (any more)
	var f = newOpenvpnSessionFake(t)
	f.on("POST", openvpnSessionKillPath, 200, `{"status":"server_not_found"}`)
	wantFailure(t, f.run("/vpn/openvpn/session", "remove", "alice", "confirm"), "u-srv", "running")
}

func TestOpenvpnRoutePrint(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search(openvpnRouteSearchPath,
		map[string]any{"virtual_address": "10.8.0.2", "common_name": "alice", "real_address": "203.0.113.7:51820",
			"last_ref": "2026-10-25 14:05:00", "last_ref__time_t_": "1761401100", "type": "server", "id": "u-srv", "description": "office"},
		map[string]any{"virtual_address": "192.168.20.0/24", "common_name": "alice", "real_address": "203.0.113.7:51820",
			"last_ref": "2026-10-25 14:05:01", "last_ref__time_t_": "1761401101", "type": "server", "id": "u-legacy", "description": ""})
	var r = f.run("/vpn/openvpn/route", "print")
	wantExit(t, r, 0)
	var rows = dnsmasqTableRows(r.stdout)
	var want = [][]string{
		{"#", "INSTANCE", "TARGET", "COMMON-NAME", "REAL-ADDRESS", "LAST-REF"},
		{"0", "office", "10.8.0.2", "alice", "203.0.113.7:51820", time.Unix(1761401100, 0).UTC().Format(time.DateTime)},
		{"1", "u-legacy", "192.168.20.0/24", "alice", "203.0.113.7:51820", time.Unix(1761401101, 0).UTC().Format(time.DateTime)},
	}
	if len(rows) != len(want) {
		t.Fatalf("want %d lines:\n%s", len(want), r.stdout)
	}
	for i := range want {
		if strings.Join(rows[i], "|") != strings.Join(want[i], "|") {
			t.Errorf("line %d: got %q, want %q", i, rows[i], want[i])
		}
	}

	r = f.run("/vpn/openvpn/route", "print", "json", "type=server")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 2 || !json.Valid([]byte(lines[1])) || !strings.Contains(lines[1], `"192.168.20.0/24"`) {
		t.Errorf("want 2 raw JSON rows:\n%s", r.stdout)
	}
	var calls = f.calls()
	if strings.Join(calls[len(calls)-1].Query["type[]"], ",") != "server" {
		t.Errorf("want type[]=server, got %v", calls[len(calls)-1])
	}
	wantNoMutations(t, f)
}

func TestOpenvpnStatusErrors(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", openvpnRouteSearchPath, 403, `{"status":403,"message":"Forbidden"}`)
	wantFailure(t, f.run("/vpn/openvpn/route", "print"), "HTTP 403")
	wantFailure(t, f.run("/vpn/openvpn/session", "print"), "empty response")
}
