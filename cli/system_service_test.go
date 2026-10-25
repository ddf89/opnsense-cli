package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const systemServiceSearchPath = "/api/core/service/search"

// systemServiceFake serves a service list whose running flags change with start/stop/restart (unless frozen)
type systemServiceFake struct {
	mu      sync.Mutex
	running map[string]bool
	frozen  bool
}

var systemServiceTestRows = []map[string]any{
	{"id": "configd", "locked": 1, "running": 1, "description": "Configd", "name": "configd"},
	{"id": "hostwatch", "locked": 0, "running": 0, "description": "Hostwatch", "name": "hostwatch"},
	{"id": "openvpn/1", "locked": 0, "running": 1, "description": "OpenVPN server: road", "name": "openvpn"},
	{"id": "openvpn/2", "locked": 0, "running": 0, "description": "OpenVPN client: site", "name": "openvpn"},
	{"id": "unbound", "locked": 0, "running": 1, "description": "Unbound", "name": "unbound"},
	{"id": "webgui", "locked": 1, "running": 1, "description": "Web GUI", "name": "webgui"},
}

func newSystemServiceFake(t *testing.T, frozen bool) (*fakeOPN, *systemServiceFake) {
	t.Helper()
	var f = newFakeOPN(t)
	var state = &systemServiceFake{running: map[string]bool{}, frozen: frozen}
	for _, row := range systemServiceTestRows {
		state.running[row["id"].(string)] = row["running"] == 1
	}
	f.onFunc("GET", systemServiceSearchPath, func(w http.ResponseWriter, _ *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		var rows []map[string]any
		for _, row := range systemServiceTestRows {
			var copied = withFields(row, map[string]any{"running": map[bool]int{true: 1, false: 0}[state.running[row["id"].(string)]]})
			rows = append(rows, copied)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"total": len(rows), "rowCount": len(rows), "current": 1, "rows": rows})
	})
	for _, action := range []string{"start", "stop", "restart"} {
		for _, row := range systemServiceTestRows {
			var id, action = row["id"].(string), action
			f.onFunc("POST", "/api/core/service/"+action+"/"+id, func(w http.ResponseWriter, _ *http.Request) {
				state.mu.Lock()
				if !state.frozen {
					state.running[id] = action != "stop"
				}
				state.mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"result":"ok"}`))
			})
		}
	}
	return f, state
}

func TestSystemServicePrint(t *testing.T) {
	t.Parallel()
	var f, _ = newSystemServiceFake(t, false)
	var r = f.run("/system/service", "print")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 7 || !strings.HasPrefix(lines[0], "#") {
		t.Fatalf("unexpected table:\n%s", r.stdout)
	}
	for i, want := range []string{"0  configd    Configd               running  yes", "2  openvpn/1  OpenVPN server: road  running  no",
		"3  openvpn/2  OpenVPN client: site  stopped  no"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("row %d: want %q in\n%s", i, want, r.stdout)
		}
	}

	r = f.run("/system/service", "print", "search=OPENVPN")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "openvpn/1", "openvpn/2")
	wantNotContains(t, "stdout", r.stdout, "unbound", "configd")

	r = f.run("/system/service", "print", "json", "search=unbound")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != `{"current":1,"description":"Unbound","id":"unbound","locked":0,"name":"unbound","rowCount":6,"running":1,"total":6}` &&
		!strings.Contains(r.stdout, `"id":"unbound"`) {
		t.Errorf("unexpected json %q", r.stdout)
	}
	if strings.Count(strings.TrimSpace(r.stdout), "\n") != 0 {
		t.Errorf("want one line, got %q", r.stdout)
	}

	r = f.run("/system/service", "print", "detail", "search=hostwatch")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "0\n  id:", "status:       stopped", "locked:       no")
	wantNoMutations(t, f)
}

func TestSystemServiceShowSelectors(t *testing.T) {
	t.Parallel()
	var f, _ = newSystemServiceFake(t, false)
	for selector, want := range map[string]string{
		"unbound":   "id:           unbound",
		"UNBOUND":   "id:           unbound",
		"openvpn/2": "OpenVPN client: site",
		"2":         "OpenVPN server: road",
	} {
		var r = f.run("/system/service", "show", selector)
		wantExit(t, r, 0)
		wantContains(t, "stdout "+selector, r.stdout, want)
	}
	wantFailure(t, f.run("/system/service", "show", "openvpn"), "too many found", "openvpn/1", "openvpn/2")
	wantFailure(t, f.run("/system/service", "show", "nosuch"), "not found")
	wantFailure(t, f.run("/system/service", "show", "17"), "not found", "6 items")
	wantNoMutations(t, f)
}

func TestSystemServiceStartStop(t *testing.T) {
	t.Parallel()
	t.Run("start a stopped one", func(t *testing.T) {
		t.Parallel()
		var f, _ = newSystemServiceFake(t, false)
		var r = f.run("/system/service", "start", "hostwatch")
		wantExit(t, r, 0)
		if r.stdout != "" || r.stderr != "" {
			t.Errorf("want silent success, got %s", r)
		}
		wantOneMutation(t, f, "POST", "/api/core/service/start/hostwatch")
	})
	t.Run("start a running one does nothing", func(t *testing.T) {
		t.Parallel()
		var f, _ = newSystemServiceFake(t, false)
		var r = f.run("/system/service", "start", "unbound")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "running already")
		wantNoMutations(t, f)
	})
	t.Run("a service that does not start is reported", func(t *testing.T) {
		t.Parallel()
		var f, _ = newSystemServiceFake(t, true)
		var r = f.run("/system/service", "start", "openvpn/2")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "warning: service openvpn/2 is stopped")
		wantOneMutation(t, f, "POST", "/api/core/service/start/openvpn/2")
	})
	t.Run("stop needs confirm", func(t *testing.T) {
		t.Parallel()
		var f, _ = newSystemServiceFake(t, false)
		wantFailure(t, f.run("/system/service", "stop", "unbound"), "stops the service", "confirm=yes")
		wantFailure(t, f.runScript("/system/service stop unbound\n"), "confirm=yes")
		wantNoCalls(t, f)
	})
	t.Run("stop", func(t *testing.T) {
		t.Parallel()
		var f, _ = newSystemServiceFake(t, false)
		var r = f.run("/system/service", "stop", "openvpn/1", "confirm=yes")
		wantExit(t, r, 0)
		if r.stdout != "" || r.stderr != "" {
			t.Errorf("want silent success, got %s", r)
		}
		wantOneMutation(t, f, "POST", "/api/core/service/stop/openvpn/1")
	})
	t.Run("stop a locked one is refused", func(t *testing.T) {
		t.Parallel()
		var f, _ = newSystemServiceFake(t, false)
		wantFailure(t, f.run("/system/service", "stop", "webgui", "confirm=yes"), "locked", "only be restarted")
		wantFailure(t, f.run("/system/service", "stop", "configd", "confirm"), "locked")
		wantNoMutations(t, f)
	})
	t.Run("stop a stopped one does nothing", func(t *testing.T) {
		t.Parallel()
		var f, _ = newSystemServiceFake(t, false)
		var r = f.run("/system/service", "stop", "hostwatch", "confirm=yes")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "not running")
		wantNoMutations(t, f)
	})
}

func TestSystemServiceRestart(t *testing.T) {
	t.Parallel()
	t.Run("an ordinary service", func(t *testing.T) {
		t.Parallel()
		var f, _ = newSystemServiceFake(t, false)
		var r = f.run("/system/service", "restart", "unbound")
		wantExit(t, r, 0)
		if r.stdout != "" || r.stderr != "" {
			t.Errorf("want silent success, got %s", r)
		}
		wantOneMutation(t, f, "POST", "/api/core/service/restart/unbound")
	})
	t.Run("critical services need confirm", func(t *testing.T) {
		t.Parallel()
		var f, _ = newSystemServiceFake(t, false)
		wantFailure(t, f.run("/system/service", "restart", "webgui"), "restarting webgui interrupts the web GUI", "confirm=yes")
		wantFailure(t, f.run("/system/service", "restart", "configd", "confirm=no"), "confirm=yes")
		wantFailure(t, f.runScript("/system/service\nrestart webgui\n"), "confirm=yes")
		wantNoMutations(t, f)
		var r = f.run("/system/service", "restart", "webgui", "confirm=yes")
		wantExit(t, r, 0)
		wantOneMutation(t, f, "POST", "/api/core/service/restart/webgui")
	})
	t.Run("the API answer is checked", func(t *testing.T) {
		t.Parallel()
		var f, _ = newSystemServiceFake(t, false)
		f.on("POST", "/api/core/service/restart/unbound", 200, `{"result":"failed"}`)
		wantFailure(t, f.run("/system/service", "restart", "unbound"), `result "failed"`)
	})
}

func TestSystemServiceIndexAfterPrint(t *testing.T) {
	t.Parallel()
	var f, _ = newSystemServiceFake(t, false)
	var r = f.runScript("/system/service\nprint search=openvpn\nstop 0 confirm=yes\n")
	wantExit(t, r, 0)
	wantOneMutation(t, f, "POST", "/api/core/service/stop/openvpn/1")
}
