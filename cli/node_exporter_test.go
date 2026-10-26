package cli

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

const (
	nodeExporterGetPath    = "/api/nodeexporter/general/get"
	nodeExporterSetPath    = "/api/nodeexporter/general/set"
	nodeExporterStatusPath = "/api/nodeexporter/service/status"
)

func nodeExporterSettingsAnswer(enabled string, address string) string {
	return `{"general":{"enabled":"` + enabled + `","listenaddress":"` + address + `","listenport":"9100","cpu":"1",
"exec":"0","filesystem":"1","loadavg":"0","meminfo":"0","netdev":"0","time":"0","devstat":"0","interrupts":"0","ntp":"0","zfs":"1"}}`
}

func nodeExporterStatusAnswer(status string) string {
	return `{"status":"` + status + `","widget":{"caption_restart":"Restart","caption_start":"Start","caption_stop":"Stop"}}`
}

func TestNodeExporterSettingsPrint(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", nodeExporterGetPath, 200, nodeExporterSettingsAnswer("1", "192.168.1.1"))
	var r = f.run("/node-exporter/settings", "print")
	wantExit(t, r, 0)
	if got := keaTestLines(r.stdout); !reflect.DeepEqual(got, []string{"enabled:|yes", "listen-address:|192.168.1.1",
		"listen-port:|9100", "collectors:|cpu,filesystem,zfs"}) {
		t.Errorf("print %q", got)
	}
	var j = f.run("/node-exporter/settings", "print", "json")
	wantExit(t, j, 0)
	wantContains(t, "json", j.stdout, `"enabled":"1"`, `"listenaddress":"192.168.1.1"`, `"zfs":"1"`, `"interrupts":"0"`)
	if strings.Count(strings.TrimSpace(j.stdout), "\n") != 0 {
		t.Errorf("want one JSON line:\n%s", j.stdout)
	}
}

func TestNodeExporterSettingsSet(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", nodeExporterGetPath, 200, nodeExporterSettingsAnswer("1", "127.0.0.1"))
	f.on("POST", nodeExporterSetPath, 200, answerSaved)
	var r = f.run("/node-exporter/settings", "set", "enabled", "listen-address=127.0.0.1", "listen-port=9101", "collectors=ZFS, cpu")
	wantExit(t, r, 0)
	wantJSON(t, wantOneMutation(t, f, "POST", nodeExporterSetPath), map[string]any{"general": map[string]any{
		"enabled": "1", "listenaddress": "127.0.0.1", "listenport": "9101",
		"cpu": "1", "exec": "0", "filesystem": "0", "loadavg": "0", "meminfo": "0", "netdev": "0", "time": "0",
		"devstat": "0", "interrupts": "0", "ntp": "0", "zfs": "1"}})
	wantNotContains(t, "stderr", r.stderr, "warning")
	if r.stdout != "" {
		t.Errorf("set is silent, got %q", r.stdout)
	}

	// only the given fields; collectors= disables all
	var g = newFakeOPN(t)
	g.on("POST", nodeExporterSetPath, 200, answerSaved)
	wantExit(t, g.run("/node-exporter/settings", "set", "listen-port=9102"), 0)
	wantJSON(t, g.mutations()[0], map[string]any{"general": map[string]any{"listenport": "9102"}})
	wantExit(t, g.run("/node-exporter/settings", "set", "collectors="), 0)
	wantJSON(t, g.mutations()[1], map[string]any{"general": map[string]any{"cpu": "0", "exec": "0", "filesystem": "0",
		"loadavg": "0", "meminfo": "0", "netdev": "0", "time": "0", "devstat": "0", "interrupts": "0", "ntp": "0", "zfs": "0"}})
}

func TestNodeExporterSettingsSetWarnsAboutAllAddresses(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", nodeExporterGetPath, 200, nodeExporterSettingsAnswer("1", "0.0.0.0"))
	f.on("POST", nodeExporterSetPath, 200, answerSaved)
	var r = f.run("/node-exporter/settings", "set", "enabled")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "warning", "all addresses (0.0.0.0)")
}

func TestNodeExporterSettingsSetRefused(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", nodeExporterSetPath, 200, answerValidation("general.listenaddress", "Please provide a valid IP address."))
	for _, args := range [][]string{
		{},
		{"listen-address=any"},
		{"listen-address=10.0.0.0/24"},
		{"listen-address="},
		{"listen-port=0"},
		{"listen-port=65536"},
		{"listen-port="},
		{"collectors=cpu,nope"},
		{"enabled=maybe"},
	} {
		wantFailure(t, f.run(append([]string{"/node-exporter/settings", "set"}, args...)...))
	}
	wantNoCalls(t, f)
	wantFailure(t, f.run("/node-exporter/settings", "set", "listen-address=::1"), "valid IP address")
}

func TestNodeExporterService(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", nodeExporterStatusPath, 200, nodeExporterStatusAnswer("running"))
	for _, action := range []string{"start", "stop", "restart"} {
		f.on("POST", "/api/nodeexporter/service/"+action, 200, `{"response":"OK"}`)
	}
	f.on("POST", "/api/nodeexporter/service/reconfigure", 200, `{"status":"ok"}`)

	var r = f.run("/node-exporter/service", "status")
	wantExit(t, r, 0)
	if got := keaTestLines(r.stdout); !reflect.DeepEqual(got, []string{"status:|running"}) {
		t.Errorf("status %q", got)
	}
	for _, action := range []string{"start", "stop", "restart", "reconfigure", "apply"} {
		var result = f.run("/node-exporter/service", action)
		wantExit(t, result, 0)
		if result.stdout != "" {
			t.Errorf("%s is silent, got %q", action, result.stdout)
		}
	}
	var posted []string
	for _, call := range f.mutations() {
		posted = append(posted, call.Path)
	}
	if !reflect.DeepEqual(posted, []string{"/api/nodeexporter/service/start", "/api/nodeexporter/service/stop",
		"/api/nodeexporter/service/restart", "/api/nodeexporter/service/reconfigure", "/api/nodeexporter/service/reconfigure"}) {
		t.Errorf("posted %v", posted)
	}

	var failing = newFakeOPN(t)
	failing.on("POST", "/api/nodeexporter/service/reconfigure", 200, `{"status":"failed","status_msg":"Service \"node_exporter\" failed to start."}`)
	failing.on("POST", "/api/nodeexporter/service/stop", 200, `{"response":"Execute error"}`)
	wantFailure(t, failing.run("/node-exporter/service", "reconfigure"), "failed to start")
	wantFailure(t, failing.run("/node-exporter/service", "stop"), "Execute error")
}

// start and restart answer OK without doing anything while the exporter is disabled or not applied yet
func TestNodeExporterServiceStartWhileDisabled(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", nodeExporterStatusPath, 200, nodeExporterStatusAnswer("disabled"))
	wantFailure(t, f.run("/node-exporter/service", "start"), "is disabled", "settings set enabled", "reconfigure")
	wantFailure(t, f.run("/node-exporter/service", "restart"), "is disabled")
	wantNoMutations(t, f)

	var stale = newFakeOPN(t)
	stale.on("GET", nodeExporterStatusPath, 200, nodeExporterStatusAnswer("stopped"))
	stale.on("POST", "/api/nodeexporter/service/start", 200, `{"response":"OK"}`)
	wantFailure(t, stale.run("/node-exporter/service", "start"), "not running afterwards (status stopped)", "reconfigure")
	wantOneMutation(t, stale, "POST", "/api/nodeexporter/service/start")
}

func TestNodeExporterNotInstalled(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	for _, path := range []string{nodeExporterGetPath, nodeExporterSetPath, nodeExporterStatusPath, "/api/nodeexporter/service/stop",
		"/api/nodeexporter/service/reconfigure"} {
		var method = "POST"
		if strings.HasSuffix(path, "/get") || strings.HasSuffix(path, "/status") {
			method = "GET"
		}
		f.on(method, path, 404, `{"errorMessage":"Endpoint not found"}`)
	}
	for _, args := range [][]string{
		{"/node-exporter/settings", "print"},
		{"/node-exporter/settings", "set", "enabled=no"},
		{"/node-exporter/service", "status"},
		{"/node-exporter/service", "start"},
		{"/node-exporter/service", "stop"},
		{"/node-exporter/service", "reconfigure"},
	} {
		wantFailure(t, f.run(args...), `os-node_exporter is not installed (install it with "/system/firmware/plugin install os-node_exporter")`)
	}
}

func TestNodeExporterError(t *testing.T) {
	t.Parallel()
	if nodeExporterError(nil) != nil {
		t.Error("nil must stay nil")
	}
	var other = &coreapi.HttpError{StatusCode: 500, Message: "boom"}
	if got := nodeExporterError(other); got != other {
		t.Errorf("other errors are kept: %v", got)
	}
	var wrapped = nodeExporterError(errors.Join(errors.New("context"), &coreapi.HttpError{StatusCode: 404, Message: "Endpoint not found"}))
	if wrapped == nil || !strings.Contains(wrapped.Error(), "os-node_exporter is not installed") {
		t.Errorf("404: %v", wrapped)
	}
}
