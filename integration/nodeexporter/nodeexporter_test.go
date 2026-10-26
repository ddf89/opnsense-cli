//go:build integration

package integrationnodeexporter

import (
	"slices"
	"strings"
	"testing"
	"time"

	"opnsense-cli/opnsense/api/nodeexporter"
)

func TestNodeExporterReadOnly(t *testing.T) {
	var lib = liveApi(t)
	var settings, err = lib.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	var printed = mustOpn(t, "/node-exporter/settings", "print")
	requireContains(t, printed, printed.stdout, "enabled:", "listen-address:", "listen-port:", "collectors:",
		settings.ListenAddress, settings.ListenPort)
	var asJSON = mustOpn(t, "/node-exporter/settings", "print", "json")
	requireContains(t, asJSON, asJSON.stdout, `"listenaddress":"`+settings.ListenAddress+`"`, `"interrupts":"`)

	var status, statusErr = lib.ServiceStatus()
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	var shown = mustOpn(t, "/node-exporter/service", "status")
	requireContains(t, shown, shown.stdout, "status:", status)
}

func TestNodeExporterRefusedLocally(t *testing.T) {
	var lib = liveApi(t)
	var before, err = lib.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	// OPNsense would save "any", the CLI refuses non-addresses before sending anything
	mustFailOpn(t, "/node-exporter/settings", "set", "listen-address=any")
	mustFailOpn(t, "/node-exporter/settings", "set", "listen-port=0")
	mustFailOpn(t, "/node-exporter/settings", "set", "collectors=cpu,"+runId)
	if after, _ := lib.SettingsGet(); after != before {
		t.Errorf("refused sets changed the settings: %+v", after)
	}
}

// waitStatus polls the service status until it is want (node_exporter needs a moment after rc.d returned)
func waitStatus(t *testing.T, lib *nodeexporter.NodeExporterApi, want string) {
	t.Helper()
	var status string
	for i := 0; i < 20; i++ {
		var err error
		if status, err = lib.ServiceStatus(); err != nil {
			t.Fatal(err)
		}
		if status == want {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("status %q, want %q", status, want)
}

// TestNodeExporterLifecycle enables the exporter on 127.0.0.1, applies, restarts, stops and starts it through the
// CLI, then disables it again; the cleanup restores the snapshot of settings and service state
func TestNodeExporterLifecycle(t *testing.T) {
	var lib = liveApi(t)
	var before, err = snapshot(lib)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := restore(lib, before); err != nil {
			t.Errorf("restoring %s failed: %v", before, err)
		}
		if after, err := snapshot(lib); err != nil || after.String() != before.String() {
			t.Errorf("not restored: %s (%v), want %s", after, err, before)
		}
	})

	var port = "19100"
	if before.settings.ListenPort == port {
		port = "19101"
	}
	var set = mustOpn(t, "/node-exporter/settings", "set", "enabled", "listen-address=127.0.0.1", "listen-port="+port,
		"collectors=cpu,loadavg,meminfo")
	if strings.Contains(set.stderr, "warning") {
		t.Errorf("no warning for 127.0.0.1:\n%s", set)
	}
	var settings, getErr = lib.SettingsGet()
	if getErr != nil {
		t.Fatal(getErr)
	}
	if settings.Enabled != "1" || settings.ListenAddress != "127.0.0.1" || settings.ListenPort != port ||
		!slices.Equal(settings.Collectors(), []string{"cpu", "loadavg", "meminfo"}) {
		t.Fatalf("not saved: %+v", settings)
	}
	var printed = mustOpn(t, "/node-exporter/settings", "print")
	requireContains(t, printed, printed.stdout, "127.0.0.1", port, "cpu,loadavg,meminfo")

	// enabled but not applied: rc.conf.d still says NO, OPNsense reports stopped and answers start with OK
	// without starting anything; the CLI notices
	if before.status == nodeexporter.StatusDisabled {
		waitStatus(t, lib, nodeexporter.StatusStopped)
		var early = mustFailOpn(t, "/node-exporter/service", "start")
		requireContains(t, early, early.stderr, "not running afterwards", "reconfigure")
	}

	mustOpn(t, "/node-exporter/service", "reconfigure")
	waitStatus(t, lib, nodeexporter.StatusRunning)
	mustOpn(t, "/node-exporter/service", "restart")
	waitStatus(t, lib, nodeexporter.StatusRunning)
	mustOpn(t, "/node-exporter/service", "stop")
	waitStatus(t, lib, nodeexporter.StatusStopped)
	var stopped = mustOpn(t, "/node-exporter/service", "status")
	requireContains(t, stopped, stopped.stdout, "stopped")
	mustOpn(t, "/node-exporter/service", "start")
	waitStatus(t, lib, nodeexporter.StatusRunning)

	// disabled: reconfigure stops it, start is refused (OPNsense would answer OK and do nothing)
	mustOpn(t, "/node-exporter/settings", "set", "enabled=no")
	mustOpn(t, "/node-exporter/service", "apply")
	waitStatus(t, lib, nodeexporter.StatusDisabled)
	var refused = mustFailOpn(t, "/node-exporter/service", "start")
	requireContains(t, refused, refused.stderr, "disabled")
}
