//go:build integration

package integrationcore

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
)

func TestServiceList(t *testing.T) {
	var opn = systemApi(t)
	var services, err = opn.CoreServiceList()
	if err != nil {
		t.Fatal(err)
	}
	var byId = map[string]system.CoreService{}
	for _, service := range services {
		byId[service.Id] = service
	}
	for _, id := range []string{"configd", "webgui", "pf"} {
		if service, ok := byId[id]; !ok || !service.Locked || !service.Running {
			t.Errorf("want %s locked and running, got %+v (%v)", id, service, ok)
		}
	}
	if _, err := opn.CoreServiceGet("a9-core-no-such-service"); !api.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
}

// TestServiceStopStoppedIsNoop stops a service that is not running (a no-op) through the library, the only live
// service action of this suite
func TestServiceStopStoppedIsNoop(t *testing.T) {
	var opn = systemApi(t)
	var services, err = opn.CoreServiceList()
	if err != nil {
		t.Fatal(err)
	}
	var stopped *system.CoreService
	for i := range services {
		if !services[i].Running && !services[i].Locked && services[i].Name == "hostwatch" {
			stopped = &services[i]
		}
	}
	if stopped == nil {
		t.Skip("hostwatch is not a stopped service on this box, nothing harmless to stop")
	}
	if err := opn.CoreServiceStop(stopped.Id); err != nil {
		t.Fatal(err)
	}
	if after, err := opn.CoreServiceGet(stopped.Id); err != nil || after.Running {
		t.Errorf("want %s still stopped, got %+v %v", stopped.Id, after, err)
	}
}

func TestCliService(t *testing.T) {
	var result = mustOpn(t, "/system/service", "print")
	requireContains(t, result, result.stdout, "configd", "webgui", "running")
	result = mustOpn(t, "/system/service", "show", "configd")
	requireContains(t, result, result.stdout, "locked:       yes", "status:       running")
	mustFailOpn(t, "locked", "/system/service", "stop", "webgui", "confirm=yes")
	mustFailOpn(t, "confirm=yes", "/system/service", "restart", "configd")
	// stop asks (and so needs confirm=yes here) only for a running service
	if unbound := runOpn(t, "/system/service", "show", "unbound"); unbound.exitCode == 0 && strings.Contains(unbound.stdout, "status:       running") {
		mustFailOpn(t, "confirm=yes", "/system/service", "stop", "unbound")
	}
	mustFailOpn(t, "not found", "/system/service", "start", "a9-core-no-such-service")
	if runOpn(t, "/system/service", "show", "hostwatch").exitCode == 0 {
		result = mustOpn(t, "/system/service", "show", "hostwatch")
		if strings.Contains(result.stdout, "stopped") {
			result = mustOpn(t, "/system/service", "stop", "hostwatch", "confirm=yes")
			requireContains(t, result, result.stderr, "not running")
		}
	}
}

func TestFirmwareReads(t *testing.T) {
	var opn = systemApi(t)
	var status, err = opn.FirmwareStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.Product.Name == "" || status.ProductVersion == "" || status.Status == "" {
		t.Errorf("unexpected status %+v", status)
	}
	info, err := opn.FirmwareInfo()
	if err != nil {
		t.Fatal(err)
	}
	var core *system.FirmwarePackage
	for i := range info.Packages {
		if info.Packages[i].Name == "opnsense" {
			core = &info.Packages[i]
		}
	}
	if core == nil || !core.Installed || core.Version == "" || len(info.Plugins) == 0 {
		t.Errorf("want the installed opnsense package and plugins, got %+v, %d plugins", core, len(info.Plugins))
	}
	if details, err := opn.FirmwarePackageDetails("opnsense"); err != nil || details == "" {
		t.Errorf("details: %q %v", details, err)
	}
	if _, err := opn.FirmwarePackageLicense("a9-core-no-such-package"); !api.IsNotFound(err) {
		t.Errorf("want NotFoundError for an unknown package, got %v", err)
	}
	if _, err := opn.FirmwareChangelog("1.0"); !api.IsNotFound(err) {
		t.Errorf("want NotFoundError for an unknown release, got %v", err)
	}
	if len(info.Changelogs) > 0 {
		if changelog, err := opn.FirmwareChangelog(info.Changelogs[0].Version); err != nil || changelog.Html == "" {
			t.Errorf("changelog %s: %+v %v", info.Changelogs[0].Version, changelog, err)
		}
	}
	settings, err := opn.FirmwareSettings()
	if err != nil {
		t.Fatal(err)
	}
	_ = settings
	options, err := opn.FirmwareOptions()
	if err != nil || len(options.Mirrors) < 2 || len(options.Types) < 2 {
		t.Errorf("options %+v %v", options, err)
	}
	if _, err := opn.FirmwareBusy(); err != nil {
		t.Error(err)
	}
	if _, err := opn.FirmwareProgress(); err != nil {
		t.Error(err)
	}
}

// TestFirmwareAudit runs a security audit through the library, a background action followed to the end. A check
// for updates is never run live: it can upgrade pkg itself (it did, 2.3.1 -> 2.8.4 on opnsense-dev)
func TestFirmwareAudit(t *testing.T) {
	var opn = systemApi(t)
	for _, action := range []system.FirmwareAction{system.FirmwareActionAudit} {
		if busy, err := opn.FirmwareBusy(); err != nil || busy {
			t.Skipf("a firmware action is running (%v), not starting %s", err, action)
		}
		var previous, err = opn.FirmwareProgress()
		if err != nil {
			t.Fatal(err)
		}
		if err := opn.FirmwareStart(action); err != nil {
			t.Fatal(err)
		}
		var output strings.Builder
		var progress, waitErr = opn.FirmwareWait(context.Background(), system.FirmwareWaitOptions{
			Timeout: 5 * time.Minute, Previous: previous.Log, Output: func(text string) { output.WriteString(text) }})
		if waitErr != nil {
			t.Fatalf("%s: %v\n%s", action, waitErr, output.String())
		}
		if progress.Status != system.FirmwareProgressDone || !strings.Contains(output.String(), "***GOT REQUEST TO") ||
			!strings.HasSuffix(strings.TrimSpace(output.String()), "***DONE***") {
			t.Errorf("%s: unexpected end %q with output:\n%s", action, progress.Status, output.String())
		}
	}
}

func TestCliFirmware(t *testing.T) {
	var result = mustOpn(t, "/system/firmware", "status")
	requireContains(t, result, result.stdout, "product:", "status:")
	result = mustOpn(t, "/system/firmware/package", "print", "search=opnsense")
	requireContains(t, result, result.stdout, "opnsense", "yes")
	result = mustOpn(t, "/system/firmware/package", "show", "opnsense")
	requireContains(t, result, result.stdout, "installed:   yes")
	mustOpn(t, "/system/firmware/plugin", "print", "all")
	result = mustOpn(t, "/system/firmware/settings", "print")
	requireContains(t, result, result.stdout, "mirror:", "type:")
	result = mustOpn(t, "/system/firmware/settings", "print", "options=mirror")
	requireContains(t, result, result.stdout, "KEY", "pkg.opnsense.org")
	result = mustOpn(t, "/system/firmware/changelog", "print")
	if strings.Count(result.stdout, "\n") > 1 {
		result = mustOpn(t, "/system/firmware/changelog", "show", "0")
		if len(result.stdout) < 50 || strings.Contains(result.stdout, "<li>") {
			t.Errorf("unexpected changelog text:\n%s", result)
		}
	}
	result = mustOpn(t, "/system/license", "print")
	requireContains(t, result, result.stdout, "product:", "copyright:")
	// not every package has a license text (opnsense has none), one of these does
	var licensed = false
	for _, name := range []string{"beep", "curl", "pkg", "php85"} {
		licensed = licensed || runOpn(t, "/system/license", "print", "package="+name).exitCode == 0
	}
	if !licensed {
		t.Error("no license text for any of beep, curl, pkg, php85")
	}
	mustFailOpn(t, "not found", "/system/license", "print", "package=a9-core-no-such-package")
	// dangerous commands are refused without confirmation, nothing is sent
	mustFailOpn(t, "confirm=yes", "/system/firmware", "update")
	mustFailOpn(t, "confirm=yes", "/system/firmware", "upgrade")
	mustFailOpn(t, "confirm=yes", "/system/firmware/package", "reinstall", "opnsense")
	mustFailOpn(t, "not found", "/system/firmware/plugin", "remove", "os-a9-core-no-such", "confirm=yes")
}

// TestCliFirmwarePluginMaintenance checks the plugin conflict hints against the live plugin state. The plugin
// resync and sync run only when both are no-ops (every installed plugin registered, every configured plugin
// installed: nothing to register, unregister or install), and the installed packages and plugins must be the same
// afterwards. cleanup is never run live: its pkg autoremove can remove packages
func TestCliFirmwarePluginMaintenance(t *testing.T) {
	var opn = systemApi(t)
	// the endpoints exist (an unknown one answers 404) and do nothing without a POST
	for _, method := range []string{"sync_plugins", "resync_plugins", "cleanup"} {
		var answer struct {
			Status string `json:"status"`
		}
		if err := opn.DoJSON("GET", opn.EndpointForPluginControllerMethod("core", "firmware", method), nil, &answer); err != nil || answer.Status != "failure" {
			t.Errorf("GET %s: want status failure, got %q %v", method, answer.Status, err)
		}
	}
	mustFailOpn(t, "confirm=yes", "/system/firmware", "cleanup")
	mustFailOpn(t, "confirm=yes", "/system/firmware/plugin", "sync")
	mustFailOpn(t, "confirm=yes", "/system/firmware/plugin", "resync")

	var before, err = opn.FirmwareInfo()
	if err != nil {
		t.Fatal(err)
	}
	var unregistered, missing = before.UnregisteredPlugins(), before.MissingPlugins()
	var result = mustOpn(t, "/system/firmware/plugin", "print")
	for _, name := range append(append([]string(nil), unregistered...), missing...) {
		requireContains(t, result, result.stderr, name)
	}
	if len(unregistered) > 0 {
		requireContains(t, result, result.stderr, "installed but not registered", "/system/firmware/plugin resync")
	}
	if len(missing) > 0 {
		requireContains(t, result, result.stderr, "configured but not installed", "/system/firmware/plugin sync")
	}
	if len(unregistered)+len(missing) == 0 && strings.Contains(result.stderr, "warning") {
		t.Errorf("want no plugin hint, got:\n%s", result)
	}
	for _, plugin := range before.Plugins {
		if plugin.Installed {
			result = mustOpn(t, "/system/firmware/plugin", "show", plugin.Name)
			if strings.Contains(result.stderr, "warning") != !plugin.Configured {
				t.Errorf("%s (configured %v): unexpected hint:\n%s", plugin.Name, plugin.Configured, result)
			}
		}
	}

	if len(unregistered)+len(missing) > 0 {
		t.Skipf("the plugins are not in sync (unregistered %v, missing %v), not running resync/sync", unregistered, missing)
	}
	for _, command := range []string{"resync", "sync"} {
		if busy, err := opn.FirmwareBusy(); err != nil || busy {
			t.Skipf("a firmware action is running (%v), not starting a plugin %s", err, command)
		}
		result = mustOpn(t, "/system/firmware/plugin", command, "confirm=yes", "timeout=10m")
		requireContains(t, result, result.stderr, "***GOT REQUEST TO "+strings.ToUpper(command)+"***", "***DONE***")
		var after, err = opn.FirmwareInfo()
		if err != nil {
			t.Fatal(err)
		}
		if got, want := firmwareInstalledState(after), firmwareInstalledState(before); !reflect.DeepEqual(got, want) {
			t.Fatalf("plugin %s changed the installed packages or plugins:\n before %v\n after  %v", command, want, got)
		}
	}
}

// firmwareInstalledState lists the installed packages with their version and the plugins with their state
func firmwareInstalledState(info system.FirmwareInfo) []string {
	var state []string
	for _, pkg := range info.Packages {
		if pkg.Installed {
			state = append(state, pkg.Name+"-"+pkg.Version)
		}
	}
	for _, plugin := range info.Plugins {
		if plugin.Installed || plugin.Configured {
			state = append(state, fmt.Sprintf("plugin %s installed=%v configured=%v locked=%v", plugin.Name, plugin.Installed, plugin.Configured, plugin.Locked))
		}
	}
	return state
}

func TestCliFirmwareAudit(t *testing.T) {
	var opn = systemApi(t)
	if busy, err := opn.FirmwareBusy(); err != nil || busy {
		t.Skipf("a firmware action is running (%v)", err)
	}
	var result = mustOpn(t, "/system/firmware", "audit", "type=security")
	requireContains(t, result, result.stdout, "***GOT REQUEST TO AUDIT SECURITY***", "***DONE***")
}

func TestHaReads(t *testing.T) {
	var opn = systemApi(t)
	var settings, err = opn.HaSyncSettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	if len(settings.Options["pfsyncversion"]) == 0 || len(settings.Options["syncitems"]) == 0 || settings.PfsyncVersion == "" {
		t.Errorf("unexpected HA settings %+v", settings)
	}
	if _, err := opn.HaPeerVersionGet(); err != nil {
		t.Error(err)
	}
	if _, _, err := opn.HaRemoteServiceListRaw(); err != nil {
		t.Error(err)
	}

	var result = mustOpn(t, "/system/ha", "print")
	requireContains(t, result, result.stdout, "pfsync-interface:", "sync-items:")
	if settings.Password != "" && strings.Contains(result.stdout, settings.Password) {
		t.Error("the HA password must not be printed")
	}
	result = mustOpn(t, "/system/ha", "print", "options=sync-items")
	requireContains(t, result, result.stdout, "aliases")
	result = mustOpn(t, "/system/ha", "status")
	requireContains(t, result, result.stdout, "peer:")
	mustOpn(t, "/system/ha/service", "print")
	mustFailOpn(t, "confirm=yes", "/system/ha", "sync")
	mustFailOpn(t, "unknown value", "/system/ha", "set", "pfsync-interface=a9-core-no-such-if")
}

func TestSnapshots(t *testing.T) {
	var opn = systemApi(t)
	var supported, err = opn.SnapshotSupported()
	if err != nil {
		t.Fatal(err)
	}
	snapshots, err := opn.SnapshotList()
	if err != nil {
		t.Fatal(err)
	}
	if !supported {
		if len(snapshots) != 0 {
			t.Errorf("want no snapshots without ZFS, got %+v", snapshots)
		}
		var result = mustOpn(t, "/system/snapshot", "print")
		requireContains(t, result, result.stderr, "does not run on ZFS")
		mustFailOpn(t, "does not run on ZFS", "/system/snapshot", "add", "name=a9-core-never")
		return
	}
	var active = 0
	for _, snapshot := range snapshots {
		if snapshot.ActiveNow() {
			active++
		}
	}
	if active != 1 {
		t.Errorf("want one running boot environment, got %+v", snapshots)
	}
	mustOpn(t, "/system/snapshot", "print")
}
