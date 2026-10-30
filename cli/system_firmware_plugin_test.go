package cli

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// systemFirmwarePluginInfo is a firmware info whose plugins are given as name:installed:configured, e.g.
// "os-ddclient:1:0"
func systemFirmwarePluginInfo(plugins ...string) string {
	var entries = make([]string, len(plugins))
	for i, plugin := range plugins {
		var parts = strings.Split(plugin, ":")
		entries[i] = fmt.Sprintf(`{"name":%q,"version":"1.0","comment":"A plugin","flatsize":"1KiB","locked":"N\/A",`+
			`"automatic":"N\/A","license":"BSD2CLAUSE","repository":"OPNsense","origin":"opnsense\/%s","provided":"1",`+
			`"installed":%q,"configured":%q,"tier":"3"}`, parts[0], parts[0], parts[1], parts[2])
	}
	return `{"product_id":"opnsense","product_version":"26.7.7","package":[],"plugin":[` + strings.Join(entries, ",") +
		`],"changelog":[],"product":` + systemFirmwareProduct + `}`
}

// systemFirmwarePluginFake answers info with before until a background action was posted, then with after
func systemFirmwarePluginFake(t *testing.T, before string, after string, progress ...string) *fakeOPN {
	t.Helper()
	var f = systemFirmwareFake(t, progress...)
	f.onFunc("GET", "/api/core/firmware/info", func(w http.ResponseWriter, _ *http.Request) {
		var answer = before
		for _, call := range f.mutations() {
			if !strings.HasPrefix(call.Path, "/api/core/firmware/details/") {
				answer = after
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(answer))
	})
	return f
}

func TestSystemFirmwarePluginHints(t *testing.T) {
	t.Parallel()
	var info = systemFirmwarePluginInfo("os-ddclient:1:0", "os-acme-client:1:1", "os-wol:0:1", "os-frr:0:0")
	var f = systemFirmwarePluginFake(t, info, info)
	f.on("POST", "/api/core/firmware/details/os-ddclient", 200, `{"details":"Dynamic DNS"}`)
	f.on("POST", "/api/core/firmware/details/os-wol", 200, `[]`)
	f.on("POST", "/api/core/firmware/details/os-acme-client", 200, `[]`)
	var r = f.run("/system/firmware/plugin", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "0  os-ddclient", "1  os-acme-client  1.0      yes        C")
	wantNotContains(t, "stdout", r.stdout, "os-wol", "warning")
	wantContains(t, "stderr", r.stderr,
		`warning: os-ddclient is installed but not registered in the configuration (no C flag), register it with "/system/firmware/plugin resync"`,
		`warning: os-wol is configured but not installed (missing), install it with "/system/firmware/plugin sync" or unregister it with "/system/firmware/plugin resync"`)
	// json keeps stdout clean, the hints go to stderr
	r = f.run("/system/firmware/plugin", "print", "json", "search=acme")
	wantExit(t, r, 0)
	wantNotContains(t, "stdout", r.stdout, "warning")
	wantContains(t, "stderr", r.stderr, "os-ddclient is installed but not registered")
	r = f.run("/system/firmware/plugin", "show", "os-ddclient")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "configured:  no", "Dynamic DNS")
	wantContains(t, "stderr", r.stderr, `os-ddclient is installed but not registered`, `"/system/firmware/plugin resync"`)
	wantNotContains(t, "stderr", r.stderr, "os-wol")
	r = f.run("/system/firmware/plugin", "show", "os-wol")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, `os-wol is configured but not installed (missing), install it with "/system/firmware/plugin sync"`)
	wantNotContains(t, "stderr", r.stderr, "os-ddclient")
	r = f.run("/system/firmware/plugin", "show", "os-acme-client")
	wantExit(t, r, 0)
	wantNotContains(t, "stderr", r.stderr, "warning")
	// the package menu has no plugin hints
	r = f.run("/system/firmware/package", "print")
	wantExit(t, r, 0)
	wantNotContains(t, "stderr", r.stderr, "warning")
	for _, call := range f.mutations() {
		if !strings.HasPrefix(call.Path, "/api/core/firmware/details/") {
			t.Errorf("unexpected mutation %v", call)
		}
	}

	t.Run("several", func(t *testing.T) {
		t.Parallel()
		var info = systemFirmwarePluginInfo("os-a:1:0", "os-b:1:0", "os-c:0:1", "os-d:0:1")
		var f = systemFirmwarePluginFake(t, info, info)
		var r = f.run("/system/firmware/plugin", "print", "all")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr,
			"warning: os-a, os-b are installed but not registered in the configuration (no C flag), register them with",
			"warning: os-c, os-d are configured but not installed (missing), install them with", "or unregister them with")
	})
	t.Run("none", func(t *testing.T) {
		t.Parallel()
		var info = systemFirmwarePluginInfo("os-a:1:1", "os-b:0:0")
		var f = systemFirmwarePluginFake(t, info, info)
		var r = f.run("/system/firmware/plugin", "print", "all")
		wantExit(t, r, 0)
		if r.stderr != "" {
			t.Errorf("want no hints, got %q", r.stderr)
		}
	})
}

func TestSystemFirmwarePluginSyncResyncCleanup(t *testing.T) {
	t.Parallel()
	const syncLog = `***GOT REQUEST TO SYNC***\nCurrently running OPNsense 26.7.7 at Fri Oct 30 21:00:00 UTC 2026\n`
	t.Run("sync installs the missing plugins", func(t *testing.T) {
		t.Parallel()
		var f = systemFirmwarePluginFake(t, systemFirmwarePluginInfo("os-wol:0:1"), systemFirmwarePluginInfo("os-wol:1:1"),
			`{"status":"running","log":"`+syncLog+`Updating OPNsense repository catalogue...\n"}`,
			`{"status":"done","log":"`+syncLog+`Updating OPNsense repository catalogue...\nInstalling os-wol-2.5...\n***DONE***"}`)
		f.on("POST", "/api/core/firmware/sync_plugins", 200, `{"status":"ok"}`)
		var r = f.run("/system/firmware/plugin", "sync", "confirm=yes")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "GOT REQUEST TO SYNC", "Installing os-wol-2.5", "***DONE***")
		if call := wantOneMutation(t, f, "POST", "/api/core/firmware/sync_plugins"); call.Body != "" {
			t.Errorf("want no body, got %q", call.Body)
		}
	})
	t.Run("a refused sync fails with the reason of the log", func(t *testing.T) {
		t.Parallel()
		var info = systemFirmwarePluginInfo("os-wol:0:1", "os-frr:0:1")
		var f = systemFirmwarePluginFake(t, info, info,
			`{"status":"done","log":"`+syncLog+`Installation out of date. The update to opnsense-26.7.8 is required.\n***DONE***"}`)
		f.on("POST", "/api/core/firmware/sync_plugins", 200, `{"status":"ok"}`)
		wantFailure(t, f.run("/system/firmware/plugin", "sync", "confirm=yes"),
			"the plugin sync did not install os-wol, os-frr: Installation out of date. The update to opnsense-26.7.8 is required.")
		wantOneMutation(t, f, "POST", "/api/core/firmware/sync_plugins")
	})
	t.Run("resync registers and unregisters", func(t *testing.T) {
		t.Parallel()
		var f = systemFirmwarePluginFake(t, systemFirmwarePluginInfo("os-ddclient:1:0", "os-wol:0:1"),
			systemFirmwarePluginInfo("os-ddclient:1:1", "os-wol:0:0"),
			`{"status":"done","log":"***GOT REQUEST TO RESYNC***\nUnregistering plugin: os-wol\nRegistering plugin: os-ddclient\n***DONE***"}`)
		f.on("POST", "/api/core/firmware/resync_plugins", 200, `{"status":"ok"}`)
		var r = f.run("/system/firmware/plugin", "resync", "confirm=yes")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "Unregistering plugin: os-wol", "Registering plugin: os-ddclient")
		wantOneMutation(t, f, "POST", "/api/core/firmware/resync_plugins")
	})
	t.Run("a resync that did not register fails", func(t *testing.T) {
		t.Parallel()
		var info = systemFirmwarePluginInfo("os-ddclient:1:0")
		var f = systemFirmwarePluginFake(t, info, info, `{"status":"done","log":"***GOT REQUEST TO RESYNC***\n***DONE***"}`)
		f.on("POST", "/api/core/firmware/resync_plugins", 200, `{"status":"ok"}`)
		wantFailure(t, f.run("/system/firmware/plugin", "resync", "confirm=yes"),
			"the plugin resync did not register os-ddclient", "reinstall it")
	})
	t.Run("background starts only", func(t *testing.T) {
		t.Parallel()
		var info = systemFirmwarePluginInfo("os-wol:0:1")
		var f = systemFirmwarePluginFake(t, info, info)
		f.on("POST", "/api/core/firmware/sync_plugins", 200, `{"status":"ok"}`)
		var r = f.run("/system/firmware/plugin", "sync", "background", "confirm=yes")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, `plugin sync started, follow it with "/system/firmware log follow"`)
		wantOneMutation(t, f, "POST", "/api/core/firmware/sync_plugins")
	})
	t.Run("not accepted", func(t *testing.T) {
		t.Parallel()
		var f = systemFirmwareFake(t)
		f.on("POST", "/api/core/firmware/resync_plugins", 200, `{"status":"execute error"}`)
		wantFailure(t, f.run("/system/firmware/plugin", "resync", "confirm=yes"),
			`firmware resync_plugins was not accepted: status "execute error"`)
	})
	t.Run("cleanup follows the log", func(t *testing.T) {
		t.Parallel()
		var f = systemFirmwareFake(t, `{"status":"running","log":"***GOT REQUEST TO CLEANUP***\n>>> Removing unused packages from system\n"}`,
			`{"status":"done","log":"***GOT REQUEST TO CLEANUP***\n>>> Removing unused packages from system\nNothing to do.\n`+
				`>>> Removing package files from cache\nNothing to do.\n***DONE***"}`)
		f.on("POST", "/api/core/firmware/cleanup", 200, systemFirmwareStarted)
		var r = f.run("/system/firmware", "cleanup", "confirm=yes")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "GOT REQUEST TO CLEANUP", "Removing package files from cache", "***DONE***")
		if r.stdout != "" {
			t.Errorf("want no stdout, got %q", r.stdout)
		}
		wantOneMutation(t, f, "POST", "/api/core/firmware/cleanup")
	})
	t.Run("busy refuses", func(t *testing.T) {
		t.Parallel()
		var f = systemFirmwareFake(t)
		f.on("GET", "/api/core/firmware/running", 200, `{"status":"busy"}`)
		for _, args := range [][]string{{"/system/firmware", "cleanup", "confirm=yes"},
			{"/system/firmware/plugin", "sync", "confirm=yes"}, {"/system/firmware/plugin", "resync", "confirm=yes", "background"}} {
			wantFailure(t, f.run(args...), "another firmware action is running")
		}
		wantNoMutations(t, f)
	})
}
