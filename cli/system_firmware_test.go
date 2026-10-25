package cli

import (
	"net/http"
	"strings"
	"sync"
	"testing"
)

const (
	systemFirmwareProduct = `{"product_name":"OPNsense","product_version":"26.7","product_series":"26.7","product_nickname":"Xenial Xenops",` +
		`"product_mirror":"https:\/\/pkg.opnsense.org\/FreeBSD:15:amd64\/26.7","product_copyright_owner":"Deciso B.V.",` +
		`"product_copyright_url":"https:\/\/www.deciso.com\/","product_copyright_years":"2014-2026","product_website":"https:\/\/opnsense.org\/",` +
		`"product_license":[]}`
	systemFirmwareStatusUpdate = `{"connection":"ok","last_check":"Sun Oct 25 15:40:11 UTC 2026","os_version":"FreeBSD 15.1-RELEASE-p1",` +
		`"product_version":"26.7","repository":"ok","upgrade_major_version":"","product":` + systemFirmwareProduct + `,` +
		`"all_packages":{"unbound":{"reason":"upgrade","old":"1.25.1_1","new":"1.26.1","repository":"OPNsense","name":"unbound"}},` +
		`"all_sets":[],"status_msg":"There is 1 update available, total download size is 1.2MiB.","status_reboot":"0","status":"update"}`
	systemFirmwareInfo = `{"product_id":"opnsense","product_version":"26.7.7","package":[` +
		`{"name":"abseil","version":"20250127.1_2","comment":"Abseil","flatsize":"5.52MiB","locked":"N\/A","automatic":"N\/A",` +
		`"license":"APACHE20","repository":"OPNsense","origin":"devel\/abseil","provided":"1","installed":"0","configured":"0"},` +
		`{"name":"beep","version":"1.0_2","comment":"Beeps","flatsize":"8.69KiB","locked":"N\/A","automatic":"1","license":"BSD4CLAUSE",` +
		`"repository":"OPNsense","origin":"audio\/beep","provided":"1","installed":"1","configured":"1"},` +
		`{"name":"curl","version":"8.21.0","comment":"Transfer","flatsize":"4MiB","locked":"1","automatic":"N\/A","license":"MIT",` +
		`"repository":"OPNsense","origin":"ftp\/curl","provided":"1","installed":"1","configured":"0"}],` +
		`"plugin":[{"name":"os-acme-client","version":"4.17","comment":"ACME Client","flatsize":"828KiB","locked":"N\/A","automatic":"N\/A",` +
		`"license":"BSD2CLAUSE","repository":"OPNsense","origin":"opnsense\/os-acme-client","provided":"1","installed":"0","configured":"0","tier":"3"}],` +
		`"changelog":[{"series":"26.7","version":"26.7.7","date":"2026-10-13"},{"series":"26.7","version":"26.7.6","date":"2026-10-08"}],` +
		`"product":` + systemFirmwareProduct + `}`
	systemFirmwareStarted = `{"msg_uuid":"9b5d45b7-526a-4d6d-b7f0-1f34848f98cd","status":"ok"}`
)

// systemFirmwareFake answers the read-only firmware endpoints; upgradestatus answers the old log until a
// background action was posted, then progress (the last answer repeats)
func systemFirmwareFake(t *testing.T, progress ...string) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", "/api/core/firmware/status", 200, systemFirmwareStatusUpdate)
	f.on("GET", "/api/core/firmware/info", 200, systemFirmwareInfo)
	f.on("GET", "/api/core/firmware/running", 200, `{"status":"ready"}`)
	var mu sync.Mutex
	var n = 0
	f.onFunc("GET", "/api/core/firmware/upgradestatus", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		var answer = `{"status":"done","log":"old\n***DONE***"}`
		if len(f.mutations()) > 0 && len(progress) > 0 {
			answer = progress[min(n, len(progress)-1)]
			n++
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(answer))
	})
	return f
}

func TestSystemFirmwareStatus(t *testing.T) {
	t.Parallel()
	var f = systemFirmwareFake(t)
	var r = f.run("/system/firmware", "status", "detail")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "product:       OPNsense 26.7", "status:        update", "updates:       1",
		"needs-reboot:  no", "unbound  1.25.1_1   1.26.1  upgrade  OPNsense")
	r = f.run("/system/firmware", "status", "json")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, `"status":"update"`)
	wantNoMutations(t, f)
}

func TestSystemFirmwareCheckAndAudit(t *testing.T) {
	t.Parallel()
	t.Run("check", func(t *testing.T) {
		t.Parallel()
		var f = systemFirmwareFake(t, `{"status":"running","log":"***GOT REQUEST TO CHECK FOR UPDATES***\n"}`,
			`{"status":"done","log":"***GOT REQUEST TO CHECK FOR UPDATES***\nOPNsense is up to date.\n***DONE***"}`)
		f.on("POST", "/api/core/firmware/check", 200, systemFirmwareStarted)
		var r = f.run("/system/firmware", "check", "log")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "GOT REQUEST TO CHECK", "***DONE***")
		wantContains(t, "stdout", r.stdout, "status:        update")
		if call := wantOneMutation(t, f, "POST", "/api/core/firmware/check"); call.Body != "" {
			t.Errorf("want no body, got %q", call.Body)
		}
	})
	t.Run("audit prints the report", func(t *testing.T) {
		t.Parallel()
		var f = systemFirmwareFake(t, `{"status":"done","log":"***GOT REQUEST TO AUDIT HEALTH***\nNo problems detected.\n***DONE***"}`)
		f.on("POST", "/api/core/firmware/health", 200, systemFirmwareStarted)
		var r = f.run("/system/firmware", "audit", "type=health")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "No problems detected.")
		wantNotContains(t, "stdout", r.stdout, "old")
		wantOneMutation(t, f, "POST", "/api/core/firmware/health")
	})
	t.Run("busy refuses", func(t *testing.T) {
		t.Parallel()
		var f = systemFirmwareFake(t)
		f.on("GET", "/api/core/firmware/running", 200, `{"status":"busy"}`)
		wantFailure(t, f.run("/system/firmware", "check"), "another firmware action is running")
		wantFailure(t, f.run("/system/firmware", "update", "confirm=yes"), "another firmware action is running")
		wantNoMutations(t, f)
	})
	t.Run("not accepted", func(t *testing.T) {
		t.Parallel()
		var f = systemFirmwareFake(t)
		f.on("POST", "/api/core/firmware/audit", 200, `{"status":"failure"}`)
		wantFailure(t, f.run("/system/firmware", "audit"), `"failure"`)
	})
}

func TestSystemFirmwareDangerousNeedConfirm(t *testing.T) {
	t.Parallel()
	var f = systemFirmwareFake(t)
	for _, args := range [][]string{
		{"/system/firmware", "update"}, {"/system/firmware", "upgrade", "confirm=no"},
		{"/system/firmware/package", "install", "abseil"}, {"/system/firmware/package", "remove", "beep"},
		{"/system/firmware/package", "reinstall", "beep"}, {"/system/firmware/package", "lock", "beep"},
		{"/system/firmware/package", "unlock", "curl"}, {"/system/firmware/plugin", "install", "os-acme-client"},
	} {
		wantFailure(t, f.run(args...), "confirm=yes")
	}
	wantFailure(t, f.runScript("/system/firmware\nupdate\n"), "confirm=yes")
	wantNoCalls(t, f)
}

func TestSystemFirmwareUpdateAndPackages(t *testing.T) {
	t.Parallel()
	t.Run("update follows to the reboot", func(t *testing.T) {
		t.Parallel()
		var f = systemFirmwareFake(t, `{"status":"running","log":"***GOT REQUEST TO UPDATE***\n"}`,
			`{"status":"reboot","log":"***GOT REQUEST TO UPDATE***\n***REBOOT***"}`)
		f.on("POST", "/api/core/firmware/update", 200, systemFirmwareStarted)
		var r = f.run("/system/firmware", "update", "confirm=yes")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "GOT REQUEST TO UPDATE", "reboots now")
		wantOneMutation(t, f, "POST", "/api/core/firmware/update")
	})
	t.Run("background", func(t *testing.T) {
		t.Parallel()
		var f = systemFirmwareFake(t)
		f.on("POST", "/api/core/firmware/install/os-acme-client", 200, systemFirmwareStarted)
		var r = f.run("/system/firmware/plugin", "install", "os-acme-client", "background", "confirm=yes")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "install of os-acme-client started")
		wantOneMutation(t, f, "POST", "/api/core/firmware/install/os-acme-client")
	})
	t.Run("package state is checked before posting", func(t *testing.T) {
		t.Parallel()
		var f = systemFirmwareFake(t)
		for args, want := range map[string]string{
			"install beep":    "installed already",
			"remove abseil":   "not installed",
			"lock curl":       "locked already",
			"unlock beep":     "not locked",
			"install nosuch":  "not found",
			"remove ../../x":  "not found",
			"reinstall 7":     "not found",
			"install os-acme": "not found",
		} {
			wantFailure(t, f.run(append([]string{"/system/firmware/package"}, append(strings.Fields(args), "confirm=yes")...)...), want)
		}
		wantNoMutations(t, f)
	})
	t.Run("lock", func(t *testing.T) {
		t.Parallel()
		var f = systemFirmwareFake(t, `{"status":"done","log":"***GOT REQUEST TO LOCK***\n***DONE***"}`)
		f.on("POST", "/api/core/firmware/lock/beep", 200, systemFirmwareStarted)
		wantExit(t, f.run("/system/firmware/package", "lock", "0", "confirm=yes"), 0)
		wantOneMutation(t, f, "POST", "/api/core/firmware/lock/beep")
	})
}

func TestSystemFirmwarePackagePrint(t *testing.T) {
	t.Parallel()
	var f = systemFirmwareFake(t)
	f.on("POST", "/api/core/firmware/details/beep", 200, `{"details":"Beeps a certain duration"}`)
	f.on("POST", "/api/core/firmware/license/beep", 200, `{"license":"BSD4CLAUSE"}`)
	var r = f.run("/system/firmware/package", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "0  beep  1.0_2    yes        A", "1  curl  8.21.0   yes        L")
	wantNotContains(t, "stdout", r.stdout, "abseil")
	r = f.run("/system/firmware/package", "print", "all", "json", "search=abs")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, `"name":"abseil"`, `"installed":false`)
	r = f.run("/system/firmware/plugin", "print", "all")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "os-acme-client", "TIER")
	r = f.run("/system/firmware/package", "show", "beep")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "automatic:   yes", "Beeps a certain duration")
	r = f.run("/system/license", "print", "package=beep")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "BSD4CLAUSE")
	for _, call := range f.mutations() {
		if call.Body != "" || (!strings.HasPrefix(call.Path, "/api/core/firmware/details/") && !strings.HasPrefix(call.Path, "/api/core/firmware/license/")) {
			t.Errorf("unexpected mutation %v", call)
		}
	}
}

func TestSystemFirmwareChangelog(t *testing.T) {
	t.Parallel()
	var f = systemFirmwareFake(t)
	f.on("POST", "/api/core/firmware/changelog/26.7.6", 200, `{"status":"ok","version":"26.7.6","date":"October 8, 2026",`+
		`"html":"<p>Intro &amp; more</p><ul><li>one</li><li>two [<a target=\"_blank\" href=\"https://x.example/1\">1</a>]</li></ul>"}`)
	f.on("POST", "/api/core/firmware/changelog/99.1", 200, `{"status":"failure"}`)
	var r = f.run("/system/firmware/changelog", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "0  26.7.7   26.7    2026-10-13  yes", "1  26.7.6")
	r = f.run("/system/firmware/changelog", "show", "1")
	wantExit(t, r, 0)
	if want := "26.7.6 (October 8, 2026)\n\nIntro & more\n\n- one\n- two [1 (https://x.example/1)]\n"; r.stdout != want {
		t.Errorf("got %q, want %q", r.stdout, want)
	}
	wantFailure(t, f.run("/system/firmware/changelog", "show", "99.1"), "not found")
	wantFailure(t, f.run("/system/firmware/changelog", "show", "a/b"), "invalid release version")
}

func TestSystemFirmwareSettings(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/core/firmware/get", 200, `{"firmware":{"mirror":"","flavour":"","plugins":"","type":"devel","subscription":"s3cret","reboot":"0","aux":"0"}}`)
	f.on("GET", "/api/core/firmware/get_options", 200, `{"families":{"business":"Business","":"Community","devel":"Development"},`+
		`"families_has_subscription":["business"],"flavours":{"":"(default)"},"mirrors":{"":"(default)","https:\/\/pkg.opnsense.org":"OPNsense"}}`)
	f.on("POST", "/api/core/firmware/set", 200, `{"status":"ok"}`)
	var r = f.run("/system/firmware/settings", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "mirror:        (default)", "type:          devel", "subscription:  (set)")
	wantNotContains(t, "stdout", r.stdout, "s3cret")
	r = f.run("/system/firmware/settings", "print", "options=type")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, `""        Community    no`, "business  Business     yes")

	wantFailure(t, f.run("/system/firmware/settings", "set"), "nothing to change")
	wantFailure(t, f.run("/system/firmware/settings", "set", "type=stable"), "type must be one of")
	wantFailure(t, f.run("/system/firmware/settings", "set", `mirror=a|b`), "must not contain")
	wantNoMutations(t, f)
	r = f.run("/system/firmware/settings", "set", "type=", "mirror=https://pkg.opnsense.org", "reboot")
	wantExit(t, r, 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/core/firmware/set"),
		map[string]any{"firmware": map[string]any{"type": "", "mirror": "https://pkg.opnsense.org", "reboot": "1"}})
}

func TestSystemLicensePrint(t *testing.T) {
	t.Parallel()
	var f = systemFirmwareFake(t)
	var r = f.run("/system/license", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "product:        OPNsense 26.7", "copyright:      (c) 2014-2026 Deciso B.V.", "website:        https://opnsense.org/")
	wantNotContains(t, "stdout", r.stdout, "license:")
	wantNoMutations(t, f)
}
