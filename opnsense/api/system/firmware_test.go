package system

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	coreapi "opnsense-cli/opnsense/api"
)

// firmwareTestProduct is the product object of OPNsense 26.7 (shortened)
const firmwareTestProduct = `{"product_abi":"26.7","product_arch":"amd64","product_check":null,` +
	`"product_copyright_owner":"Deciso B.V.","product_copyright_url":"https:\/\/www.deciso.com\/",` +
	`"product_copyright_years":"2014-2026","product_email":"project@opnsense.org","product_hash":"821598263",` +
	`"product_id":"opnsense","product_latest":"26.7","product_license":[],"product_log":0,` +
	`"product_mirror":"https:\/\/pkg.opnsense.org\/FreeBSD:15:amd64\/26.7","product_name":"OPNsense",` +
	`"product_nickname":"Xenial Xenops","product_repos":"OPNsense (Priority: 11)","product_series":"26.7",` +
	`"product_tier":"1","product_time":"Mon Jul 13 15:01:42 UTC 2026","product_version":"26.7",` +
	`"product_website":"https:\/\/opnsense.org\/"}`

// firmwareTestStatusNone is the status before the first check
const firmwareTestStatusNone = `{"product":` + firmwareTestProduct + `,"status_msg":"Firmware status requires to check ` +
	`for update first to provide more information.","status":"none"}`

// firmwareTestStatusUpdate is the status after a check that found updates (shortened)
const firmwareTestStatusUpdate = `{"api_version":"2","connection":"ok","downgrade_packages":[],"download_size":"168MiB",` +
	`"last_check":"Sun Oct 25 15:40:11 UTC 2026","needs_reboot":"1","new_packages":[{"name":"py313-typing-extensions",` +
	`"repository":"OPNsense","version":"4.16.0"}],"os_version":"FreeBSD 15.1-RELEASE-p1","product_id":"opnsense",` +
	`"product_target":"opnsense","product_version":"26.7","product_abi":"26.7","reinstall_packages":[],` +
	`"remove_packages":[],"repository":"ok","upgrade_major_message":"","upgrade_major_version":"",` +
	`"upgrade_needs_reboot":"0","upgrade_packages":[{"name":"unbound","repository":"OPNsense",` +
	`"current_version":"1.25.1_1","new_version":"1.26.1"}],"upgrade_sets":[],"product":` + firmwareTestProduct + `,` +
	`"all_packages":{"unbound":{"reason":"upgrade","old":"1.25.1_1","new":"1.26.1","repository":"OPNsense","name":"unbound"},` +
	`"base":{"reason":"upgrade","old":"26.7","new":"26.7.7","repository":"OPNsense","name":"base"},` +
	`"py313-typing-extensions":{"new":"4.16.0","reason":"new","name":"py313-typing-extensions","repository":"OPNsense","old":"N\/A"}},` +
	`"all_sets":[],"status_msg":"There are 3 updates available, total download size is 293.4MiB. This update requires a reboot.",` +
	`"status_reboot":"1","status":"update"}`

const firmwareTestInfo = `{"product_id":"opnsense","product_version":"26.7","package":[` +
	`{"name":"abseil","version":"20250127.1_2","comment":"Abseil Common Libraries (C++)","flatsize":"5.52MiB","locked":"N\/A",` +
	`"automatic":"N\/A","license":"APACHE20","repository":"OPNsense","origin":"devel\/abseil","provided":"1","installed":"0",` +
	`"path":"OPNsense\/devel\/abseil","configured":"0"},` +
	`{"name":"beep","version":"1.0_2","comment":"Beeps","flatsize":"8.69KiB","locked":"1","automatic":"1","license":"BSD4CLAUSE",` +
	`"repository":"OPNsense","origin":"audio\/beep","provided":"1","installed":"1","path":"OPNsense\/audio\/beep","configured":"1"}],` +
	`"plugin":[{"name":"os-acme-client","version":"4.17","comment":"ACME Client","flatsize":"828KiB","locked":"N\/A",` +
	`"automatic":"N\/A","license":"BSD2CLAUSE","repository":"OPNsense","origin":"opnsense\/os-acme-client","provided":"1",` +
	`"installed":"0","path":"OPNsense\/opnsense\/os-acme-client","configured":"0","tier":"3"}],` +
	`"changelog":[{"series":"26.7","version":"26.7.7","date":"2026-10-13"},{"series":"26.7","version":"26.7.6","date":"2026-10-08"}],` +
	`"product":` + firmwareTestProduct + `}`

func TestFirmwareStatus(t *testing.T) {
	var api, server = newCoreTestApi(t, map[string]string{"GET /api/core/firmware/status": firmwareTestStatusNone})
	var status, err = api.FirmwareStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != FirmwareStatusNone || status.ProductVersion != "26.7" || status.LastCheck != "" ||
		len(status.Updates) != 0 || status.Product.Name != "OPNsense" || status.Product.CopyrightYears != "2014-2026" {
		t.Errorf("unexpected status %+v", status)
	}

	server.set("GET /api/core/firmware/status", firmwareTestStatusUpdate)
	status, err = api.FirmwareStatus()
	if err != nil {
		t.Fatal(err)
	}
	var want = []FirmwareUpdate{
		{Name: "base", Reason: "upgrade", Old: "26.7", New: "26.7.7", Repository: "OPNsense"},
		{Name: "py313-typing-extensions", Reason: "new", Old: "N/A", New: "4.16.0", Repository: "OPNsense"},
		{Name: "unbound", Reason: "upgrade", Old: "1.25.1_1", New: "1.26.1", Repository: "OPNsense"},
	}
	if !reflect.DeepEqual(status.Updates, want) {
		t.Errorf("updates:\n got  %+v\n want %+v", status.Updates, want)
	}
	if status.Status != FirmwareStatusUpdate || !status.Reboot || status.LastCheck == "" || len(status.Sets) != 0 ||
		status.OsVersion != "FreeBSD 15.1-RELEASE-p1" || status.Connection != "ok" {
		t.Errorf("unexpected status %+v", status)
	}
	if len(server.posts()) != 0 {
		t.Errorf("status must be a GET (a POST probes the mirror): %v", server.posts())
	}
}

func TestFirmwareInfo(t *testing.T) {
	var api, _ = newCoreTestApi(t, map[string]string{"GET /api/core/firmware/info": firmwareTestInfo})
	var info, err = api.FirmwareInfo()
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Packages) != 2 || len(info.Plugins) != 1 || len(info.Changelogs) != 2 || info.Product.Nickname != "Xenial Xenops" {
		t.Fatalf("unexpected info %+v", info)
	}
	var abseil = FirmwarePackage{Name: "abseil", Version: "20250127.1_2", Comment: "Abseil Common Libraries (C++)",
		FlatSize: "5.52MiB", License: "APACHE20", Repository: "OPNsense", Origin: "devel/abseil", Provided: true}
	if info.Packages[0] != abseil {
		t.Errorf("got  %+v\nwant %+v", info.Packages[0], abseil)
	}
	if beep := info.Packages[1]; !beep.Installed || !beep.Locked || !beep.Automatic || !beep.Configured {
		t.Errorf("unexpected flags %+v", beep)
	}
	if info.Plugins[0].Tier != "3" || info.Changelogs[0] != (FirmwareChangelogItem{Series: "26.7", Version: "26.7.7", Date: "2026-10-13"}) {
		t.Errorf("unexpected plugin / changelog %+v %+v", info.Plugins[0], info.Changelogs[0])
	}
}

func TestFirmwareChangelogAndPackageTexts(t *testing.T) {
	var api, server = newCoreTestApi(t, map[string]string{
		"POST /api/core/firmware/changelog/26.7.7": `{"status":"ok","version":"26.7.7","html":"<p>Here</p>","date":"October 13, 2026"}`,
		"POST /api/core/firmware/changelog/99.1":   `{"status":"failure"}`,
		"POST /api/core/firmware/details/beep":     `{"details":"Beeps a certain duration"}`,
		"POST /api/core/firmware/details/nope":     `[]`,
		"POST /api/core/firmware/license/beep":     `{"license":"BSD4CLAUSE"}`,
		"POST /api/core/firmware/license/nope":     `[]`,
	})
	var changelog, err = api.FirmwareChangelog("26.7.7")
	if err != nil || changelog != (FirmwareChangelog{Version: "26.7.7", Date: "October 13, 2026", Html: "<p>Here</p>"}) {
		t.Errorf("changelog %+v %v", changelog, err)
	}
	if _, err := api.FirmwareChangelog("99.1"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if details, err := api.FirmwarePackageDetails("beep"); err != nil || details != "Beeps a certain duration" {
		t.Errorf("details %q %v", details, err)
	}
	if license, err := api.FirmwarePackageLicense("beep"); err != nil || license != "BSD4CLAUSE" {
		t.Errorf("license %q %v", license, err)
	}
	for _, call := range []func(string) (string, error){api.FirmwarePackageDetails, api.FirmwarePackageLicense} {
		if _, err := call("nope"); !coreapi.IsNotFound(err) {
			t.Errorf("want NotFoundError, got %v", err)
		}
	}
	var before = len(server.recorded())
	for _, bad := range []string{"", "../x", "a b", "-x", "x/y"} {
		if _, err := api.FirmwarePackageDetails(bad); err == nil {
			t.Errorf("package %q: want an error", bad)
		}
		if _, err := api.FirmwareChangelog(bad); err == nil {
			t.Errorf("version %q: want an error", bad)
		}
	}
	if len(server.recorded()) != before {
		t.Errorf("invalid names must not be sent")
	}
	for _, call := range server.recorded() {
		if call.Method != "POST" || call.Body != "" {
			t.Errorf("want POSTs without body, got %+v", call)
		}
	}
}

func TestFirmwareSettings(t *testing.T) {
	var api, server = newCoreTestApi(t, map[string]string{
		"GET /api/core/firmware/get": `{"firmware":{"mirror":"","flavour":"","plugins":"os-x","type":"","subscription":"s3cret",` +
			`"reboot":"0","aux":"1"}}`,
		"GET /api/core/firmware/get_options": `{"families":{"business":"Business","":"Community","devel":"Development"},` +
			`"families_has_subscription":["business"],"flavours":{"":"(default)"},"flavours_has_subscription":[""],` +
			`"mirrors":{"":"(default)","https:\/\/opnsense-update.deciso.com":"Deciso (HTTPS, Commercial)",` +
			`"https:\/\/pkg.opnsense.org":"OPNsense (HTTPS, Amsterdam, NL)"},"mirrors_has_subscription":["https:\/\/opnsense-update.deciso.com"]}`,
		"POST /api/core/firmware/set": `{"status":"ok"}`,
	})
	var settings, err = api.FirmwareSettings()
	if err != nil || settings != (FirmwareSettings{Plugins: "os-x", Subscription: "s3cret", Reboot: "0", Aux: "1"}) {
		t.Errorf("settings %+v %v", settings, err)
	}
	var options, optionsErr = api.FirmwareOptions()
	if optionsErr != nil {
		t.Fatal(optionsErr)
	}
	var wantTypes = []FirmwareOption{{Key: "business", Name: "Business", Subscription: true}, {Key: "", Name: "Community"},
		{Key: "devel", Name: "Development"}}
	if !reflect.DeepEqual(options.Types, wantTypes) || len(options.Mirrors) != 3 || !options.Mirrors[1].Subscription ||
		options.Mirrors[2].Key != "https://pkg.opnsense.org" || !options.Flavours[0].Subscription {
		t.Errorf("unexpected options %+v", options)
	}

	var mirror, yes = "https://pkg.opnsense.org", true
	if err := api.FirmwareSettingsUpdate(FirmwareSettingsPatch{Mirror: &mirror, Reboot: &yes}); err != nil {
		t.Fatal(err)
	}
	var posts = server.posts()
	if len(posts) != 1 || posts[0].Path != "/api/core/firmware/set" ||
		strings.TrimSpace(posts[0].Body) != `{"firmware":{"mirror":"https://pkg.opnsense.org","reboot":"1"}}` {
		t.Errorf("unexpected set %+v", posts)
	}

	server.set("POST /api/core/firmware/set", `{"status":"failure","status_msg":["The mirror URL contains invalid or unencoded characters."]}`)
	coreTestWantError(t, api.FirmwareSettingsUpdate(FirmwareSettingsPatch{Mirror: &mirror}), "invalid or unencoded")
	var bad = `x"y`
	coreTestWantError(t, api.FirmwareSettingsUpdate(FirmwareSettingsPatch{Flavour: &bad}), "not allowed")
	coreTestWantError(t, api.FirmwareSettingsUpdate(FirmwareSettingsPatch{}), "no firmware setting")
	if len(server.posts()) != 2 {
		t.Errorf("invalid patches must not be sent: %v", server.posts())
	}
}

func TestFirmwareActions(t *testing.T) {
	var api, server = newCoreTestApi(t, map[string]string{
		"GET /api/core/firmware/running":           `{"status":"busy"}`,
		"POST /api/core/firmware/check":            `{"msg_uuid":"9b5d45b7-526a-4d6d-b7f0-1f34848f98cd","status":"ok"}`,
		"POST /api/core/firmware/update":           `{"msg_uuid":"x","status":"ok"}`,
		"POST /api/core/firmware/install/os-acme":  `{"msg_uuid":"x","status":"ok"}`,
		"POST /api/core/firmware/audit":            `{"status":"failure"}`,
		"POST /api/core/firmware/lock/beep":        `{"msg_uuid":"x","status":"ok"}`,
		"POST /api/core/firmware/reinstall/beep":   `{"status":"failure"}`,
		"POST /api/core/firmware/remove/os-acme":   `{"msg_uuid":"x","status":"ok"}`,
		"POST /api/core/firmware/unlock/beep":      `{"msg_uuid":"x","status":"ok"}`,
		"POST /api/core/firmware/upgrade":          `{"msg_uuid":"x","status":"ok"}`,
		"POST /api/core/firmware/health":           `{"msg_uuid":"x","status":"ok"}`,
		"POST /api/core/firmware/connection":       `{"msg_uuid":"x","status":"ok"}`,
		"GET /api/core/firmware/upgradestatus":     `{"status":"done","log":"x\n***DONE***"}`,
		"POST /api/core/firmware/install/bad name": `{"status":"ok"}`,
	})
	if busy, err := api.FirmwareBusy(); err != nil || !busy {
		t.Errorf("busy %v %v", busy, err)
	}
	server.set("GET /api/core/firmware/running", `{"status":"ready"}`)
	if busy, err := api.FirmwareBusy(); err != nil || busy {
		t.Errorf("ready %v %v", busy, err)
	}
	server.set("GET /api/core/firmware/running", `{"status":"what"}`)
	if _, err := api.FirmwareBusy(); err == nil {
		t.Error("want an error for an unknown running state")
	}

	coreTestWantError(t, api.FirmwareStart(FirmwareActionCheck), "")
	coreTestWantError(t, api.FirmwareStart(FirmwareActionUpdate), "")
	coreTestWantError(t, api.FirmwareStart(FirmwareActionUpgrade), "")
	coreTestWantError(t, api.FirmwareStart(FirmwareActionHealth), "")
	coreTestWantError(t, api.FirmwareStart(FirmwareActionConnection), "")
	coreTestWantError(t, api.FirmwareStart(FirmwareActionAudit), `status "failure"`)
	coreTestWantError(t, api.FirmwarePackageAction(FirmwareActionInstall, "os-acme"), "")
	coreTestWantError(t, api.FirmwarePackageAction(FirmwareActionRemove, "os-acme"), "")
	coreTestWantError(t, api.FirmwarePackageAction(FirmwareActionLock, "beep"), "")
	coreTestWantError(t, api.FirmwarePackageAction(FirmwareActionUnlock, "beep"), "")
	coreTestWantError(t, api.FirmwarePackageAction(FirmwareActionReinstall, "beep"), `reinstall of beep was not accepted`)
	var sent = len(server.posts())
	coreTestWantError(t, api.FirmwareStart(FirmwareActionInstall), "needs a package")
	coreTestWantError(t, api.FirmwareStart("reboot"), "unknown firmware action")
	coreTestWantError(t, api.FirmwareStart("poweroff"), "unknown firmware action")
	coreTestWantError(t, api.FirmwarePackageAction(FirmwareActionCheck, "beep"), "not a package action")
	coreTestWantError(t, api.FirmwarePackageAction(FirmwareActionInstall, "bad name"), "invalid package name")
	if len(server.posts()) != sent || sent != 11 {
		t.Errorf("want 11 posts and none for invalid actions, got %v", server.posts())
	}
	for _, call := range server.posts() {
		if call.Body != "" {
			t.Errorf("want POST without body, got %+v", call)
		}
	}
}

// firmwareTestProgressScript answers the n-th upgradestatus request with answers[n], the last one repeats
func firmwareTestProgressScript(t *testing.T, answers ...string) *SystemApi {
	t.Helper()
	var api, server = newCoreTestApi(t, map[string]string{})
	server.sequence("GET /api/core/firmware/upgradestatus", answers...)
	return api
}

func TestFirmwareWait(t *testing.T) {
	var progress = func(status string, log string) string {
		return `{"status":"` + status + `","log":` + strings.ReplaceAll(`"`+strings.ReplaceAll(log, "\n", `\n`)+`"`, "\t", `\t`) + `}`
	}
	var previous = "***GOT REQUEST TO AUDIT***\nold\n***DONE***"
	for _, tc := range []struct {
		name    string
		answers []string
		options FirmwareWaitOptions
		want    string
		output  string
		wantErr string
	}{
		{"previous then new", []string{progress("done", previous), progress("error", ""), progress("running", "a\n"),
			progress("running", "a\nb\n"), progress("done", "a\nb\n***DONE***")},
			FirmwareWaitOptions{Previous: previous}, FirmwareProgressDone, "a\nb\n***DONE***\n", ""},
		{"reboot", []string{progress("running", "x\n"), progress("reboot", "x\n***REBOOT***")},
			FirmwareWaitOptions{}, FirmwareProgressReboot, "x\n***REBOOT***\n", ""},
		{"never starts", []string{progress("done", previous)},
			FirmwareWaitOptions{Previous: previous, Timeout: 100 * time.Millisecond}, FirmwareProgressDone, "", "did not start"},
		{"never ends", []string{progress("running", "x\n")},
			FirmwareWaitOptions{Timeout: 100 * time.Millisecond}, FirmwareProgressRunning, "x\n", "goes on in the background"},
		{"api down", []string{progress("running", "x\n"), `500 {"errorMessage":"down"}`},
			FirmwareWaitOptions{Timeout: 100 * time.Millisecond}, FirmwareProgressRunning, "x\n", "last error"},
		{"running known", []string{progress("running", "a\nb\n"), progress("done", "a\nb\nc\n***DONE***")},
			FirmwareWaitOptions{Running: "a\n"}, FirmwareProgressDone, "b\nc\n***DONE***\n", ""},
		{"new log replaces the old one", []string{progress("running", "other\n"), progress("done", "new\n***DONE***")},
			FirmwareWaitOptions{Running: "a\nb\n"}, FirmwareProgressDone, "other\nnew\n***DONE***\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var api = firmwareTestProgressScript(t, tc.answers...)
			var output strings.Builder
			tc.options.PollInterval = 5 * time.Millisecond
			tc.options.Output = func(text string) { output.WriteString(text) }
			var result, err = api.FirmwareWait(context.Background(), tc.options)
			coreTestWantError(t, err, tc.wantErr)
			if result.Status != tc.want || output.String() != tc.output {
				t.Errorf("got %q with output %q, want %q with %q", result.Status, output.String(), tc.want, tc.output)
			}
		})
	}
}

func TestFirmwareWaitCancelled(t *testing.T) {
	var api, _ = newCoreTestApi(t, map[string]string{"GET /api/core/firmware/upgradestatus": `{"status":"running","log":"x"}`})
	var ctx, cancel = context.WithCancel(context.Background())
	var done = make(chan error, 1)
	go func() {
		var _, err = api.FirmwareWait(ctx, FirmwareWaitOptions{PollInterval: time.Hour})
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("want context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the wait did not stop on cancel")
	}
}
