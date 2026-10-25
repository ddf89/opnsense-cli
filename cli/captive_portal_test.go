package cli

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	captivePortalTestZoneSearch     = "/api/captiveportal/settings/search_zones"
	captivePortalTestTemplateSearch = "/api/captiveportal/template/search_templates"
	captivePortalTestProviders      = "/api/captiveportal/voucher/list_providers"
)

func captivePortalTestZoneRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "z-1", "enabled": "0", "zoneid": "0", "interfaces": "lan", "%interfaces": "LAN", "disableRules": "0",
		"authservers": "Local Database", "roaming": "1", "alwaysSendAccountingReqs": "0", "authEnforceGroup": "1999",
		"idletimeout": "30", "hardtimeout": "0", "concurrentlogins": "1", "certificate": "", "servername": "",
		"allowedAddresses": "", "allowedMACAddresses": "", "extendedPreAuthData": "0", "template": "t-1", "description": "guests",
	}, overrides)
}

func captivePortalTestFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(captivePortalTestZoneSearch, captivePortalTestZoneRow(nil))
	f.search(captivePortalTestTemplateSearch,
		map[string]any{"uuid": "t-1", "fileid": "6ade2378b8019", "name": "guest page", "content": "UEsDBBQAAAAIAA=="},
		map[string]any{"uuid": "t-2", "fileid": "6ade2378b8020", "name": "unused", "content": "UEsDBBQAAAAIAA=="})
	f.on("GET", "/api/captiveportal/settings/get_zone", 200, `{"zone":{"enabled":"1","interfaces":{"lan":{"value":"LAN","selected":1},`+
		`"opt2":{"value":"GUEST","selected":0}},"authservers":{"Local Database":{"value":"Local Database","selected":0},`+
		`"Vouchers":{"value":"Vouchers","selected":0}},"authEnforceGroup":{"":{"value":"None","selected":1},"1999":{"value":"admins","selected":0}},`+
		`"certificate":{"":{"value":"None","selected":1},"6ade1fe2418b9":{"value":"Web GUI TLS certificate","selected":0}},`+
		`"template":{"":{"value":"None","selected":1}},"description":""}}`)
	return f
}

func captivePortalTestZip(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	var writer = zip.NewWriter(&buffer)
	var file, _ = writer.Create("index.html")
	_, _ = file.Write([]byte("<html>portal</html>"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestCaptivePortalZone(t *testing.T) {
	t.Parallel()
	t.Run("print and show", func(t *testing.T) {
		t.Parallel()
		var f = captivePortalTestFake(t)
		var r = f.run("/captive-portal/zone", "print")
		wantExit(t, r, 0)
		systemCronWantTable(t, r.stdout, []string{"#", "DISABLED", "ZONE-ID", "INTERFACES", "AUTH-SERVERS", "IDLE-TIMEOUT", "HARD-TIMEOUT", "DESCRIPTION"},
			7, "guests")
		r = f.run("/captive-portal/zone", "show", "guests")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "enforce-group:           admins\n", "template:                guest page\n", "interfaces:              LAN\n")
		wantNoMutations(t, f)
	})
	t.Run("add is always disabled and resolves names", func(t *testing.T) {
		t.Parallel()
		var f = captivePortalTestFake(t)
		f.on("POST", "/api/captiveportal/settings/add_zone", 200, answerAdded("z-new"))
		var r = f.run("/captive-portal/zone", "add", "description=staff", "interfaces=guest", "auth-servers=local database,Vouchers",
			"enforce-group=admins", "template=Guest Page", "certificate=Web GUI TLS certificate", "allowed-macs=02:00:00:00:00:01", "idle-timeout=10")
		wantExit(t, r, 0)
		if r.stdout != "z-new\n" {
			t.Errorf("stdout %q", r.stdout)
		}
		wantJSON(t, wantOneMutation(t, f, "POST", "/api/captiveportal/settings/add_zone"), map[string]any{"zone": map[string]any{
			"enabled": "0", "description": "staff", "interfaces": "opt2", "authservers": "Local Database,Vouchers", "authEnforceGroup": "1999",
			"template": "t-1", "certificate": "6ade1fe2418b9", "allowedMACAddresses": "02:00:00:00:00:01", "idletimeout": "10"}})
	})
	t.Run("refusals send nothing", func(t *testing.T) {
		t.Parallel()
		var f = captivePortalTestFake(t)
		wantFailure(t, f.run("/captive-portal/zone", "add", "description=guests", "interfaces=lan"), "exists already")
		wantFailure(t, f.run("/captive-portal/zone", "add", "description=x", "interfaces=wan"), `valid are: "LAN", "GUEST"`)
		wantExit(t, f.run("/captive-portal/zone", "add", "description=x"), 1)
		wantExit(t, f.run("/captive-portal/zone", "set", "guests", "idle-timeout=20000"), 1)
		wantExit(t, f.run("/captive-portal/zone", "set", "guests", "disabled=no"), 1)
		wantFailure(t, f.run("/captive-portal/zone", "enable", "guests"), "confirm")
		wantNoMutations(t, f)
	})
	t.Run("enable with confirmation, set", func(t *testing.T) {
		t.Parallel()
		var f = captivePortalTestFake(t)
		f.on("POST", "/api/captiveportal/settings/toggle_zone/z-1/1", 200, `{"result":"Enabled","changed":true}`)
		wantExit(t, f.run("/captive-portal/zone", "enable", "guests", "confirm=yes"), 0)
		wantOneMutation(t, f, "POST", "/api/captiveportal/settings/toggle_zone/z-1/1")

		var g = captivePortalTestFake(t)
		g.on("POST", "/api/captiveportal/settings/set_zone/z-1", 200, answerSaved)
		wantExit(t, g.run("/captive-portal/zone", "set", "0", "template=", "allowed-addresses=192.0.2.0/24"), 0)
		wantJSON(t, wantOneMutation(t, g, "POST", "/api/captiveportal/settings/set_zone/z-1"), map[string]any{"zone": map[string]any{
			"template": "", "allowedAddresses": "192.0.2.0/24"}})
	})
}

func TestCaptivePortalTemplate(t *testing.T) {
	t.Parallel()
	var zipped = captivePortalTestZip(t)
	t.Run("print, refuse removing a used one", func(t *testing.T) {
		t.Parallel()
		var f = captivePortalTestFake(t)
		var r = f.run("/captive-portal/template", "print")
		wantExit(t, r, 0)
		systemCronWantTable(t, r.stdout, []string{"#", "NAME", "FILE-ID", "SIZE", "USED-BY"}, 4, "guests", "-")
		r = f.run("/captive-portal/template", "print", "detail")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "name:", "file-id:", "used-by:  guests")
		wantFailure(t, f.run("/captive-portal/template", "remove", "guest page"), "used by the zones guests")
		wantNoMutations(t, f)
		f.on("POST", "/api/captiveportal/template/del_template/t-2", 200, answerDeleted)
		wantExit(t, f.run("/captive-portal/template", "remove", "unused"), 0)
	})
	t.Run("upload and download", func(t *testing.T) {
		t.Parallel()
		var f = captivePortalTestFake(t)
		f.on("POST", "/api/captiveportal/template/save_template", 200, `{"name":"guest page"}`)
		f.onFunc("GET", "/api/captiveportal/template/get_template/6ade2378b8019", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(zipped)
		})
		var dir = t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "page.zip"), zipped, 0o600)
		_ = os.WriteFile(filepath.Join(dir, "bad.zip"), []byte("no zip"), 0o600)
		wantFailure(t, runOpnIn(t, dir, f.env(), "/captive-portal/template", "upload", "name=guest page", "file=page.zip"), "exists already")
		wantFailure(t, runOpnIn(t, dir, f.env(), "/captive-portal/template", "upload", "name=new", "file=bad.zip"), "not a zip")
		wantExit(t, runOpnIn(t, dir, f.env(), "/captive-portal/template", "upload", "name=bad-name", "file=page.zip"), 1)
		wantNoMutations(t, f)
		var r = runOpnIn(t, dir, f.env(), "/captive-portal/template", "upload", "name=guest page", "file=page.zip", "replace")
		wantExit(t, r, 0)
		if r.stdout != "t-1\n" {
			t.Errorf("stdout %q", r.stdout)
		}
		wantJSON(t, wantOneMutation(t, f, "POST", "/api/captiveportal/template/save_template"), map[string]any{
			"name": "guest page", "uuid": "t-1", "content": base64.StdEncoding.EncodeToString(zipped)})

		wantExit(t, runOpnIn(t, dir, f.env(), "/captive-portal/template", "download", "guest page"), 0)
		if content, err := os.ReadFile(filepath.Join(dir, "template_6ade2378b8019.zip")); err != nil || !bytes.Equal(content, zipped) {
			t.Errorf("downloaded %v", err)
		}
		wantFailure(t, runOpnIn(t, dir, f.env(), "/captive-portal/template", "download", "guest page"), "already exists")
	})
}

func TestCaptivePortalSession(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/captiveportal/session/zones", 200, `["guests"]`)
	f.on("GET", "/api/captiveportal/session/search", 200, `{"rows":[{"zoneid":0,"sessionId":"s-1","authenticated_via":"Local Database",`+
		`"userName":"alice","startTime":1761400000.5,"ipAddress":"192.168.1.50","macAddress":"02:00:00:00:00:01","packets_in":1,"packets_out":2,`+
		`"bytes_in":1500,"bytes_out":2500000,"last_accessed":1761400100,"acc_session_timeout":null,"ipAddresses":["192.168.1.50"]}]}`)
	f.on("POST", "/api/captiveportal/session/disconnect", 200, `{"zoneid":0,"sessionid":"s-1","username":"alice","terminateCause":"Admin-Reset"}`)
	var r = f.run("/captive-portal/session", "print", "zone=Guests")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "guests", "alice", "192.168.1.50", "1.5 kB", "2.5 MB")
	for _, call := range f.calls() {
		if call.Path == "/api/captiveportal/session/search" && call.Query.Get("selected_zones[]") != "0" {
			t.Errorf("zone filter %v", call.Query)
		}
	}
	wantFailure(t, f.run("/captive-portal/session", "print", "zone=nope"), `valid are: "guests"`)
	wantFailure(t, f.run("/captive-portal/session", "disconnect", "alice"), "confirm")
	wantNoMutations(t, f)
	wantExit(t, f.run("/captive-portal/session", "disconnect", "192.168.1.50", "confirm=yes"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/captiveportal/session/disconnect"), map[string]any{"sessionId": "s-1"})
}

func TestCaptivePortalVoucher(t *testing.T) {
	t.Parallel()
	var newFake = func(t *testing.T, providers string) *fakeOPN {
		var f = newFakeOPN(t)
		f.on("GET", captivePortalTestProviders, 200, providers)
		f.on("GET", "/api/captiveportal/voucher/list_voucher_groups/Vouchers/", 200, `["event"]`)
		f.on("GET", "/api/captiveportal/voucher/list_vouchers/Vouchers/event/", 200, `[{"username":"abc","validity":3600,"expirytime":0,`+
			`"starttime":1761400000,"endtime":1761403600,"state":"unused","vouchergroup":"event"}]`)
		f.on("POST", "/api/captiveportal/voucher/generate_vouchers/Vouchers/", 200,
			`[{"username":"u1","password":"p,1","vouchergroup":"event","validity":"14400","expirytime":0,"starttime":null}]`)
		f.on("POST", "/api/captiveportal/voucher/expire_voucher/Vouchers/", 200, `{"status":"ok"}`)
		f.on("POST", "/api/captiveportal/voucher/drop_voucher_group/Vouchers/event/", 200, `{"status":"drop"}`)
		return f
	}
	var f = newFake(t, `["Vouchers"]`)
	var r = f.run("/captive-portal/voucher", "print")
	wantExit(t, r, 0)
	systemCronWantTable(t, r.stdout, []string{"#", "USERNAME", "GROUP", "STATE", "VALIDITY", "VALID-UNTIL", "EXPIRES"}, 1, "abc")

	var dir = t.TempDir()
	r = runOpnIn(t, dir, f.env(), "/captive-portal/voucher", "generate", "group=event", "count=1", "validity=4h", "expiry=168h")
	wantExit(t, r, 0)
	var content, err = os.ReadFile(filepath.Join(dir, "event.csv"))
	if err != nil || string(content) != "username,password,vouchergroup,expirytime,validity\nu1,\"p,1\",event,0,14400\n" {
		t.Errorf("csv %q %v", content, err)
	}
	wantNotContains(t, "stdout", r.stdout+r.stderr, "p,1")
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/captiveportal/voucher/generate_vouchers/Vouchers/"), map[string]any{
		"count": "1", "validity": "14400", "expirytime": "604800", "vouchergroup": "event"})

	var g = newFake(t, `["Vouchers"]`)
	wantFailure(t, g.run("/captive-portal/voucher", "drop-group", "group=event"), "confirm")
	wantExit(t, g.run("/captive-portal/voucher", "generate", "group=a/b", "count=1", "validity=60"), 1)
	wantExit(t, g.run("/captive-portal/voucher", "generate", "group=x", "count=0", "validity=60"), 1)
	wantNoMutations(t, g)
	wantExit(t, g.run("/captive-portal/voucher", "drop-group", "group=event", "confirm=yes"), 0)
	r = g.runScript("/captive-portal/voucher\nprint group=event\nexpire 0 confirm=yes\n")
	wantExit(t, r, 0)
	var mutations = g.mutations()
	if len(mutations) != 2 || mutations[1].Path != "/api/captiveportal/voucher/expire_voucher/Vouchers/" {
		t.Fatalf("mutations %v", mutations)
	}
	wantJSON(t, mutations[1], map[string]any{"username": "abc"})

	var h = newFake(t, `["Vouchers","Other"]`)
	wantFailure(t, h.run("/captive-portal/voucher", "groups"), "several voucher providers")
	wantFailure(t, newFake(t, `[]`).run("/captive-portal/voucher", "groups"), "there is none")
	wantExit(t, h.run("/captive-portal/voucher", "groups", "provider=vouchers"), 0)
}

func TestCaptivePortalService(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	wantFailure(t, f.run("/captive-portal/service", "stop"), "confirm")
	wantNoCalls(t, f)
	f.on("GET", "/api/captiveportal/service/status", 200, `{"status":"disabled"}`)
	f.on("POST", "/api/captiveportal/service/reconfigure", 200, `{"status":"ok"}`)
	wantContains(t, "stdout", f.run("/captive-portal/service", "status").stdout, "status:  disabled")
	wantExit(t, f.run("/captive-portal/service", "reconfigure"), 0)
	wantOneMutation(t, f, "POST", "/api/captiveportal/service/reconfigure")
	if !strings.Contains(f.run("/captive-portal", "?").stdout, "voucher") {
		t.Error("menu help lacks voucher")
	}
}
