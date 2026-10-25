package cli

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Fixtures are shaped like OPNsense 26.7 (OpenVPN ExportController): providers is an object keyed by vpnid (the
// instance uuid, a number for legacy servers), [] when there is none; accounts always has the "(none)" entry

const (
	openvpnExportProvidersPath = "/api/openvpn/export/providers"
	openvpnExportTemplatesPath = "/api/openvpn/export/templates"
	openvpnExportAccountsPath  = "/api/openvpn/export/accounts/"
	openvpnExportStorePath     = "/api/openvpn/export/store_presets/"
	openvpnExportDownloadPath  = "/api/openvpn/export/download/"

	openvpnExportWarrior = "3f0c6a2e-9b1d-4c8e-a7f5-0d2b6e4c1a90"
	openvpnExportOffice  = "8d1e2f3a-4b5c-4d6e-8f70-112233445566"
	openvpnExportAlice   = "6ade13f1bff83"
	openvpnExportBob     = "6ade13f1aaa01"

	openvpnExportProvidersAnswer = `{"` + openvpnExportWarrior + `":{"name":"Road Warrior udp:1194","mode":"server_tls_user","vpnid":"` + openvpnExportWarrior + `",` +
		`"hostname":"vpn.example.com","template":"PlainOpenVPN","local_port":"1194","random_local_port":"1",` +
		`"validate_server_cn":"1","cryptoapi":null,"auth_nocache":null,"static_challenge":null,"plain_config":"verb 4\nmute 10"},` +
		`"` + openvpnExportOffice + `":{"name":"office tcp:443","mode":"","vpnid":"` + openvpnExportOffice + `",` +
		`"hostname":null,"template":null,"local_port":"443","random_local_port":"1","validate_server_cn":"1",` +
		`"cryptoapi":null,"auth_nocache":null,"static_challenge":null,"plain_config":null}}`

	openvpnExportAccountsAnswer = `{"":{"description":"(none) Exclude certificate from export","users":[]},` +
		`"` + openvpnExportAlice + `":{"description":"alice laptop","users":["alice"]},` +
		`"` + openvpnExportBob + `":{"description":"bob phone","users":["bob"]}}`

	openvpnExportNoneOnly = `{"":{"description":"(none) Exclude certificate from export","users":[]}}`

	openvpnExportTemplatesAnswer = `{"ArchiveOpenVPN":{"name":"Archive","supportedOptions":["plain_config","p12_password","random_local_port","auth_nocache","cryptoapi","static_challenge"]},` +
		`"PlainOpenVPN":{"name":"File Only","supportedOptions":["plain_config","random_local_port","auth_nocache","cryptoapi","static_challenge"]},` +
		`"ViscosityVisz":{"name":"Viscosity (visz)","supportedOptions":["plain_config","p12_password","random_local_port","auth_nocache","cryptoapi","static_challenge"]}}`

	openvpnExportOvpn = "dev tun\npersist-tun\npersist-key\nclient\nresolv-retry infinite\nremote vpn.example.com 1194 udp\nlport 0\n" +
		"<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n<cert>\n-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n</cert>\n" +
		"<key>\n-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n</key>"
)

func openvpnExportDownloadAnswer(changed bool, filename string, filetype string, content string) string {
	var answer, _ = json.Marshal(map[string]any{
		"result": "ok", "changed": changed, "filename": filename, "filetype": filetype,
		"content": base64.StdEncoding.EncodeToString([]byte(content)),
	})
	return string(answer)
}

func openvpnExportFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", openvpnExportProvidersPath, 200, openvpnExportProvidersAnswer)
	f.on("GET", openvpnExportTemplatesPath, 200, openvpnExportTemplatesAnswer)
	f.on("GET", openvpnExportAccountsPath+openvpnExportWarrior, 200, openvpnExportAccountsAnswer)
	f.on("GET", openvpnExportAccountsPath+openvpnExportOffice, 200, openvpnExportNoneOnly)
	f.on("POST", openvpnExportDownloadPath+openvpnExportWarrior+"/"+openvpnExportAlice, 200,
		openvpnExportDownloadAnswer(false, "Road_Warrior_alice.ovpn", "text/ovpn", openvpnExportOvpn))
	return f
}

// openvpnExportBody returns the openvpn_export object of a mutation
func openvpnExportBody(t *testing.T, call apiCall) map[string]any {
	t.Helper()
	var body = call.json(t)
	var options, ok = body["openvpn_export"].(map[string]any)
	if len(body) != 1 || !ok {
		t.Fatalf("body of %s is not {\"openvpn_export\":{...}}: %s", call.Path, call.Body)
	}
	return options
}

func TestOpenvpnExportPrint(t *testing.T) {
	t.Parallel()
	var f = openvpnExportFake(t)
	var r = f.run("/vpn/openvpn/export", "print")
	wantExit(t, r, 0)
	var rows = systemBackupWantTable(t, r.stdout, []string{"#", "DESCRIPTION", "LISTEN", "AUTH", "HOSTNAME", "PORT", "TEMPLATE", "UUID"}, 1,
		"Road Warrior", "office")
	if len(rows) == 3 {
		if strings.Join(rows[1], "|") != "0|Road Warrior|udp:1194|certificate+user|vpn.example.com|1194|PlainOpenVPN|"+openvpnExportWarrior {
			t.Errorf("row 0: %q", rows[1])
		}
		if strings.Join(rows[2], "|") != "1|office|tcp:443|certificate|-|443|-|"+openvpnExportOffice {
			t.Errorf("row 1: %q", rows[2])
		}
	}
	wantNoMutations(t, f)

	t.Run("none", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", openvpnExportProvidersPath, 200, `[]`)
		var r = f.run("/vpn/openvpn/export", "print")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "only enabled OpenVPN server instances")
	})
	t.Run("search", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		var r = f.run("/vpn/openvpn/export", "print", "search=TCP:")
		wantExit(t, r, 0)
		systemBackupWantTable(t, r.stdout, []string{"#", "DESCRIPTION", "LISTEN", "AUTH", "HOSTNAME", "PORT", "TEMPLATE", "UUID"}, 1, "office")
		if r.stderr != "" {
			t.Errorf("no hint for an empty search result: %q", r.stderr)
		}
	})
	t.Run("detail", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		var r = f.run("/vpn/openvpn/export", "print", "detail")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "0\n  uuid:", "name:                Road Warrior udp:1194", "random-local-port:   yes",
			"cryptoapi:           no", `plain-config:        verb 4\nmute 10`, "\n1\n", "hostname:            \n")
	})
	t.Run("json is the raw provider", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		var r = f.run("/vpn/openvpn/export", "print", "json")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != 2 {
			t.Fatalf("want 2 lines: %q", r.stdout)
		}
		var server map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &server); err != nil || server["vpnid"] != openvpnExportWarrior ||
			server["cryptoapi"] != nil || server["plain_config"] != "verb 4\nmute 10" {
			t.Errorf("json: %v %s", err, lines[0])
		}
	})
}

func TestOpenvpnExportShow(t *testing.T) {
	t.Parallel()
	for _, selector := range []string{"1", "office", "OFFICE", "office tcp:443", openvpnExportOffice} {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()
			var f = openvpnExportFake(t)
			var r = f.run("/vpn/openvpn/export", "show", selector)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, "uuid:                "+openvpnExportOffice, "auth:                certificate\n",
				"port:                443\n", "validate-server-cn:  yes\n")
		})
	}
	t.Run("unknown", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		wantFailure(t, f.run("/vpn/openvpn/export", "show", "nope"), "not found", "nope", "only enabled")
		wantFailure(t, f.run("/vpn/openvpn/export", "show", "5"), "#5")
	})
}

func TestOpenvpnExportAccounts(t *testing.T) {
	t.Parallel()
	var f = openvpnExportFake(t)
	var r = f.run("/vpn/openvpn/export", "accounts", "Road Warrior")
	wantExit(t, r, 0)
	var rows = systemBackupWantTable(t, r.stdout, []string{"#", "CERTIFICATE", "USERS", "REFID"}, 1, "alice laptop", "bob phone")
	if len(rows) == 3 && strings.Join(rows[1], "|") != "0|alice laptop|alice|"+openvpnExportAlice {
		t.Errorf("row 0: %q", rows[1])
	}
	wantNotContains(t, "stdout", r.stdout, "(none)")
	wantNoMutations(t, f)

	t.Run("by # and json", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		var r = f.run("/vpn/openvpn/export", "accounts", "item=0", "json")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		var account map[string]any
		if len(lines) != 2 || json.Unmarshal([]byte(lines[1]), &account) != nil || account["certref"] != openvpnExportBob ||
			!reflect.DeepEqual(account["users"], []any{"bob"}) {
			t.Errorf("json: %q", r.stdout)
		}
	})
	t.Run("search", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		var r = f.run("/vpn/openvpn/export", "accounts", "0", "search=BOB")
		wantExit(t, r, 0)
		systemBackupWantTable(t, r.stdout, []string{"#", "CERTIFICATE", "USERS", "REFID"}, 1, "bob phone")
	})
	t.Run("server without client certificates", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		var r = f.run("/vpn/openvpn/export", "accounts", "office")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "account=none")
	})
	t.Run("unknown server", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		wantFailure(t, f.run("/vpn/openvpn/export", "accounts", "nope"), "not found", "only enabled")
		systemBackupWantNoCallTo(t, f, openvpnExportAccountsPath)
	})
}

func TestOpenvpnExportTemplates(t *testing.T) {
	t.Parallel()
	var f = openvpnExportFake(t)
	var r = f.run("/vpn/openvpn/export", "templates")
	wantExit(t, r, 0)
	var rows = systemBackupWantTable(t, r.stdout, []string{"NAME", "DESCRIPTION", "OPTIONS"}, 0, "ArchiveOpenVPN", "PlainOpenVPN", "ViscosityVisz")
	if len(rows) == 4 && strings.Join(rows[2], "|") != "PlainOpenVPN|File Only|plain-config,random-local-port,auth-nocache,cryptoapi,static-challenge" {
		t.Errorf("row: %q", rows[2])
	}

	r = f.run("/vpn/openvpn/export", "templates", "json")
	wantExit(t, r, 0)
	var template map[string]any
	if err := json.Unmarshal([]byte(strings.Split(r.stdout, "\n")[0]), &template); err != nil || template["name"] != "ArchiveOpenVPN" || template["description"] != "Archive" {
		t.Errorf("json: %v %q", err, r.stdout)
	}
}

func TestOpenvpnExportSet(t *testing.T) {
	t.Parallel()
	var storeWarrior = openvpnExportStorePath + openvpnExportWarrior

	t.Run("only the given presets are sent", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		f.on("POST", storeWarrior, 200, `{"result":"ok","changed":true}`)
		var r = f.run("/vpn/openvpn/export", "set", "0", "template=archiveopenvpn", "hostname=vpn.example.com, 198.51.100.7",
			"port=", "auth-nocache", "random-local-port=no", `plain-config=verb 4\nmute 10`)
		wantExit(t, r, 0)
		if r.stdout != "" {
			t.Errorf("set is silent: %q", r.stdout)
		}
		wantJSON(t, wantOneMutation(t, f, "POST", storeWarrior), map[string]any{"openvpn_export": map[string]any{
			"template": "ArchiveOpenVPN", "hostname": "vpn.example.com,198.51.100.7", "local_port": "",
			"auth_nocache": "1", "random_local_port": "0", "plain_config": "verb 4\nmute 10",
		}})
	})
	t.Run("clearing the template needs no template list", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		f.on("POST", storeWarrior, 200, `{"result":"ok","changed":false}`)
		wantExit(t, f.run("/vpn/openvpn/export", "set", "Road Warrior", "template="), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", storeWarrior), map[string]any{"openvpn_export": map[string]any{"template": ""}})
		systemBackupWantNoCallTo(t, f, openvpnExportTemplatesPath)
	})
	t.Run("validation messages use the argument names", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		var storeOffice = openvpnExportStorePath + openvpnExportOffice
		f.on("POST", storeOffice, 200, `{"result":"failed","changed":true,"validations":{"openvpn_export.hostname":"A value is required.","openvpn_export.local_port":["Port needs to be an integer value between 1 and 65535."]}}`)
		var r = f.run("/vpn/openvpn/export", "set", "office", "cryptoapi")
		wantFailure(t, r, "hostname: A value is required.", "port: Port needs")
		wantNotContains(t, "output", r.stderr, "local_port", "openvpn_export")
	})
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"nothing to change", []string{"0"}, []string{"nothing to change"}},
		{"invalid port", []string{"0", "port=70000"}, []string{"port", "65535"}},
		{"invalid boolean", []string{"0", "cryptoapi=maybe"}, []string{"cryptoapi"}},
		{"p12 password is not a preset", []string{"0", "p12-password=x"}, []string{"p12-password"}},
		{"unknown template", []string{"0", "template=nope"}, []string{"unknown export type", "PlainOpenVPN"}},
		{"unknown server", []string{"nope", "hostname=x.example"}, []string{"not found", "only enabled"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = openvpnExportFake(t)
			wantFailure(t, f.run(append([]string{"/vpn/openvpn/export", "set"}, tc.args...)...), tc.want...)
			wantNoMutations(t, f)
		})
	}
}

func TestOpenvpnExportDownload(t *testing.T) {
	t.Parallel()
	var downloadAlice = openvpnExportDownloadPath + openvpnExportWarrior + "/" + openvpnExportAlice

	var wantFile = func(t *testing.T, path string, content string) {
		t.Helper()
		var data, err = os.ReadFile(path)
		if err != nil {
			t.Fatalf("file not written: %v", err)
		}
		if string(data) != content {
			t.Errorf("%s has %q, want %q", path, data, content)
		}
		if info, _ := os.Stat(path); info != nil && info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v, want 0600 (it contains the private key)", path, info.Mode().Perm())
		}
	}
	var wantNoFiles = func(t *testing.T, dir string) {
		t.Helper()
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("files written: %v", entries)
		}
	}
	// the presets of Road Warrior as download must send them, with the overrides
	var warriorPresets = func(overrides map[string]any) map[string]any {
		return withFields(map[string]any{
			"template": "PlainOpenVPN", "hostname": "vpn.example.com", "local_port": "1194", "random_local_port": "1",
			"validate_server_cn": "1", "cryptoapi": "0", "auth_nocache": "0", "static_challenge": "0", "plain_config": "verb 4\nmute 10",
		}, overrides)
	}

	t.Run("to the suggested file name with the presets", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		var dir = t.TempDir()
		var r = runOpnIn(t, dir, f.env(), "/vpn/openvpn/export", "download", "0", "account=alice")
		wantExit(t, r, 0)
		wantFile(t, filepath.Join(dir, "Road_Warrior_alice.ovpn"), openvpnExportOvpn)
		if r.stdout != "" {
			t.Errorf("stdout: %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, "saved Road_Warrior_alice.ovpn")
		wantNotContains(t, "stderr", r.stderr, "presets")
		var call = wantOneMutation(t, f, "POST", downloadAlice)
		if got := openvpnExportBody(t, call); !reflect.DeepEqual(got, warriorPresets(nil)) {
			t.Errorf("body\n got  %v\n want %v", got, warriorPresets(nil))
		}
	})
	t.Run("account by # of accounts in a script", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		f.on("POST", openvpnExportDownloadPath+openvpnExportWarrior+"/"+openvpnExportBob, 200,
			openvpnExportDownloadAnswer(false, "Road_Warrior_bob.ovpn", "text/ovpn", "bob"))
		// print after accounts: the # of the servers and of the accounts are kept apart
		var r = f.runScript("/vpn/openvpn/export\naccounts 0 search=bob\nprint\ndownload 0 account=0 file=-\n")
		wantExit(t, r, 0)
		if !strings.HasSuffix(r.stdout, "bob") {
			t.Errorf("want bob's file: %q", r.stdout)
		}
	})
	t.Run("account # without accounts is the list position", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		var r = f.run("/vpn/openvpn/export", "download", "Road Warrior", "account=0", "file=-")
		wantExit(t, r, 0)
		if r.stdout != openvpnExportOvpn {
			t.Errorf("stdout %q", r.stdout)
		}
	})
	t.Run("account by refid and description", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		wantExit(t, f.run("/vpn/openvpn/export", "download", openvpnExportWarrior, "account="+openvpnExportAlice, "file=-"), 0)
		wantExit(t, f.run("/vpn/openvpn/export", "download", "0", "account=Alice Laptop", "file=-"), 0)
	})
	t.Run("without certificate", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		var downloadOffice = openvpnExportDownloadPath + openvpnExportOffice
		f.on("POST", downloadOffice, 200, openvpnExportDownloadAnswer(true, "office.ovpn", "text/ovpn", "client\n"))
		var r = f.run("/vpn/openvpn/export", "download", "office", "account=none", "hostname=office.example.com", "file=-")
		wantExit(t, r, 0)
		if r.stdout != "client\n" {
			t.Errorf("stdout %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, "stored as presets of office tcp:443")
		systemBackupWantNoCallTo(t, f, openvpnExportAccountsPath)
		var body = openvpnExportBody(t, wantOneMutation(t, f, "POST", downloadOffice))
		var want = map[string]any{"template": "PlainOpenVPN", "hostname": "office.example.com", "local_port": "443", "random_local_port": "1",
			"validate_server_cn": "1", "cryptoapi": "0", "auth_nocache": "0", "static_challenge": "0", "plain_config": ""}
		if !reflect.DeepEqual(body, want) {
			t.Errorf("body\n got  %v\n want %v", body, want)
		}
	})
	t.Run("archive with p12 password to file=", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		var zip = "PK\x03\x04\x00\xff binary"
		f.on("POST", downloadAlice, 200, openvpnExportDownloadAnswer(true, "Road_Warrior_alice.zip", "application/zip", zip))
		var dir = t.TempDir()
		var r = runOpnIn(t, dir, f.env(), "/vpn/openvpn/export", "download", "0", "account=alice", "template=archiveOpenVPN",
			"p12-password=s3cret", "file=alice.zip")
		wantExit(t, r, 0)
		wantFile(t, filepath.Join(dir, "alice.zip"), zip)
		var body = openvpnExportBody(t, wantOneMutation(t, f, "POST", downloadAlice))
		if !reflect.DeepEqual(body, warriorPresets(map[string]any{"template": "ArchiveOpenVPN", "p12_password": "s3cret"})) {
			t.Errorf("body %v", body)
		}
	})
	t.Run("binary to stdout", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		var zip = "PK\x03\x04\x00\xff\n\r binary"
		f.on("POST", downloadAlice, 200, openvpnExportDownloadAnswer(false, "x.zip", "application/zip", zip))
		var r = f.run("/vpn/openvpn/export", "download", "0", "account=alice", "file=-")
		wantExit(t, r, 0)
		if r.stdout != zip {
			t.Errorf("stdout %q", r.stdout)
		}
	})
	t.Run("existing file is not overwritten without overwrite", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		var dir = t.TempDir()
		var path = filepath.Join(dir, "Road_Warrior_alice.ovpn")
		if err := os.WriteFile(path, []byte("keep me"), 0o644); err != nil {
			t.Fatal(err)
		}
		wantFailure(t, runOpnIn(t, dir, f.env(), "/vpn/openvpn/export", "download", "0", "account=alice"), "Road_Warrior_alice.ovpn", "already exists", "overwrite")
		if data, _ := os.ReadFile(path); string(data) != "keep me" {
			t.Errorf("file was overwritten: %q", data)
		}
		wantExit(t, runOpnIn(t, dir, f.env(), "/vpn/openvpn/export", "download", "0", "account=alice", "overwrite"), 0)
		if data, _ := os.ReadFile(path); string(data) != openvpnExportOvpn {
			t.Errorf("file not overwritten with overwrite: %q", data)
		}
	})
	t.Run("validation messages use the argument names", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		f.on("POST", openvpnExportDownloadPath+openvpnExportOffice, 200,
			`{"result":"failed","changed":false,"validations":{"openvpn_export.hostname":"A value is required."}}`)
		var dir = t.TempDir()
		wantFailure(t, runOpnIn(t, dir, f.env(), "/vpn/openvpn/export", "download", "office", "account=none"), "hostname: A value is required.")
		wantNoFiles(t, dir)
	})
	t.Run("certificate of another CA", func(t *testing.T) {
		t.Parallel()
		var f = openvpnExportFake(t)
		f.on("POST", downloadAlice, 400, `{"errorMessage":"Certificate does not belong to server CA","errorTitle":"OpenVPN export"}`)
		var dir = t.TempDir()
		wantFailure(t, runOpnIn(t, dir, f.env(), "/vpn/openvpn/export", "download", "0", "account=alice"), "Certificate does not belong to server CA")
		wantNoFiles(t, dir)
	})
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"account is required", []string{"0"}, []string{"account"}},
		{"overwrite with stdout", []string{"0", "account=alice", "file=-", "overwrite"}, []string{"overwrite has no effect"}},
		{"unknown server", []string{"nope", "account=none"}, []string{"not found", "only enabled"}},
		{"unknown account", []string{"0", "account=carol"}, []string{"not found", "carol", "Road Warrior"}},
		{"account # out of range", []string{"0", "account=2"}, []string{"#2", "2 items"}},
		{"unknown template", []string{"0", "account=alice", "template=nope"}, []string{"unknown export type"}},
		{"p12 password with the preset template", []string{"0", "account=alice", "p12-password=x"}, []string{"p12-password does not apply to the template PlainOpenVPN"}},
		{"p12 password with the default template", []string{"office", "account=none", "hostname=h.example", "p12-password=x"}, []string{"PlainOpenVPN"}},
		{"invalid port", []string{"0", "account=alice", "port=0"}, []string{"port"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = openvpnExportFake(t)
			var dir = t.TempDir()
			wantFailure(t, runOpnIn(t, dir, f.env(), append([]string{"/vpn/openvpn/export", "download"}, tc.args...)...), tc.want...)
			wantNoMutations(t, f)
			wantNoFiles(t, dir)
		})
	}
}

func TestOpenvpnExportComplete(t *testing.T) {
	t.Parallel()
	var f = openvpnExportFake(t)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/vpn/openvpn/export show o":                 {"office"},
		"/vpn/openvpn/export accounts item=o":        {"item=office"},
		"/vpn/openvpn/export download 0 account=a":   {`account="alice laptop"`, "account=alice"},
		"/vpn/openvpn/export download 0 account=n":   {"account=none"},
		"/vpn/openvpn/export set 0 template=P":       {"template=PlainOpenVPN"},
		"/vpn/openvpn/export download 0 template=Vi": {"template=ViscosityVisz"},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}
