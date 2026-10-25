package cli

import (
	"strings"
	"testing"
)

const (
	systemTrustSettingsGetPath         = "/api/trust/settings/get"
	systemTrustSettingsSetPath         = "/api/trust/settings/set"
	systemTrustSettingsReconfigurePath = "/api/trust/settings/reconfigure"
)

// systemTrustSettingsAnswer is a trimmed trust/settings/get answer of OPNsense 26.7 (with a few options selected)
const systemTrustSettingsAnswer = `{"trust":{"store_intermediate_certs":"0","install_crls":"1","fetch_crls":"0","enable_legacy_sect":"1",` +
	`"enable_config_constraints":"1",` +
	`"CipherString":{"DHE-PSK-AES128-CBC-SHA":{"value":"TLS_DHE_PSK_WITH_AES_128_CBC_SHA","selected":0},` +
	`"ECDHE-RSA-AES256-GCM-SHA384":{"value":"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","selected":1},` +
	`"AES128-SHA":{"value":"TLS_RSA_WITH_AES_128_CBC_SHA","selected":1}},` +
	`"Ciphersuites":{"TLS_AES_128_GCM_SHA256":{"value":"TLS_AES_128_GCM_SHA256","selected":0},"TLS_AES_256_GCM_SHA384":{"value":"TLS_AES_256_GCM_SHA384","selected":0}},` +
	`"SignatureAlgorithms":{"ECDSA+SHA256":{"value":"ECDSA+SHA256","selected":1},"RSA+SHA256":{"value":"RSA+SHA256","selected":0}},` +
	`"groups":{"X25519":{"value":"X25519","selected":1},"prime256v1":{"value":"prime256v1","selected":1},"secp384r1":{"value":"secp384r1","selected":0}},` +
	`"MinProtocol":{"":{"value":"None","selected":0},"TLSv1.2":{"value":"TLSv1.2","selected":1},"TLSv1.3":{"value":"TLSv1.3","selected":0}},` +
	`"MinProtocol_DTLS":{"":{"value":"None","selected":1},"DTLSv1":{"value":"DTLSv1","selected":0},"DTLSv1.1":{"value":"DTLSv1.1","selected":0}}}}`

func systemTrustSettingsFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", systemTrustSettingsGetPath, 200, systemTrustSettingsAnswer)
	f.on("POST", systemTrustSettingsSetPath, 200, answerSaved)
	f.on("POST", systemTrustSettingsReconfigurePath, 200, `{"status":"ok"}`)
	return f
}

func systemTrustSettings(args ...string) []string {
	return append([]string{"/system/trust/settings"}, args...)
}

func TestSystemTrustSettingsPrint(t *testing.T) {
	t.Parallel()
	var f = systemTrustSettingsFake(t)
	var r = f.run(systemTrustSettings("print")...)
	wantExit(t, r, 0)
	var fields = systemLoggingFields(r.stdout)
	for key, want := range map[string]string{
		"store-intermediate-certs": "no", "install-crls": "yes", "fetch-crls": "no", "enable-legacy-sect": "yes",
		"enable-config-constraints": "yes", "cipher-string": "ECDHE-RSA-AES256-GCM-SHA384,AES128-SHA", "ciphersuites": "",
		"signature-algorithms": "ECDSA+SHA256", "groups": "X25519,prime256v1", "min-protocol": "TLSv1.2", "min-protocol-dtls": "",
	} {
		if got, ok := fields[key]; !ok || got != want {
			t.Errorf("%s: got %q (present %v), want %q\n%s", key, got, ok, want, r.stdout)
		}
	}
	if len(fields) != 11 {
		t.Errorf("want 11 fields, got %d:\n%s", len(fields), r.stdout)
	}

	r = f.run(systemTrustSettings("print", "json")...)
	wantExit(t, r, 0)
	var want = `{"store_intermediate_certs":"0","install_crls":"1","fetch_crls":"0","enable_legacy_sect":"1","enable_config_constraints":"1",` +
		`"CipherString":"ECDHE-RSA-AES256-GCM-SHA384,AES128-SHA","Ciphersuites":"","SignatureAlgorithms":"ECDSA+SHA256",` +
		`"groups":"X25519,prime256v1","MinProtocol":"TLSv1.2","MinProtocol_DTLS":""}`
	if strings.TrimSpace(r.stdout) != want {
		t.Errorf("json:\n got  %s\n want %s", strings.TrimSpace(r.stdout), want)
	}
	wantNoMutations(t, f)
}

func TestSystemTrustSettingsPrintOptions(t *testing.T) {
	t.Parallel()
	var f = systemTrustSettingsFake(t)
	var r = f.run(systemTrustSettings("print", "options=min-protocol")...)
	wantExit(t, r, 0)
	systemLoggingWantTable(t, r.stdout, []string{"KEY", "NAME", "SELECTED"}, 0, `""`, "TLSv1.2", "TLSv1.3")
	wantContains(t, "stdout", r.stdout, "TLSv1.2  TLSv1.2  yes")

	r = f.run(systemTrustSettings("print", "options=cipher-string")...)
	wantExit(t, r, 0)
	systemLoggingWantTable(t, r.stdout, []string{"KEY", "NAME", "SELECTED"}, 1,
		"TLS_DHE_PSK_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_CBC_SHA")

	r = f.run(systemTrustSettings("print", "options=groups", "json")...)
	wantExit(t, r, 0)
	if !strings.HasPrefix(r.stdout, `{"key":"X25519","selected":true,"value":"X25519"}`+"\n") || strings.Count(r.stdout, "\n") != 3 {
		t.Errorf("want one JSON object per option:\n%s", r.stdout)
	}
	wantFailure(t, f.run(systemTrustSettings("print", "options=fetch-crls")...), "options", "cipher-string")
	wantNoMutations(t, f)
}

func TestSystemTrustSettingsSet(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		args    []string
		want    map[string]any
		needGet bool
	}{
		{"booleans", []string{"fetch-crls", "install-crls=no", "store-intermediate-certs=yes", "enable-legacy-sect=off", "enable-config-constraints=1"},
			map[string]any{"fetch_crls": "1", "install_crls": "0", "store_intermediate_certs": "1", "enable_legacy_sect": "0", "enable_config_constraints": "1"}, false},
		{"lists normalized", []string{"cipher-string=aes128-sha,ECDHE-RSA-AES256-GCM-SHA384", "groups=x25519", "signature-algorithms=rsa+sha256,ECDSA+SHA256"},
			map[string]any{"CipherString": "AES128-SHA,ECDHE-RSA-AES256-GCM-SHA384", "groups": "X25519", "SignatureAlgorithms": "RSA+SHA256,ECDSA+SHA256"}, true},
		{"clear", []string{"ciphersuites=", "min-protocol=", "groups="}, map[string]any{"Ciphersuites": "", "MinProtocol": "", "groups": ""}, true},
		{"protocols", []string{"min-protocol=tlsv1.3", "min-protocol-dtls=DTLSv1.1"}, map[string]any{"MinProtocol": "TLSv1.3", "MinProtocol_DTLS": "DTLSv1.1"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = systemTrustSettingsFake(t)
			var r = f.run(systemTrustSettings(append([]string{"set"}, tc.args...)...)...)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("set must be silent, got %q", r.stdout)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", systemTrustSettingsSetPath), map[string]any{"trust": tc.want})
			if got := len(f.calls()) == 2; got != tc.needGet {
				t.Errorf("want the options loaded first: %v, calls %v", tc.needGet, f.calls())
			}
		})
	}
}

func TestSystemTrustSettingsSetErrors(t *testing.T) {
	t.Parallel()
	var f = systemTrustSettingsFake(t)
	wantFailure(t, f.run(systemTrustSettings("set")...), "nothing to change")
	wantFailure(t, f.run(systemTrustSettings("set", "fetch-crls=maybe")...), "fetch-crls", "yes or no")
	wantNoCalls(t, f)

	wantFailure(t, f.run(systemTrustSettings("set", "min-protocol=SSLv3")...), "min-protocol", `"SSLv3"`, "TLSv1.2, TLSv1.3")
	wantFailure(t, f.run(systemTrustSettings("set", "min-protocol=TLSv1.2,TLSv1.3")...), "min-protocol", "one value")
	wantFailure(t, f.run(systemTrustSettings("set", "groups=X25519,X448")...), "groups", `"X448"`, "secp384r1")
	wantFailure(t, f.run(systemTrustSettings("set", "fetch-crls", "ciphersuites=TLS_FOO")...), "ciphersuites")
	wantNoMutations(t, f)

	var failing = newFakeOPN(t)
	failing.on("POST", systemTrustSettingsSetPath, 200, answerValidation("trust.fetch_crls", "Invalid value."))
	wantFailure(t, failing.run(systemTrustSettings("set", "fetch-crls")...), "validation failed", "Invalid value.")
}

func TestSystemTrustSettingsApply(t *testing.T) {
	t.Parallel()
	var f = systemTrustSettingsFake(t)
	var r = f.run(systemTrustSettings("apply")...)
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("apply must be silent, got %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", systemTrustSettingsReconfigurePath)

	var failing = newFakeOPN(t)
	failing.on("POST", systemTrustSettingsReconfigurePath, 200, `{"status":"failed"}`)
	wantFailure(t, failing.run(systemTrustSettings("apply")...), "trust reconfigure failed")
}

func TestSystemTrustSettingsComplete(t *testing.T) {
	t.Parallel()
	var f = systemTrustSettingsFake(t)
	var session = fakeSession(t, f)
	var candidates, _ = session.Complete("/system/trust/settings set min-protocol=TLS")
	if strings.Join(candidates, " ") != "min-protocol=TLSv1.2 min-protocol=TLSv1.3" {
		t.Errorf("min-protocol completion: %q", candidates)
	}
	candidates, _ = session.Complete("/system/trust/settings set groups=X25519,se")
	if strings.Join(candidates, " ") != "groups=X25519,secp384r1" {
		t.Errorf("groups completion: %q", candidates)
	}
}
