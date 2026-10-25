//go:build integration

package integrationsystem

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"opnsense-cli/opnsense/api/trust"
)

// /system/trust/settings through the opn binary. The settings are snapshotted and restored exactly (see
// trust_settings_test.go); apply runs once, after the original settings were restored and verified, so it only
// rewrites the trust store with the settings it already had

func TestCliTrustSettings(t *testing.T) {
	var ts = trustSettingsApi(t)
	var before, restore = trustSettingsSnapshot(t, ts)

	var printed = mustOpn(t, "/system/trust/settings", "print")
	requireContains(t, printed, printed.stdout, "store-intermediate-certs:", "fetch-crls:", "cipher-string:", "min-protocol-dtls:")

	var asJSON = mustOpn(t, "/system/trust/settings", "print", "json")
	var decoded trust.Settings
	if err := json.Unmarshal([]byte(asJSON.stdout), &decoded); err != nil || !reflect.DeepEqual(decoded, trustSettingsValues(before)) {
		t.Errorf("print json: got %+v (%v), want %+v", decoded, err, trustSettingsValues(before))
	}

	var options = mustOpn(t, "/system/trust/settings", "print", "options=min-protocol")
	requireContains(t, options, options.stdout, "KEY", `""`, "None", "TLSv1.2", "TLSv1.3")

	// a boolean (partial set)
	var fetch = map[string]string{"0": "yes", "1": "no"}[before.FetchCrls]
	requireNoStdout(t, mustOpn(t, "/system/trust/settings", "set", "fetch-crls="+fetch))
	var want = trustSettingsValues(before)
	want.FetchCrls = trustSettingsFlip(before.FetchCrls)
	if after, err := ts.SettingsGet(); err != nil || !reflect.DeepEqual(trustSettingsValues(after), want) {
		t.Errorf("after set fetch-crls=%s: %+v (%v), want %+v", fetch, trustSettingsValues(after), err, want)
	}

	// invalid option values are refused before anything is sent
	var invalid = mustFailOpn(t, "/system/trust/settings", "set", "fetch-crls="+fetch, "min-protocol=SSLv3")
	requireContains(t, invalid, invalid.stderr, "min-protocol", "TLSv1.2")
	mustFailOpn(t, "/system/trust/settings", "set", "signature-algorithms=ECDSA+SHA256,NOPE")

	if before.EnableConfigConstraints == "0" {
		// option values, given in lower case, are stored as OPNsense spells them
		var algorithms = trustSettingsUnselected(before, "SignatureAlgorithms", 2)
		requireNoStdout(t, mustOpn(t, "/system/trust/settings", "set", "signature-algorithms="+strings.ToLower(strings.Join(algorithms, ","))))
		want.SignatureAlgorithms = strings.Join(algorithms, ",")
		if after, err := ts.SettingsGet(); err != nil || !reflect.DeepEqual(trustSettingsValues(after), want) {
			t.Errorf("after set signature-algorithms: %+v (%v), want %+v", trustSettingsValues(after), err, want)
		}
	}

	// restore, then apply the original settings
	restore()
	requireNoStdout(t, mustOpn(t, "/system/trust/settings", "apply"))
	if after, err := ts.SettingsGet(); err != nil || !reflect.DeepEqual(trustSettingsValues(after), trustSettingsValues(before)) {
		t.Errorf("settings changed by apply: %+v (%v)", trustSettingsValues(after), err)
	}
}
