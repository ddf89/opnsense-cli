//go:build integration

package integrationsystem

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/trust"
)

// The trust settings are snapshotted and restored exactly. Only the configuration is changed: apply
// (reconfigure, which rewrites the trust store and restarts cron) is only run by TestCliTrustSettings after
// the original values are restored. The OpenSSL constraints are only changed while they are disabled
// (enable_config_constraints=0), so they could not take effect even if someone applied in between

func trustSettingsApi(t *testing.T) *trust.TrustApi {
	t.Helper()
	return &trust.TrustApi{OPNsense: coreApi(t)}
}

// trustSettingsValues are the settings without the option lists, for comparisons
func trustSettingsValues(settings trust.Settings) trust.Settings {
	settings.Options = nil
	return settings
}

// trustSettingsSnapshot reads the settings and registers their exact restore. The returned restore can also be
// called earlier, it fails the test unless the settings equal the snapshot afterwards
func trustSettingsSnapshot(t *testing.T, ts *trust.TrustApi) (trust.Settings, func()) {
	t.Helper()
	var before, err = ts.SettingsGet()
	if err != nil {
		t.Fatalf("SettingsGet: %v", err)
	}
	var restore = func() {
		t.Helper()
		var fields = trust.SettingsFields{
			StoreIntermediateCerts: strPtr(before.StoreIntermediateCerts), InstallCrls: strPtr(before.InstallCrls),
			FetchCrls: strPtr(before.FetchCrls), EnableLegacySect: strPtr(before.EnableLegacySect),
			EnableConfigConstraints: strPtr(before.EnableConfigConstraints), CipherString: strPtr(before.CipherString),
			Ciphersuites: strPtr(before.Ciphersuites), SignatureAlgorithms: strPtr(before.SignatureAlgorithms),
			Groups: strPtr(before.Groups), MinProtocol: strPtr(before.MinProtocol), MinProtocolDTLS: strPtr(before.MinProtocolDTLS),
		}
		if err := ts.SettingsSet(fields); err != nil {
			t.Errorf("restoring the trust settings %+v failed: %v", trustSettingsValues(before), err)
			return
		}
		if after, err := ts.SettingsGet(); err != nil || !reflect.DeepEqual(trustSettingsValues(after), trustSettingsValues(before)) {
			t.Errorf("trust settings not restored: got %+v (%v), want %+v", trustSettingsValues(after), err, trustSettingsValues(before))
		}
	}
	t.Cleanup(restore)
	return before, restore
}

// trustSettingsFlip returns the other boolean value
func trustSettingsFlip(flag string) string {
	if flag == "1" {
		return "0"
	}
	return "1"
}

// trustSettingsUnselected returns up to n option keys of field that are not selected (and not the "" none choice)
func trustSettingsUnselected(settings trust.Settings, field string, n int) []string {
	var keys []string
	for _, option := range settings.Options[field] {
		if !option.Selected && option.Key != "" && len(keys) < n {
			keys = append(keys, option.Key)
		}
	}
	return keys
}

func TestTrustSettingsGet(t *testing.T) {
	var settings, err = trustSettingsApi(t).SettingsGet()
	if err != nil {
		t.Fatalf("SettingsGet: %v", err)
	}
	for name, value := range map[string]string{
		"store_intermediate_certs": settings.StoreIntermediateCerts, "install_crls": settings.InstallCrls,
		"fetch_crls": settings.FetchCrls, "enable_legacy_sect": settings.EnableLegacySect,
		"enable_config_constraints": settings.EnableConfigConstraints,
	} {
		if value != "0" && value != "1" {
			t.Errorf("%s: want 0 or 1, got %q", name, value)
		}
	}
	for _, field := range trust.SettingsOptionFields {
		if len(settings.Options[field]) == 0 {
			t.Errorf("no options for %s", field)
		}
	}
	// the none choice of the single selects
	for _, field := range []string{"MinProtocol", "MinProtocol_DTLS"} {
		if settings.Options[field][0].Key != "" {
			t.Errorf("%s: want the none choice first, got %+v", field, settings.Options[field])
		}
	}
	var signature = map[string]bool{}
	for _, option := range settings.Options["SignatureAlgorithms"] {
		signature[option.Key] = true
	}
	if !signature["ECDSA+SHA256"] || !signature["RSA+SHA256"] {
		t.Errorf("unexpected SignatureAlgorithms options %+v", settings.Options["SignatureAlgorithms"])
	}
}

func TestTrustSettingsSet(t *testing.T) {
	var ts = trustSettingsApi(t)
	var before, _ = trustSettingsSnapshot(t, ts)

	// a boolean: partial set keeps everything else
	var fetch = trustSettingsFlip(before.FetchCrls)
	if err := ts.SettingsSet(trust.SettingsFields{FetchCrls: &fetch}); err != nil {
		t.Fatalf("SettingsSet(fetch_crls=%s): %v", fetch, err)
	}
	var after, err = ts.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	var want = trustSettingsValues(before)
	want.FetchCrls = fetch
	if !reflect.DeepEqual(trustSettingsValues(after), want) {
		t.Errorf("after setting fetch_crls:\n got  %+v\n want %+v", trustSettingsValues(after), want)
	}

	if before.EnableConfigConstraints != "0" {
		t.Skip("the OpenSSL constraints are enabled on this instance, they are not changed")
	}
	// a multi-select, a single select, then clearing them
	var algorithms = strings.Join(trustSettingsUnselected(before, "SignatureAlgorithms", 2), ",")
	var dtls = trustSettingsUnselected(before, "MinProtocol_DTLS", 1)[0]
	if err := ts.SettingsSet(trust.SettingsFields{SignatureAlgorithms: &algorithms, MinProtocolDTLS: &dtls}); err != nil {
		t.Fatalf("SettingsSet(SignatureAlgorithms=%s, MinProtocol_DTLS=%s): %v", algorithms, dtls, err)
	}
	if after, err = ts.SettingsGet(); err != nil {
		t.Fatal(err)
	}
	want.SignatureAlgorithms, want.MinProtocolDTLS = algorithms, dtls
	if !reflect.DeepEqual(trustSettingsValues(after), want) {
		t.Errorf("after setting the constraints:\n got  %+v\n want %+v", trustSettingsValues(after), want)
	}

	var empty = ""
	if err := ts.SettingsSet(trust.SettingsFields{SignatureAlgorithms: &empty, MinProtocolDTLS: &empty}); err != nil {
		t.Fatalf("clearing: %v", err)
	}
	if after, err = ts.SettingsGet(); err != nil {
		t.Fatal(err)
	}
	if after.SignatureAlgorithms != "" || after.MinProtocolDTLS != "" {
		t.Errorf("not cleared: %+v", trustSettingsValues(after))
	}
}

func TestTrustSettingsSetInvalid(t *testing.T) {
	var ts = trustSettingsApi(t)
	var before, _ = trustSettingsSnapshot(t, ts)

	var invalid = "SSLv3"
	var err = ts.SettingsSet(trust.SettingsFields{MinProtocol: &invalid})
	var validation *api.ValidationError
	if !errors.As(err, &validation) || len(validation.Validations) == 0 {
		t.Fatalf("want a validation error for MinProtocol=SSLv3, got %v", err)
	}
	if after, err := ts.SettingsGet(); err != nil || !reflect.DeepEqual(trustSettingsValues(after), trustSettingsValues(before)) {
		t.Errorf("a refused set changed the settings: %+v (%v)", trustSettingsValues(after), err)
	}
}
