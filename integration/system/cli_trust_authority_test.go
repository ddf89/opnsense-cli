//go:build integration

package integrationsystem

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"opnsense-cli/opnsense/api/trust"
)

// TestCliTrustAuthority drives /system/trust/authority against the live instance with CAs owned by this run
func TestCliTrustAuthority(t *testing.T) {
	var ts = trustAuthorityApi(t)
	const menu = "/system/trust/authority"
	var rootDescr = testDescription("cli-ca-root")
	var interDescr = testDescription("cli-ca-inter")
	var importDescr = testDescription("cli-ca-import")
	var dir = t.TempDir()

	var add = mustOpn(t, menu, "add", "description="+rootDescr, "common-name=a8 cli root", "key-type=prime256v1", "lifetime=2",
		"country=mt", "organization=a8 cli")
	var rootUuid = uuidFrom(t, add)
	trustAuthorityCleanup(t, ts, rootUuid)
	if strings.TrimSpace(add.stdout) != rootUuid {
		t.Errorf("add must print only the uuid:\n%s", add)
	}

	add = mustOpn(t, menu, "add", "method=intermediate", "issuer="+rootDescr, "description="+interDescr, "common-name=a8 cli inter",
		"key-type=rsa-2048", "lifetime=1")
	var interUuid = uuidFrom(t, add)
	trustAuthorityCleanup(t, ts, interUuid)

	t.Run("print", func(t *testing.T) {
		var result = mustOpn(t, menu, "print", "search="+runPrefix+" cli-ca")
		requireContains(t, result, result.stdout, "DESCRIPTION", "ISSUER", "VALID-UNTIL", rootDescr, interDescr, "self-signed",
			"prime256v1", "rsa-2048")
		var interLine string
		for _, line := range strings.Split(result.stdout, "\n") {
			if strings.Contains(line, interDescr) {
				interLine = line
			}
		}
		if !strings.Contains(interLine, rootDescr) {
			t.Errorf("the intermediate's issuer is not the root:\n%s", result)
		}
		if strings.Contains(result.stdout, "PRIVATE KEY") {
			t.Errorf("print leaks a private key:\n%s", result)
		}

		result = mustOpn(t, menu, "print", "json", "search="+runPrefix+" cli-ca")
		if strings.Contains(result.stdout, "PRIVATE KEY") || strings.Contains(result.stdout, `"prv"`) {
			t.Errorf("print json leaks a private key:\n%s", result)
		}
		for _, line := range strings.Split(strings.TrimSpace(result.stdout), "\n") {
			var object map[string]any
			if err := json.Unmarshal([]byte(line), &object); err != nil {
				t.Errorf("not a JSON line %q: %v", line, err)
			}
		}
	})

	t.Run("show", func(t *testing.T) {
		var result = mustOpn(t, menu, "show", interDescr)
		requireContains(t, result, result.stdout, "uuid:", interUuid, "issuer:", rootDescr, "subject:", "C=MT", "O=a8 cli", "private-key:", "yes", "key-type:", "rsa-2048")
		if strings.Contains(result.stdout, "PRIVATE KEY") {
			t.Errorf("show leaks a private key:\n%s", result)
		}
		requireContains(t, result, mustOpn(t, menu, "show", rootUuid).stdout, "in-use:", "1", "C=MT")
	})

	t.Run("remove refuses an issuer in use", func(t *testing.T) {
		var result = mustFailOpn(t, menu, "remove", rootDescr)
		requireContains(t, result, result.stderr, "in use", interDescr)
		if _, err := ts.CaGet(rootUuid); err != nil {
			t.Errorf("the root must still exist: %v", err)
		}
	})

	t.Run("dump", func(t *testing.T) {
		var result = mustOpn(t, menu, "dump", interUuid)
		requireContains(t, result, result.stdout, "Certificate:", "CN=a8 cli inter", "CN=a8 cli root")
	})

	t.Run("export", func(t *testing.T) {
		var result = runOpnIn(t, dir, menu, "export", rootDescr, "file=root.pem")
		if result.exitCode != 0 {
			t.Fatalf("export failed:\n%s", result)
		}
		requireNoStdout(t, result)
		var certificate, err = os.ReadFile(filepath.Join(dir, "root.pem"))
		if err != nil || !strings.Contains(string(certificate), "BEGIN CERTIFICATE") {
			t.Fatalf("root.pem: %v", err)
		}
		if result = runOpnIn(t, dir, menu, "export", rootDescr, "file=root.pem"); result.exitCode != 1 || !strings.Contains(result.stderr, "already exists") {
			t.Errorf("want a refused overwrite:\n%s", result)
		}
		if result = runOpnIn(t, dir, menu, "export", rootDescr, "type=key", "file=root.key"); result.exitCode != 0 {
			t.Fatalf("key export failed:\n%s", result)
		}
		var info, statErr = os.Stat(filepath.Join(dir, "root.key"))
		if statErr != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("root.key: %v %v", info, statErr)
		}
		var key, _ = os.ReadFile(filepath.Join(dir, "root.key"))
		if err := trust.CaCheckPair(string(certificate), string(key)); err != nil {
			t.Errorf("exported key and certificate do not match: %v", err)
		}
		result = mustOpn(t, menu, "export", interDescr, "file=-")
		if !strings.HasPrefix(result.stdout, "-----BEGIN CERTIFICATE-----") {
			t.Errorf("want the certificate on stdout:\n%s", result)
		}
	})

	t.Run("import", func(t *testing.T) {
		var result = runOpnIn(t, dir, menu, "add", "method=import", "description="+importDescr, "certificate-file=root.pem")
		if result.exitCode != 0 {
			t.Fatalf("import failed:\n%s", result)
		}
		var importUuid = uuidFrom(t, result)
		trustAuthorityCleanup(t, ts, importUuid)
		requireContains(t, result, mustOpn(t, menu, "show", importDescr).stdout, "private-key:", "no", "a8 cli root")

		result = runOpnIn(t, dir, menu, "add", "method=import", "description="+importDescr, "certificate-file=root.pem")
		if result.exitCode != 1 || !strings.Contains(result.stderr, "exists already") {
			t.Errorf("want a duplicate refused:\n%s", result)
		}
		if result = runOpnIn(t, dir, menu, "set", importDescr, "key-file=root.key"); result.exitCode != 0 {
			t.Fatalf("set key failed:\n%s", result)
		}
		requireNoStdout(t, result)
		requireContains(t, result, mustOpn(t, menu, "show", importUuid).stdout, "private-key:", "yes")
		requireNoStdout(t, mustOpn(t, menu, "remove", importUuid))
	})

	t.Run("set", func(t *testing.T) {
		var renamed = testDescription("cli-ca-inter renamed")
		var result = mustOpn(t, menu, "set", interDescr, "description="+renamed, "serial=7")
		requireNoStdout(t, result)
		var inter, err = ts.CaGet(interUuid)
		if err != nil || inter.Description != renamed || inter.Serial != "7" {
			t.Errorf("unexpected CA after set: %+v %v", inter, err)
		}
		mustFailOpn(t, menu, "set", renamed)
		interDescr = renamed
	})

	t.Run("replace regenerates in place", func(t *testing.T) {
		var before, _ = ts.CaGet(interUuid)
		mustFailOpn(t, menu, "add", "description="+rootDescr, "common-name=x", "replace") // in use
		var result = mustOpn(t, menu, "add", "method=intermediate", "issuer="+rootUuid, "description="+interDescr,
			"common-name=a8 cli regenerated", "lifetime=1", "replace")
		if strings.TrimSpace(result.stdout) != interUuid {
			t.Errorf("replace must print the existing uuid:\n%s", result)
		}
		var after, err = ts.CaGet(interUuid)
		if err != nil || after.Refid != before.Refid || after.CommonName != "a8 cli regenerated" || after.Certificate == before.Certificate {
			t.Errorf("unexpected CA after replace: %+v %v", after, err)
		}
	})

	t.Run("remove intermediate then root", func(t *testing.T) {
		requireNoStdout(t, mustOpn(t, menu, "remove", interDescr))
		requireNoStdout(t, mustOpn(t, menu, "remove", rootDescr))
		var left, err = ts.CaSearch(runPrefix + " cli-ca")
		if err != nil || len(left) != 0 {
			t.Errorf("CAs left: %+v %v", left, err)
		}
	})
}
