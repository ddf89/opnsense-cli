//go:build integration

package integrationsystem

import (
	"crypto/tls"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"opnsense-cli/opnsense/api/trust"
)

const trustCertMenu = "/system/trust/certificate"

// TestCliTrustCertificate drives /system/trust/certificate against the live instance: issue, import, sign,
// complete a request, print, show, dump, export, rename, reissue, replace and remove
func TestCliTrustCertificate(t *testing.T) {
	var core = coreApi(t)
	var ca = trustCertCreateCa(t, core, "certcli ca")
	defer trustCertRequireNoneLeft(t, core, "certcli")
	var dir = t.TempDir()
	var write = func(name string, content string) string {
		var path = filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	var add = func(args ...string) string {
		t.Helper()
		var result = mustOpn(t, append([]string{trustCertMenu, "add"}, args...)...)
		var uuid = uuidFrom(t, result)
		trustCertCleanup(t, core, uuid)
		return uuid
	}

	// issue a server and a client certificate, the issuer given by its description
	var serverDescr = testDescription("certcli server")
	var serverUuid = add("description="+serverDescr, "issuer="+ca.descr, "common-name=srv.certcli.invalid", "type=server",
		"alt-dns=srv.certcli.invalid,www.certcli.invalid", "alt-ip=10.9.8.7", "key-type=prime256v1", "lifetime=20", "organization=a8")
	var clientUuid = add("description="+testDescription("certcli client"), "issuer="+ca.refid, "common-name=client.certcli.invalid",
		"type=client", "lifetime=5")
	var selfUuid = add("description="+testDescription("certcli self"), "method=self-signed", "common-name=self.certcli.invalid", "lifetime=3")

	// import one with its key, sign a request, create a request
	var certPEM, keyPEM, csrPEM = trustCertLocalPair(t, "import.certcli.invalid")
	var importUuid = add("description="+testDescription("certcli imported"), "method=import",
		"certificate-file="+write("imp.pem", certPEM), "key-file="+write("imp.key", keyPEM))
	var signedUuid = add("description="+testDescription("certcli signed"), "method=sign-csr", "issuer="+ca.descr,
		"csr-file="+write("req.csr", csrPEM), "type=server", "alt-dns=import.certcli.invalid", "lifetime=4")
	var requestDescr = testDescription("certcli request")
	var requestUuid = add("description="+requestDescr, "method=csr", "common-name=request.certcli.invalid", "country=DE")

	// a duplicate description is refused, nothing is created
	mustFailOpn(t, trustCertMenu, "add", "description="+serverDescr, "method=self-signed", "common-name=x.invalid")
	mustFailOpn(t, trustCertMenu, "add", "description="+testDescription("certcli bad"), "common-name=x.invalid") // no issuer

	// print: the run's certificates, never a private key
	var printed = mustOpn(t, trustCertMenu, "print", "search="+runPrefix+" certcli")
	requireContains(t, printed, printed.stdout, "DESCRIPTION", "COMMON-NAME", "ISSUER", "VALID-UNTIL", serverDescr, "srv.certcli.invalid",
		ca.descr, "self-signed", "csr", "import.certcli.invalid")
	var lines = strings.Split(strings.TrimSpace(printed.stdout), "\n")
	if len(lines) != 7 { // header and 6 certificates
		t.Errorf("want 6 certificates:\n%s", printed)
	}
	var expiring = mustOpn(t, trustCertMenu, "print", "search="+runPrefix+" certcli", "expiring=6")
	if strings.Contains(expiring.stdout, serverDescr) || !strings.Contains(expiring.stdout, "client.certcli.invalid") {
		t.Errorf("expiring=6 should list the 5 day client but not the 20 day server certificate:\n%s", expiring)
	}
	var jsonOut = mustOpn(t, trustCertMenu, "print", "json", "search="+runPrefix+" certcli")
	for _, line := range strings.Split(strings.TrimSpace(jsonOut.stdout), "\n") {
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("not JSON: %q", line)
		}
		if _, hasPrv := row["prv"]; hasPrv || row["prv_payload"] != nil {
			t.Errorf("json contains the private key: %s", line)
		}
	}
	for _, output := range []opnResult{printed, jsonOut, mustOpn(t, trustCertMenu, "print", "detail", "search="+runPrefix+" certcli")} {
		if strings.Contains(output.stdout, "PRIVATE KEY") {
			t.Errorf("output contains a private key:\n%s", output)
		}
	}

	// show by description and refid, dump
	var raw, _ = trustCertRaw(t, core, serverUuid)
	for _, selector := range []string{serverDescr, raw.Refid, serverUuid} {
		var shown = mustOpn(t, trustCertMenu, "show", selector)
		requireContains(t, shown, shown.stdout, "uuid:", serverUuid, "issuer:", ca.descr, "type:", "server",
			"alt-dns:", "srv.certcli.invalid,www.certcli.invalid", "key-type:", "prime256v1", "private-key:", "stored on the firewall")
		if strings.Contains(shown.stdout, "PRIVATE KEY") {
			t.Errorf("show printed the private key:\n%s", shown)
		}
	}
	var dumped = mustOpn(t, trustCertMenu, "dump", serverDescr)
	requireContains(t, dumped, dumped.stdout, "Fingerprint", "Certificate:", "srv.certcli.invalid")

	// export: default name, refused overwrite, key mode, pkcs12, stdout
	trustCertMustOpnIn(t, dir, trustCertMenu, "export", serverDescr)
	var crtFile = filepath.Join(dir, trust.CertSafeFilename(serverDescr)+"_crt.pem")
	var crt, crtErr = os.ReadFile(crtFile)
	if crtErr != nil {
		t.Fatalf("export wrote no %s: %v", crtFile, crtErr)
	}
	var refused = runOpnIn(t, dir, trustCertMenu, "export", serverDescr)
	if refused.exitCode != 1 || !strings.Contains(refused.stderr, "overwrite") {
		t.Errorf("want a refusal to overwrite:\n%s", refused)
	}
	trustCertMustOpnIn(t, dir, trustCertMenu, "export", serverDescr, "overwrite")
	trustCertMustOpnIn(t, dir, trustCertMenu, "export", serverDescr, "type=key", "file=server.key")
	var key, keyErr = os.ReadFile(filepath.Join(dir, "server.key"))
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	if _, err := tls.X509KeyPair(crt, key); err != nil {
		t.Errorf("exported certificate and key do not match: %v", err)
	}
	if info, err := os.Stat(filepath.Join(dir, "server.key")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %v %v", info.Mode(), err)
	}
	trustCertMustOpnIn(t, dir, trustCertMenu, "export", serverDescr, "type=pkcs12", "password=s3cret", "file=server.p12")
	if p12, err := os.ReadFile(filepath.Join(dir, "server.p12")); err != nil || len(p12) < 100 || p12[0] != 0x30 {
		t.Errorf("pkcs12: %d bytes %v", len(p12), err)
	}
	var stdoutCrt = mustOpn(t, trustCertMenu, "export", serverDescr, "file=-")
	if stdoutCrt.stdout != string(crt) {
		t.Errorf("file=- differs from the exported file")
	}
	mustFailOpn(t, trustCertMenu, "export", testDescription("certcli signed"), "type=key", "file=-") // no key on the firewall

	// complete the request with a certificate signed "elsewhere"
	var csrOut = mustOpn(t, trustCertMenu, "export", requestDescr, "type=csr", "file=-")
	mustFailOpn(t, trustCertMenu, "import-signed", requestDescr, "certificate-file="+write("wrong.pem", certPEM))
	requireNoStdout(t, mustOpn(t, trustCertMenu, "import-signed", requestDescr,
		"certificate-file="+write("signed.pem", trustCertSignLocally(t, ca, csrOut.stdout))))
	if row, _ := trustCertRaw(t, core, requestUuid); row.Crt == "" || row.Caref != ca.refid {
		t.Errorf("the request was not completed: %+v", row)
	}

	// rename keeps the certificate, reissue renews it
	var renamed = testDescription("certcli server renamed")
	requireNoStdout(t, mustOpn(t, trustCertMenu, "set", serverDescr, "description="+renamed))
	var afterRename, _ = trustCertRaw(t, core, serverUuid)
	if afterRename.Descr != renamed || afterRename.Crt != raw.Crt {
		t.Errorf("set changed more than the description: %+v", afterRename)
	}
	mustFailOpn(t, trustCertMenu, "reissue", renamed) // needs confirm=yes non-interactively
	requireNoStdout(t, mustOpn(t, trustCertMenu, "reissue", renamed, "lifetime=9", "confirm=yes"))
	var reissued, _ = trustCertRaw(t, core, serverUuid)
	if reissued.Crt == raw.Crt || reissued.Refid != raw.Refid || trustCertLifetimeDays(t, reissued) != 9 {
		t.Errorf("unexpected reissue %+v", reissued)
	}
	mustFailOpn(t, trustCertMenu, "reissue", testDescription("certcli self"), "confirm=yes")

	// replace keeps uuid and refid
	var selfBefore, _ = trustCertRaw(t, core, selfUuid)
	var replaced = mustOpn(t, trustCertMenu, "add", "description="+testDescription("certcli self"), "issuer="+ca.descr,
		"common-name=replaced.certcli.invalid", "lifetime=2", "replace")
	if uuidFrom(t, replaced) != selfUuid {
		t.Errorf("replace printed another uuid:\n%s", replaced)
	}
	var selfAfter, _ = trustCertRaw(t, core, selfUuid)
	if selfAfter.Refid != selfBefore.Refid || selfAfter.CommonName != "replaced.certcli.invalid" || selfAfter.Caref != ca.refid {
		t.Errorf("unexpected replace %+v", selfAfter)
	}

	// remove all of them, by description and uuid
	for _, selector := range []string{renamed, clientUuid, testDescription("certcli self"), importUuid, signedUuid, requestDescr} {
		requireNoStdout(t, mustOpn(t, trustCertMenu, "remove", selector))
	}
	for _, uuid := range []string{serverUuid, clientUuid, selfUuid, importUuid, signedUuid, requestUuid} {
		if _, ok := trustCertRaw(t, core, uuid); ok {
			t.Errorf("certificate %s still exists", uuid)
		}
	}
	mustFailOpn(t, trustCertMenu, "remove", renamed)
}

// trustCertMustOpnIn runs the CLI in dir and fails the test unless it exits with 0
func trustCertMustOpnIn(t *testing.T, dir string, args ...string) opnResult {
	t.Helper()
	var result = runOpnIn(t, dir, args...)
	if result.exitCode != 0 {
		t.Fatalf("want exit code 0, got:\n%s", result)
	}
	return result
}
