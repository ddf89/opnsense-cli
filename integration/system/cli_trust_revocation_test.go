//go:build integration

package integrationsystem

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"opnsense-cli/opnsense/api/trust"
)

// TestCliTrustRevocation runs the /system/trust/revocation menu through the opn binary on a test CA of this run
func TestCliTrustRevocation(t *testing.T) {
	var ts = trustRevocationApi(t)
	var pki = trustRevocationSetup(t, "crl-cli")
	var c1, c2 = pki.certs[0], pki.certs[1]
	var c2Serial = trust.CrlSerialHex(c2.serial)
	const menu = "/system/trust/revocation"
	var listDescr = testDescription("crl-cli list")

	var printed = mustOpn(t, menu, "print", "search="+pki.caDescr)
	requireContains(t, printed, printed.stdout, "#", "CA", "TYPE", "REVOKED", pki.caDescr)
	mustFailOpn(t, menu, "show", pki.caDescr)

	var added = mustOpn(t, menu, "add", pki.caDescr, "description="+listDescr, "lifetime=30")
	if strings.TrimSpace(added.stdout) != pki.caRefid {
		t.Errorf("add should print the refid of the CA:\n%s", added)
	}
	if descr := trustRevocationRawCrlDescr(t, pki.caRefid); descr == nil || *descr != listDescr {
		t.Fatalf("no list after add: %v", descr)
	}
	var duplicate = mustFailOpn(t, menu, "add", pki.caRefid)
	requireContains(t, duplicate, duplicate.stderr, "has a revocation list already")

	requireNoStdout(t, mustOpn(t, menu, "revoke", pki.caDescr, "certificate="+c1.descr, "reason=key-compromise"))
	requireNoStdout(t, mustOpn(t, menu, "revoke", pki.caRefid, "certificate="+c2Serial, "reason=superseded"))
	if got := trustRevocationRevokedRefs(t, ts, pki.caRefid); len(got) != 2 || got[c1.refid] != "1" || got[c2.refid] != "4" {
		t.Errorf("revoked after revoke: %v", got)
	}

	var show = mustOpn(t, menu, "show", pki.caDescr)
	requireContains(t, show, show.stdout, "description:  "+listDescr, "type:         internal", "revoked:      2",
		"lifetime:     30 days", "key-compromise", "superseded", c1.descr, c2.descr, c2Serial)

	var detail = mustOpn(t, menu, "print", "search="+pki.caDescr, "detail")
	requireContains(t, detail, detail.stdout, "ca-refid:     "+pki.caRefid, "revoked:      2")
	var json = mustOpn(t, menu, "print", "search="+pki.caDescr, "json")
	requireContains(t, json, json.stdout, `"crl_descr":"`+listDescr+`"`)

	// the # of the last print in a script
	var script = runOpnStdin(t, "", menu+"\nprint search=\""+pki.caDescr+"\"\nunrevoke 0 certificate=\""+c1.descr+"\"\n")
	if script.exitCode != 0 {
		t.Fatalf("script failed:\n%s", script)
	}
	if got := trustRevocationRevokedRefs(t, ts, pki.caRefid); len(got) != 1 || got[c2.refid] != "4" {
		t.Errorf("revoked after unrevoke: %v", got)
	}
	mustFailOpn(t, menu, "unrevoke", pki.caDescr, "certificate="+c1.descr)
	mustFailOpn(t, menu, "revoke", pki.caDescr, "certificate=no such certificate")

	var dump = mustOpn(t, menu, "dump", pki.caDescr)
	requireContains(t, dump, dump.stdout, "Certificate Revocation List (CRL)", "Serial Number: "+c2Serial)

	var exported = mustOpn(t, menu, "export", pki.caDescr, "file=-")
	requireContains(t, exported, exported.stdout, "-----BEGIN X509 CRL-----")
	var dir = t.TempDir()
	var file = filepath.Join(dir, "list.crl")
	mustOpn(t, menu, "export", pki.caDescr, "file="+file)
	if data, err := os.ReadFile(file); err != nil || string(data) != exported.stdout {
		t.Errorf("exported file differs from stdout: %v", err)
	}
	var exists = mustFailOpn(t, menu, "export", pki.caDescr, "file="+file)
	requireContains(t, exists, exists.stderr, "already exists")
	mustOpn(t, menu, "export", pki.caDescr, "file="+file, "overwrite")

	// an imported list keeps its entries but can not revoke
	requireNoStdout(t, mustOpn(t, menu, "set", pki.caDescr, "method=import", "crl-file="+file))
	var imported = mustOpn(t, menu, "show", pki.caDescr)
	requireContains(t, imported, imported.stdout, "type:         imported", "revoked:      1", c2Serial)
	var refused = mustFailOpn(t, menu, "revoke", pki.caDescr, "certificate="+c1.descr)
	requireContains(t, refused, refused.stderr, "imported")
	requireNoStdout(t, mustOpn(t, menu, "set", pki.caDescr, "method=internal"))
	if crl, err := ts.CrlGet(pki.caRefid); err != nil || crl.Imported() || len(crl.Revoked()) != 0 {
		t.Errorf("after set method=internal: %+v %v", crl, err)
	}

	var unconfirmed = mustFailOpn(t, menu, "remove", pki.caDescr)
	requireContains(t, unconfirmed, unconfirmed.stderr, "confirm=yes")
	if descr := trustRevocationRawCrlDescr(t, pki.caRefid); descr == nil {
		t.Fatalf("remove without confirm removed the list")
	}
	requireNoStdout(t, mustOpn(t, menu, "remove", pki.caDescr, "confirm=yes"))
	if descr := trustRevocationRawCrlDescr(t, pki.caRefid); descr != nil {
		t.Errorf("the list still exists after remove: %q", *descr)
	}
	mustFailOpn(t, menu, "remove", pki.caDescr, "confirm=yes")
}
