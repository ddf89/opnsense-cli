//go:build integration

package integrationsystem

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/trust"
)

// The revocation tests create their own CA and two client certificates it signs with the raw API (not the CA and
// certificate libraries), then work on the revocation list of that CA only. Cleanup removes the list, the
// certificates and the CA, in that order, and checks that nothing with the test description is left

func trustRevocationApi(t *testing.T) *trust.TrustApi {
	t.Helper()
	return &trust.TrustApi{OPNsense: coreApi(t)}
}

type trustRevocationCert struct {
	uuid   string
	refid  string
	descr  string
	serial *big.Int
}

// trustRevocationPKI is a test CA with two client certificates
type trustRevocationPKI struct {
	caUuid  string
	caRefid string
	caDescr string
	certs   []trustRevocationCert
}

// trustRevocationRawCerts reads refid and serial of the certificates directly from trust/cert/search
func trustRevocationRawCerts(t *testing.T, core *api.OPNsense, prefix string) []trustRevocationCert {
	t.Helper()
	type row struct {
		Uuid  string `json:"uuid"`
		Refid string `json:"refid"`
		Descr string `json:"descr"`
		Crt   string `json:"crt_payload"`
	}
	var rows, err = api.Search[row](core, core.EndpointForModule("trust/cert/search"), prefix)
	if err != nil {
		t.Fatalf("trust/cert/search: %v", err)
	}
	var certs []trustRevocationCert
	for _, r := range rows {
		if !strings.HasPrefix(r.Descr, prefix) {
			continue
		}
		var cert = trustRevocationCert{uuid: r.Uuid, refid: r.Refid, descr: r.Descr}
		if block, _ := pem.Decode([]byte(r.Crt)); block != nil {
			if parsed, err := x509.ParseCertificate(block.Bytes); err == nil {
				cert.serial = parsed.SerialNumber
			}
		}
		certs = append(certs, cert)
	}
	return certs
}

// trustRevocationSetup creates a CA (descr testDescription(label)+" ca") and the client certificates
// "<label> c1" and "<label> c2" signed by it, and registers their removal (list, certificates, CA)
func trustRevocationSetup(t *testing.T, label string) trustRevocationPKI {
	t.Helper()
	var core = coreApi(t)
	var prefix = testDescription(label)
	var pki = trustRevocationPKI{caDescr: prefix + " ca"}
	var commonName = strings.ReplaceAll(prefix, " ", "-")

	var caUuid, err = core.Mutate(core.EndpointForModule("trust/ca/add"), map[string]any{"ca": map[string]string{
		"action": "internal", "descr": pki.caDescr, "commonname": commonName + "-ca", "lifetime": "30", "country": "NL",
		"key_type": "2048", "digest": "sha256",
	}})
	if err != nil {
		t.Fatalf("creating the test CA: %v", err)
	}
	pki.caUuid = caUuid

	// removal in reverse order of registration: the list, the certificates, the CA, then the check
	t.Cleanup(func() {
		for _, endpoint := range []string{"trust/cert/search", "trust/ca/search"} {
			if rows, err := rawSearch(core, endpoint, prefix); err != nil {
				t.Errorf("cleanup check %s: %v", endpoint, err)
			} else {
				for _, row := range rows {
					if strings.HasPrefix(row.Descr, prefix) {
						t.Errorf("cleanup left %s %s (%s)", endpoint, row.Uuid, row.Descr)
					}
				}
			}
		}
	})
	t.Cleanup(func() {
		if _, err := core.Mutate(core.EndpointForModule("trust/ca/del/"+caUuid), nil); err != nil {
			t.Errorf("cleanup of the test CA %s: %v", caUuid, err)
		}
	})

	var rows, searchErr = rawSearch(core, "trust/ca/search", pki.caDescr)
	if searchErr != nil {
		t.Fatal(searchErr)
	}
	for _, row := range rows {
		if row.Uuid == caUuid {
			pki.caRefid = row.Refid
		}
	}
	if pki.caRefid == "" {
		t.Fatalf("the test CA %s has no refid in trust/ca/search", caUuid)
	}

	for _, name := range []string{"c1", "c2"} {
		var uuid, err = core.Mutate(core.EndpointForModule("trust/cert/add"), map[string]any{"cert": map[string]string{
			"action": "internal", "descr": prefix + " " + name, "caref": pki.caRefid, "commonname": commonName + "-" + name,
			"cert_type": "usr_cert", "lifetime": "30", "country": "NL", "key_type": "2048", "digest": "sha256",
			"private_key_location": "firewall",
		}})
		if err != nil {
			t.Fatalf("creating the test certificate %s: %v", name, err)
		}
		t.Cleanup(func() {
			if _, err := core.Mutate(core.EndpointForModule("trust/cert/del/"+uuid), nil); err != nil {
				t.Errorf("cleanup of the test certificate %s: %v", uuid, err)
			}
		})
	}
	t.Cleanup(func() {
		var answer struct {
			Status string `json:"status"`
		}
		if err := core.DoJSON("POST", core.EndpointForModule("trust/crl/del/"+pki.caRefid), nil, &answer); err != nil {
			t.Errorf("cleanup of the revocation list of %s: %v", pki.caRefid, err)
		} else if answer.Status != "deleted" && answer.Status != "not found" {
			t.Errorf("cleanup of the revocation list of %s: status %q", pki.caRefid, answer.Status)
		}
	})

	pki.certs = trustRevocationRawCerts(t, core, prefix+" c")
	if len(pki.certs) != 2 || pki.certs[0].serial == nil || pki.certs[1].serial == nil {
		t.Fatalf("unexpected test certificates %+v", pki.certs)
	}
	if pki.certs[0].descr != prefix+" c1" {
		pki.certs[0], pki.certs[1] = pki.certs[1], pki.certs[0]
	}
	return pki
}

// trustRevocationRawCrlDescr returns the crl_descr of the CA in trust/crl/search, nil without list
func trustRevocationRawCrlDescr(t *testing.T, refid string) *string {
	t.Helper()
	var core = coreApi(t)
	type row struct {
		Refid    string  `json:"refid"`
		CrlDescr *string `json:"crl_descr"`
	}
	var rows, err = api.Search[row](core, core.EndpointForModule("trust/crl/search"), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Refid == refid {
			return r.CrlDescr
		}
	}
	t.Fatalf("CA %s not in trust/crl/search", refid)
	return nil
}

func trustRevocationRevokedRefs(t *testing.T, ts *trust.TrustApi, caref string) map[string]string {
	t.Helper()
	var crl, err = ts.CrlGet(caref)
	if err != nil {
		t.Fatal(err)
	}
	var revoked = map[string]string{}
	for _, ref := range crl.Revoked() {
		revoked[ref.Refid] = ref.Reason
	}
	return revoked
}

// trustRevocationEntries returns serial (hex) -> reason code of the entries of the current list
func trustRevocationEntries(t *testing.T, ts *trust.TrustApi, caref string) map[string]int {
	t.Helper()
	var text, err = ts.CrlExport(caref)
	if err != nil {
		t.Fatal(err)
	}
	list, err := trust.CrlParse(text)
	if err != nil {
		t.Fatal(err)
	}
	var entries = map[string]int{}
	for _, entry := range list.RevokedCertificateEntries {
		entries[trust.CrlSerialHex(entry.SerialNumber)] = entry.ReasonCode
	}
	return entries
}

func TestTrustRevocationLifecycle(t *testing.T) {
	var ts = trustRevocationApi(t)
	var pki = trustRevocationSetup(t, "crl-lib")
	var c1, c2 = pki.certs[0], pki.certs[1]
	var c1Serial, c2Serial = trust.CrlSerialHex(c1.serial), trust.CrlSerialHex(c2.serial)

	t.Run("a new CA has no list", func(t *testing.T) {
		var authorities, err = ts.CrlList()
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, authority := range authorities {
			if authority.Refid == pki.caRefid {
				found = true
				if authority.HasCrl() || authority.Descr != pki.caDescr {
					t.Errorf("unexpected row %+v", authority)
				}
			}
		}
		if !found {
			t.Errorf("CA %s not listed", pki.caRefid)
		}
		crl, err := ts.CrlGet(pki.caRefid)
		if err != nil {
			t.Fatal(err)
		}
		if crl.Exists() || len(crl.Certificates) != 2 || len(crl.Revoked()) != 0 {
			t.Errorf("unexpected list %+v", crl)
		}
		if _, err := ts.CrlDump(pki.caRefid); !api.IsNotFound(err) {
			t.Errorf("dump without list: want *NotFoundError, got %v", err)
		}
		if err := ts.CrlRevoke(pki.caRefid, "0", c1.refid); !api.IsNotFound(err) {
			t.Errorf("revoke without list: want *NotFoundError, got %v", err)
		}
	})

	if err := ts.CrlSet(pki.caRefid, trust.CrlSettings{Descr: testDescription("crl-lib list"), Lifetime: "30", Method: trust.CrlMethodInternal}); err != nil {
		t.Fatalf("CrlSet: %v", err)
	}

	t.Run("the list exists and is empty", func(t *testing.T) {
		var crl, err = ts.CrlGet(pki.caRefid)
		if err != nil {
			t.Fatal(err)
		}
		if !crl.Exists() || crl.Imported() || crl.Lifetime != "30" || crl.Descr != testDescription("crl-lib list") || len(crl.Revoked()) != 0 {
			t.Errorf("unexpected list %+v", crl)
		}
		if descr := trustRevocationRawCrlDescr(t, pki.caRefid); descr == nil || *descr != testDescription("crl-lib list") {
			t.Errorf("crl_descr in search: %v", descr)
		}
		if entries := trustRevocationEntries(t, ts, pki.caRefid); len(entries) != 0 {
			t.Errorf("entries %v", entries)
		}
	})

	t.Run("revoke", func(t *testing.T) {
		if err := ts.CrlRevoke(pki.caRefid, "1", c1.refid); err != nil {
			t.Fatal(err)
		}
		if err := ts.CrlRevoke(pki.caRefid, "4", c2.refid); err != nil {
			t.Fatal(err)
		}
		if got := trustRevocationRevokedRefs(t, ts, pki.caRefid); len(got) != 2 || got[c1.refid] != "1" || got[c2.refid] != "4" {
			t.Errorf("revoked %v", got)
		}
		if got := trustRevocationEntries(t, ts, pki.caRefid); len(got) != 2 || got[c1Serial] != 1 || got[c2Serial] != 4 {
			t.Errorf("entries %v, want %s keyCompromise and %s superseded", got, c1Serial, c2Serial)
		}
		var times, err = ts.CrlRevocationTimes(pki.caRefid)
		if err != nil {
			t.Fatal(err)
		}
		if times[c1Serial].IsZero() || times[c2Serial].Before(times[c1Serial]) {
			t.Errorf("revocation times %v", times)
		}
		var certificates, certErr = ts.CrlCertificates(pki.caRefid)
		if certErr != nil || len(certificates) != 2 {
			t.Errorf("certificates of the CA: %+v %v", certificates, certErr)
		}
	})

	t.Run("revoking an unknown certificate sends nothing", func(t *testing.T) {
		if err := ts.CrlRevoke(pki.caRefid, "0", "0000000000000"); !api.IsNotFound(err) {
			t.Errorf("want *NotFoundError, got %v", err)
		}
	})

	t.Run("unrevoke", func(t *testing.T) {
		if err := ts.CrlUnrevoke(pki.caRefid, c1.refid); err != nil {
			t.Fatal(err)
		}
		if got := trustRevocationRevokedRefs(t, ts, pki.caRefid); len(got) != 1 || got[c2.refid] != "4" {
			t.Errorf("revoked %v", got)
		}
		if got := trustRevocationEntries(t, ts, pki.caRefid); len(got) != 1 || got[c2Serial] != 4 {
			t.Errorf("entries %v", got)
		}
		if err := ts.CrlUnrevoke(pki.caRefid, c1.refid); !api.IsNotFound(err) {
			t.Errorf("second unrevoke: want *NotFoundError, got %v", err)
		}
	})

	t.Run("dump", func(t *testing.T) {
		var dump, err = ts.CrlDump(pki.caRefid)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"Certificate Revocation List (CRL)", "Serial Number: " + c2Serial, "Superseded"} {
			if !strings.Contains(dump, want) {
				t.Errorf("dump lacks %q:\n%s", want, dump)
			}
		}
	})

	t.Run("import", func(t *testing.T) {
		var text, err = ts.CrlExport(pki.caRefid)
		if err != nil {
			t.Fatal(err)
		}
		if err := ts.CrlImport(pki.caRefid, testDescription("crl-lib imported"), text); err != nil {
			t.Fatal(err)
		}
		crl, err := ts.CrlGet(pki.caRefid)
		if err != nil {
			t.Fatal(err)
		}
		if !crl.Imported() || len(crl.Revoked()) != 0 || crl.Descr != testDescription("crl-lib imported") {
			t.Errorf("unexpected list %+v", crl)
		}
		if got := trustRevocationEntries(t, ts, pki.caRefid); len(got) != 1 || got[c2Serial] != 4 {
			t.Errorf("entries of the imported list %v", got)
		}
		if err := ts.CrlRevoke(pki.caRefid, "0", c1.refid); err == nil || !strings.Contains(err.Error(), "imported") {
			t.Errorf("revoke on an imported list: %v", err)
		}
		var validation *api.ValidationError
		if err := ts.CrlSet(pki.caRefid, trust.CrlSettings{Descr: "x", Method: "bogus"}); err == nil || errors.As(err, &validation) {
			t.Errorf("an invalid method must be refused before sending: %v", err)
		}
	})

	t.Run("remove", func(t *testing.T) {
		if err := ts.CrlRemove(pki.caRefid); err != nil {
			t.Fatal(err)
		}
		if descr := trustRevocationRawCrlDescr(t, pki.caRefid); descr != nil {
			t.Errorf("the list still exists: %q", *descr)
		}
		if err := ts.CrlRemove(pki.caRefid); !api.IsNotFound(err) {
			t.Errorf("second remove: want *NotFoundError, got %v", err)
		}
		if _, err := ts.CrlExport(pki.caRefid); !api.IsNotFound(err) {
			t.Errorf("export without list: want *NotFoundError, got %v", err)
		}
	})

	t.Run("an unknown CA", func(t *testing.T) {
		if _, err := ts.CrlGet("0000000000000"); !api.IsNotFound(err) {
			t.Errorf("get: want *NotFoundError, got %v", err)
		}
		// OPNsense would store an imported list for any caref, the library refuses
		if err := ts.CrlImport("0000000000000", testDescription("crl-lib ghost"), "junk"); !api.IsNotFound(err) {
			t.Errorf("import: want *NotFoundError, got %v", err)
		}
	})
}
