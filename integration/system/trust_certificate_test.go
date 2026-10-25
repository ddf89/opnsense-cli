//go:build integration

package integrationsystem

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
	"opnsense-cli/opnsense/api/trust"
)

// The certificate tests only touch certificates and CAs whose description carries this run's prefix. The Web GUI
// certificate is only read (its uuid is not even stable: legacy records get a new one when the config is reloaded)

const trustCertWebGui = "Web GUI TLS certificate"

func trustCertApi(t *testing.T) *trust.TrustApi {
	t.Helper()
	return &trust.TrustApi{OPNsense: coreApi(t)}
}

// trustCertCa is a CA created with the raw API (deliberately not the CA library) for one test
type trustCertCa struct {
	uuid  string
	refid string
	descr string
	cert  *x509.Certificate
	key   any
}

// trustCertCreateCa creates an internal CA owned by this run and registers its removal. Register it before the
// certificates: cleanups run last in first out, so the certificates are removed first
func trustCertCreateCa(t *testing.T, core *api.OPNsense, label string) trustCertCa {
	t.Helper()
	var descr = testDescription(label)
	var uuid, err = core.Mutate(core.EndpointForModule("trust/ca/add"), map[string]any{"ca": map[string]string{
		"action": "internal", "descr": descr, "commonname": strings.ReplaceAll(descr, " ", "-") + ".ca.invalid",
		"country": "NL", "key_type": "2048", "digest": "sha256", "lifetime": "30",
	}})
	if err != nil {
		t.Fatalf("creating the test CA: %v", err)
	}
	t.Cleanup(func() {
		if _, err := core.Mutate(core.EndpointForModule("trust/ca/del/"+uuid), nil); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of CA %s failed: %v", uuid, err)
		}
	})

	type caRow struct {
		Uuid       string `json:"uuid"`
		Refid      string `json:"refid"`
		Descr      string `json:"descr"`
		CrtPayload string `json:"crt_payload"`
		PrvPayload string `json:"prv_payload"`
	}
	var rows, searchErr = api.Search[caRow](core, core.EndpointForModule("trust/ca/search"), descr)
	if searchErr != nil {
		t.Fatal(searchErr)
	}
	for _, row := range rows {
		if row.Uuid != uuid {
			continue
		}
		var ca = trustCertCa{uuid: uuid, refid: row.Refid, descr: row.Descr}
		if ca.cert, err = trust.CertParsePEM(row.CrtPayload); err != nil {
			t.Fatalf("CA certificate: %v", err)
		}
		var block, _ = pem.Decode([]byte(row.PrvPayload))
		if block == nil {
			t.Fatalf("CA %s has no PEM key", uuid)
		}
		if ca.key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			t.Fatalf("CA key: %v", err)
		}
		return ca
	}
	t.Fatalf("the test CA %s is not listed", uuid)
	return trustCertCa{}
}

// trustCertCleanup removes the certificate uuid when the test ends (it may have been removed already)
func trustCertCleanup(t *testing.T, core *api.OPNsense, uuid string) {
	t.Helper()
	t.Cleanup(func() {
		if _, err := core.Mutate(core.EndpointForModule("trust/cert/del/"+uuid), nil); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of certificate %s failed: %v", uuid, err)
		}
	})
}

// trustCertRaw reads the certificate uuid with the raw API (independent of the library), ok is false when it
// does not exist
type trustCertRawRow struct {
	Uuid        string `json:"uuid"`
	Refid       string `json:"refid"`
	Descr       string `json:"descr"`
	Caref       string `json:"caref"`
	Crt         string `json:"crt"`
	Csr         string `json:"csr"`
	Prv         string `json:"prv"`
	CommonName  string `json:"commonname"`
	AltNamesDNS string `json:"altnames_dns"`
	AltNamesIP  string `json:"altnames_ip"`
	CertType    string `json:"cert_type"`
	KeyType     string `json:"key_type"`
	ValidFrom   string `json:"valid_from"`
	ValidTo     string `json:"valid_to"`
}

func trustCertRaw(t *testing.T, core *api.OPNsense, uuid string) (trustCertRawRow, bool) {
	t.Helper()
	var rows, err = api.Search[trustCertRawRow](core, core.EndpointForModule("trust/cert/search"), runPrefix)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Uuid == uuid {
			return row, true
		}
	}
	return trustCertRawRow{}, false
}

// trustCertLifetimeDays is valid_to - valid_from in days
func trustCertLifetimeDays(t *testing.T, row trustCertRawRow) int {
	t.Helper()
	var from, fromErr = strconv.ParseInt(row.ValidFrom, 10, 64)
	var to, toErr = strconv.ParseInt(row.ValidTo, 10, 64)
	if fromErr != nil || toErr != nil {
		t.Fatalf("no validity in %+v", row)
	}
	return int((to - from) / 86400)
}

// trustCertLocalPair returns a self-signed EC certificate, its key and a signing request for the same key
func trustCertLocalPair(t *testing.T, commonName string) (certPEM string, keyPEM string, csrPEM string) {
	t.Helper()
	var key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var template = &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(5 * 24 * time.Hour), DNSNames: []string{commonName},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDer, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDer}))
}

// trustCertSignLocally signs the request csrPEM with the test CA (like an external CA would)
func trustCertSignLocally(t *testing.T, ca trustCertCa, csrPEM string) string {
	t.Helper()
	var request, err = trust.CertParseRequestPEM(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	var template = &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: request.Subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(3 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, request.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// trustCertRequireNoneLeft fails when a certificate of this run with the given label prefix remains
func trustCertRequireNoneLeft(t *testing.T, core *api.OPNsense, label string) {
	t.Helper()
	var rows, err = api.Search[trustCertRawRow](core, core.EndpointForModule("trust/cert/search"), testDescription(label))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if strings.HasPrefix(row.Descr, testDescription(label)) {
			t.Errorf("certificate %s %q was not removed", row.Uuid, row.Descr)
		}
	}
}

func TestTrustCertificateWebGuiReadOnly(t *testing.T) {
	var ts = trustCertApi(t)
	var cert, err = ts.CertGetByDescription(trustCertWebGui)
	if api.IsNotFound(err) {
		t.Skipf("no %q on this instance", trustCertWebGui)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !cert.InUseFlag() || !cert.HasPrivateKey || !cert.IsSelfSigned() || cert.CertificatePEM == "" {
		t.Errorf("unexpected web GUI certificate %+v", cert)
	}
	if byRefid, err := ts.CertGetByRefid(cert.Refid); err != nil || byRefid.Descr != trustCertWebGui {
		t.Errorf("CertGetByRefid(%s): %+v %v", cert.Refid, byRefid, err)
	}
	var dump, dumpErr = ts.CertDump(cert.Uuid)
	if dumpErr != nil && !api.IsNotFound(dumpErr) { // not found: its uuid changed in between, see above
		t.Fatal(dumpErr)
	}
	if dumpErr == nil && !strings.Contains(dump, "Certificate:") {
		t.Errorf("unexpected dump %q", dump)
	}
}

func TestTrustCertificateLifecycle(t *testing.T) {
	var ts = trustCertApi(t)
	var core = ts.OPNsense
	var ca = trustCertCreateCa(t, core, "certlib ca")
	defer trustCertRequireNoneLeft(t, core, "certlib")

	// a server certificate signed by the CA
	var serverDescr = testDescription("certlib server")
	var serverUuid, err = ts.CertCreate(trust.CertRequest{
		Method: trust.CertMethodInternal, Description: serverDescr, IssuerRef: ca.refid, Type: trust.CertTypeServer,
		KeyType: "prime256v1", Digest: "sha384", Lifetime: 20, CommonName: "srv.certlib.invalid", Organization: "a8 test",
		AltNamesDNS: []string{"srv.certlib.invalid", "www.certlib.invalid"}, AltNamesIP: []string{"10.9.8.7"},
	})
	if err != nil {
		t.Fatalf("CertCreate server: %v", err)
	}
	trustCertCleanup(t, core, serverUuid)

	var raw, ok = trustCertRaw(t, core, serverUuid)
	if !ok {
		t.Fatalf("server certificate %s is not listed", serverUuid)
	}
	if raw.Caref != ca.refid || raw.CommonName != "srv.certlib.invalid" || raw.AltNamesDNS != "srv.certlib.invalid\nwww.certlib.invalid" ||
		raw.AltNamesIP != "10.9.8.7" || raw.CertType != "server_cert" || raw.KeyType != "prime256v1" || raw.Prv == "" {
		t.Errorf("unexpected server certificate %+v", raw)
	}
	if days := trustCertLifetimeDays(t, raw); days != 20 {
		t.Errorf("want a lifetime of 20 days, got %d", days)
	}

	// the library view
	var cert, getErr = ts.CertGet(serverUuid)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if cert.CarefName != ca.descr || !cert.HasPrivateKey || cert.IsPending() || cert.IsSelfSigned() || cert.InUseFlag() {
		t.Errorf("unexpected certificate %+v", cert)
	}
	var parsed, parseErr = cert.X509()
	if parseErr != nil || parsed.CheckSignatureFrom(ca.cert) != nil || !slices.Contains(parsed.DNSNames, "www.certlib.invalid") {
		t.Errorf("the certificate is not signed by the test CA or lacks the alt names: %v", parseErr)
	}
	if byDescr, err := ts.CertGetByDescription(serverDescr); err != nil || byDescr.Uuid != serverUuid {
		t.Errorf("CertGetByDescription: %+v %v", byDescr, err)
	}
	var issuers, issuersErr = ts.CertIssuers()
	if issuersErr != nil || !slices.ContainsFunc(issuers, func(issuer trust.CertIssuer) bool { return issuer.Refid == ca.refid }) {
		t.Errorf("CertIssuers lacks the test CA: %+v %v", issuers, issuersErr)
	}
	if issuer, err := ts.CertIssuerByName(strings.ToUpper(ca.descr)); err != nil || issuer.Refid != ca.refid {
		t.Errorf("CertIssuerByName: %+v %v", issuer, err)
	}

	// renaming keeps the certificate (a set without action manual would reissue it)
	var renamed = testDescription("certlib server renamed")
	if err := ts.CertUpdate(serverUuid, trust.CertPatch{Description: &renamed}); err != nil {
		t.Fatal(err)
	}
	var after, _ = trustCertRaw(t, core, serverUuid)
	if after.Descr != renamed || after.Crt != raw.Crt || after.Prv != raw.Prv || after.ValidTo != raw.ValidTo {
		t.Errorf("rename changed the certificate: before %+v after %+v", raw, after)
	}

	// reissue: new certificate, same key, refid and uuid
	if err := ts.CertReissue(serverUuid, 7, ""); err != nil {
		t.Fatalf("CertReissue: %v", err)
	}
	var reissued, _ = trustCertRaw(t, core, serverUuid)
	if reissued.Crt == raw.Crt || reissued.Prv != raw.Prv || reissued.Refid != raw.Refid || trustCertLifetimeDays(t, reissued) != 7 {
		t.Errorf("unexpected reissue: before %+v after %+v", raw, reissued)
	}

	// exports
	var crt, crtName, crtErr = ts.CertExport(serverUuid, trust.CertExportCertificate, "")
	var prv, _, prvErr = ts.CertExport(serverUuid, trust.CertExportPrivateKey, "")
	if crtErr != nil || prvErr != nil {
		t.Fatalf("CertExport: %v / %v", crtErr, prvErr)
	}
	if _, err := tls.X509KeyPair(crt, prv); err != nil {
		t.Errorf("exported certificate and key do not match: %v", err)
	}
	if !strings.HasSuffix(crtName, "_crt.pem") || strings.ContainsAny(crtName, " /") {
		t.Errorf("unexpected file name %q", crtName)
	}
	var p12, p12Name, p12Err = ts.CertExport(serverUuid, trust.CertExportPKCS12, "s3cret")
	if p12Err != nil || len(p12) < 100 || p12[0] != 0x30 || !strings.HasSuffix(p12Name, "_cert.p12") {
		t.Errorf("pkcs12: %d bytes %q %v", len(p12), p12Name, p12Err)
	}
	if _, _, err := ts.CertExport(serverUuid, trust.CertExportSigningRequest, ""); err == nil || !strings.Contains(err.Error(), "no signing request") {
		t.Errorf("want no signing request, got %v", err)
	}
	if dump, err := ts.CertDump(serverUuid); err != nil || !strings.Contains(dump, "srv.certlib.invalid") || !strings.Contains(dump, "Fingerprint") {
		t.Errorf("CertDump: %v\n%s", err, dump)
	}

	// a client certificate and a self-signed one
	var clientUuid, clientErr = ts.CertCreate(trust.CertRequest{Method: trust.CertMethodInternal, Description: testDescription("certlib client"),
		IssuerRef: ca.refid, Type: trust.CertTypeClient, CommonName: "client.certlib.invalid", Lifetime: 5})
	if clientErr != nil {
		t.Fatalf("CertCreate client: %v", clientErr)
	}
	trustCertCleanup(t, core, clientUuid)
	if row, _ := trustCertRaw(t, core, clientUuid); row.CertType != "usr_cert" || row.Caref != ca.refid {
		t.Errorf("unexpected client certificate %+v", row)
	}
	var selfUuid, selfErr = ts.CertCreate(trust.CertRequest{Method: trust.CertMethodSelfSigned, Description: testDescription("certlib self"),
		Type: trust.CertTypeCombined, CommonName: "self.certlib.invalid", Lifetime: 3})
	if selfErr != nil {
		t.Fatalf("CertCreate self-signed: %v", selfErr)
	}
	trustCertCleanup(t, core, selfUuid)
	if self, err := ts.CertGet(selfUuid); err != nil || !self.IsSelfSigned() || self.Caref != "" || self.CertType != trust.CertTypeCombined {
		t.Errorf("unexpected self-signed certificate %+v %v", self, err)
	}
	// OPNsense can not reissue self-signed certificates, the library refuses before sending
	if err := ts.CertReissue(selfUuid, 0, ""); err == nil {
		t.Error("want a refusal to reissue a self-signed certificate")
	}

	// replace keeps uuid and refid
	var selfBefore, _ = trustCertRaw(t, core, selfUuid)
	if err := ts.CertReplace(selfUuid, trust.CertRequest{Method: trust.CertMethodInternal, Description: testDescription("certlib self"),
		IssuerRef: ca.refid, CommonName: "replaced.certlib.invalid", Lifetime: 2}); err != nil {
		t.Fatalf("CertReplace: %v", err)
	}
	var selfAfter, _ = trustCertRaw(t, core, selfUuid)
	if selfAfter.Refid != selfBefore.Refid || selfAfter.Caref != ca.refid || selfAfter.CommonName != "replaced.certlib.invalid" ||
		selfAfter.Crt == selfBefore.Crt || trustCertLifetimeDays(t, selfAfter) != 2 {
		t.Errorf("unexpected replace: before %+v after %+v", selfBefore, selfAfter)
	}

	// in use: a disabled cron job of this run referring to the refid
	var cronUuid, _ = createCronJob(t, &system.SystemApi{OPNsense: core}, "certlib in use", system.CronJob{Parameters: raw.Refid})
	var inUse *trust.CertInUseError
	if err := ts.CertRemove(serverUuid); !errors.As(err, &inUse) {
		t.Errorf("want in use, got %v", err)
	}
	if err := (&system.SystemApi{OPNsense: core}).CronJobRemove(cronUuid); err != nil {
		t.Fatal(err)
	}

	for _, uuid := range []string{serverUuid, clientUuid, selfUuid} {
		if err := ts.CertRemove(uuid); err != nil {
			t.Errorf("CertRemove(%s): %v", uuid, err)
		}
		if _, ok := trustCertRaw(t, core, uuid); ok {
			t.Errorf("certificate %s still exists", uuid)
		}
	}
	if err := ts.CertRemove(serverUuid); !api.IsNotFound(err) {
		t.Errorf("want not found for a removed certificate, got %v", err)
	}
}

func TestTrustCertificateImportAndSign(t *testing.T) {
	var ts = trustCertApi(t)
	var core = ts.OPNsense
	var ca = trustCertCreateCa(t, core, "certimp ca")
	defer trustCertRequireNoneLeft(t, core, "certimp")

	// import a certificate with its key
	var certPEM, keyPEM, csrPEM = trustCertLocalPair(t, "import.certimp.invalid")
	var importUuid, err = ts.CertCreate(trust.CertRequest{Method: trust.CertMethodImport, Description: testDescription("certimp imported"),
		CertificatePEM: certPEM, PrivateKeyPEM: keyPEM})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	trustCertCleanup(t, core, importUuid)
	var imported, getErr = ts.CertGet(importUuid)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if imported.CertificatePEM != certPEM || !imported.HasPrivateKey || imported.CommonName != "import.certimp.invalid" || !imported.IsSelfSigned() {
		t.Errorf("unexpected imported certificate %+v", imported)
	}
	var key, _, keyErr = ts.CertExport(importUuid, trust.CertExportPrivateKey, "")
	if keyErr != nil || string(key) != keyPEM {
		t.Errorf("exported key differs: %v", keyErr)
	}

	// sign a request with the CA: no key on the firewall
	var signedUuid, signErr = ts.CertCreate(trust.CertRequest{Method: trust.CertMethodSignRequest, Description: testDescription("certimp signed"),
		IssuerRef: ca.refid, SigningRequestPEM: csrPEM, Type: trust.CertTypeServer, Lifetime: 4, AltNamesDNS: []string{"import.certimp.invalid"}})
	if signErr != nil {
		t.Fatalf("sign-csr: %v", signErr)
	}
	trustCertCleanup(t, core, signedUuid)
	var signed, _ = ts.CertGet(signedUuid)
	var parsed, parseErr = signed.X509()
	if parseErr != nil || signed.HasPrivateKey || signed.Caref != ca.refid || parsed.CheckSignatureFrom(ca.cert) != nil ||
		parsed.Subject.CommonName != "import.certimp.invalid" {
		t.Errorf("unexpected signed certificate %+v (%v)", signed, parseErr)
	}
	if _, _, err := ts.CertExport(signedUuid, trust.CertExportPrivateKey, ""); err == nil || !strings.Contains(err.Error(), "no private key") {
		t.Errorf("want no private key, got %v", err)
	}
	if _, _, err := ts.CertExport(signedUuid, trust.CertExportPKCS12, ""); err == nil {
		t.Error("want a pkcs12 error without key")
	}

	// a signing request created on the firewall, completed with a certificate signed "elsewhere"
	var requestUuid, requestErr = ts.CertCreate(trust.CertRequest{Method: trust.CertMethodSigningRequest, Description: testDescription("certimp request"),
		CommonName: "request.certimp.invalid", Country: "DE"})
	if requestErr != nil {
		t.Fatalf("csr: %v", requestErr)
	}
	trustCertCleanup(t, core, requestUuid)
	var pending, _ = ts.CertGet(requestUuid)
	if !pending.IsPending() || !pending.HasPrivateKey || pending.Country != "DE" {
		t.Fatalf("unexpected pending request %+v", pending)
	}
	if _, _, err := ts.CertExport(requestUuid, trust.CertExportCertificate, ""); err == nil {
		t.Error("want an error exporting the certificate of a pending request")
	}
	var csr, _, csrErr = ts.CertExport(requestUuid, trust.CertExportSigningRequest, "")
	if csrErr != nil {
		t.Fatal(csrErr)
	}
	if dump, err := ts.CertDump(requestUuid); err != nil || !strings.Contains(dump, "Certificate Request") {
		t.Errorf("CertDump of a request: %v %q", err, dump)
	}
	// a certificate for another key is refused locally, the right one is stored
	if err := ts.CertImportSigned(requestUuid, certPEM); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("want a key mismatch, got %v", err)
	}
	var signedElsewhere = trustCertSignLocally(t, ca, string(csr))
	if err := ts.CertImportSigned(requestUuid, signedElsewhere); err != nil {
		t.Fatalf("CertImportSigned: %v", err)
	}
	var completed, _ = ts.CertGet(requestUuid)
	if completed.IsPending() || completed.CertificatePEM != signedElsewhere || completed.Caref != ca.refid {
		t.Errorf("unexpected completed request %+v", completed)
	}
	var crt, _, _ = ts.CertExport(requestUuid, trust.CertExportCertificate, "")
	var prv, _, _ = ts.CertExport(requestUuid, trust.CertExportPrivateKey, "")
	if _, err := tls.X509KeyPair(crt, prv); err != nil {
		t.Errorf("completed request: certificate and key do not match: %v", err)
	}

	for _, uuid := range []string{importUuid, signedUuid, requestUuid} {
		if err := ts.CertRemove(uuid); err != nil {
			t.Errorf("CertRemove(%s): %v", uuid, err)
		}
	}
}

func TestTrustCertificateErrors(t *testing.T) {
	var ts = trustCertApi(t)
	var core = ts.OPNsense
	defer trustCertRequireNoneLeft(t, core, "certerr")

	var unknown = "00000000-1111-4222-8333-444444444444"
	if _, err := ts.CertGet(unknown); !api.IsNotFound(err) {
		t.Errorf("CertGet: want not found, got %v", err)
	}
	var description = testDescription("certerr ghost")
	if err := ts.CertUpdate(unknown, trust.CertPatch{Description: &description}); !api.IsNotFound(err) {
		t.Errorf("CertUpdate: want not found, got %v", err)
	}
	if err := ts.CertRemove(unknown); !api.IsNotFound(err) {
		t.Errorf("CertRemove: want not found, got %v", err)
	}
	if _, err := ts.CertDump(unknown); !api.IsNotFound(err) {
		t.Errorf("CertDump: want not found, got %v", err)
	}
	if _, _, err := ts.CertExport(unknown, trust.CertExportCertificate, ""); !api.IsNotFound(err) {
		t.Errorf("CertExport: want not found, got %v", err)
	}
	if _, err := ts.CertCreate(trust.CertRequest{Method: trust.CertMethodInternal, Description: description,
		IssuerRef: "0000000000000", CommonName: "x.invalid"}); !api.IsNotFound(err) {
		t.Errorf("unknown issuer: want not found, got %v", err)
	}

	// a key of another certificate is refused locally
	var certPEM, _, _ = trustCertLocalPair(t, "a.certerr.invalid")
	var _, otherKey, _ = trustCertLocalPair(t, "b.certerr.invalid")
	if _, err := ts.CertCreate(trust.CertRequest{Method: trust.CertMethodImport, Description: description,
		CertificatePEM: certPEM, PrivateKeyPEM: otherKey}); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("want a key mismatch, got %v", err)
	}
	// OPNsense answers failing actions with HTTP 500 (the library checks imports locally, so use the raw API)
	var _, rawErr = core.Mutate(core.EndpointForModule("trust/cert/add"), map[string]any{"cert": map[string]string{
		"action": "import", "descr": description, "crt_payload": "garbage"}})
	var httpErr *api.HttpError
	if !errors.As(rawErr, &httpErr) || httpErr.StatusCode != 500 || !strings.Contains(httpErr.Message, "Invalid X509") {
		t.Errorf("want HTTP 500 Invalid X509 certificate provided, got %v", rawErr)
	}
}
