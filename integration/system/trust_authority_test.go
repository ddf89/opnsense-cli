//go:build integration

package integrationsystem

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/trust"
)

// Only CAs created here (description testDescription(...)) are changed or removed, all with lifetimes of days

func trustAuthorityApi(t *testing.T) *trust.TrustApi {
	t.Helper()
	return &trust.TrustApi{OPNsense: coreApi(t)}
}

// trustAuthorityCleanup removes the CA with uuid at the end of the test; register children after their issuer so
// they are removed first
func trustAuthorityCleanup(t *testing.T, ts *trust.TrustApi, uuid string) {
	t.Helper()
	t.Cleanup(func() {
		var ca, err = ts.CaGet(uuid)
		if api.IsNotFound(err) {
			return
		}
		if err != nil || !ownedByRun(ca.Description) {
			t.Errorf("cleanup: not removing certificate authority %s (%q): %v", uuid, ca.Description, err)
			return
		}
		if err := ts.CaRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of certificate authority %s failed: %v", uuid, err)
		}
	})
}

// trustAuthorityCreateRoot generates a self-signed CA owned by this run
func trustAuthorityCreateRoot(t *testing.T, ts *trust.TrustApi, label string) (string, trust.Authority) {
	t.Helper()
	var uuid, err = ts.CaCreateInternal(trust.AuthorityInternal{
		Description: testDescription(label), KeyType: "prime256v1", Digest: "sha256", LifetimeDays: 2,
		Subject: trust.AuthoritySubject{CommonName: "a8 " + label, Country: "MT", City: "Valletta", Organization: "a8 test",
			Email: "ca@a8.example"},
	})
	if err != nil {
		t.Fatalf("CaCreateInternal: %v", err)
	}
	trustAuthorityCleanup(t, ts, uuid)
	var ca, getErr = ts.CaGet(uuid)
	if getErr != nil {
		t.Fatalf("CaGet(%s): %v", uuid, getErr)
	}
	return uuid, ca
}

// trustAuthorityLocalPair creates a self-signed CA certificate and key in PEM
func trustAuthorityLocalPair(t *testing.T, commonName string) (string, string) {
	t.Helper()
	var key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var template = &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDer, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer}))
}

func TestTrustAuthorityLifecycle(t *testing.T) {
	var ts = trustAuthorityApi(t)
	var rootUuid, root = trustAuthorityCreateRoot(t, ts, "ca-root")

	t.Run("the generated root", func(t *testing.T) {
		if root.CommonName != "a8 ca-root" || root.Country != "MT" || root.City != "Valletta" || root.KeyType != "prime256v1" ||
			root.Digest != "sha256" || !root.HasPrivateKey || root.InUse() != 0 || root.Caref != "" || len(root.Refid) != 13 {
			t.Errorf("unexpected root %+v", root)
		}
		var until, ok = root.NotAfter()
		if !ok || time.Until(until) < 47*time.Hour || time.Until(until) > 49*time.Hour {
			t.Errorf("want a lifetime of 2 days, valid until %v", until)
		}
		var cert, err = root.X509()
		if err != nil || !cert.IsCA || cert.Subject.CommonName != "a8 ca-root" {
			t.Errorf("unexpected certificate %v %v", cert, err)
		}
	})

	t.Run("lookups", func(t *testing.T) {
		if ca, err := ts.CaGetByDescription(root.Description); err != nil || ca.Uuid != rootUuid {
			t.Errorf("CaGetByDescription: %+v %v", ca, err)
		}
		if ca, err := ts.CaGetByRefid(root.Refid); err != nil || ca.Uuid != rootUuid {
			t.Errorf("CaGetByRefid: %+v %v", ca, err)
		}
		var authorities, raw, err = ts.CaSearchRaw(runPrefix)
		if err != nil || len(authorities) == 0 || len(raw) != len(authorities) {
			t.Fatalf("CaSearchRaw: %d %d %v", len(authorities), len(raw), err)
		}
		for _, row := range raw {
			if strings.Contains(string(row), "PRIVATE KEY") || strings.Contains(string(row), `"prv"`) {
				t.Errorf("raw search row leaks the private key: %.200s", row)
			}
		}
	})

	t.Run("info, dump and export", func(t *testing.T) {
		var info, err = ts.CaInfo(root.Refid)
		if err != nil || info.CommonName != "a8 ca-root" || info.KeyType != "prime256v1" || info.Country != "MT" {
			t.Errorf("CaInfo: %+v %v", info, err)
		}
		dump, err := ts.CaDump(rootUuid)
		if err != nil || !strings.Contains(dump, "Certificate:") || !strings.Contains(dump, "CN=a8 ca-root") || !strings.Contains(dump, "sha256 Fingerprint=") {
			t.Errorf("CaDump: %.300q %v", dump, err)
		}
		certificate, descr, err := ts.CaExport(rootUuid, trust.CaExportCertificate)
		if err != nil || certificate != root.Certificate || descr != root.Description {
			t.Errorf("CaExport crt: %q %v", descr, err)
		}
		key, _, err := ts.CaExport(rootUuid, trust.CaExportPrivateKey)
		if err != nil {
			t.Fatalf("CaExport prv: %v", err)
		}
		if err := trust.CaCheckPair(certificate, key); err != nil {
			t.Errorf("the exported key does not match: %v", err)
		}
	})

	var interUuid, err = ts.CaCreateIntermediate(root.Refid, trust.AuthorityInternal{
		Description: testDescription("ca-intermediate"), KeyType: "2048", Digest: "sha384", LifetimeDays: 1,
		Subject: trust.AuthoritySubject{CommonName: "a8 ca-intermediate", City: "Mdina"},
	})
	if err != nil {
		t.Fatalf("CaCreateIntermediate: %v", err)
	}
	trustAuthorityCleanup(t, ts, interUuid)

	t.Run("the intermediate is signed by the root", func(t *testing.T) {
		var inter, err = ts.CaGet(interUuid)
		if err != nil {
			t.Fatal(err)
		}
		if inter.Caref != root.Refid || inter.CarefDescription != root.Description || inter.KeyType != "2048" || inter.Digest != "sha384" ||
			inter.Country != "MT" || inter.City != "Mdina" || inter.Organization != "a8 test" || !inter.HasPrivateKey {
			t.Errorf("unexpected intermediate %+v", inter)
		}
		var interCert, _ = inter.X509()
		var rootCert, _ = root.X509()
		if interCert == nil || rootCert == nil || interCert.CheckSignatureFrom(rootCert) != nil {
			t.Error("the intermediate certificate is not signed by the root")
		}
		updatedRoot, err := ts.CaGet(rootUuid)
		if err != nil || updatedRoot.InUse() != 1 || updatedRoot.Serial != "1" {
			t.Errorf("want the root in use once with serial 1: %+v %v", updatedRoot, err)
		}
	})

	t.Run("an issuer in use is not removed", func(t *testing.T) {
		var err = ts.CaRemove(rootUuid)
		var inUse *trust.AuthorityInUseError
		if !errors.As(err, &inUse) || len(inUse.Authorities) != 1 || inUse.Authorities[0] != testDescription("ca-intermediate") {
			t.Fatalf("want in use by the intermediate, got %v", err)
		}
		if _, err := ts.CaGet(rootUuid); err != nil {
			t.Errorf("the root must still exist: %v", err)
		}
	})

	t.Run("update description and serial", func(t *testing.T) {
		var description = testDescription("ca-intermediate renamed")
		var serial = 41
		if err := ts.CaUpdate(interUuid, trust.AuthorityPatch{Description: &description, Serial: &serial}); err != nil {
			t.Fatal(err)
		}
		var inter, err = ts.CaGet(interUuid)
		if err != nil || inter.Description != description || inter.Serial != "41" || inter.Caref != root.Refid || !inter.HasPrivateKey {
			t.Errorf("unexpected intermediate %+v %v", inter, err)
		}
	})

	t.Run("a certificate of another key is refused", func(t *testing.T) {
		var other, _ = trustAuthorityLocalPair(t, "a8 other")
		if err := ts.CaUpdate(interUuid, trust.AuthorityPatch{Certificate: &other}); err == nil || !strings.Contains(err.Error(), "does not belong") {
			t.Errorf("want a key mismatch, got %v", err)
		}
	})

	t.Run("replace regenerates in place", func(t *testing.T) {
		var before, _ = ts.CaGet(interUuid)
		if err := ts.CaReplaceInternal(interUuid, trust.AuthorityInternal{Description: before.Description, Issuer: root.Refid,
			KeyType: "prime256v1", LifetimeDays: 1, Subject: trust.AuthoritySubject{CommonName: "a8 regenerated", Country: "DE"}}); err != nil {
			t.Fatal(err)
		}
		var after, err = ts.CaGet(interUuid)
		if err != nil || after.Refid != before.Refid || after.CommonName != "a8 regenerated" || after.Country != "DE" ||
			after.KeyType != "prime256v1" || after.Certificate == before.Certificate || after.Caref != root.Refid {
			t.Errorf("unexpected regenerated CA %+v %v", after, err)
		}
	})

	t.Run("remove intermediate then root", func(t *testing.T) {
		if err := ts.CaRemove(interUuid); err != nil {
			t.Fatal(err)
		}
		if err := ts.CaRemove(rootUuid); err != nil {
			t.Fatal(err)
		}
		for _, uuid := range []string{interUuid, rootUuid} {
			if _, err := ts.CaGet(uuid); !api.IsNotFound(err) {
				t.Errorf("%s still exists: %v", uuid, err)
			}
		}
	})
}

func TestTrustAuthorityImport(t *testing.T) {
	var ts = trustAuthorityApi(t)
	var certificate, key = trustAuthorityLocalPair(t, "a8 imported")

	var uuid, err = ts.CaImport(trust.AuthorityImport{Description: testDescription("ca-import"), Certificate: certificate})
	if err != nil {
		t.Fatalf("CaImport: %v", err)
	}
	trustAuthorityCleanup(t, ts, uuid)

	var ca, getErr = ts.CaGet(uuid)
	if getErr != nil || ca.HasPrivateKey || ca.CommonName != "a8 imported" || ca.Certificate != certificate || ca.KeyType != "prime256v1" {
		t.Fatalf("unexpected import %+v %v", ca, getErr)
	}
	if _, _, err := ts.CaExport(uuid, trust.CaExportPrivateKey); err == nil || !strings.Contains(err.Error(), "no private key") {
		t.Errorf("want no private key, got %v", err)
	}

	t.Run("an intermediate needs an issuer with key", func(t *testing.T) {
		var before, _ = ts.CaSearch(runPrefix)
		if _, err := ts.CaCreateIntermediate(ca.Refid, trust.AuthorityInternal{Description: testDescription("ca-unsignable"),
			Subject: trust.AuthoritySubject{CommonName: "x"}}); err == nil || !strings.Contains(err.Error(), "no private key") {
			t.Errorf("want no private key, got %v", err)
		}
		var after, _ = ts.CaSearch(runPrefix)
		if len(after) != len(before) {
			t.Errorf("a CA was created: %d before, %d after", len(before), len(after))
		}
	})

	t.Run("add the key", func(t *testing.T) {
		if err := ts.CaUpdate(uuid, trust.AuthorityPatch{PrivateKey: &key}); err != nil {
			t.Fatal(err)
		}
		var exported, _, err = ts.CaExport(uuid, trust.CaExportPrivateKey)
		if err != nil || exported != key {
			t.Errorf("want the added key back, got %v", err)
		}
	})

	t.Run("a renewed certificate of the same key", func(t *testing.T) {
		var signer, _ = x509.ParsePKCS8PrivateKey(pemBytes(t, key))
		var ecKey = signer.(*ecdsa.PrivateKey)
		var template = &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "a8 imported renewed"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(72 * time.Hour), BasicConstraintsValid: true, IsCA: true}
		var der, err = x509.CreateCertificate(rand.Reader, template, template, &ecKey.PublicKey, ecKey)
		if err != nil {
			t.Fatal(err)
		}
		var renewed = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		if err := ts.CaUpdate(uuid, trust.AuthorityPatch{Certificate: &renewed}); err != nil {
			t.Fatal(err)
		}
		updated, err := ts.CaGet(uuid)
		if err != nil || updated.CommonName != "a8 imported renewed" || !updated.HasPrivateKey || updated.Refid != ca.Refid {
			t.Errorf("unexpected renewed CA %+v %v", updated, err)
		}
	})

	t.Run("replace without key drops the key", func(t *testing.T) {
		if err := ts.CaReplaceImport(uuid, trust.AuthorityImport{Description: ca.Description, Certificate: certificate}); err != nil {
			t.Fatal(err)
		}
		var replaced, err = ts.CaGet(uuid)
		if err != nil || replaced.HasPrivateKey || replaced.CommonName != "a8 imported" || replaced.Refid != ca.Refid {
			t.Errorf("unexpected replaced CA %+v %v", replaced, err)
		}
	})
}

func pemBytes(t *testing.T, text string) []byte {
	t.Helper()
	var block, _ = pem.Decode([]byte(text))
	if block == nil {
		t.Fatal("no PEM block")
	}
	return block.Bytes
}

func TestTrustAuthorityErrors(t *testing.T) {
	var ts = trustAuthorityApi(t)
	const unknownUuid = "00000000-0000-4000-8000-00000000a8a8"

	if _, err := ts.CaGet(unknownUuid); !api.IsNotFound(err) {
		t.Errorf("CaGet: want not found, got %v", err)
	}
	var before, _ = ts.CaList()
	var description = testDescription("ca-upsert")
	// set/<unknown uuid> would create a CA on OPNsense, the library must refuse
	if err := ts.CaUpdate(unknownUuid, trust.AuthorityPatch{Description: &description}); !api.IsNotFound(err) {
		t.Errorf("CaUpdate: want not found, got %v", err)
	}
	if err := ts.CaRemove(unknownUuid); !api.IsNotFound(err) {
		t.Errorf("CaRemove: want not found, got %v", err)
	}
	if _, err := ts.CaDump(unknownUuid); !api.IsNotFound(err) {
		t.Errorf("CaDump: want not found, got %v", err)
	}
	if _, _, err := ts.CaExport(unknownUuid, trust.CaExportCertificate); !api.IsNotFound(err) {
		t.Errorf("CaExport: want not found, got %v", err)
	}
	if _, err := ts.CaInfo("0000000000000"); !api.IsNotFound(err) {
		t.Errorf("CaInfo: want not found, got %v", err)
	}
	if _, err := ts.CaCreateInternal(trust.AuthorityInternal{Description: testDescription("ca-bad-issuer"), Issuer: "0000000000000"}); !api.IsNotFound(err) {
		t.Errorf("unknown issuer: want not found, got %v", err)
	}
	var validation *api.ValidationError
	if _, err := ts.CaCreateInternal(trust.AuthorityInternal{Description: testDescription("ca-bad-key"), KeyType: "999",
		Subject: trust.AuthoritySubject{CommonName: "x"}}); !errors.As(err, &validation) || validation.Validations["ca.key_type"] == "" {
		t.Errorf("invalid key type: want a validation error, got %v", err)
	}
	if _, err := ts.CaImport(trust.AuthorityImport{Description: testDescription("ca-garbage"), Certificate: "garbage"}); err == nil {
		t.Error("garbage must not be imported")
	}
	var after, _ = ts.CaList()
	if len(after) != len(before) {
		t.Errorf("a CA was created by the failing calls: %d before, %d after", len(before), len(after))
	}

	var options, err = ts.CaOptions()
	if err != nil || len(options.KeyTypes) == 0 || len(options.Digests) == 0 || len(options.Countries) < 100 {
		t.Errorf("CaOptions: %d key types, %d digests, %d countries, %v", len(options.KeyTypes), len(options.Digests), len(options.Countries), err)
	}
}
