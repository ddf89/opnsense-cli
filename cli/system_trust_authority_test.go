package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	systemTrustAuthoritySearchPath   = "/api/trust/ca/search"
	systemTrustAuthorityGetPath      = "/api/trust/ca/get"
	systemTrustAuthorityAddPath      = "/api/trust/ca/add"
	systemTrustAuthoritySetPath      = "/api/trust/ca/set/"
	systemTrustAuthorityDelPath      = "/api/trust/ca/del/"
	systemTrustAuthorityInfoPath     = "/api/trust/ca/ca_info/"
	systemTrustAuthorityDumpPath     = "/api/trust/ca/raw_dump/"
	systemTrustAuthorityGeneratePath = "/api/trust/ca/generate_file/"
	systemTrustAuthorityCertSearch   = "/api/trust/cert/search"

	systemTrustAuthorityRootRefid  = "6ade13e520da0"
	systemTrustAuthorityNoKeyRefid = "6ade14086671b"

	// systemTrustAuthoritySecret is part of every private key of the fake rows, it must never be printed
	systemTrustAuthoritySecret = "TOPSECRETKEYMATERIAL"
)

// systemTrustAuthorityGet is get without uuid: the defaults of a new CA with the option lists (trimmed)
const systemTrustAuthorityGet = `{"ca":{"refid":"","descr":"","caref":{"":{"value":"self-signed","selected":1}},` +
	`"action":{"existing":{"value":"Import","selected":0},"internal":{"value":"Create","selected":1}},` +
	`"key_type":{"512":{"value":"RSA-512","selected":0},"2048":{"value":"RSA-2048","selected":1},"4096":{"value":"RSA-4096","selected":0},` +
	`"prime256v1":{"value":"Elliptic Curve prime256v1","selected":0},"secp384r1":{"value":"Elliptic Curve secp384r1","selected":0}},` +
	`"digest":{"sha1":{"value":"SHA1","selected":0},"sha256":{"value":"SHA256","selected":1},"sha512":{"value":"SHA512","selected":0}},` +
	`"lifetime":"825","country":{"DE":{"value":"Germany","selected":0},"MT":{"value":"Malta","selected":0},"NL":{"value":"Netherlands","selected":1}}}}`

// systemTrustAuthorityPem creates a certificate signed by parent (self-signed when nil) and returns the PEM
// certificate, the PEM key and the parsed certificate with its key for signing further certificates
type systemTrustAuthorityPem struct {
	cert    string
	key     string
	parsed  *x509.Certificate
	private *ecdsa.PrivateKey
}

func systemTrustAuthorityNewPem(t *testing.T, commonName string, parent *systemTrustAuthorityPem) systemTrustAuthorityPem {
	t.Helper()
	var key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var template = &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign}
	var signerCert, signerKey = template, key
	if parent != nil {
		signerCert, signerKey = parent.parsed, parent.private
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDer, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return systemTrustAuthorityPem{
		cert:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		key:     string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer})),
		parsed:  parsed,
		private: key,
	}
}

// systemTrustAuthorityRow is a search row as OPNsense 26.7 returns it, including the private key
func systemTrustAuthorityRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "refid": "", "descr": "", "crt": "LS0tLS1CRUdJTg==", "prv": "", "serial": "", "caref": "",
		"action": "existing", "%action": "Import an existing Certificate Authority", "key_type": "prime256v1",
		"%key_type": "Elliptic Curve prime256v1", "digest": "sha256", "%digest": "SHA256", "lifetime": "825", "city": "",
		"state": "", "organization": "", "organizationalunit": "", "country": "NL", "%country": "Netherlands", "email": "",
		"commonname": "", "ocsp_uri": "", "crt_payload": "", "prv_payload": "", "refcount": "0", "name": "",
		"valid_from": "1792938981", "valid_to": "4102444800",
	}, overrides)
}

// systemTrustAuthorityWithKey adds a private key (with the secret marker) to a row
func systemTrustAuthorityWithKey(row map[string]any) map[string]any {
	return withFields(row, map[string]any{
		"prv":         "VE9QU0VDUkVUS0VZTUFURVJJQUw=",
		"prv_payload": "-----BEGIN PRIVATE KEY-----\n" + systemTrustAuthoritySecret + "\n-----END PRIVATE KEY-----\n",
	})
}

// systemTrustAuthorityRows: a root (in use by the intermediate and a certificate), the intermediate, an imported
// CA without key signed by an external CA, an orphaned intermediate and an expired CA
func systemTrustAuthorityRows(t *testing.T) []map[string]any {
	t.Helper()
	var root = systemTrustAuthorityNewPem(t, "Lab Root", nil)
	var inter = systemTrustAuthorityNewPem(t, "Lab Inter", &root)
	var external = systemTrustAuthorityNewPem(t, "External Root", nil)
	var imported = systemTrustAuthorityNewPem(t, "Imported Sub", &external)
	return []map[string]any{
		systemTrustAuthorityWithKey(systemTrustAuthorityRow(map[string]any{"uuid": "u-root", "refid": systemTrustAuthorityRootRefid,
			"descr": "lab-root", "commonname": "Lab Root", "name": "/C=NL/CN=Lab Root", "crt_payload": root.cert, "refcount": "2", "serial": "3"})),
		systemTrustAuthorityWithKey(systemTrustAuthorityRow(map[string]any{"uuid": "u-inter", "refid": "6ade13f1cb603",
			"descr": "lab-inter", "commonname": "Lab Inter", "caref": systemTrustAuthorityRootRefid, "%caref": "lab-root",
			"key_type": "2048", "%key_type": "RSA-2048", "crt_payload": inter.cert})),
		systemTrustAuthorityRow(map[string]any{"uuid": "u-imported", "refid": systemTrustAuthorityNoKeyRefid, "descr": "imported",
			"commonname": "Imported Sub", "crt_payload": imported.cert}),
		systemTrustAuthorityWithKey(systemTrustAuthorityRow(map[string]any{"uuid": "u-orphan", "refid": "6ade14086671c", "descr": "orphan",
			"commonname": "Orphan", "caref": "0000000000000", "crt_payload": inter.cert})),
		systemTrustAuthorityWithKey(systemTrustAuthorityRow(map[string]any{"uuid": "u-old", "refid": "6ade14086671d", "descr": "old ca",
			"commonname": "Old", "crt_payload": root.cert, "valid_to": "1000000000"})),
	}
}

func systemTrustAuthorityFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(systemTrustAuthoritySearchPath, systemTrustAuthorityRows(t)...)
	f.on("GET", systemTrustAuthorityGetPath, 200, systemTrustAuthorityGet)
	f.on("GET", systemTrustAuthorityInfoPath+systemTrustAuthorityRootRefid, 200, `{"valid_from":1792938981,"valid_to":4102444800,`+
		`"name":"\/C=MT\/O=Lab\/CN=Lab Root","serialNumber":"0","country":"MT","state":"Malta","city":"Valletta","organization":"Lab",`+
		`"email":"ca@lab.example","commonname":"Lab Root","issuer":{"commonname":"Lab Root"},"key_type":"prime256v1","digest":"sha256"}`)
	f.search(systemTrustAuthorityCertSearch,
		map[string]any{"uuid": "c-web", "descr": "web cert", "caref": systemTrustAuthorityRootRefid},
		map[string]any{"uuid": "c-gui", "descr": "Web GUI TLS certificate", "caref": ""})
	return f
}

// systemTrustAuthorityWantNoSecret fails when output contains private key material
func systemTrustAuthorityWantNoSecret(t *testing.T, r runResult) {
	t.Helper()
	wantNotContains(t, "output", r.stdout+r.stderr, systemTrustAuthoritySecret, "VE9QU0VDUkVUS0VZ", "PRIVATE KEY", `"prv"`, "prv_payload")
}

func TestSystemTrustAuthorityPrint(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	var r = f.run("/system/trust/authority", "print")
	wantExit(t, r, 0)
	systemTrustAuthorityWantNoSecret(t, r)
	var rows = systemCronWantTable(t, r.stdout, []string{"#", "DESCRIPTION", "COMMON-NAME", "ISSUER", "VALID-UNTIL", "KEY", "PRIVATE-KEY", "IN-USE"},
		1, "lab-root", "lab-inter", "imported", "orphan", "old ca")
	var issuers = []string{rows[1][3], rows[2][3], rows[3][3], rows[4][3], rows[5][3]}
	var want = []string{"self-signed", "lab-root", "external: CN=External Root", "unknown (refid 0000000000000)", "self-signed"}
	if !reflect.DeepEqual(issuers, want) {
		t.Errorf("issuers %q, want %q", issuers, want)
	}
	if rows[1][5] != "prime256v1" || rows[2][5] != "rsa-2048" || rows[1][6] != "yes" || rows[3][6] != "no" || rows[1][7] != "2" {
		t.Errorf("unexpected rows %q", rows)
	}
	if rows[1][4] != "2100-01-01" || rows[5][4] != "2001-09-09 (expired)" {
		t.Errorf("unexpected validity %q / %q", rows[1][4], rows[5][4])
	}
	wantSearchPhrases(t, f, systemTrustAuthoritySearchPath, "")
	wantNoMutations(t, f)
}

func TestSystemTrustAuthorityPrintJSONAndDetailHideKeys(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	var r = f.run("/system/trust/authority", "print", "json")
	wantExit(t, r, 0)
	systemTrustAuthorityWantNoSecret(t, r)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 5 {
		t.Fatalf("want 5 JSON lines, got:\n%s", r.stdout)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first["uuid"] != "u-root" || first["refid"] != systemTrustAuthorityRootRefid || !strings.Contains(first["crt_payload"].(string), "BEGIN CERTIFICATE") {
		t.Errorf("unexpected object %v", first)
	}
	if _, has := first["crt"]; has {
		t.Errorf("the base64 certificate is left out: %v", first)
	}

	r = f.run("/system/trust/authority", "print", "detail", "search=lab")
	wantExit(t, r, 0)
	systemTrustAuthorityWantNoSecret(t, r)
	wantContains(t, "stdout", r.stdout, "0\n  uuid:", "refid:         "+systemTrustAuthorityRootRefid, "private-key:   yes",
		"in-use:        2", "next-serial:   3", "issuer:        lab-root", "fingerprint:", "\n1\n")
	wantSearchPhrases(t, f, systemTrustAuthoritySearchPath, "", "lab")
}

func TestSystemTrustAuthorityShowSelectors(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	for _, selector := range []string{"1", "u-inter", "lab-inter", "LAB-INTER", "6ade13f1cb603"} {
		var r = f.run("/system/trust/authority", "show", selector)
		wantExit(t, r, 0)
		systemTrustAuthorityWantNoSecret(t, r)
		wantContains(t, "stdout", r.stdout, "uuid:          u-inter", "issuer:        lab-root", "issuer-refid:  "+systemTrustAuthorityRootRefid,
			"key-type:      rsa-2048", "expired:       no")
	}
	wantFailure(t, f.run("/system/trust/authority", "show", "lab"), "not found")
	wantFailure(t, f.run("/system/trust/authority", "show", "9"), "not found", "#9")
	var r = f.run("/system/trust/authority", "show", "old ca")
	wantContains(t, "stdout", r.stdout, "expired:       yes")
	wantNoMutations(t, f)
}

func TestSystemTrustAuthorityAddInternal(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	f.on("POST", systemTrustAuthorityAddPath, 200, answerAdded("u-new"))

	var r = f.run("/system/trust/authority", "add", "description=new root", "common-name=New Root", "key-type=RSA-4096",
		"digest=SHA512", "lifetime=30", "country=de", "organization=Lab", "email=ca@lab.example", "ocsp-uri=http://ocsp.lab.example")
	wantExit(t, r, 0)
	if r.stdout != "u-new\n" {
		t.Errorf("want the uuid on stdout, got %q", r.stdout)
	}
	var call = wantOneMutation(t, f, "POST", systemTrustAuthorityAddPath)
	wantJSON(t, call, map[string]any{"ca": map[string]any{
		"action": "internal", "descr": "new root", "caref": "", "key_type": "4096", "digest": "sha512", "lifetime": "30",
		"commonname": "New Root", "country": "DE", "state": "", "city": "", "organization": "Lab", "organizationalunit": "",
		"email": "ca@lab.example", "ocsp_uri": "http://ocsp.lab.example",
	}})
}

func TestSystemTrustAuthorityAddInternalDefaults(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	f.on("POST", systemTrustAuthorityAddPath, 200, answerAdded("u-new"))

	wantExit(t, f.run("/system/trust/authority", "add", "description=defaults", "common-name=Defaults"), 0)
	var body = wantOneMutation(t, f, "POST", systemTrustAuthorityAddPath).json(t)["ca"].(map[string]any)
	for field, want := range map[string]string{"key_type": "2048", "digest": "sha256", "lifetime": "825", "country": "NL", "caref": ""} {
		if body[field] != want {
			t.Errorf("%s: got %v, want %q", field, body[field], want)
		}
	}
}

func TestSystemTrustAuthorityAddIntermediate(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	f.on("POST", systemTrustAuthorityAddPath, 200, answerAdded("u-sub"))

	var r = f.run("/system/trust/authority", "add", "method=intermediate", "issuer=lab-root", "description=sub", "common-name=Sub CA",
		"city=Mdina", "key-type=prime256v1", "lifetime=10")
	wantExit(t, r, 0)
	if r.stdout != "u-sub\n" {
		t.Errorf("want the uuid on stdout, got %q", r.stdout)
	}
	var call = wantOneMutation(t, f, "POST", systemTrustAuthorityAddPath)
	wantJSON(t, call, map[string]any{"ca": map[string]any{
		"action": "internal", "descr": "sub", "caref": systemTrustAuthorityRootRefid, "key_type": "prime256v1", "digest": "sha256",
		"lifetime": "10", "commonname": "Sub CA", "country": "MT", "state": "Malta", "city": "Mdina", "organization": "Lab",
		"organizationalunit": "", "email": "ca@lab.example", "ocsp_uri": "",
	}})
}

func TestSystemTrustAuthorityAddIntermediateIssuerChecks(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	wantFailure(t, f.run("/system/trust/authority", "add", "method=intermediate", "issuer=imported", "description=sub", "common-name=x"),
		`issuer "imported" has no private key`)
	wantFailure(t, f.run("/system/trust/authority", "add", "method=intermediate", "issuer=nope", "description=sub", "common-name=x"),
		"issuer:", "not found")
	wantFailure(t, f.run("/system/trust/authority", "add", "method=intermediate", "description=sub", "common-name=x"), "needs issuer=")
	wantFailure(t, f.run("/system/trust/authority", "add", "issuer=lab-root", "description=sub", "common-name=x"), "issuer can not be used with method=internal")
	wantNoMutations(t, f)
}

func TestSystemTrustAuthorityAddArgumentChecks(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"description=x"}, "needs common-name="},
		{[]string{"description=x", "common-name=x", "key-type=999"}, `unknown key-type "999", valid are: rsa-512, rsa-2048`},
		{[]string{"description=x", "common-name=x", "digest=md5"}, `unknown digest "md5"`},
		{[]string{"description=x", "common-name=x", "country=XX"}, `unknown country "XX"`},
		{[]string{"description=x", "common-name=x", "country=Netherlands"}, "two letter country code"},
		{[]string{"description=x", "common-name=x", "lifetime=0"}, "lifetime"},
		{[]string{"description=x", "common-name=x", "ocsp-uri=ftp:x"}, "must be a URL"},
		{[]string{"description=x", "common-name=x", "certificate-file=a.pem"}, "certificate-file can not be used with method=internal"},
		{[]string{"description=", "common-name=x"}, "description must not be empty"},
		{[]string{"method=import", "description=x"}, "needs certificate-file="},
		{[]string{"method=import", "description=x", "certificate-file=a.pem", "lifetime=3"}, "lifetime can not be used with method=import"},
		{[]string{"method=import", "description=x", "certificate-file=a.pem", "common-name=x"}, "common-name can not be used with method=import"},
		{[]string{"method=import", "description=x", "certificate-file=missing.pem"}, "missing.pem"},
		{[]string{"description=lab-root", "common-name=x"}, `description "lab-root" exists already (u-root)`},
		{[]string{"description=lab-root", "common-name=x", "replace"}, "is in use (2 reference(s)), it can not be replaced"},
	} {
		var r = f.run(append([]string{"/system/trust/authority", "add"}, test.args...)...)
		wantFailure(t, r, test.want)
	}
	wantNoMutations(t, f)
}

func TestSystemTrustAuthorityAddReplace(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	f.on("POST", systemTrustAuthoritySetPath+"u-inter", 200, answerSaved)

	var r = f.run("/system/trust/authority", "add", "description=lab-inter", "common-name=Regenerated", "lifetime=5", "replace")
	wantExit(t, r, 0)
	if r.stdout != "u-inter\n" {
		t.Errorf("want the uuid on stdout, got %q", r.stdout)
	}
	wantContains(t, "stderr", r.stderr, "regenerated")
	var body = wantOneMutation(t, f, "POST", systemTrustAuthoritySetPath+"u-inter").json(t)["ca"].(map[string]any)
	if body["action"] != "internal" || body["commonname"] != "Regenerated" || body["lifetime"] != "5" || body["caref"] != "" {
		t.Errorf("unexpected body %v", body)
	}
}

func TestSystemTrustAuthorityAddImport(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	f.on("POST", systemTrustAuthorityAddPath, 200, answerAdded("u-imp"))
	var dir = t.TempDir()
	var pair = systemTrustAuthorityNewPem(t, "To Import", nil)
	var other = systemTrustAuthorityNewPem(t, "Other", nil)
	for name, content := range map[string]string{"ca.pem": pair.cert, "ca.key": pair.key, "other.key": other.key, "junk.txt": "hello"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	wantFailure(t, runOpnIn(t, dir, f.env(), "/system/trust/authority", "add", "method=import", "description=imp", "certificate-file=ca.pem",
		"key-file=other.key"), "does not belong")
	wantFailure(t, runOpnIn(t, dir, f.env(), "/system/trust/authority", "add", "method=import", "description=imp", "certificate-file=junk.txt"),
		"not a PEM file")
	wantFailure(t, runOpnIn(t, dir, f.env(), "/system/trust/authority", "add", "method=import", "description=imp", "certificate-file=ca.key"),
		"no PEM certificate")
	wantNoMutations(t, f)

	var r = runOpnIn(t, dir, f.env(), "/system/trust/authority", "add", "method=import", "description=imp", "certificate-file=ca.pem", "key-file=ca.key")
	wantExit(t, r, 0)
	if r.stdout != "u-imp\n" {
		t.Errorf("want the uuid on stdout, got %q", r.stdout)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", systemTrustAuthorityAddPath), map[string]any{"ca": map[string]any{
		"action": "existing", "descr": "imp", "caref": "", "crt_payload": pair.cert, "prv_payload": pair.key,
	}})
}

func TestSystemTrustAuthoritySet(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	f.on("POST", systemTrustAuthoritySetPath+"u-inter", 200, answerSaved)

	var r = f.run("/system/trust/authority", "set", "lab-inter", "description=renamed", "serial=42")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("set must be silent, got %q", r.stdout)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", systemTrustAuthoritySetPath+"u-inter"),
		map[string]any{"ca": map[string]any{"descr": "renamed", "serial": "42"}})
}

func TestSystemTrustAuthoritySetFailures(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	var dir = t.TempDir()
	var other = systemTrustAuthorityNewPem(t, "Other", nil)
	if err := os.WriteFile(filepath.Join(dir, "other.key"), []byte(other.key), 0o600); err != nil {
		t.Fatal(err)
	}
	wantFailure(t, f.run("/system/trust/authority", "set", "lab-inter"), "nothing to change")
	wantFailure(t, f.run("/system/trust/authority", "set", "nope", "description=x"), "not found")
	wantFailure(t, f.run("/system/trust/authority", "set", "lab-inter", "serial=-1"), "serial")
	wantFailure(t, runOpnIn(t, dir, f.env(), "/system/trust/authority", "set", "imported", "key-file=other.key"), "does not belong")
	wantNoMutations(t, f)
}

func TestSystemTrustAuthorityRemove(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	f.on("POST", systemTrustAuthorityDelPath+"u-inter", 200, answerDeleted)

	var r = f.run("/system/trust/authority", "remove", "lab-root")
	wantFailure(t, r, `"lab-root" is in use (2 reference(s)`, `authorities "lab-inter"`, `certificates "web cert"`)
	wantNoMutations(t, f)

	r = f.run("/system/trust/authority", "remove", "lab-inter")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("remove must be silent, got %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", systemTrustAuthorityDelPath+"u-inter")
}

func TestSystemTrustAuthorityDump(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	f.on("GET", systemTrustAuthorityDumpPath+"u-root", 200,
		`{"exit_status":0,"stderr":"","stdout":"sha256 Fingerprint=A3:B6\nCertificate:\n    Data:\n"}`)

	var r = f.run("/system/trust/authority", "dump", "0")
	wantExit(t, r, 0)
	if r.stdout != "sha256 Fingerprint=A3:B6\nCertificate:\n    Data:\n" {
		t.Errorf("unexpected dump %q", r.stdout)
	}
	wantNoMutations(t, f)
}

func TestSystemTrustAuthorityExport(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	f.on("POST", systemTrustAuthorityGeneratePath+"u-old/crt", 200, `{"status":"ok","descr":"old ca","payload":"-----BEGIN CERTIFICATE-----\nX\n"}`)
	f.on("POST", systemTrustAuthorityGeneratePath+"u-old/prv", 200, `{"status":"ok","descr":"old ca","payload":"-----BEGIN PRIVATE KEY-----\nY\n"}`)
	var dir = t.TempDir()

	var r = runOpnIn(t, dir, f.env(), "/system/trust/authority", "export", "old ca")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("export to a file prints nothing on stdout, got %q", r.stdout)
	}
	wantContains(t, "stderr", r.stderr, "saved old_ca_crt.pem")
	systemTrustAuthorityWantFile(t, filepath.Join(dir, "old_ca_crt.pem"), "-----BEGIN CERTIFICATE-----\nX\n", 0o644)

	wantFailure(t, runOpnIn(t, dir, f.env(), "/system/trust/authority", "export", "old ca"), "already exists", "overwrite")

	wantExit(t, runOpnIn(t, dir, f.env(), "/system/trust/authority", "export", "old ca", "type=key", "file=old.pem"), 0)
	systemTrustAuthorityWantFile(t, filepath.Join(dir, "old.pem"), "-----BEGIN PRIVATE KEY-----\nY\n", 0o600)

	// overwriting a readable file with a key makes it private
	wantExit(t, runOpnIn(t, dir, f.env(), "/system/trust/authority", "export", "old ca", "type=key", "file=old_ca_crt.pem", "overwrite"), 0)
	systemTrustAuthorityWantFile(t, filepath.Join(dir, "old_ca_crt.pem"), "-----BEGIN PRIVATE KEY-----\nY\n", 0o600)

	r = runOpnIn(t, dir, f.env(), "/system/trust/authority", "export", "old ca", "file=-")
	wantExit(t, r, 0)
	if r.stdout != "-----BEGIN CERTIFICATE-----\nX\n" {
		t.Errorf("unexpected stdout %q", r.stdout)
	}
}

func TestSystemTrustAuthorityExportFailures(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	var dir = t.TempDir()
	wantFailure(t, runOpnIn(t, dir, f.env(), "/system/trust/authority", "export", "imported", "type=key"), `"imported" has no private key`)
	wantFailure(t, runOpnIn(t, dir, f.env(), "/system/trust/authority", "export", "imported", "file=-", "overwrite"), "overwrite has no effect")
	wantFailure(t, runOpnIn(t, dir, f.env(), "/system/trust/authority", "export", "imported", "type=pkcs12"), "type must be one of")
	wantNoCallsTo(t, f, "POST")
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("no file must be written, got %v", entries)
	}
}

// wantNoCallsTo asserts no call with method was made
func wantNoCallsTo(t *testing.T, f *fakeOPN, method string) {
	t.Helper()
	for _, call := range f.calls() {
		if call.Method == method {
			t.Errorf("want no %s calls, got %v", method, call)
		}
	}
}

func systemTrustAuthorityWantFile(t *testing.T, path string, content string, mode os.FileMode) {
	t.Helper()
	var got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Errorf("%s: got %q, want %q", path, got, content)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != mode {
		t.Errorf("%s: mode %v, want %v", path, info.Mode().Perm(), mode)
	}
}

func TestSystemTrustAuthorityComplete(t *testing.T) {
	t.Parallel()
	var f = systemTrustAuthorityFake(t)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/system/trust/authority remove lab-":              {"lab-inter", "lab-root"},
		"/system/trust/authority show i":                   {"imported", "item="},
		"/system/trust/authority add issuer=lab-r":         {"issuer=lab-root"},
		"/system/trust/authority add key-type=sec":         {"key-type=secp384r1"},
		"/system/trust/authority add key-type=rsa-4":       {"key-type=rsa-4096"},
		"/system/trust/authority add digest=sha5":          {"digest=sha512"},
		"/system/trust/authority add country=M":            {"country=MT"},
		"/system/trust/authority add method=i":             {"method=import", "method=intermediate", "method=internal"},
		"/system/trust/authority export imported type=":    {"type=cert", "type=key"},
		"/system/trust/authority add description=x key-ty": {"key-type="},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}
