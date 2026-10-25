package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	systemTrustCertSearchPath = "/api/trust/cert/search"
	systemTrustCertCaListPath = "/api/trust/cert/ca_list"
	systemTrustCertAddPath    = "/api/trust/cert/add"
	systemTrustCertSetPath    = "/api/trust/cert/set/"
	systemTrustCertDelPath    = "/api/trust/cert/del/"
	systemTrustCertDumpPath   = "/api/trust/cert/raw_dump/"
	systemTrustCertFilePath   = "/api/trust/cert/generate_file/"

	systemTrustCertUuidWeb     = "a1111111-0000-4000-8000-000000000001"
	systemTrustCertUuidSelf    = "a1111111-0000-4000-8000-000000000002"
	systemTrustCertUuidPending = "a1111111-0000-4000-8000-000000000003"
	systemTrustCertUuidOld     = "a1111111-0000-4000-8000-000000000004"
	systemTrustCertUuidVpn     = "a1111111-0000-4000-8000-000000000005"
	systemTrustCertUuidNew     = "a1111111-0000-4000-8000-0000000000ff"

	systemTrustCertCaList = `{"rows":[{"caref":"6ade14316965d","descr":"Lab CA"},{"caref":"6ade1431aaaaa","descr":"Other CA"}],"count":2}`

	// systemTrustCertSecret stands in for the private key in the rows, it must never be printed
	systemTrustCertSecret = "-----BEGIN PRIVATE KEY-----\nTOPSECRETKEYMATERIAL\n-----END PRIVATE KEY-----\n"
)

// systemTrustCertPEMs is test material generated once per test
type systemTrustCertPEMs struct {
	selfSigned string // a self-signed leaf certificate
	leaf       string // a certificate for the key of csr
	leafKey    string
	csr        string
}

func systemTrustCertGenerate(t *testing.T) systemTrustCertPEMs {
	t.Helper()
	var key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var encode = func(kind string, der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}))
	}
	var template = &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "self.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	selfDer, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDer, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "self.example"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return systemTrustCertPEMs{
		selfSigned: encode("CERTIFICATE", selfDer),
		leaf:       encode("CERTIFICATE", selfDer),
		leafKey:    encode("PRIVATE KEY", keyDer),
		csr:        encode("CERTIFICATE REQUEST", csrDer),
	}
}

// systemTrustCertRow is a trust/cert/search row as OPNsense 26.7 returns it (payloads trimmed)
func systemTrustCertRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "refid": "6ade143944723", "descr": "", "caref": "6ade14316965d", "%caref": "Lab CA",
		"crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t", "csr": "", "prv": base64.StdEncoding.EncodeToString([]byte(systemTrustCertSecret)),
		"action": "reissue", "%action": "Reissue and replace certificate (does not restart services)",
		"key_type": "2048", "%key_type": "RSA-2048", "digest": "sha256", "%digest": "SHA256",
		"cert_type": "server_cert", "%cert_type": "Server Certificate", "lifetime": "397", "private_key_location": "firewall",
		"%private_key_location": "Save on this firewall", "city": "", "state": "", "organization": "",
		"organizationalunit": "", "country": "NL", "%country": "Netherlands", "email": "", "commonname": "web.example",
		"ocsp_uri": "", "altnames_dns": "web.example\nwww.example", "altnames_ip": "10.0.0.1", "altnames_uri": "",
		"altnames_email": "", "crt_payload": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", "csr_payload": "",
		"prv_payload": systemTrustCertSecret, "rfc3280_purpose": "id-kp-serverAuth", "in_use": "0", "is_user": "0",
		"name": "/C=NL/CN=web.example", "valid_from": "1792939065", "valid_to": strconv.FormatInt(time.Now().Add(200*24*time.Hour).Unix(), 10),
	}, overrides)
}

// systemTrustCertRows: web (CA signed), self (self-signed), pending (CSR), old (expired), vpn (in use, expires soon)
func systemTrustCertRows(pems systemTrustCertPEMs) []map[string]any {
	var now = time.Now()
	return []map[string]any{
		systemTrustCertRow(map[string]any{"uuid": systemTrustCertUuidWeb, "descr": "web"}),
		systemTrustCertRow(map[string]any{"uuid": systemTrustCertUuidSelf, "descr": "self", "refid": "6ade14394ad72",
			"caref": "", "%caref": "", "crt_payload": pems.selfSigned, "commonname": "self.example", "altnames_dns": "",
			"altnames_ip": "", "cert_type": "combined_server_client", "key_type": "prime256v1"}),
		systemTrustCertRow(map[string]any{"uuid": systemTrustCertUuidPending, "descr": "pending", "refid": "6ade143956bea",
			"caref": "", "%caref": "", "crt": "", "crt_payload": "", "csr": "LS0t", "csr_payload": pems.csr, "action": "import_csr",
			"commonname": "csr.example", "altnames_dns": "", "altnames_ip": "", "cert_type": "usr_cert", "rfc3280_purpose": "",
			"valid_from": "", "valid_to": ""}),
		systemTrustCertRow(map[string]any{"uuid": systemTrustCertUuidOld, "descr": "old", "refid": "6ade143964410",
			"commonname": "old.example", "cert_type": "usr_cert", "altnames_dns": "", "altnames_ip": "", "prv": "", "prv_payload": "", "action": "manual",
			"valid_to": strconv.FormatInt(now.Add(-48*time.Hour).Unix(), 10)}),
		systemTrustCertRow(map[string]any{"uuid": systemTrustCertUuidVpn, "descr": "vpn server", "refid": "6ade1439aaaaa",
			"commonname": "vpn.example", "altnames_dns": "vpn.example", "in_use": "1", "valid_to": strconv.FormatInt(now.Add(10*24*time.Hour).Unix(), 10)}),
	}
}

func systemTrustCertFake(t *testing.T) (*fakeOPN, systemTrustCertPEMs) {
	t.Helper()
	var pems = systemTrustCertGenerate(t)
	var f = newFakeOPN(t)
	f.search(systemTrustCertSearchPath, systemTrustCertRows(pems)...)
	f.on("GET", systemTrustCertCaListPath, 200, systemTrustCertCaList)
	return f, pems
}

func systemTrustCertWantNoSecret(t *testing.T, r runResult) {
	t.Helper()
	for _, secret := range []string{"TOPSECRETKEYMATERIAL", "PRIVATE KEY", base64.StdEncoding.EncodeToString([]byte(systemTrustCertSecret))[:20], `"prv`} {
		if strings.Contains(r.stdout+r.stderr, secret) {
			t.Errorf("output contains the private key (%q):\n%s", secret, r)
		}
	}
}

// --- print / show / dump

func TestSystemTrustCertPrint(t *testing.T) {
	t.Parallel()
	var f, _ = systemTrustCertFake(t)

	var r = f.run("/system/trust/certificate", "print")
	wantExit(t, r, 0)
	systemTrustCertWantNoSecret(t, r)
	var rows = systemBackupTable(r.stdout)
	if !reflect.DeepEqual(rows[0], []string{"#", "DESCRIPTION", "COMMON-NAME", "ISSUER", "TYPE", "VALID-UNTIL", "IN-USE"}) {
		t.Fatalf("header %q", rows[0])
	}
	if len(rows) != 6 {
		t.Fatalf("want 5 certificates:\n%s", r.stdout)
	}
	var want = [][]string{
		{"0", "web", "web.example", "Lab CA", "server"},
		{"1", "self", "self.example", "self-signed", "combined"},
		{"2", "pending", "csr.example", "-", "csr", "-", "no"},
		{"3", "old", "old.example", "Lab CA", "client"},
		{"4", "vpn server", "vpn.example", "Lab CA", "server"},
	}
	for i, prefix := range want {
		if !reflect.DeepEqual(rows[i+1][:len(prefix)], prefix) {
			t.Errorf("row %d: got %q, want prefix %q", i, rows[i+1], prefix)
		}
	}
	wantContains(t, "old row", strings.Join(rows[4], " "), "(expired)")
	if rows[5][len(rows[5])-1] != "yes" || rows[1][len(rows[1])-1] != "no" {
		t.Errorf("IN-USE column: %q / %q", rows[5], rows[1])
	}
	// the API's searchPhrase also matches the base64 payloads, print never sends it
	wantSearchPhrases(t, f, systemTrustCertSearchPath, "")
	wantNoMutations(t, f)
}

func TestSystemTrustCertPrintFilters(t *testing.T) {
	t.Parallel()
	var f, _ = systemTrustCertFake(t)

	var r = f.run("/system/trust/certificate", "print", "expiring=30")
	wantExit(t, r, 0)
	systemBackupWantTable(t, r.stdout, []string{"#", "DESCRIPTION", "COMMON-NAME", "ISSUER", "TYPE", "VALID-UNTIL", "IN-USE"}, 1, "old", "vpn server")

	r = f.run("/system/trust/certificate", "print", "search=WWW")
	wantExit(t, r, 0)
	systemBackupWantTable(t, r.stdout, []string{"#", "DESCRIPTION", "COMMON-NAME", "ISSUER", "TYPE", "VALID-UNTIL", "IN-USE"}, 1, "web")

	r = f.run("/system/trust/certificate", "print", "search=self-signed")
	wantExit(t, r, 0)
	systemBackupWantTable(t, r.stdout, []string{"#", "DESCRIPTION", "COMMON-NAME", "ISSUER", "TYPE", "VALID-UNTIL", "IN-USE"}, 1, "self")

	// the # of a filtered print refers to the printed rows
	f.on("POST", systemTrustCertSetPath+systemTrustCertUuidVpn, 200, answerSaved)
	r = f.runScript("/system/trust/certificate\nprint expiring=30\nset 1 description=vpn")
	wantExit(t, r, 0)
	wantOneMutation(t, f, "POST", systemTrustCertSetPath+systemTrustCertUuidVpn)
}

func TestSystemTrustCertPrintJSONAndDetail(t *testing.T) {
	t.Parallel()
	var f, _ = systemTrustCertFake(t)

	var r = f.run("/system/trust/certificate", "print", "json")
	wantExit(t, r, 0)
	systemTrustCertWantNoSecret(t, r)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 5 || !strings.Contains(lines[0], `"uuid":"`+systemTrustCertUuidWeb+`"`) || !strings.Contains(lines[0], `"crt_payload":`) {
		t.Errorf("unexpected json:\n%s", r.stdout)
	}

	r = f.run("/system/trust/certificate", "print", "detail")
	wantExit(t, r, 0)
	systemTrustCertWantNoSecret(t, r)
	wantContains(t, "detail", r.stdout, "uuid:", systemTrustCertUuidSelf, "fingerprint:", "issuer:            self-signed",
		"private-key:       stored on the firewall", "state:             signing request", "alt-dns:           web.example,www.example")
}

func TestSystemTrustCertShow(t *testing.T) {
	t.Parallel()
	var f, _ = systemTrustCertFake(t)

	for _, selector := range []string{"self", "SELF", "6ade14394ad72", systemTrustCertUuidSelf, "1"} {
		var r = f.run("/system/trust/certificate", "show", selector)
		wantExit(t, r, 0)
		systemTrustCertWantNoSecret(t, r)
		wantContains(t, "show "+selector, r.stdout, "uuid:              "+systemTrustCertUuidSelf, "refid:             6ade14394ad72",
			"common-name:       self.example", "type:              combined", "key-type:          prime256v1", "serial:            7",
			"issuer:            self-signed", "in-use:            no")
	}

	var r = f.run("/system/trust/certificate", "show", "old")
	wantExit(t, r, 0)
	wantContains(t, "show old", r.stdout, "private-key:       no", "key-type:          rsa-2048", "issuer-refid:      6ade14316965d")

	wantFailure(t, f.run("/system/trust/certificate", "show", "nope"), "not found")
	wantNoMutations(t, f)
}

func TestSystemTrustCertDump(t *testing.T) {
	t.Parallel()
	var f, _ = systemTrustCertFake(t)
	f.on("GET", systemTrustCertDumpPath+systemTrustCertUuidWeb, 200,
		`{"exit_status":0,"stderr":"","stdout":"sha256 Fingerprint=FA:2B\nCertificate:\n    Data:\n"}`)

	var r = f.run("/system/trust/certificate", "dump", "web")
	wantExit(t, r, 0)
	if r.stdout != "sha256 Fingerprint=FA:2B\nCertificate:\n    Data:\n" {
		t.Errorf("unexpected dump %q", r.stdout)
	}
	// unknown to raw_dump: []
	f.on("GET", systemTrustCertDumpPath+systemTrustCertUuidOld, 200, `[]`)
	wantFailure(t, f.run("/system/trust/certificate", "dump", "old"), "not found")
	wantNoMutations(t, f)
}

// --- add

func TestSystemTrustCertAddInternal(t *testing.T) {
	t.Parallel()
	var f, _ = systemTrustCertFake(t)
	f.on("POST", systemTrustCertAddPath, 200, answerAdded(systemTrustCertUuidNew))

	var r = f.run("/system/trust/certificate", "add", "description=mail", "issuer=lab ca", "common-name=mail.example",
		"type=server", "alt-dns=mail.example,smtp.example", "alt-ip=10.0.0.25", "key-type=secp384r1", "digest=sha384",
		"lifetime=90", "organization=ACME", "country=DE")
	wantExit(t, r, 0)
	if r.stdout != systemTrustCertUuidNew+"\n" {
		t.Errorf("want the uuid on stdout, got %q", r.stdout)
	}
	var call = wantOneMutation(t, f, "POST", systemTrustCertAddPath)
	wantJSON(t, call, map[string]any{"cert": map[string]any{
		"action": "internal", "descr": "mail", "caref": "6ade14316965d", "private_key_location": "firewall",
		"cert_type": "server_cert", "key_type": "secp384r1", "digest": "sha384", "lifetime": "90",
		"commonname": "mail.example", "country": "DE", "state": "", "city": "", "organization": "ACME",
		"organizationalunit": "", "email": "", "altnames_dns": "mail.example\nsmtp.example", "altnames_ip": "10.0.0.25",
		"altnames_email": "", "altnames_uri": "",
	}})
}

func TestSystemTrustCertAddOtherMethods(t *testing.T) {
	t.Parallel()
	var f, pems = systemTrustCertFake(t)
	f.on("POST", systemTrustCertAddPath, 200, answerAdded(systemTrustCertUuidNew))
	var dir = t.TempDir()
	var write = func(name string, content string) string {
		var path = filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	var certFile, keyFile, csrFile = write("c.pem", pems.leaf), write("k.pem", pems.leafKey), write("r.csr", pems.csr)

	for _, test := range []struct {
		args []string
		want map[string]any
	}{
		{[]string{"description=s", "method=self-signed", "common-name=s.example"}, map[string]any{"action": "internal", "caref": "",
			"cert_type": "usr_cert", "key_type": "2048", "lifetime": "397"}},
		{[]string{"description=r", "method=csr", "common-name=r.example", "key-type=rsa-4096"}, map[string]any{"action": "external", "key_type": "4096"}},
		{[]string{"description=i", "method=import", "certificate-file=" + certFile, "key-file=" + keyFile},
			map[string]any{"action": "import", "crt_payload": pems.leaf, "prv_payload": pems.leafKey}},
		{[]string{"description=g", "method=sign-csr", "issuer=6ade1431aaaaa", "csr-file=" + csrFile, "type=client", "alt-email=a@example.com"},
			map[string]any{"action": "sign_csr", "caref": "6ade1431aaaaa", "csr_payload": pems.csr, "cert_type": "usr_cert", "altnames_email": "a@example.com"}},
	} {
		var before = len(f.mutations())
		var r = f.run(append([]string{"/system/trust/certificate", "add"}, test.args...)...)
		wantExit(t, r, 0)
		var mutations = f.mutations()
		if len(mutations) != before+1 {
			t.Fatalf("%v: want one more mutation, got %v", test.args, mutations)
		}
		var cert = mutations[len(mutations)-1].json(t)["cert"].(map[string]any)
		for field, value := range test.want {
			if cert[field] != value {
				t.Errorf("%v: %s = %v, want %v", test.args, field, cert[field], value)
			}
		}
		systemTrustCertWantNoSecret(t, r)
	}
}

func TestSystemTrustCertAddRefuses(t *testing.T) {
	t.Parallel()
	var f, pems = systemTrustCertFake(t)
	var other = systemTrustCertGenerate(t)
	var dir = t.TempDir()
	var certFile = filepath.Join(dir, "c.pem")
	var keyFile = filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certFile, []byte(pems.leaf), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(other.leafKey), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"description=x", "common-name=x"}, "method=internal needs issuer="},
		{[]string{"description=x", "issuer=Lab CA"}, "needs common-name="},
		{[]string{"description=x", "method=self-signed", "common-name=x", "issuer=Lab CA"}, "does not take issuer="},
		{[]string{"description=x", "method=import", "certificate-file=" + certFile, "common-name=x"}, "does not take common-name="},
		{[]string{"description=x", "method=csr", "common-name=x", "lifetime=5"}, "does not take lifetime="},
		{[]string{"description=x", "method=sign-csr", "issuer=Lab CA"}, "needs csr-file="},
		{[]string{"description=x", "method=import", "certificate-file=" + filepath.Join(dir, "missing.pem")}, "no such file"},
		{[]string{"description=x", "method=import", "certificate-file=" + keyFile}, "no PEM encoded certificate"},
		{[]string{"description=x", "method=import", "certificate-file=" + certFile, "key-file=" + keyFile}, "does not belong"},
		{[]string{"description=x", "issuer=Nope CA", "common-name=x"}, "not found"},
		{[]string{"description=x", "method=self-signed", "common-name=x", "country=nl"}, "two letter"},
		{[]string{"description=x", "method=self-signed", "common-name=x", "alt-ip=10.0.0"}, "alt-ip"},
		{[]string{"description=x", "method=self-signed", "common-name=x", "key-type=rsa-2000"}, "key-type"},
		{[]string{"description=web", "method=self-signed", "common-name=x"}, "exists already"},
		{[]string{"description=WEB", "method=self-signed", "common-name=x"}, "exists already"},
	} {
		wantFailure(t, f.run(append([]string{"/system/trust/certificate", "add"}, test.args...)...), test.want)
	}
	wantNoMutations(t, f)
}

func TestSystemTrustCertAddReplace(t *testing.T) {
	t.Parallel()
	var f, _ = systemTrustCertFake(t)
	f.on("POST", systemTrustCertSetPath+systemTrustCertUuidVpn, 200, answerSaved)

	var r = f.run("/system/trust/certificate", "add", "description=vpn server", "issuer=Lab CA", "common-name=vpn2.example", "replace")
	wantExit(t, r, 0)
	if r.stdout != systemTrustCertUuidVpn+"\n" {
		t.Errorf("want the uuid of the replaced certificate, got %q", r.stdout)
	}
	wantContains(t, "stderr", r.stderr, "in use", "restart")
	var cert = wantOneMutation(t, f, "POST", systemTrustCertSetPath+systemTrustCertUuidVpn).json(t)["cert"].(map[string]any)
	if cert["action"] != "internal" || cert["commonname"] != "vpn2.example" || cert["crt"] != "" || cert["prv"] != "" ||
		cert["csr_payload"] != "" || cert["altnames_dns"] != "" {
		t.Errorf("unexpected replace body %v", cert)
	}
}

// --- set / remove / reissue / import-signed

func TestSystemTrustCertSet(t *testing.T) {
	t.Parallel()
	var f, _ = systemTrustCertFake(t)
	f.on("POST", systemTrustCertSetPath+systemTrustCertUuidWeb, 200, answerSaved)

	var r = f.run("/system/trust/certificate", "set", "web", "description=web 2027")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("set must be silent, got %q", r.stdout)
	}
	// action manual: without it OPNsense would reissue the certificate
	wantJSON(t, wantOneMutation(t, f, "POST", systemTrustCertSetPath+systemTrustCertUuidWeb),
		map[string]any{"cert": map[string]any{"action": "manual", "descr": "web 2027"}})

	wantFailure(t, f.run("/system/trust/certificate", "set", "web"), "description")
	wantFailure(t, f.run("/system/trust/certificate", "set", "nope", "description=x"), "not found")
}

func TestSystemTrustCertRemove(t *testing.T) {
	t.Parallel()
	var f, _ = systemTrustCertFake(t)
	f.on("POST", systemTrustCertDelPath+systemTrustCertUuidOld, 200, answerDeleted)

	wantFailure(t, f.run("/system/trust/certificate", "remove", "vpn server"), "in use")
	wantNoMutations(t, f)

	var r = f.run("/system/trust/certificate", "remove", "old")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("remove must be silent, got %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", systemTrustCertDelPath+systemTrustCertUuidOld)
}

func TestSystemTrustCertRemoveInUseAnswer(t *testing.T) {
	t.Parallel()
	var f, _ = systemTrustCertFake(t)
	f.on("POST", systemTrustCertDelPath+systemTrustCertUuidOld, 500,
		`{"errorMessage":"cron - nightly {cron.jobs.job.c1}\n","errorTitle":"Item in use by"}`)
	wantFailure(t, f.run("/system/trust/certificate", "remove", "old"), "in use by cron - nightly {cron.jobs.job.c1}")
}

func TestSystemTrustCertReissue(t *testing.T) {
	t.Parallel()
	var f, _ = systemTrustCertFake(t)
	f.on("POST", systemTrustCertSetPath+systemTrustCertUuidVpn, 200, answerSaved)

	wantFailure(t, f.run("/system/trust/certificate", "reissue", "vpn server"), "confirm")
	wantFailure(t, f.run("/system/trust/certificate", "reissue", "self", "confirm=yes"), "not issued by a certificate authority")
	wantFailure(t, f.run("/system/trust/certificate", "reissue", "old", "confirm=yes"), "no stored private key")
	wantNoMutations(t, f)

	var r = f.run("/system/trust/certificate", "reissue", "vpn server", "lifetime=30", "confirm=yes")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "restart")
	wantJSON(t, wantOneMutation(t, f, "POST", systemTrustCertSetPath+systemTrustCertUuidVpn),
		map[string]any{"cert": map[string]any{"action": "reissue", "lifetime": "30"}})
}

func TestSystemTrustCertImportSigned(t *testing.T) {
	t.Parallel()
	var f, pems = systemTrustCertFake(t)
	f.on("POST", systemTrustCertSetPath+systemTrustCertUuidPending, 200, answerSaved)
	var dir = t.TempDir()
	var good = filepath.Join(dir, "good.pem")
	var bad = filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(good, []byte(pems.leaf), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte(systemTrustCertGenerate(t).leaf), 0o600); err != nil {
		t.Fatal(err)
	}

	wantFailure(t, f.run("/system/trust/certificate", "import-signed", "pending", "certificate-file="+bad), "does not belong")
	wantFailure(t, f.run("/system/trust/certificate", "import-signed", "web", "certificate-file="+good), "not a pending signing request")
	wantNoMutations(t, f)

	wantExit(t, f.run("/system/trust/certificate", "import-signed", "pending", "certificate-file="+good), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", systemTrustCertSetPath+systemTrustCertUuidPending),
		map[string]any{"cert": map[string]any{"action": "import_csr", "crt_payload": pems.leaf}})
}

// --- export

func TestSystemTrustCertExport(t *testing.T) {
	t.Parallel()
	var f, _ = systemTrustCertFake(t)
	var base = systemTrustCertFilePath + systemTrustCertUuidWeb + "/"
	f.on("POST", base+"crt", 200, `{"status":"ok","descr":"web","payload":"-----BEGIN CERTIFICATE-----\nCRT\n"}`)
	f.on("POST", base+"prv", 200, `{"status":"ok","descr":"web","payload":"-----BEGIN PRIVATE KEY-----\nKEY\n"}`)
	f.on("POST", base+"csr", 200, `{"status":"ok","descr":"web","payload":""}`)
	f.on("POST", base+"pkcs12", 200, `{"status":"ok","descr":"web","payload_b64":"`+base64.StdEncoding.EncodeToString([]byte("P12\x00DATA"))+`"}`)
	var dir = t.TempDir()
	var env = f.env()

	// default file name, then refused overwrite, then overwrite
	var r = runOpnIn(t, dir, env, "/system/trust/certificate", "export", "web")
	wantExit(t, r, 0)
	if content, err := os.ReadFile(filepath.Join(dir, "web_crt.pem")); err != nil || string(content) != "-----BEGIN CERTIFICATE-----\nCRT\n" {
		t.Errorf("web_crt.pem: %q %v", content, err)
	}
	if r.stdout != "" {
		t.Errorf("export to a file prints nothing on stdout, got %q", r.stdout)
	}
	wantFailure(t, runOpnIn(t, dir, env, "/system/trust/certificate", "export", "web"), "already exists", "overwrite")
	wantExit(t, runOpnIn(t, dir, env, "/system/trust/certificate", "export", "web", "overwrite"), 0)

	// keys are written with mode 0600
	if err := os.WriteFile(filepath.Join(dir, "web.key"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	wantExit(t, runOpnIn(t, dir, env, "/system/trust/certificate", "export", "web", "type=key", "file=web.key", "overwrite"), 0)
	if info, err := os.Stat(filepath.Join(dir, "web.key")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode: %v %v", info.Mode(), err)
	}

	// stdout
	r = f.run("/system/trust/certificate", "export", "web", "type=key", "file=-")
	wantExit(t, r, 0)
	if r.stdout != "-----BEGIN PRIVATE KEY-----\nKEY\n" {
		t.Errorf("stdout: %q", r.stdout)
	}

	// pkcs12 with password
	wantExit(t, runOpnIn(t, dir, env, "/system/trust/certificate", "export", "web", "type=pkcs12", "password=s3cret"), 0)
	if content, err := os.ReadFile(filepath.Join(dir, "web_cert.p12")); err != nil || string(content) != "P12\x00DATA" {
		t.Errorf("web_cert.p12: %q %v", content, err)
	}
	var last = f.mutations()[len(f.mutations())-1]
	if last.Path != base+"pkcs12" {
		t.Fatalf("last call %v", last)
	}
	wantJSON(t, last, map[string]any{"password": "s3cret"})

	wantFailure(t, f.run("/system/trust/certificate", "export", "web", "type=csr", "file=-"), "has no signing request")
	var before = len(f.calls())
	wantFailure(t, f.run("/system/trust/certificate", "export", "web", "password=x"), "only used with type=pkcs12")
	wantFailure(t, f.run("/system/trust/certificate", "export", "web", "file=-", "overwrite"), "no effect")
	if len(f.calls()) != before {
		t.Errorf("Check must refuse before any API call: %v", f.calls()[before:])
	}
}

// --- help and completion

func TestSystemTrustCertHelp(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var r = f.run("/system/trust/certificate", "?")
	wantExit(t, r, 0)
	wantContains(t, "help", r.stdout, "print", "show", "add", "set", "remove", "dump", "export", "reissue", "import-signed")
	r = f.run("/system/trust", "?")
	wantExit(t, r, 0)
	wantContains(t, "help", r.stdout, "certificate", "certificates and signing requests")
	wantNoCalls(t, f)
}

func TestSystemTrustCertComplete(t *testing.T) {
	t.Parallel()
	var f, _ = systemTrustCertFake(t)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/system/trust/certificate remove v":           {`"vpn server"`},
		"/system/trust/certificate show s":             {"self"},
		"/system/trust/certificate add issuer=":        {`issuer="Lab CA"`, `issuer="Other CA"`},
		"/system/trust/certificate add method=s":       {"method=self-signed", "method=sign-csr"},
		"/system/trust/certificate export web type=pk": {"type=pkcs12"},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}
