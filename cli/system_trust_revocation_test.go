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
	systemTrustRevocationSearchPath = "/api/trust/crl/search"
	systemTrustRevocationGetPath    = "/api/trust/crl/get/"
	systemTrustRevocationSetPath    = "/api/trust/crl/set/"
	systemTrustRevocationDelPath    = "/api/trust/crl/del/"
	systemTrustRevocationDumpPath   = "/api/trust/crl/raw_dump/"
	systemTrustRevocationOcspPath   = "/api/trust/crl/get_ocsp_info_data/"
	systemTrustRevocationCertPath   = "/api/trust/cert/search"

	// the CAs: corp has an internal list, partner an imported one, lab none
	systemTrustRevocationCorp    = "6ade146cd9e0e"
	systemTrustRevocationPartner = "6ade146cd9e0f"
	systemTrustRevocationLab     = "6ade146cd9e10"
)

// systemTrustRevocationListTime is the last update of the test lists, the internal list is rebuilt on every change
var systemTrustRevocationListTime = time.Date(2026, 10, 25, 14, 39, 6, 0, time.UTC)

// systemTrustRevocationTestCrl returns a revocation list in PEM format signed by a throw-away CA, revoking the serials
// with the reason codes
func systemTrustRevocationTestCrl(t *testing.T, number int64, revoked map[int64]int) string {
	t.Helper()
	var key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var caTemplate = &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: systemTrustRevocationListTime.Add(-time.Hour), NotAfter: systemTrustRevocationListTime.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3}}
	caDer, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDer)
	if err != nil {
		t.Fatal(err)
	}
	var template = &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: systemTrustRevocationListTime,
		NextUpdate: systemTrustRevocationListTime.Add(30 * 24 * time.Hour)}
	for serial, reason := range revoked {
		template.RevokedCertificateEntries = append(template.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber: big.NewInt(serial), RevocationTime: systemTrustRevocationListTime, ReasonCode: reason})
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, ca, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))
}

// systemTrustRevocationCertPem is a certificate with this serial
func systemTrustRevocationCertPem(t *testing.T, serial int64) string {
	t.Helper()
	var key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var template = &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "client"},
		NotBefore: systemTrustRevocationListTime, NotAfter: systemTrustRevocationListTime.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// systemTrustRevocationGetAnswer renders get/<caref> like OPNsense 26.7: certs are [refid, descr], revoked maps refid
// to the reason code, method is internal or existing, descr "" for a CA without list
func systemTrustRevocationGetAnswer(caref string, descr string, method string, text string, certs [][2]string, revoked map[string]string) string {
	var selected = func(value string) string {
		if value == method {
			return "1"
		}
		return "0"
	}
	var crl = map[string]any{
		"caref": caref, "descr": descr, "serial": "2", "lifetime": "30",
		"crlmethod": map[string]any{
			"internal": map[string]string{"value": "Internal", "selected": selected("internal")},
			"existing": map[string]string{"value": "Import existing", "selected": selected("existing")},
		},
	}
	if descr == "" {
		crl["serial"], crl["lifetime"] = "0", "9999"
	} else {
		crl["text"] = text
	}
	for code := 0; code <= 6; code++ {
		var options any = []any{}
		if len(certs) > 0 {
			var list = map[string]any{}
			for _, cert := range certs {
				var flag = "0"
				if revoked[cert[0]] == string(rune('0'+code)) {
					flag = "1"
				}
				list[cert[0]] = map[string]string{"value": cert[1], "selected": flag}
			}
			options = list
		}
		crl["revoked_reason_"+string(rune('0'+code))] = options
	}
	var data, _ = json.Marshal(map[string]any{"crl": crl})
	return string(data)
}

// systemTrustRevocationFake serves three CAs: corp (internal list revoking "laptop" serial 01 with key-compromise),
// partner (an imported list revoking serial 0x7CA97B), lab (no list); corp issued laptop (01), phone (02) and
// "tablet" twice (03, 04)
func systemTrustRevocationFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(systemTrustRevocationSearchPath,
		map[string]any{"descr": "corp", "refid": systemTrustRevocationCorp, "crl_descr": "corp crl"},
		map[string]any{"descr": "partner", "refid": systemTrustRevocationPartner, "crl_descr": "partner crl"},
		map[string]any{"descr": "lab", "refid": systemTrustRevocationLab},
	)
	var corpCerts = [][2]string{{"c00000000001", "laptop"}, {"c00000000002", "phone"}, {"c00000000003", "tablet"}, {"c00000000004", "tablet"}}
	f.on("GET", systemTrustRevocationGetPath+systemTrustRevocationCorp, 200, systemTrustRevocationGetAnswer(systemTrustRevocationCorp, "corp crl", "internal",
		systemTrustRevocationTestCrl(t, 2, map[int64]int{1: 1}), corpCerts, map[string]string{"c00000000001": "1"}))
	f.on("GET", systemTrustRevocationGetPath+systemTrustRevocationPartner, 200, systemTrustRevocationGetAnswer(systemTrustRevocationPartner, "partner crl", "existing",
		systemTrustRevocationTestCrl(t, 7, map[int64]int{0x7ca97b: 4}), nil, nil))
	f.on("GET", systemTrustRevocationGetPath+systemTrustRevocationLab, 200, systemTrustRevocationGetAnswer(systemTrustRevocationLab, "", "internal", "",
		[][2]string{{"l00000000001", "lab box"}}, nil))
	f.on("GET", systemTrustRevocationOcspPath+systemTrustRevocationCorp, 200,
		`{"payload":"R\t261124143837Z\t261020101500Z\t01\tunknown\t\/CN=laptop\nV\t261124143837Z\t\t02\tunknown\t\/CN=phone\n"}`)
	var cert = func(uuid, refid, descr, caref string, serial int64) map[string]any {
		return map[string]any{"uuid": uuid, "refid": refid, "descr": descr, "caref": caref, "commonname": descr,
			"crt_payload": systemTrustRevocationCertPem(t, serial), "prv_payload": "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n"}
	}
	f.search(systemTrustRevocationCertPath,
		cert("u-laptop", "c00000000001", "laptop", systemTrustRevocationCorp, 1),
		cert("u-phone", "c00000000002", "phone", systemTrustRevocationCorp, 2),
		cert("u-tablet1", "c00000000003", "tablet", systemTrustRevocationCorp, 3),
		cert("u-tablet2", "c00000000004", "tablet", systemTrustRevocationCorp, 4),
		cert("u-labbox", "l00000000001", "lab box", systemTrustRevocationLab, 5),
		cert("u-web", "w00000000001", "Web GUI TLS certificate", "", 0x7ca97b),
	)
	f.on("POST", systemTrustRevocationSetPath+systemTrustRevocationCorp, 200, `{"status":"saved"}`)
	f.on("POST", systemTrustRevocationSetPath+systemTrustRevocationPartner, 200, `{"status":"saved"}`)
	f.on("POST", systemTrustRevocationSetPath+systemTrustRevocationLab, 200, `{"status":"saved"}`)
	return f
}

// systemTrustRevocationWantSet asserts exactly one set for caref and returns its crl object
func systemTrustRevocationWantSet(t *testing.T, f *fakeOPN, caref string) map[string]any {
	t.Helper()
	var body, _ = wantOneMutation(t, f, "POST", systemTrustRevocationSetPath+caref).json(t)["crl"].(map[string]any)
	return body
}

// systemTrustRevocationReasons returns the revoked_reason_<n> fields of a set body
func systemTrustRevocationReasonFields(body map[string]any) map[string]any {
	var reasons = map[string]any{}
	for key, value := range body {
		if strings.HasPrefix(key, "revoked_reason_") {
			reasons[key] = value
		}
	}
	return reasons
}

func systemTrustRevocationNoReasons(overrides map[string]any) map[string]any {
	var reasons = map[string]any{}
	for code := 0; code <= 6; code++ {
		reasons["revoked_reason_"+string(rune('0'+code))] = ""
	}
	for key, value := range overrides {
		reasons[key] = value
	}
	return reasons
}

func TestSystemTrustRevocationPrint(t *testing.T) {
	t.Parallel()
	var f = systemTrustRevocationFake(t)
	var r = f.run("/system/trust/revocation", "print")
	wantExit(t, r, 0)
	var rows = systemCronTable(r.stdout)
	var want = [][]string{
		{"#", "CA", "DESCRIPTION", "TYPE", "REVOKED", "LIFETIME", "UPDATED"},
		{"0", "corp", "corp crl", "internal", "1", "30 days", "2026-10-25 14:39:06"},
		{"1", "partner", "partner crl", "imported", "1", "-", "2026-10-25 14:39:06"},
		{"2", "lab", "-", "-", "-", "-", "-"},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("table %q, want %q\n%s", rows, want, r.stdout)
	}
	wantNoMutations(t, f)
	for _, call := range f.calls() {
		if call.Path == systemTrustRevocationGetPath+systemTrustRevocationLab {
			t.Errorf("print fetched the CA without list: %v", call)
		}
	}

	t.Run("search", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		var r = f.run("/system/trust/revocation", "print", "search=PARTNER")
		wantExit(t, r, 0)
		systemCronWantTable(t, r.stdout, want[0], 1, "partner")
	})
	t.Run("json is the raw search rows", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		var r = f.run("/system/trust/revocation", "print", "json")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != 3 || !strings.Contains(lines[0], `"crl_descr":"corp crl"`) || strings.Contains(lines[2], "crl_descr") {
			t.Errorf("json output:\n%s", r.stdout)
		}
	})
	t.Run("detail", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		var r = f.run("/system/trust/revocation", "print", "detail")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "0\n  ca:           corp\n  ca-refid:     "+systemTrustRevocationCorp, "number:       2",
			"next-update:  2026-11-24 14:39:06", "\n2\n  ca:           lab")
	})
	t.Run("the # of a filtered print selects in a script", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		var r = f.runScript("/system/trust/revocation\nprint search=part\nset 0 description=renamed\n")
		wantExit(t, r, 0)
		var body = systemTrustRevocationWantSet(t, f, systemTrustRevocationPartner)
		if body["descr"] != "renamed" || body["crlmethod"] != "existing" || !strings.Contains(body["text"].(string), "BEGIN X509 CRL") {
			t.Errorf("set body %v", body)
		}
	})
}

func TestSystemTrustRevocationShow(t *testing.T) {
	t.Parallel()
	for _, selector := range []string{"corp", "CORP", systemTrustRevocationCorp, "0"} {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()
			var f = systemTrustRevocationFake(t)
			var r = f.run("/system/trust/revocation", "show", selector)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, "ca:           corp\n", "description:  corp crl", "type:         internal",
				"revoked:      1", "lifetime:     30 days", "last-update:  2026-10-25 14:39:06")
			// the date of the OCSP index, not the rebuild time of the list
			var table = systemCronTable(r.stdout[strings.Index(r.stdout, "SERIAL"):])
			if want := [][]string{{"SERIAL", "REASON", "REVOKED", "CERTIFICATE"}, {"01", "key-compromise", "2026-10-20 10:15:00", "laptop"}}; !reflect.DeepEqual(table, want) {
				t.Errorf("revoked table %q, want %q", table, want)
			}
			wantNotContains(t, "stdout", r.stdout, "PRIVATE KEY", "SECRET")
			wantNoMutations(t, f)
		})
	}
	t.Run("imported list: entries of the list without OCSP dates", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		var r = f.run("/system/trust/revocation", "show", "partner")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "type:         imported", "lifetime:     \n", "number:       7",
			"7CA97B  superseded  2026-10-25 14:39:06  -")
		for _, call := range f.calls() {
			if strings.HasPrefix(call.Path, systemTrustRevocationOcspPath) {
				t.Errorf("OCSP index read for an imported list: %v", call)
			}
		}
	})
	t.Run("a CA without list", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		wantFailure(t, f.run("/system/trust/revocation", "show", "lab"), "not found", "add one first")
	})
	t.Run("unknown CA", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		wantFailure(t, f.run("/system/trust/revocation", "show", "nope"), "not found")
	})
}

func TestSystemTrustRevocationAdd(t *testing.T) {
	t.Parallel()
	t.Run("internal with the defaults prints the refid", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		var r = f.run("/system/trust/revocation", "add", "lab")
		wantExit(t, r, 0)
		if strings.TrimSpace(r.stdout) != systemTrustRevocationLab {
			t.Errorf("stdout %q, want the refid", r.stdout)
		}
		var body = systemTrustRevocationWantSet(t, f, systemTrustRevocationLab)
		var want = systemTrustRevocationNoReasons(map[string]any{"descr": "lab", "lifetime": "9999", "crlmethod": "internal"})
		if !reflect.DeepEqual(body, want) {
			t.Errorf("set body %v, want %v", body, want)
		}
	})
	t.Run("import", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		var file = filepath.Join(t.TempDir(), "list.crl")
		var list = systemTrustRevocationTestCrl(t, 1, nil)
		if err := os.WriteFile(file, []byte(list), 0o600); err != nil {
			t.Fatal(err)
		}
		wantExit(t, f.run("/system/trust/revocation", "add", "lab", "method=import", "crl-file="+file, "description=from partner"), 0)
		var body = systemTrustRevocationWantSet(t, f, systemTrustRevocationLab)
		var want = map[string]any{"descr": "from partner", "lifetime": "9999", "crlmethod": "existing", "text": list}
		if !reflect.DeepEqual(body, want) {
			t.Errorf("set body %v, want %v", body, want)
		}
	})
	t.Run("replace an empty list", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		f.on("GET", systemTrustRevocationGetPath+systemTrustRevocationPartner, 200, systemTrustRevocationGetAnswer(systemTrustRevocationPartner, "partner crl", "existing",
			systemTrustRevocationTestCrl(t, 7, nil), nil, nil))
		wantExit(t, f.run("/system/trust/revocation", "add", "partner", "replace", "lifetime=7"), 0)
		var body = systemTrustRevocationWantSet(t, f, systemTrustRevocationPartner)
		if body["crlmethod"] != "internal" || body["lifetime"] != "7" || body["descr"] != "partner" {
			t.Errorf("set body %v", body)
		}
	})
	for name, tc := range map[string]struct {
		args  []string
		wants []string
		calls bool
	}{
		"existing list":                 {[]string{"corp"}, []string{"has a revocation list already"}, true},
		"replace drops revocations":     {[]string{"corp", "replace"}, []string{"revokes 1 certificate", "unrevoke"}, true},
		"crl-file without import":       {[]string{"lab", "crl-file=x.crl"}, []string{"only used with method=import"}, false},
		"import without crl-file":       {[]string{"lab", "method=import"}, []string{"needs crl-file"}, false},
		"missing crl-file":              {[]string{"lab", "method=import", "crl-file=/nonexistent/list.crl"}, []string{"no such file"}, true},
		"lifetime 0":                    {[]string{"lab", "lifetime=0"}, []string{"lifetime"}, false},
		"lifetime text":                 {[]string{"lab", "lifetime=long"}, []string{"lifetime"}, false},
		"unknown method":                {[]string{"lab", "method=external"}, []string{"method"}, false},
		"description with a line break": {[]string{"lab", "description=a\nb"}, []string{"line breaks"}, false},
		"description of 256 characters": {[]string{"lab", "description=" + strings.Repeat("x", 256)}, []string{"255"}, false},
		"unknown CA":                    {[]string{"nope"}, []string{"not found"}, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var f = systemTrustRevocationFake(t)
			wantFailure(t, f.run(append([]string{"/system/trust/revocation", "add"}, tc.args...)...), tc.wants...)
			wantNoMutations(t, f)
			if !tc.calls {
				wantNoCalls(t, f)
			}
		})
	}
	t.Run("not a CRL", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		var file = filepath.Join(t.TempDir(), "cert.pem")
		if err := os.WriteFile(file, []byte(systemTrustRevocationCertPem(t, 9)), 0o600); err != nil {
			t.Fatal(err)
		}
		wantFailure(t, f.run("/system/trust/revocation", "add", "lab", "method=import", "crl-file="+file), "invalid revocation list")
		wantNoMutations(t, f)
	})
	t.Run("validation errors of OPNsense", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		f.on("POST", systemTrustRevocationSetPath+systemTrustRevocationLab, 200, `{"status":"failed","validations":{"crl.caref":"Certificate private key missing"}}`)
		wantFailure(t, f.run("/system/trust/revocation", "add", "lab"), "Certificate private key missing")
	})
}

func TestSystemTrustRevocationSet(t *testing.T) {
	t.Parallel()
	t.Run("keeps the revoked certificates and the other fields", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		var r = f.run("/system/trust/revocation", "set", "corp", "lifetime=90")
		wantExit(t, r, 0)
		if r.stdout != "" {
			t.Errorf("set printed %q", r.stdout)
		}
		var body = systemTrustRevocationWantSet(t, f, systemTrustRevocationCorp)
		var want = systemTrustRevocationNoReasons(map[string]any{"descr": "corp crl", "lifetime": "90", "crlmethod": "internal",
			"revoked_reason_1": "c00000000001"})
		if !reflect.DeepEqual(body, want) {
			t.Errorf("set body %v, want %v", body, want)
		}
	})
	t.Run("imported list to internal starts empty", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		wantExit(t, f.run("/system/trust/revocation", "set", "partner", "method=internal"), 0)
		var body = systemTrustRevocationWantSet(t, f, systemTrustRevocationPartner)
		if body["crlmethod"] != "internal" || body["text"] != nil || !reflect.DeepEqual(systemTrustRevocationReasonFields(body), systemTrustRevocationNoReasons(nil)) {
			t.Errorf("set body %v", body)
		}
	})
	for name, tc := range map[string]struct {
		args  []string
		wants []string
	}{
		"internal to import needs a file": {[]string{"corp", "method=import"}, []string{"needs crl-file"}},
		"crl-file on an internal list":    {[]string{"corp", "crl-file=/tmp/x"}, []string{"only used with method=import"}},
		"no list":                         {[]string{"lab", "lifetime=5"}, []string{"not found", "add one first"}},
		"empty description":               {[]string{"corp", "description="}, []string{"must not be empty"}},
		"nothing to change":               {[]string{"corp"}, []string{"set: nothing to change"}},
		"lifetime not a number":           {[]string{"corp", "lifetime=long"}, []string{"lifetime must be a number"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var f = systemTrustRevocationFake(t)
			wantFailure(t, f.run(append([]string{"/system/trust/revocation", "set"}, tc.args...)...), tc.wants...)
			wantNoMutations(t, f)
		})
	}
}

func TestSystemTrustRevocationRevoke(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		args []string
		want map[string]any
	}{
		"by description, default reason": {[]string{"phone"},
			map[string]any{"revoked_reason_0": "c00000000002", "revoked_reason_1": "c00000000001"}},
		"by serial with reason": {[]string{"certificate=0x02", "reason=certificate-hold"},
			map[string]any{"revoked_reason_6": "c00000000002", "revoked_reason_1": "c00000000001"}},
		"several by refid, uuid and serial": {[]string{"certificate=c00000000003,u-phone,04", "reason=superseded"},
			map[string]any{"revoked_reason_4": "c00000000002,c00000000003,c00000000004", "revoked_reason_1": "c00000000001"}},
		"changes the reason of a revoked certificate": {[]string{"laptop", "reason=ca-compromise"},
			map[string]any{"revoked_reason_2": "c00000000001"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var f = systemTrustRevocationFake(t)
			var args = append([]string{"/system/trust/revocation", "revoke", "item=corp"}, tc.args...)
			if !strings.Contains(tc.args[0], "=") {
				args = append([]string{"/system/trust/revocation", "revoke", "corp", "certificate=" + tc.args[0]}, tc.args[1:]...)
			}
			var r = f.run(args...)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("revoke printed %q", r.stdout)
			}
			var body = systemTrustRevocationWantSet(t, f, systemTrustRevocationCorp)
			if got := systemTrustRevocationReasonFields(body); !reflect.DeepEqual(got, systemTrustRevocationNoReasons(tc.want)) {
				t.Errorf("reasons %v, want %v", got, systemTrustRevocationNoReasons(tc.want))
			}
			if body["descr"] != "corp crl" || body["lifetime"] != "30" || body["crlmethod"] != "internal" {
				t.Errorf("set body %v", body)
			}
		})
	}
	for name, tc := range map[string]struct {
		args  []string
		wants []string
	}{
		"ambiguous description":  {[]string{"corp", "certificate=tablet"}, []string{"matches 2 certificates", "c00000000003", "c00000000004"}},
		"certificate of another": {[]string{"corp", "certificate=lab box"}, []string{"not found"}},
		"not issued by a CA":     {[]string{"corp", "certificate=7CA97B"}, []string{"not found"}},
		"imported list":          {[]string{"partner", "certificate=laptop"}, []string{"imported", "method=internal"}},
		"no list":                {[]string{"lab", "certificate=lab box"}, []string{"add one first"}},
		"unknown reason":         {[]string{"corp", "certificate=phone", "reason=lost"}, []string{"reason"}},
		"no certificate":         {[]string{"corp"}, []string{"certificate"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var f = systemTrustRevocationFake(t)
			wantFailure(t, f.run(append([]string{"/system/trust/revocation", "revoke"}, tc.args...)...), tc.wants...)
			wantNoMutations(t, f)
		})
	}
}

func TestSystemTrustRevocationUnrevoke(t *testing.T) {
	t.Parallel()
	var f = systemTrustRevocationFake(t)
	wantExit(t, f.run("/system/trust/revocation", "unrevoke", "corp", "certificate=01"), 0)
	if got := systemTrustRevocationReasonFields(systemTrustRevocationWantSet(t, f, systemTrustRevocationCorp)); !reflect.DeepEqual(got, systemTrustRevocationNoReasons(nil)) {
		t.Errorf("reasons %v", got)
	}

	t.Run("not on the list", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		wantFailure(t, f.run("/system/trust/revocation", "unrevoke", "corp", "certificate=phone"), "not found")
		wantNoMutations(t, f)
	})
}

func TestSystemTrustRevocationRemove(t *testing.T) {
	t.Parallel()
	t.Run("needs confirmation", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		wantFailure(t, f.run("/system/trust/revocation", "remove", "corp"), "no longer reported as revoked", "confirm=yes")
		wantNoCalls(t, f)
	})
	t.Run("with confirm", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		f.on("POST", systemTrustRevocationDelPath+systemTrustRevocationCorp, 200, `{"status":"deleted"}`)
		var r = f.run("/system/trust/revocation", "remove", "corp", "confirm=yes")
		wantExit(t, r, 0)
		if r.stdout != "" {
			t.Errorf("remove printed %q", r.stdout)
		}
		if call := wantOneMutation(t, f, "POST", systemTrustRevocationDelPath+systemTrustRevocationCorp); call.Body != "" {
			t.Errorf("del body %q", call.Body)
		}
	})
	t.Run("no list", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		f.on("POST", systemTrustRevocationDelPath+systemTrustRevocationLab, 200, `{"status":"not found"}`)
		wantFailure(t, f.run("/system/trust/revocation", "remove", "lab", "confirm=yes"), "not found", "add one first")
	})
}

func TestSystemTrustRevocationDump(t *testing.T) {
	t.Parallel()
	var f = systemTrustRevocationFake(t)
	f.on("GET", systemTrustRevocationDumpPath+systemTrustRevocationCorp, 200, `{"exit_status":"0","stderr":"","stdout":"SHA2-256 Fingerprint=DD:85\nCertificate Revocation List (CRL):\n"}`)
	f.on("GET", systemTrustRevocationDumpPath+systemTrustRevocationLab, 200, `[]`)
	var r = f.run("/system/trust/revocation", "dump", "corp")
	wantExit(t, r, 0)
	if r.stdout != "SHA2-256 Fingerprint=DD:85\nCertificate Revocation List (CRL):\n" {
		t.Errorf("dump %q", r.stdout)
	}
	wantFailure(t, f.run("/system/trust/revocation", "dump", "lab"), "not found", "add one first")
	wantNoMutations(t, f)
}

func TestSystemTrustRevocationExport(t *testing.T) {
	t.Parallel()
	t.Run("stdout", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		var r = f.run("/system/trust/revocation", "export", "corp", "file=-")
		wantExit(t, r, 0)
		if !strings.HasPrefix(r.stdout, "-----BEGIN X509 CRL-----\n") || !strings.HasSuffix(r.stdout, "-----END X509 CRL-----\n") {
			t.Errorf("export %q", r.stdout)
		}
	})
	t.Run("file named after the list, no overwrite", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		var dir = t.TempDir()
		var r = runOpnIn(t, dir, f.env(), "/system/trust/revocation", "export", "corp")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "saved corp_crl.crl")
		var data, err = os.ReadFile(filepath.Join(dir, "corp_crl.crl"))
		if err != nil || !strings.HasPrefix(string(data), "-----BEGIN X509 CRL-----") {
			t.Errorf("exported file %q %v", data, err)
		}
		wantFailure(t, runOpnIn(t, dir, f.env(), "/system/trust/revocation", "export", "corp"), "already exists", "overwrite")
		wantExit(t, runOpnIn(t, dir, f.env(), "/system/trust/revocation", "export", "corp", "overwrite"), 0)
		wantNoMutations(t, f)
	})
	t.Run("file=", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		var file = filepath.Join(t.TempDir(), "partner.pem")
		wantExit(t, f.run("/system/trust/revocation", "export", "partner", "file="+file), 0)
		if data, err := os.ReadFile(file); err != nil || !strings.Contains(string(data), "BEGIN X509 CRL") {
			t.Errorf("exported file %q %v", data, err)
		}
	})
	t.Run("overwrite with stdout", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		wantFailure(t, f.run("/system/trust/revocation", "export", "corp", "file=-", "overwrite"), "no effect")
		wantNoCalls(t, f)
	})
	t.Run("no list", func(t *testing.T) {
		t.Parallel()
		var f = systemTrustRevocationFake(t)
		wantFailure(t, f.run("/system/trust/revocation", "export", "lab", "file=-"), "add one first")
	})
}

func TestSystemTrustRevocationComplete(t *testing.T) {
	t.Parallel()
	var f = systemTrustRevocationFake(t)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/system/trust/revocation remove p":                  {"partner"},
		"/system/trust/revocation show l":                    {"lab"},
		"/system/trust/revocation revoke corp certificate=p": {"certificate=phone"},
		"/system/trust/revocation revoke corp reason=key":    {"reason=key-compromise"},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}
