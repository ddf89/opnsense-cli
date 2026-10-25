package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// crlTestPem is an internal list as OPNsense 26.7 (phpseclib) builds it: CRL number 1, serial 01 revoked with
// keyCompromise on 2026-10-25 14:38:51 UTC, next update 30 days later
const crlTestPem = `-----BEGIN X509 CRL-----
MIIBzDCBtQIBATANBgkqhkiG9w0BAQsFADAuMQswCQYDVQQGEwJOTDEfMB0GA1UE
AwwWYTgtc3lzLWNybHByb2JlNjc3Mi1jYRcNMjYxMDI1MTQzODUxWhcNMjYxMTI0
MTQzODUxWjAiMCACAQEXDTI2MTAyNTE0Mzg1MVowDDAKBgNVHRUEAwoBAaAvMC0w
CgYDVR0UBAMCAQEwHwYDVR0jBBgwFoAURtqfwiMmnruYZsVjFcRAAfbFGHIwDQYJ
KoZIhvcNAQELBQADggEBAE3kPt+hav9pIQQinW0k2bU4QdLzuGFO9R5RQzatci9J
XZLuDl0UFpz35bQJPaFuTLpQJCVDJWEVBzerW1CDwD7zZs1b0O0nDRF1UtdTEDRa
tsRuAdKqsydDKhEcePwcDhEplDKgQdbJLSUB6WyQsUoxGx3sjG+Z9OC/IjIdFKZg
mQ72ehKEsk49JXk+5SqRfL1U41AjzRjXkaeM5kRszh0yXQXCNsFlrKcX/JOqp7Xm
SWw30G3BI11z0dxX7E4ipqV8lDDcTVF4GSPaTzwTRl6AvvMb+1mzuGHr+Mg2XTzm
nC4NgiEfgZlexdsR0s5B9qHxyi1pYDc8FPIIOlAlJp4=
-----END X509 CRL-----
`

// crlTestOptions renders a revoked_reason_<code> option list of get: every certificate, selected when revoked
// with this reason. An empty list is [] like PHP sends it
func crlTestOptions(code string, certs [][2]string, revoked map[string]string) any {
	if len(certs) == 0 {
		return []any{}
	}
	var options = map[string]any{}
	for _, cert := range certs {
		var selected = "0"
		if revoked[cert[0]] == code {
			selected = "1"
		}
		options[cert[0]] = map[string]string{"value": cert[1], "selected": selected}
	}
	return options
}

// crlTestGet renders get/<caref> like OPNsense 26.7: certs are [refid, descr], revoked maps refid to reason code
func crlTestGet(caref string, descr string, method string, text string, certs [][2]string, revoked map[string]string) string {
	var selected = func(m string) string {
		if m == method {
			return "1"
		}
		return "0"
	}
	var crl = map[string]any{
		"caref": caref, "descr": descr, "serial": "3", "lifetime": "30",
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
	for _, reason := range CrlReasons {
		crl["revoked_reason_"+reason.Code] = crlTestOptions(reason.Code, certs, revoked)
	}
	var data, _ = json.Marshal(map[string]any{"crl": crl})
	return string(data)
}

var crlTestCerts = [][2]string{{"aaa0000000001", "client one"}, {"aaa0000000002", "client two"}, {"aaa0000000003", "deleted cert"}}

type crlTestRequest struct {
	Method string
	Path   string
	Body   string
}

// crlTestServer answers "METHOD /path" with the canned responses (404 otherwise) and records the requests
func crlTestServer(t *testing.T, responses map[string]string) (*TrustApi, func() []crlTestRequest) {
	t.Helper()
	var mu sync.Mutex
	var requests []crlTestRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, crlTestRequest{Method: r.Method, Path: r.URL.Path, Body: string(body)})
		mu.Unlock()
		var response, ok = responses[r.Method+" "+r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errorMessage":"Endpoint not found"}`)
			return
		}
		_, _ = io.WriteString(w, response)
	}))
	t.Cleanup(server.Close)
	var serverUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	var api = &TrustApi{OPNsense: &coreapi.OPNsense{BaseUrl: *serverUrl, ApiKey: "key", ApiSecret: "secret"}}
	return api, func() []crlTestRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]crlTestRequest(nil), requests...)
	}
}

func crlTestPosts(requests []crlTestRequest) []crlTestRequest {
	var posts []crlTestRequest
	for _, request := range requests {
		if request.Method != "GET" {
			posts = append(posts, request)
		}
	}
	return posts
}

// crlTestSetBody decodes the body of a set request
func crlTestSetBody(t *testing.T, request crlTestRequest) map[string]string {
	t.Helper()
	var body map[string]map[string]string
	if err := json.Unmarshal([]byte(request.Body), &body); err != nil {
		t.Fatalf("set body %q: %v", request.Body, err)
	}
	return body["crl"]
}

const (
	crlTestCa       = "ca00000000001"
	crlTestGetPath  = "GET /api/trust/crl/get/" + crlTestCa
	crlTestSetPath  = "POST /api/trust/crl/set/" + crlTestCa
	crlTestSaved    = `{"status":"saved"}`
	crlTestNotFound = `{"caref":"","descr":""}`
)

func TestCrlList(t *testing.T) {
	var api, _ = crlTestServer(t, map[string]string{
		"GET /api/trust/crl/search": `{"total":2,"rowCount":2,"current":1,"rows":[{"descr":"ca one","refid":"ca1"},{"descr":"ca two","refid":"ca2","crl_descr":"crl two"}]}`,
	})
	var authorities, err = api.CrlList()
	if err != nil {
		t.Fatal(err)
	}
	if len(authorities) != 2 || authorities[0].HasCrl() || !authorities[1].HasCrl() || *authorities[1].CrlDescr != "crl two" || authorities[1].Refid != "ca2" {
		t.Errorf("unexpected authorities %+v", authorities)
	}
}

func TestCrlGet(t *testing.T) {
	var api, _ = crlTestServer(t, map[string]string{
		crlTestGetPath: crlTestGet(crlTestCa, "my crl", "internal", crlTestPem, crlTestCerts,
			map[string]string{"aaa0000000002": "4", "aaa0000000003": "0"}),
		"GET /api/trust/crl/get/nocrl0000000": crlTestGet("nocrl0000000", "", "internal", "", nil, nil),
		"GET /api/trust/crl/get/unknown":      crlTestNotFound,
	})

	var crl, err = api.CrlGet(crlTestCa)
	if err != nil {
		t.Fatal(err)
	}
	if !crl.Exists() || crl.Imported() || crl.Descr != "my crl" || crl.Serial != "3" || crl.Lifetime != "30" || crl.Text != crlTestPem {
		t.Errorf("unexpected crl %+v", crl)
	}
	var want = []CrlCertificateRef{{"aaa0000000001", "client one", ""}, {"aaa0000000002", "client two", "4"}, {"aaa0000000003", "deleted cert", "0"}}
	if !reflect.DeepEqual(crl.Certificates, want) {
		t.Errorf("certificates %+v, want %+v", crl.Certificates, want)
	}
	if revoked := crl.Revoked(); len(revoked) != 2 || revoked[0].Refid != "aaa0000000002" {
		t.Errorf("revoked %+v", revoked)
	}

	crl, err = api.CrlGet("nocrl0000000")
	if err != nil {
		t.Fatal(err)
	}
	if crl.Exists() || crl.Method != CrlMethodInternal || len(crl.Certificates) != 0 {
		t.Errorf("a CA without list: %+v", crl)
	}

	if _, err = api.CrlGet("unknown"); !coreapi.IsNotFound(err) {
		t.Errorf("unknown CA: want *NotFoundError, got %v", err)
	}
	if _, err = api.CrlGet("../x/y"); err == nil {
		t.Errorf("a caref with / must be refused")
	}
}

func TestCrlParsePhpseclibList(t *testing.T) {
	var list, err = CrlParse(crlTestPem)
	if err != nil {
		t.Fatal(err)
	}
	if list.Number.Int64() != 1 || !list.ThisUpdate.Equal(time.Date(2026, 10, 25, 14, 38, 51, 0, time.UTC)) ||
		!list.NextUpdate.Equal(time.Date(2026, 11, 24, 14, 38, 51, 0, time.UTC)) {
		t.Errorf("unexpected list number %v this %v next %v", list.Number, list.ThisUpdate, list.NextUpdate)
	}
	if len(list.RevokedCertificateEntries) != 1 {
		t.Fatalf("entries %+v", list.RevokedCertificateEntries)
	}
	var entry = list.RevokedCertificateEntries[0]
	if CrlSerialHex(entry.SerialNumber) != "01" || entry.ReasonCode != 1 {
		t.Errorf("unexpected entry serial %v reason %d", entry.SerialNumber, entry.ReasonCode)
	}

	for _, bad := range []string{"", "junk", "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n"} {
		if _, err := CrlParse(bad); err == nil {
			t.Errorf("CrlParse(%q) accepted", bad)
		}
	}
}

func TestCrlSerial(t *testing.T) {
	for _, tc := range []struct {
		serial int64
		hex    string
	}{{1, "01"}, {255, "FF"}, {256, "0100"}, {0x7ca97b, "7CA97B"}} {
		if got := CrlSerialHex(big.NewInt(tc.serial)); got != tc.hex {
			t.Errorf("CrlSerialHex(%d) = %q, want %q", tc.serial, got, tc.hex)
		}
	}
	for text, want := range map[string]int64{"01": 1, "0x1": 1, "7c:a9:7b": 0x7ca97b, " FF ": 255, "0X10": 16} {
		if got, ok := CrlParseSerial(text); !ok || got.Int64() != want {
			t.Errorf("CrlParseSerial(%q) = %v %v, want %d", text, got, ok, want)
		}
	}
	for _, bad := range []string{"", "0x", "xyz", "-1", "client one"} {
		if _, ok := CrlParseSerial(bad); ok {
			t.Errorf("CrlParseSerial(%q) accepted", bad)
		}
	}
}

func TestCrlRevokeKeepsTheOthers(t *testing.T) {
	var api, requests = crlTestServer(t, map[string]string{
		crlTestGetPath: crlTestGet(crlTestCa, "my crl", "internal", crlTestPem, crlTestCerts, map[string]string{"aaa0000000003": "0"}),
		crlTestSetPath: crlTestSaved,
	})
	if err := api.CrlRevoke(crlTestCa, "1", "aaa0000000001", "aaa0000000002"); err != nil {
		t.Fatal(err)
	}
	var posts = crlTestPosts(requests())
	if len(posts) != 1 {
		t.Fatalf("want one set, got %+v", posts)
	}
	var want = map[string]string{
		"descr": "my crl", "lifetime": "30", "crlmethod": "internal",
		"revoked_reason_0": "aaa0000000003", "revoked_reason_1": "aaa0000000001,aaa0000000002",
		"revoked_reason_2": "", "revoked_reason_3": "", "revoked_reason_4": "", "revoked_reason_5": "", "revoked_reason_6": "",
	}
	if got := crlTestSetBody(t, posts[0]); !reflect.DeepEqual(got, want) {
		t.Errorf("set body %v, want %v", got, want)
	}
}

func TestCrlRevokeErrors(t *testing.T) {
	var api, requests = crlTestServer(t, map[string]string{
		crlTestGetPath:                        crlTestGet(crlTestCa, "my crl", "internal", crlTestPem, crlTestCerts, nil),
		"GET /api/trust/crl/get/imported0000": crlTestGet("imported0000", "imported", "existing", crlTestPem, crlTestCerts, nil),
		"GET /api/trust/crl/get/nocrl0000000": crlTestGet("nocrl0000000", "", "internal", "", crlTestCerts, nil),
		"GET /api/trust/crl/get/unknown":      crlTestNotFound,
		crlTestSetPath:                        crlTestSaved,
	})
	if err := api.CrlRevoke(crlTestCa, "1", "other0000001"); !coreapi.IsNotFound(err) {
		t.Errorf("a certificate of another CA: want *NotFoundError, got %v", err)
	}
	if err := api.CrlRevoke(crlTestCa, "7", "aaa0000000001"); err == nil {
		t.Errorf("reason 7 accepted")
	}
	if err := api.CrlRevoke(crlTestCa, "1"); err == nil {
		t.Errorf("no certificate accepted")
	}
	if err := api.CrlRevoke("imported0000", "1", "aaa0000000001"); err == nil || !strings.Contains(err.Error(), "imported") {
		t.Errorf("imported list: %v", err)
	}
	if err := api.CrlRevoke("nocrl0000000", "1", "aaa0000000001"); !coreapi.IsNotFound(err) {
		t.Errorf("no list: want *NotFoundError, got %v", err)
	}
	if err := api.CrlRevoke("unknown", "1", "aaa0000000001"); !coreapi.IsNotFound(err) {
		t.Errorf("unknown CA: want *NotFoundError, got %v", err)
	}
	if err := api.CrlUnrevoke(crlTestCa, "aaa0000000001"); !coreapi.IsNotFound(err) {
		t.Errorf("unrevoke of a certificate not on the list: want *NotFoundError, got %v", err)
	}
	if posts := crlTestPosts(requests()); len(posts) != 0 {
		t.Errorf("want no set, got %+v", posts)
	}
}

func TestCrlUnrevoke(t *testing.T) {
	var api, requests = crlTestServer(t, map[string]string{
		crlTestGetPath: crlTestGet(crlTestCa, "my crl", "internal", crlTestPem, crlTestCerts,
			map[string]string{"aaa0000000001": "1", "aaa0000000002": "1"}),
		crlTestSetPath: crlTestSaved,
	})
	if err := api.CrlUnrevoke(crlTestCa, "aaa0000000001"); err != nil {
		t.Fatal(err)
	}
	var posts = crlTestPosts(requests())
	if len(posts) != 1 {
		t.Fatalf("want one set, got %+v", posts)
	}
	if body := crlTestSetBody(t, posts[0]); body["revoked_reason_1"] != "aaa0000000002" || body["revoked_reason_0"] != "" {
		t.Errorf("set body %v", body)
	}
}

func TestCrlSet(t *testing.T) {
	var api, requests = crlTestServer(t, map[string]string{
		crlTestGetPath:                   crlTestGet(crlTestCa, "", "internal", "", crlTestCerts, nil),
		crlTestSetPath:                   crlTestSaved,
		"GET /api/trust/crl/get/broken":  crlTestGet("broken", "", "internal", "", nil, nil),
		"POST /api/trust/crl/set/broken": `{"status":"failed","validations":{"crl.caref":"Certificate private key missing"}}`,
		"GET /api/trust/crl/get/unknown": crlTestNotFound,
	})

	if err := api.CrlSet(crlTestCa, CrlSettings{Descr: "new", Method: CrlMethodInternal}); err != nil {
		t.Fatal(err)
	}
	if err := api.CrlImport(crlTestCa, "imported", crlTestPem); err != nil {
		t.Fatal(err)
	}
	var posts = crlTestPosts(requests())
	if len(posts) != 2 {
		t.Fatalf("want two sets, got %+v", posts)
	}
	if body := crlTestSetBody(t, posts[0]); body["lifetime"] != CrlDefaultLifetime || body["descr"] != "new" || body["crlmethod"] != "internal" ||
		body["revoked_reason_6"] != "" || len(body) != 10 {
		t.Errorf("internal set body %v", body)
	}
	if body := crlTestSetBody(t, posts[1]); body["crlmethod"] != "existing" || body["text"] != crlTestPem || body["descr"] != "imported" ||
		len(body) != 4 {
		t.Errorf("import set body %v", body)
	}

	var validation *coreapi.ValidationError
	if err := api.CrlSet("broken", CrlSettings{Descr: "x", Method: CrlMethodInternal}); !errors.As(err, &validation) ||
		validation.Validations["crl.caref"] != "Certificate private key missing" {
		t.Errorf("want the validation error, got %v", err)
	}

	for name, settings := range map[string]CrlSettings{
		"empty description":      {Method: CrlMethodInternal},
		"newline in description": {Descr: "a\nb", Method: CrlMethodInternal},
		"long description":       {Descr: strings.Repeat("x", 256), Method: CrlMethodInternal},
		"lifetime 0":             {Descr: "x", Lifetime: "0", Method: CrlMethodInternal},
		"lifetime abc":           {Descr: "x", Lifetime: "abc", Method: CrlMethodInternal},
		"unknown method":         {Descr: "x", Method: "bogus"},
		"import without text":    {Descr: "x", Method: CrlMethodImport},
		"import junk":            {Descr: "x", Method: CrlMethodImport, Text: "junk"},
		"import with revoked":    {Descr: "x", Method: CrlMethodImport, Text: crlTestPem, Revoked: map[string]string{"aaa0000000001": "0"}},
		"internal with text":     {Descr: "x", Method: CrlMethodInternal, Text: crlTestPem},
		"cert of another CA":     {Descr: "x", Method: CrlMethodInternal, Revoked: map[string]string{"other": "0"}},
	} {
		var before = len(crlTestPosts(requests()))
		if err := api.CrlSet(crlTestCa, settings); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if len(crlTestPosts(requests())) != before {
			t.Errorf("%s: a set was sent", name)
		}
	}

	// OPNsense stores an imported list for any caref, the library checks the CA first
	if err := api.CrlImport("unknown", "x", crlTestPem); !coreapi.IsNotFound(err) {
		t.Errorf("import for an unknown CA: want *NotFoundError, got %v", err)
	}
}

func TestCrlRemove(t *testing.T) {
	var api, requests = crlTestServer(t, map[string]string{
		"POST /api/trust/crl/del/" + crlTestCa: `{"status":"deleted"}`,
		"POST /api/trust/crl/del/none":         `{"status":"not found"}`,
	})
	if err := api.CrlRemove(crlTestCa); err != nil {
		t.Fatal(err)
	}
	if err := api.CrlRemove("none"); !coreapi.IsNotFound(err) {
		t.Errorf("want *NotFoundError, got %v", err)
	}
	if got := requests(); len(got) != 2 || got[0].Body != "" {
		t.Errorf("requests %+v", got)
	}
}

func TestCrlDumpAndExport(t *testing.T) {
	var api, _ = crlTestServer(t, map[string]string{
		"GET /api/trust/crl/raw_dump/" + crlTestCa: `{"exit_status":"0","stderr":"","stdout":"Certificate Revocation List (CRL):\n"}`,
		"GET /api/trust/crl/raw_dump/none":         `[]`,
		"GET /api/trust/crl/raw_dump/bad":          `{"exit_status":1,"stderr":"unable to load CRL\n","stdout":""}`,
		crlTestGetPath:                             crlTestGet(crlTestCa, "my crl", "internal", crlTestPem, nil, nil),
		"GET /api/trust/crl/get/none":              crlTestGet("none", "", "internal", "", nil, nil),
	})
	if dump, err := api.CrlDump(crlTestCa); err != nil || dump != "Certificate Revocation List (CRL):\n" {
		t.Errorf("dump %q %v", dump, err)
	}
	if _, err := api.CrlDump("none"); !coreapi.IsNotFound(err) {
		t.Errorf("dump without list: want *NotFoundError, got %v", err)
	}
	if _, err := api.CrlDump("bad"); err == nil || !strings.Contains(err.Error(), "unable to load CRL") {
		t.Errorf("dump with openssl error: %v", err)
	}
	if pem, err := api.CrlExport(crlTestCa); err != nil || pem != crlTestPem {
		t.Errorf("export %q %v", pem, err)
	}
	if _, err := api.CrlExport("none"); !coreapi.IsNotFound(err) {
		t.Errorf("export without list: want *NotFoundError, got %v", err)
	}
}

func TestCrlRevocationTimes(t *testing.T) {
	var api, _ = crlTestServer(t, map[string]string{
		"GET /api/trust/crl/get_ocsp_info_data/" + crlTestCa: `{"payload":"R\t261124143837Z\t261025143851Z\t01\tunknown\t\/CN=c1\n` +
			`V\t261124143837Z\t\t02\tunknown\t\/CN=c2\nR\t261124143837Z\t261025143906Z,keyCompromise\t7CA97B\tunknown\t\/CN=c3\n"}`,
	})
	var times, err = api.CrlRevocationTimes(crlTestCa)
	if err != nil {
		t.Fatal(err)
	}
	var want = map[string]time.Time{
		"01":     time.Date(2026, 10, 25, 14, 38, 51, 0, time.UTC),
		"7CA97B": time.Date(2026, 10, 25, 14, 39, 6, 0, time.UTC),
	}
	if !reflect.DeepEqual(times, want) {
		t.Errorf("times %v, want %v", times, want)
	}
}

// crlTestCertificatePem returns a self-signed certificate with this serial
func crlTestCertificatePem(t *testing.T, serial int64) string {
	t.Helper()
	var key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var template = &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCrlCertificates(t *testing.T) {
	var rows = []map[string]string{
		{"uuid": "u1", "refid": "r1", "descr": "one", "caref": crlTestCa, "commonname": "one.example", "crt_payload": crlTestCertificatePem(t, 0x7ca97b),
			"prv_payload": "-----BEGIN PRIVATE KEY-----"},
		{"uuid": "u2", "refid": "r2", "descr": "other ca", "caref": "other", "crt_payload": crlTestCertificatePem(t, 2)},
		{"uuid": "u3", "refid": "r3", "descr": "broken", "caref": crlTestCa, "crt_payload": "junk"},
	}
	var answer, _ = json.Marshal(map[string]any{"rows": rows})
	var api, _ = crlTestServer(t, map[string]string{"GET /api/trust/cert/search": string(answer)})

	var certificates, err = api.CrlCertificates(crlTestCa)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 2 || certificates[0].Refid != "r1" || CrlSerialHex(certificates[0].Serial) != "7CA97B" ||
		certificates[0].CommonName != "one.example" || certificates[0].Uuid != "u1" || certificates[1].Serial != nil {
		t.Errorf("unexpected certificates %+v", certificates)
	}
	all, err := api.CrlCertificates("")
	if err != nil || len(all) != 3 {
		t.Errorf("all certificates: %d %v", len(all), err)
	}
}

func TestCrlReasonName(t *testing.T) {
	if CrlReasonName("1") != "keyCompromise" || CrlReasonName("6") != "certificateHold" || CrlReasonName("9") != "9" {
		t.Errorf("unexpected reason names")
	}
}
