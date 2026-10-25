package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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

// certTestServer is a fake OPNsense answering "METHOD /path" with canned bodies and recording the requests
type certTestServer struct {
	t        *testing.T
	mu       sync.Mutex
	answers  map[string]certTestAnswer
	requests []certTestRequest
}

type certTestAnswer struct {
	status int
	body   string
}

type certTestRequest struct {
	method string
	path   string
	body   string
}

func (r certTestRequest) json(t *testing.T) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(r.body), &decoded); err != nil {
		t.Fatalf("body of %s %s is not JSON: %v: %q", r.method, r.path, err, r.body)
	}
	return decoded
}

func certTestApi(t *testing.T) (*TrustApi, *certTestServer) {
	t.Helper()
	var fake = &certTestServer{t: t, answers: map[string]certTestAnswer{}}
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		fake.mu.Lock()
		fake.requests = append(fake.requests, certTestRequest{method: r.Method, path: r.URL.Path, body: string(body)})
		var answer, ok = fake.answers[r.Method+" "+r.URL.Path]
		fake.mu.Unlock()
		if !ok {
			return // empty 200 like OPNsense for unknown endpoints
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(answer.status)
		_, _ = io.WriteString(w, answer.body)
	}))
	t.Cleanup(server.Close)
	var serverUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &TrustApi{OPNsense: &coreapi.OPNsense{BaseUrl: *serverUrl, ApiKey: "key", ApiSecret: "secret"}}, fake
}

func (f *certTestServer) on(method string, path string, status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[method+" "+path] = certTestAnswer{status: status, body: body}
}

// mutations returns the non GET requests
func (f *certTestServer) mutations() []certTestRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var result []certTestRequest
	for _, request := range f.requests {
		if request.method != "GET" {
			result = append(result, request)
		}
	}
	return result
}

func (f *certTestServer) oneMutation(path string) certTestRequest {
	f.t.Helper()
	var mutations = f.mutations()
	if len(mutations) != 1 || mutations[0].method != "POST" || mutations[0].path != path {
		f.t.Fatalf("want exactly one POST %s, got %+v", path, mutations)
	}
	return mutations[0]
}

func (f *certTestServer) noMutations() {
	f.t.Helper()
	if mutations := f.mutations(); len(mutations) != 0 {
		f.t.Errorf("want no mutations, got %+v", mutations)
	}
}

// --- test material generated at run time

type certTestPair struct {
	certPEM string
	keyPEM  string
	csrPEM  string // a request for the same key
}

func certTestGenerate(t *testing.T, commonName string) certTestPair {
	t.Helper()
	var key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var template = &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{commonName},
	}
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
	return certTestPair{
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		keyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer})),
		csrPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDer})),
	}
}

// certTestRow returns a 26.7 shaped search row
func certTestRow(uuid string, descr string, overrides map[string]any) map[string]any {
	var row = map[string]any{
		"uuid": uuid, "refid": "6ade143944723", "descr": descr, "caref": "6ade14316965d", "%caref": "test ca",
		"crt": "Y3J0", "csr": "", "prv": "cHJpdmF0ZQ==", "action": "reissue", "%action": "Reissue",
		"key_type": "2048", "%key_type": "RSA-2048", "digest": "sha256", "cert_type": "server_cert",
		"lifetime": "397", "private_key_location": "firewall", "city": "", "state": "", "organization": "",
		"organizationalunit": "", "country": "NL", "email": "", "commonname": "srv.example", "ocsp_uri": "",
		"altnames_dns": "srv.example\nwww.example", "altnames_ip": "10.0.0.1", "altnames_uri": "", "altnames_email": "",
		"crt_payload": "-----BEGIN CERTIFICATE-----\n", "csr_payload": "", "prv_payload": "-----BEGIN PRIVATE KEY-----\nsecret\n",
		"rfc3280_purpose": "id-kp-serverAuth", "in_use": "0", "is_user": "0", "name": "/C=NL/CN=srv.example",
		"valid_from": "1792939065", "valid_to": "1794667065",
	}
	for key, value := range overrides {
		row[key] = value
	}
	return row
}

func certTestSearch(rows ...map[string]any) string {
	var encoded, _ = json.Marshal(map[string]any{"rows": rows, "rowCount": len(rows), "total": len(rows), "current": 1})
	return string(encoded)
}

const (
	certTestUuid1 = "11111111-2222-3333-4444-555555555555"
	certTestUuid2 = "22222222-2222-3333-4444-555555555555"
	certTestUuid3 = "33333333-2222-3333-4444-555555555555"
)

const certTestCaList = `{"rows":[{"caref":"6ade14316965d","descr":"test ca"},{"caref":"6ade1431aaaaa","descr":"Dup"},` +
	`{"caref":"6ade1431bbbbb","descr":"dup"},{"caref":"6ade1431ccccc","descr":"twin"},{"caref":"6ade1431ddddd","descr":"twin"}],"count":5}`

// --- reading

func TestCertSearchRawDecodesAndRedacts(t *testing.T) {
	var api, fake = certTestApi(t)
	fake.on("GET", "/api/trust/cert/search", 200, certTestSearch(
		certTestRow(certTestUuid1, "web", nil),
		certTestRow(certTestUuid2, "pending", map[string]any{"crt": "", "crt_payload": "", "prv": "", "prv_payload": "",
			"csr_payload": "-----BEGIN CERTIFICATE REQUEST-----\n", "valid_to": "", "valid_from": ""}),
	))

	var certs, raw, err = api.CertSearchRaw("")
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 || len(raw) != 2 {
		t.Fatalf("want 2 certificates, got %d / %d", len(certs), len(raw))
	}
	var web = certs[0]
	if web.Uuid != certTestUuid1 || web.Descr != "web" || web.Caref != "6ade14316965d" || web.CarefName != "test ca" ||
		web.CertType != CertTypeServer || !web.HasPrivateKey || web.IsPending() || web.IsExternal() || web.InUseFlag() {
		t.Errorf("unexpected certificate %+v", web)
	}
	if got := CertSplitLines(web.AltNamesDNS); !reflect.DeepEqual(got, []string{"srv.example", "www.example"}) {
		t.Errorf("alt names: %q", got)
	}
	if notAfter, ok := web.NotAfter(); !ok || notAfter.Unix() != 1794667065 {
		t.Errorf("NotAfter: %v %v", notAfter, ok)
	}
	if !certs[1].IsPending() || certs[1].HasPrivateKey {
		t.Errorf("want a pending request without key: %+v", certs[1])
	}
	if _, ok := certs[1].NotAfter(); ok {
		t.Error("a pending request has no validity")
	}

	for _, row := range raw {
		var text = string(row)
		if strings.Contains(text, "prv") || strings.Contains(text, "PRIVATE KEY") || strings.Contains(text, "cHJpdmF0ZQ") {
			t.Errorf("raw row contains the private key: %s", text)
		}
	}
	// key order is kept
	if !strings.HasPrefix(string(raw[0]), `{"uuid":`) && !strings.HasPrefix(string(raw[0]), `{"%action":`) {
		t.Errorf("unexpected raw row %s", raw[0])
	}
}

func TestCertRedactKeepsOrder(t *testing.T) {
	var redacted, err = certRedact(json.RawMessage(`{"uuid":"u","prv":"x","descr":"d \"q\"","prv_payload":"y","in_use":"0","n":{"a":[1, 2]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(redacted) != `{"uuid":"u","descr":"d \"q\"","in_use":"0","n":{"a":[1,2]}}` {
		t.Errorf("got %s", redacted)
	}
	if _, err := certRedact(json.RawMessage(`[1]`)); err == nil {
		t.Error("want an error for a non object")
	}
}

func TestCertGetLookups(t *testing.T) {
	var api, fake = certTestApi(t)
	fake.on("GET", "/api/trust/cert/search", 200, certTestSearch(
		certTestRow(certTestUuid1, "web", map[string]any{"refid": "aaaaaaaaaaaaa"}),
		certTestRow(certTestUuid2, "twin", map[string]any{"refid": "bbbbbbbbbbbbb"}),
		certTestRow(certTestUuid3, "twin", map[string]any{"refid": "ccccccccccccc"}),
	))

	if cert, err := api.CertGet(strings.ToUpper(certTestUuid1)); err != nil || cert.Descr != "web" {
		t.Errorf("CertGet: %+v %v", cert, err)
	}
	if _, err := api.CertGet("99999999-2222-3333-4444-555555555555"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if cert, err := api.CertGetByRefid("bbbbbbbbbbbbb"); err != nil || cert.Uuid != certTestUuid2 {
		t.Errorf("CertGetByRefid: %+v %v", cert, err)
	}
	if cert, err := api.CertGetByDescription("web"); err != nil || cert.Uuid != certTestUuid1 {
		t.Errorf("CertGetByDescription: %+v %v", cert, err)
	}
	var tooMany *coreapi.TooManyFoundError
	if _, err := api.CertGetByDescription("twin"); !errors.As(err, &tooMany) || !strings.Contains(err.Error(), certTestUuid3) {
		t.Errorf("want too many found, got %v", err)
	}
	if _, err := api.CertGetByDescription("WEB"); !coreapi.IsNotFound(err) {
		t.Errorf("descriptions are exact, got %v", err)
	}
	if _, err := api.CertGetByDescription(""); err == nil {
		t.Error("want an error for an empty description")
	}
}

func TestCertIssuerByName(t *testing.T) {
	var api, fake = certTestApi(t)
	fake.on("GET", "/api/trust/cert/ca_list", 200, certTestCaList)

	for name, want := range map[string]string{"test ca": "6ade14316965d", "TEST CA": "6ade14316965d", "6ade1431aaaaa": "6ade1431aaaaa",
		"Dup": "6ade1431aaaaa", "dup": "6ade1431bbbbb"} {
		if issuer, err := api.CertIssuerByName(name); err != nil || issuer.Refid != want {
			t.Errorf("%q: got %+v %v, want %s", name, issuer, err, want)
		}
	}
	var tooMany *coreapi.TooManyFoundError
	if _, err := api.CertIssuerByName("TWIN"); !errors.As(err, &tooMany) {
		t.Errorf("want too many found, got %v", err)
	}
	if _, err := api.CertIssuerByName("nope"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
}

// --- creating

func TestCertCreateInternal(t *testing.T) {
	var api, fake = certTestApi(t)
	fake.on("GET", "/api/trust/cert/ca_list", 200, certTestCaList)
	fake.on("POST", "/api/trust/cert/add", 200, `{"result":"saved","uuid":"`+certTestUuid1+`"}`)

	var uuid, err = api.CertCreate(CertRequest{
		Method: CertMethodInternal, Description: "web", IssuerRef: "6ade14316965d", Type: CertTypeServer,
		KeyType: "prime256v1", Digest: "sha384", Lifetime: 30, CommonName: "web.example", Organization: "ACME",
		AltNamesDNS: []string{"web.example", "www.example"}, AltNamesIP: []string{"10.0.0.1", "fd00::1"},
	})
	if err != nil || uuid != certTestUuid1 {
		t.Fatalf("got %q %v", uuid, err)
	}
	var request = fake.oneMutation("/api/trust/cert/add")
	var want = map[string]any{"cert": map[string]any{
		"action": "internal", "descr": "web", "caref": "6ade14316965d", "private_key_location": "firewall",
		"cert_type": "server_cert", "key_type": "prime256v1", "digest": "sha384", "lifetime": "30",
		"commonname": "web.example", "country": "NL", "state": "", "city": "", "organization": "ACME",
		"organizationalunit": "", "email": "", "altnames_dns": "web.example\nwww.example", "altnames_ip": "10.0.0.1\nfd00::1",
		"altnames_email": "", "altnames_uri": "",
	}}
	if got := request.json(t); !reflect.DeepEqual(got, want) {
		t.Errorf("body:\n got  %v\n want %v", got, want)
	}
}

func TestCertCreateSelfSignedAndSigningRequest(t *testing.T) {
	var api, fake = certTestApi(t)
	fake.on("POST", "/api/trust/cert/add", 200, `{"result":"saved","uuid":"`+certTestUuid1+`"}`)

	if _, err := api.CertCreate(CertRequest{Method: CertMethodSelfSigned, Description: "self", CommonName: "self.example"}); err != nil {
		t.Fatal(err)
	}
	var cert = fake.mutations()[0].json(t)["cert"].(map[string]any)
	if cert["action"] != "internal" || cert["caref"] != "" || cert["lifetime"] != "397" || cert["key_type"] != "2048" ||
		cert["cert_type"] != "usr_cert" || cert["digest"] != "sha256" {
		t.Errorf("unexpected self-signed body %v", cert)
	}

	if _, err := api.CertCreate(CertRequest{Method: CertMethodSigningRequest, Description: "csr", CommonName: "csr.example",
		Country: "DE", AltNamesEmail: []string{"a@example.com"}}); err != nil {
		t.Fatal(err)
	}
	cert = fake.mutations()[1].json(t)["cert"].(map[string]any)
	if cert["action"] != "external" || cert["country"] != "DE" || cert["altnames_email"] != "a@example.com" {
		t.Errorf("unexpected csr body %v", cert)
	}
	for _, field := range []string{"caref", "cert_type", "lifetime"} {
		if _, sent := cert[field]; sent {
			t.Errorf("csr must not send %s: %v", field, cert)
		}
	}
}

func TestCertCreateImportAndSignRequest(t *testing.T) {
	var api, fake = certTestApi(t)
	fake.on("GET", "/api/trust/cert/ca_list", 200, certTestCaList)
	fake.on("POST", "/api/trust/cert/add", 200, `{"result":"saved","uuid":"`+certTestUuid1+`"}`)
	var pair = certTestGenerate(t, "import.example")

	if _, err := api.CertCreate(CertRequest{Method: CertMethodImport, Description: "imp", CertificatePEM: pair.certPEM,
		PrivateKeyPEM: pair.keyPEM}); err != nil {
		t.Fatal(err)
	}
	var want = map[string]any{"cert": map[string]any{"action": "import", "descr": "imp", "crt_payload": pair.certPEM,
		"prv_payload": pair.keyPEM}}
	if got := fake.mutations()[0].json(t); !reflect.DeepEqual(got, want) {
		t.Errorf("import body %v", got)
	}

	if _, err := api.CertCreate(CertRequest{Method: CertMethodSignRequest, Description: "signed", IssuerRef: "6ade14316965d",
		SigningRequestPEM: pair.csrPEM, Type: CertTypeCombined, Lifetime: 10, AltNamesDNS: []string{"import.example"}}); err != nil {
		t.Fatal(err)
	}
	var cert = fake.mutations()[1].json(t)["cert"].(map[string]any)
	if cert["action"] != "sign_csr" || cert["csr_payload"] != pair.csrPEM || cert["caref"] != "6ade14316965d" ||
		cert["cert_type"] != "combined_server_client" || cert["lifetime"] != "10" || cert["altnames_dns"] != "import.example" {
		t.Errorf("unexpected sign_csr body %v", cert)
	}
	if _, sent := cert["key_type"]; sent {
		t.Errorf("sign_csr must not send a key type: %v", cert)
	}
}

func TestCertCreateRefusesBeforeSending(t *testing.T) {
	var api, fake = certTestApi(t)
	fake.on("GET", "/api/trust/cert/ca_list", 200, certTestCaList)
	var pair = certTestGenerate(t, "a.example")
	var other = certTestGenerate(t, "b.example")

	for name, test := range map[string]struct {
		request CertRequest
		want    string
	}{
		"no description":       {CertRequest{Method: CertMethodSelfSigned, CommonName: "x"}, "description"},
		"no method":            {CertRequest{Description: "x", CommonName: "x"}, "unknown method"},
		"internal no issuer":   {CertRequest{Method: CertMethodInternal, Description: "x", CommonName: "x"}, "issuer"},
		"unknown issuer":       {CertRequest{Method: CertMethodInternal, Description: "x", CommonName: "x", IssuerRef: "0000000000000"}, "not found"},
		"self-signed issuer":   {CertRequest{Method: CertMethodSelfSigned, Description: "x", CommonName: "x", IssuerRef: "6ade14316965d"}, "does not use an issuer"},
		"no common name":       {CertRequest{Method: CertMethodSelfSigned, Description: "x"}, "common name"},
		"bad country":          {CertRequest{Method: CertMethodSelfSigned, Description: "x", CommonName: "x", Country: "nl"}, "country"},
		"bad ip":               {CertRequest{Method: CertMethodSelfSigned, Description: "x", CommonName: "x", AltNamesIP: []string{"10.0.0"}}, "IP address"},
		"bad uri":              {CertRequest{Method: CertMethodSelfSigned, Description: "x", CommonName: "x", AltNamesURI: []string{"host"}}, "URI"},
		"bad key type":         {CertRequest{Method: CertMethodSelfSigned, Description: "x", CommonName: "x", KeyType: "rsa"}, "key type"},
		"bad digest":           {CertRequest{Method: CertMethodSelfSigned, Description: "x", CommonName: "x", Digest: "md5"}, "digest"},
		"bad type":             {CertRequest{Method: CertMethodSelfSigned, Description: "x", CommonName: "x", Type: "server"}, "certificate type"},
		"csr lifetime":         {CertRequest{Method: CertMethodSigningRequest, Description: "x", CommonName: "x", Lifetime: 3}, "lifetime"},
		"import garbage":       {CertRequest{Method: CertMethodImport, Description: "x", CertificatePEM: "garbage"}, "no PEM encoded certificate"},
		"import key mismatch":  {CertRequest{Method: CertMethodImport, Description: "x", CertificatePEM: pair.certPEM, PrivateKeyPEM: other.keyPEM}, "does not belong"},
		"import subject":       {CertRequest{Method: CertMethodImport, Description: "x", CertificatePEM: pair.certPEM, CommonName: "x"}, "subject"},
		"sign no request":      {CertRequest{Method: CertMethodSignRequest, Description: "x", IssuerRef: "6ade14316965d", SigningRequestPEM: pair.certPEM}, "signing request"},
		"sign no issuer":       {CertRequest{Method: CertMethodSignRequest, Description: "x", SigningRequestPEM: pair.csrPEM}, "issuer"},
		"multi line describes": {CertRequest{Method: CertMethodSelfSigned, Description: "a\nb", CommonName: "x"}, "one line"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := api.CertCreate(test.request); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("want an error containing %q, got %v", test.want, err)
			}
		})
	}
	fake.noMutations()
}

func TestCertCreateMapsActionFailures(t *testing.T) {
	var api, fake = certTestApi(t)
	fake.on("POST", "/api/trust/cert/add", 500, `{"errorMessage":"Invalid X509 certificate provided","errorTitle":"Certificate error"}`)
	var _, err = api.CertCreate(CertRequest{Method: CertMethodSelfSigned, Description: "x", CommonName: "x"})
	if err == nil || !strings.Contains(err.Error(), "OPNsense refused it: Invalid X509 certificate provided") {
		t.Errorf("got %v", err)
	}

	fake.on("POST", "/api/trust/cert/add", 200, `{"result":"failed","validations":{"cert.descr":"A value is required."}}`)
	_, err = api.CertCreate(CertRequest{Method: CertMethodSelfSigned, Description: "x", CommonName: "x"})
	var validation *coreapi.ValidationError
	if !errors.As(err, &validation) {
		t.Errorf("want a validation error, got %v", err)
	}
}

// --- changing

func TestCertReplaceSendsEveryField(t *testing.T) {
	var api, fake = certTestApi(t)
	fake.on("GET", "/api/trust/cert/search", 200, certTestSearch(certTestRow(certTestUuid1, "web", nil)))
	fake.on("POST", "/api/trust/cert/set/"+certTestUuid1, 200, `{"result":"saved"}`)

	if err := api.CertReplace(certTestUuid1, CertRequest{Method: CertMethodSelfSigned, Description: "web", CommonName: "new.example"}); err != nil {
		t.Fatal(err)
	}
	var cert = fake.oneMutation("/api/trust/cert/set/" + certTestUuid1).json(t)["cert"].(map[string]any)
	for _, field := range certNodeFields {
		if _, sent := cert[field]; !sent {
			t.Errorf("replace did not send %s", field)
		}
	}
	if cert["action"] != "internal" || cert["commonname"] != "new.example" || cert["crt"] != "" || cert["prv_payload"] != "" || cert["csr"] != "" {
		t.Errorf("unexpected body %v", cert)
	}

	if err := api.CertReplace("99999999-2222-3333-4444-555555555555", CertRequest{Method: CertMethodSelfSigned, Description: "web", CommonName: "x"}); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
}

func TestCertUpdateSendsManual(t *testing.T) {
	var api, fake = certTestApi(t)
	fake.on("GET", "/api/trust/cert/search", 200, certTestSearch(certTestRow(certTestUuid1, "web", nil), certTestRow(certTestUuid2, "racy", nil)))
	fake.on("POST", "/api/trust/cert/set/"+certTestUuid1, 200, `{"result":"saved"}`)
	var description = "renamed"
	if err := api.CertUpdate(certTestUuid1, CertPatch{Description: &description}); err != nil {
		t.Fatal(err)
	}
	var want = map[string]any{"cert": map[string]any{"action": "manual", "descr": "renamed"}}
	if got := fake.oneMutation("/api/trust/cert/set/" + certTestUuid1).json(t); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}

	// unknown uuids are not sent: set would create a record
	if err := api.CertUpdate(certTestUuid3, CertPatch{Description: &description}); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	// removed between lookup and set
	fake.on("POST", "/api/trust/cert/set/"+certTestUuid2, 200, `{"result":"failed"}`)
	if err := api.CertUpdate(certTestUuid2, CertPatch{Description: &description}); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if mutations := fake.mutations(); len(mutations) != 2 {
		t.Errorf("want 2 set calls, got %+v", mutations)
	}
	var empty = " "
	if err := api.CertUpdate(certTestUuid1, CertPatch{Description: &empty}); err == nil {
		t.Error("want an error for an empty description")
	}
	if err := api.CertUpdate("a,b", CertPatch{Description: &description}); err == nil {
		t.Error("want an error for a uuid list")
	}
}

func TestCertReissue(t *testing.T) {
	var api, fake = certTestApi(t)
	fake.on("GET", "/api/trust/cert/search", 200, certTestSearch(
		certTestRow(certTestUuid1, "web", nil),
		certTestRow(certTestUuid2, "self", map[string]any{"caref": "", "%caref": ""}),
		certTestRow(certTestUuid3, "nokey", map[string]any{"prv": "", "prv_payload": ""}),
	))
	fake.on("POST", "/api/trust/cert/set/"+certTestUuid1, 200, `{"result":"saved"}`)

	for uuid, want := range map[string]string{certTestUuid2: "not issued by a certificate authority", certTestUuid3: "no stored private key"} {
		if err := api.CertReissue(uuid, 0, ""); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", uuid, want, err)
		}
	}
	fake.noMutations()

	if err := api.CertReissue(certTestUuid1, 30, "sha512"); err != nil {
		t.Fatal(err)
	}
	var want = map[string]any{"cert": map[string]any{"action": "reissue", "lifetime": "30", "digest": "sha512"}}
	if got := fake.oneMutation("/api/trust/cert/set/" + certTestUuid1).json(t); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}

func TestCertImportSigned(t *testing.T) {
	var api, fake = certTestApi(t)
	var pair = certTestGenerate(t, "csr.example")
	var other = certTestGenerate(t, "other.example")
	fake.on("GET", "/api/trust/cert/search", 200, certTestSearch(
		certTestRow(certTestUuid1, "pending", map[string]any{"crt": "", "crt_payload": "", "csr_payload": pair.csrPEM}),
		certTestRow(certTestUuid2, "web", nil),
	))
	fake.on("POST", "/api/trust/cert/set/"+certTestUuid1, 200, `{"result":"saved"}`)

	if err := api.CertImportSigned(certTestUuid1, other.certPEM); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("want a key mismatch, got %v", err)
	}
	if err := api.CertImportSigned(certTestUuid2, pair.certPEM); err == nil || !strings.Contains(err.Error(), "not a pending signing request") {
		t.Errorf("want not a signing request, got %v", err)
	}
	fake.noMutations()

	if err := api.CertImportSigned(certTestUuid1, pair.certPEM); err != nil {
		t.Fatal(err)
	}
	var want = map[string]any{"cert": map[string]any{"action": "import_csr", "crt_payload": pair.certPEM}}
	if got := fake.oneMutation("/api/trust/cert/set/" + certTestUuid1).json(t); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}

// --- removing

func TestCertRemove(t *testing.T) {
	var api, fake = certTestApi(t)
	fake.on("GET", "/api/trust/cert/search", 200, certTestSearch(
		certTestRow(certTestUuid1, "free", nil),
		certTestRow(certTestUuid2, "used", map[string]any{"in_use": "1"}),
		certTestRow(certTestUuid3, "racy", nil),
		certTestRow("acme1", "external", nil),
	))
	fake.on("POST", "/api/trust/cert/del/"+certTestUuid1, 200, `{"result":"deleted"}`)
	fake.on("POST", "/api/trust/cert/del/"+certTestUuid3, 500,
		`{"errorMessage":"cron - nightly {cron.jobs.job.u1}\nopenvpn - vpn {OPNsense.OpenVPN.Instances.Instance.u2}\n","errorTitle":"Item in use by"}`)

	var inUse *CertInUseError
	if err := api.CertRemove(certTestUuid2); !errors.As(err, &inUse) || len(inUse.Usages) != 0 {
		t.Errorf("want in use, got %v", err)
	}
	if err := api.CertRemove("acme1"); err == nil || !strings.Contains(err.Error(), "not a uuid") {
		t.Errorf("want a refusal, got %v", err)
	}
	if err := api.CertRemove(certTestUuid1 + "," + certTestUuid2); err == nil {
		t.Error("want a refusal for a list")
	}
	if err := api.CertRemove("99999999-2222-3333-4444-555555555555"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	fake.noMutations()

	if err := api.CertRemove(certTestUuid1); err != nil {
		t.Fatal(err)
	}
	var err = api.CertRemove(certTestUuid3)
	if !errors.As(err, &inUse) || len(inUse.Usages) != 2 || !strings.Contains(err.Error(), "cron - nightly") {
		t.Errorf("want in use by 2 items, got %v", err)
	}
}

func TestCertExternalCanNotChange(t *testing.T) {
	var cert = Cert{Uuid: "acme1"}
	if !cert.IsExternal() {
		t.Error("an id without dashes is external")
	}
}

// --- dump and export

func TestCertDump(t *testing.T) {
	var api, fake = certTestApi(t)
	fake.on("GET", "/api/trust/cert/raw_dump/"+certTestUuid1, 200, `{"exit_status":0,"stderr":"","stdout":"sha256 Fingerprint=AA\nCertificate:\n"}`)
	fake.on("GET", "/api/trust/cert/raw_dump/"+certTestUuid2, 200, `[]`)
	fake.on("GET", "/api/trust/cert/raw_dump/"+certTestUuid3, 200, `{"exit_status":1,"stderr":"unable to load","stdout":""}`)

	if dump, err := api.CertDump(certTestUuid1); err != nil || !strings.HasPrefix(dump, "sha256 Fingerprint=AA") {
		t.Errorf("got %q %v", dump, err)
	}
	if _, err := api.CertDump(certTestUuid2); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if _, err := api.CertDump(certTestUuid3); err == nil || !strings.Contains(err.Error(), "unable to load") {
		t.Errorf("want the openssl error, got %v", err)
	}
}

func TestCertExport(t *testing.T) {
	var api, fake = certTestApi(t)
	var base = "/api/trust/cert/generate_file/" + certTestUuid1 + "/"
	fake.on("POST", base+"crt", 200, `{"status":"ok","descr":"web / test","payload":"-----BEGIN CERTIFICATE-----\n"}`)
	fake.on("POST", base+"prv", 200, `{"status":"ok","descr":"web / test","payload":""}`)
	fake.on("POST", base+"pkcs12", 200, fmt.Sprintf(`{"status":"ok","descr":"web","payload_b64":%q}`, base64.StdEncoding.EncodeToString([]byte{0x30, 0x82, 0})))
	fake.on("POST", "/api/trust/cert/generate_file/"+certTestUuid2+"/crt", 200, `{"status":"failed","descr":"","error":"Missing certificate"}`)
	fake.on("POST", "/api/trust/cert/generate_file/"+certTestUuid3+"/pkcs12", 200,
		`{"status":"failed","descr":"signed","error":" error:0480006C:PEM routines::no start line"}`)

	var content, filename, err = api.CertExport(certTestUuid1, CertExportCertificate, "")
	if err != nil || string(content) != "-----BEGIN CERTIFICATE-----\n" || filename != "web_test_crt.pem" {
		t.Errorf("crt: %q %q %v", content, filename, err)
	}
	if _, _, err = api.CertExport(certTestUuid1, CertExportPrivateKey, ""); err == nil || !strings.Contains(err.Error(), "has no private key") {
		t.Errorf("prv: want no private key, got %v", err)
	}
	content, filename, err = api.CertExport(certTestUuid1, CertExportPKCS12, "s3cret")
	if err != nil || string(content) != "\x30\x82\x00" || filename != "web_cert.p12" {
		t.Errorf("pkcs12: %q %q %v", content, filename, err)
	}
	var requests = fake.mutations()
	if got := requests[len(requests)-1].json(t); !reflect.DeepEqual(got, map[string]any{"password": "s3cret"}) {
		t.Errorf("pkcs12 body %v", got)
	}
	if requests[0].body != "" {
		t.Errorf("crt must be POSTed without a body, got %q", requests[0].body)
	}
	if _, _, err = api.CertExport(certTestUuid2, CertExportCertificate, ""); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if _, _, err = api.CertExport(certTestUuid3, CertExportPKCS12, ""); err == nil || !strings.Contains(err.Error(), "needs a certificate and its private key") {
		t.Errorf("want a pkcs12 error, got %v", err)
	}
	if _, _, err = api.CertExport(certTestUuid1, CertExportCertificate, "pw"); err == nil {
		t.Error("want an error for a password with crt")
	}
	if _, _, err = api.CertExport(certTestUuid1, "der", ""); err == nil {
		t.Error("want an error for an unknown format")
	}
}

func TestCertSafeFilename(t *testing.T) {
	for in, want := range map[string]string{"Web GUI TLS certificate": "Web_GUI_TLS_certificate", "../../etc/passwd": "etc_passwd",
		"": "cert", "...": "cert", "a.b-c_d": "a.b-c_d"} {
		if got := CertSafeFilename(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestCertParseHelpers(t *testing.T) {
	var pair = certTestGenerate(t, "self.example")
	var cert = Cert{Descr: "self", CertificatePEM: pair.certPEM}
	if !cert.IsSelfSigned() {
		t.Error("want self-signed")
	}
	var parsed, err = cert.X509()
	if err != nil || parsed.Subject.CommonName != "self.example" {
		t.Fatalf("X509: %v", err)
	}
	if fingerprint := CertFingerprint(parsed); len(fingerprint) != 95 || strings.ToUpper(fingerprint) != fingerprint {
		t.Errorf("fingerprint %q", fingerprint)
	}
	if _, err := (Cert{Descr: "pending"}).X509(); err == nil {
		t.Error("want an error without certificate")
	}
	if _, err := CertParseRequestPEM(pair.csrPEM); err != nil {
		t.Errorf("request: %v", err)
	}
}
