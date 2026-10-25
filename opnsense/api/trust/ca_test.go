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

// caTestServer is a fake OPNsense answering per "METHOD /path" and recording every request
type caTestServer struct {
	t        *testing.T
	mu       sync.Mutex
	handlers map[string]string
	status   map[string]int
	requests []caTestRequest
}

type caTestRequest struct {
	method string
	path   string
	query  url.Values
	body   string
}

func caTestApi(t *testing.T) (*TrustApi, *caTestServer) {
	t.Helper()
	var fake = &caTestServer{t: t, handlers: map[string]string{}, status: map[string]int{}}
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		fake.mu.Lock()
		fake.requests = append(fake.requests, caTestRequest{method: r.Method, path: r.URL.Path, query: r.URL.Query(), body: string(body)})
		var key = r.Method + " " + r.URL.Path
		var answer, known = fake.handlers[key]
		var status = fake.status[key]
		fake.mu.Unlock()
		if !known {
			t.Errorf("unexpected request %s", key)
			return
		}
		if status != 0 {
			w.WriteHeader(status)
		}
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(server.Close)
	var serverUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &TrustApi{OPNsense: &coreapi.OPNsense{BaseUrl: *serverUrl, ApiKey: "key", ApiSecret: "secret"}}, fake
}

func (s *caTestServer) on(method string, path string, answer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[method+" "+path] = answer
	delete(s.status, method+" "+path)
}

func (s *caTestServer) onStatus(method string, path string, status int, answer string) {
	s.on(method, path, answer)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status[method+" "+path] = status
}

func (s *caTestServer) posts() []caTestRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []caTestRequest
	for _, request := range s.requests {
		if request.method != "GET" {
			result = append(result, request)
		}
	}
	return result
}

// onePost asserts exactly one POST to path and returns its decoded "ca" object
func (s *caTestServer) onePost(path string) map[string]any {
	s.t.Helper()
	var posts = s.posts()
	if len(posts) != 1 || posts[0].path != path {
		s.t.Fatalf("want one POST %s, got %+v", path, posts)
	}
	if posts[0].body == "" {
		return nil
	}
	var container struct {
		Ca map[string]any `json:"ca"`
	}
	if err := json.Unmarshal([]byte(posts[0].body), &container); err != nil {
		s.t.Fatalf("body %q: %v", posts[0].body, err)
	}
	return container.Ca
}

func (s *caTestServer) wantNoPosts() {
	s.t.Helper()
	if posts := s.posts(); len(posts) != 0 {
		s.t.Errorf("want no POST, got %+v", posts)
	}
}

// caTestPair returns a PEM CA certificate and its PEM private key (PKCS#8)
func caTestPair(t *testing.T, commonName string, isCA bool) (string, string) {
	t.Helper()
	var key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var template = &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageCertSign,
	}
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

const (
	caTestSearchPath = "/api/trust/ca/search"
	caTestAddPath    = "/api/trust/ca/add"
)

// caTestRow is a search row as OPNsense 26.7 returns it (with the private key)
func caTestRow(uuid string, refid string, descr string, caref string, refcount string, withKey bool) map[string]any {
	var row = map[string]any{
		"uuid": uuid, "refid": refid, "descr": descr, "crt": "LS0tLS1CRUdJTg==", "prv": "", "serial": "1", "caref": caref,
		"action": "existing", "%action": "Import an existing Certificate Authority", "key_type": "prime256v1",
		"%key_type": "Elliptic Curve prime256v1", "digest": "sha256", "%digest": "SHA256", "lifetime": "825", "city": "",
		"state": "", "organization": "", "organizationalunit": "", "country": "NL", "%country": "Netherlands", "email": "",
		"commonname": descr + " cn", "ocsp_uri": "", "crt_payload": "-----BEGIN CERTIFICATE-----\n", "prv_payload": "",
		"refcount": refcount, "name": "/C=NL/CN=" + descr + " cn", "valid_from": "1792938981", "valid_to": "1795530981",
	}
	if withKey {
		row["prv"] = "c2VjcmV0"
		row["prv_payload"] = "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n"
	}
	if caref != "" {
		row["%caref"] = "issuer of " + descr
	}
	return row
}

func caTestSearch(rows ...map[string]any) string {
	var answer, _ = json.Marshal(map[string]any{"rows": rows, "rowCount": len(rows), "total": len(rows), "current": 1})
	return string(answer)
}

var caTestRows = []map[string]any{
	caTestRow("u-root", "6ade13e520da0", "root", "", "2", true),
	caTestRow("u-inter", "6ade13f1cb603", "inter", "6ade13e520da0", "0", true),
	caTestRow("u-nokey", "6ade14086671b", "imported", "", "0", false),
	caTestRow("u-d1", "6ade14086671c", "dup", "", "0", false),
	caTestRow("u-d2", "6ade14086671d", "dup", "", "0", false),
}

func TestCaSearchDecodesWithoutPrivateKey(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.on("GET", caTestSearchPath, caTestSearch(caTestRows...))

	var authorities, raw, err = api.CaSearchRaw("")
	if err != nil {
		t.Fatal(err)
	}
	if len(authorities) != 5 || len(raw) != 5 {
		t.Fatalf("want 5 authorities, got %d / %d", len(authorities), len(raw))
	}
	var inter = authorities[1]
	if inter.Uuid != "u-inter" || inter.Caref != "6ade13e520da0" || inter.CarefDescription != "issuer of inter" ||
		!inter.HasPrivateKey || inter.KeyType != "prime256v1" || inter.Certificate == "" || inter.InUse() != 0 {
		t.Errorf("unexpected authority %+v", inter)
	}
	if authorities[2].HasPrivateKey {
		t.Errorf("imported has no key: %+v", authorities[2])
	}
	if authorities[0].InUse() != 2 {
		t.Errorf("want refcount 2, got %+v", authorities[0])
	}
	if until, ok := authorities[0].NotAfter(); !ok || until.Unix() != 1795530981 {
		t.Errorf("NotAfter %v %v", until, ok)
	}
	for _, row := range raw {
		if strings.Contains(string(row), "PRIVATE KEY") || strings.Contains(string(row), "c2VjcmV0") ||
			strings.Contains(string(row), `"prv"`) || strings.Contains(string(row), `"crt"`) {
			t.Errorf("raw row leaks the key or the base64 certificate: %s", row)
		}
		if !strings.Contains(string(row), `"crt_payload"`) || !strings.Contains(string(row), `"refid"`) {
			t.Errorf("raw row lacks fields: %s", row)
		}
	}
}

func TestCaGetVariants(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.on("GET", caTestSearchPath, caTestSearch(caTestRows...))

	if ca, err := api.CaGet("u-inter"); err != nil || ca.Description != "inter" {
		t.Errorf("CaGet: %+v %v", ca, err)
	}
	if ca, err := api.CaGetByRefid("6ade14086671b"); err != nil || ca.Uuid != "u-nokey" {
		t.Errorf("CaGetByRefid: %+v %v", ca, err)
	}
	if ca, err := api.CaGetByDescription("root"); err != nil || ca.Uuid != "u-root" {
		t.Errorf("CaGetByDescription: %+v %v", ca, err)
	}
	if _, err := api.CaGet("unknown"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if _, err := api.CaGetByDescription("roo"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found for a prefix, got %v", err)
	}
	var tooMany *coreapi.TooManyFoundError
	if _, err := api.CaGetByDescription("dup"); !errors.As(err, &tooMany) || !strings.Contains(err.Error(), "u-d1, u-d2") {
		t.Errorf("want too many found, got %v", err)
	}
	if _, err := api.CaGetByRefid(""); err == nil {
		t.Error("empty refid must fail")
	}
}

func TestCaOptionsSorted(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.on("GET", "/api/trust/ca/get", `{"ca":{"refid":"","caref":{"":{"value":"self-signed","selected":1}},`+
		`"key_type":{"512":{"value":"RSA-512","selected":0},"1024":{"value":"RSA-1024","selected":0},"2048":{"value":"RSA-2048","selected":1},`+
		`"prime256v1":{"value":"Elliptic Curve prime256v1","selected":0},"8192":{"value":"RSA-8192","selected":0}},`+
		`"digest":{"sha256":{"value":"SHA256","selected":1},"sha1":{"value":"SHA1","selected":0}},`+
		`"country":{"NL":{"value":"Netherlands","selected":1},"DE":{"value":"Germany","selected":0}},"lifetime":"825"}}`)

	var options, err = api.CaOptions()
	if err != nil {
		t.Fatal(err)
	}
	var keys = func(values []AuthorityOption) []string {
		var result []string
		for _, value := range values {
			result = append(result, value.Key)
		}
		return result
	}
	if got := keys(options.KeyTypes); !reflect.DeepEqual(got, []string{"512", "1024", "2048", "8192", "prime256v1"}) {
		t.Errorf("key types %v", got)
	}
	if got := keys(options.Digests); !reflect.DeepEqual(got, []string{"sha1", "sha256"}) {
		t.Errorf("digests %v", got)
	}
	if got := keys(options.Countries); !reflect.DeepEqual(got, []string{"DE", "NL"}) {
		t.Errorf("countries %v", got)
	}
	if options.KeyTypes[2].Description != "RSA-2048" {
		t.Errorf("descriptions %+v", options.KeyTypes)
	}
}

func TestCaInfo(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.on("GET", "/api/trust/ca/ca_info/6ade13e520da0", `{"valid_from":1792938981,"valid_to":1795530981,"name":"\/C=NL\/CN=x",`+
		`"serialNumber":"0","city":"Amsterdam","issuer":{"commonname":"x"},"country":"NL","commonname":"x","rfc3280_purpose":"",`+
		`"key_type":2048,"digest":"sha256"}`)
	fake.on("GET", "/api/trust/ca/ca_info/0000000000000", `[]`)

	var info, err = api.CaInfo("6ade13e520da0")
	if err != nil {
		t.Fatal(err)
	}
	if info.KeyType != "2048" || info.ValidTo != "1795530981" || info.City != "Amsterdam" || info.Issuer["commonname"] != "x" {
		t.Errorf("unexpected info %+v", info)
	}
	if _, err := api.CaInfo("0000000000000"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
}

func TestCaDump(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.on("GET", "/api/trust/ca/raw_dump/u-root", `{"exit_status":0,"stderr":"","stdout":"sha256 Fingerprint=A3\nCertificate:\n"}`)
	fake.on("GET", "/api/trust/ca/raw_dump/unknown", `[]`)
	fake.on("GET", "/api/trust/ca/raw_dump/broken", `{"exit_status":1,"stderr":"unable to load certificate","stdout":""}`)

	if dump, err := api.CaDump("u-root"); err != nil || dump != "sha256 Fingerprint=A3\nCertificate:\n" {
		t.Errorf("dump %q %v", dump, err)
	}
	if _, err := api.CaDump("unknown"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if _, err := api.CaDump("broken"); err == nil || !strings.Contains(err.Error(), "unable to load certificate") {
		t.Errorf("want the openssl error, got %v", err)
	}
}

func TestCaExport(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.on("POST", "/api/trust/ca/generate_file/u-root/crt", `{"status":"ok","descr":"root","payload":"-----BEGIN CERTIFICATE-----\n"}`)
	fake.on("POST", "/api/trust/ca/generate_file/u-root/prv", `{"status":"ok","descr":"root","payload":"-----BEGIN PRIVATE KEY-----\n"}`)
	fake.on("POST", "/api/trust/ca/generate_file/u-nokey/prv", `{"status":"ok","descr":"imported","payload":""}`)
	fake.on("POST", "/api/trust/ca/generate_file/unknown/crt", `{"status":"failed","descr":"","error":"Missing certificate"}`)

	if payload, descr, err := api.CaExport("u-root", CaExportCertificate); err != nil || descr != "root" || !strings.Contains(payload, "CERTIFICATE") {
		t.Errorf("export crt: %q %q %v", payload, descr, err)
	}
	if payload, _, err := api.CaExport("u-root", CaExportPrivateKey); err != nil || !strings.Contains(payload, "PRIVATE KEY") {
		t.Errorf("export prv: %q %v", payload, err)
	}
	if _, _, err := api.CaExport("u-nokey", CaExportPrivateKey); err == nil || !strings.Contains(err.Error(), "has no private key") {
		t.Errorf("want no private key, got %v", err)
	}
	if _, _, err := api.CaExport("unknown", CaExportCertificate); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if _, _, err := api.CaExport("u-root", "pkcs12"); err == nil {
		t.Error("unknown type must fail")
	}
	for _, request := range fake.posts() {
		if request.body != "" {
			t.Errorf("generate_file must be posted without body, got %q", request.body)
		}
	}
}

func TestCaCreateInternalSendsDefaults(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.on("POST", caTestAddPath, `{"result":"saved","uuid":"new-uuid"}`)

	var uuid, err = api.CaCreateInternal(AuthorityInternal{Description: "my root", Subject: AuthoritySubject{CommonName: "My Root", City: "Delft"}})
	if err != nil || uuid != "new-uuid" {
		t.Fatalf("create: %q %v", uuid, err)
	}
	var want = map[string]any{
		"action": "internal", "descr": "my root", "caref": "", "key_type": "2048", "digest": "sha256", "lifetime": "825",
		"commonname": "My Root", "country": "NL", "state": "", "city": "Delft", "organization": "", "organizationalunit": "",
		"email": "", "ocsp_uri": "",
	}
	if got := fake.onePost(caTestAddPath); !reflect.DeepEqual(got, want) {
		t.Errorf("body\n got  %v\n want %v", got, want)
	}
}

func TestCaCreateIntermediateInheritsSubjectAndChecksIssuer(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.on("GET", caTestSearchPath, caTestSearch(caTestRows...))
	fake.on("GET", "/api/trust/ca/ca_info/6ade13e520da0", `{"name":"x","country":"DE","state":"Bavaria","city":"Munich",`+
		`"organization":"Org","organizationalunit":"","email":"ca@example.com","commonname":"Root CN","key_type":"prime256v1"}`)
	fake.on("POST", caTestAddPath, `{"result":"saved","uuid":"inter-uuid"}`)

	var uuid, err = api.CaCreateIntermediate("6ade13e520da0", AuthorityInternal{Description: "sub", KeyType: "prime256v1", Digest: "sha384",
		LifetimeDays: 10, Subject: AuthoritySubject{CommonName: "Sub CN", City: "Berlin"}})
	if err != nil || uuid != "inter-uuid" {
		t.Fatalf("create: %q %v", uuid, err)
	}
	var body = fake.onePost(caTestAddPath)
	for field, want := range map[string]string{"caref": "6ade13e520da0", "commonname": "Sub CN", "city": "Berlin", "country": "DE",
		"state": "Bavaria", "organization": "Org", "email": "ca@example.com", "key_type": "prime256v1", "digest": "sha384", "lifetime": "10"} {
		if body[field] != want {
			t.Errorf("%s: got %v, want %q", field, body[field], want)
		}
	}
}

func TestCaCreateIntermediateRefusesIssuerWithoutKey(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.on("GET", caTestSearchPath, caTestSearch(caTestRows...))
	fake.on("GET", "/api/trust/ca/ca_info/6ade14086671b", `{"name":"x","country":"NL","commonname":"imported cn"}`)

	if _, err := api.CaCreateIntermediate("6ade14086671b", AuthorityInternal{Description: "sub"}); err == nil ||
		!strings.Contains(err.Error(), "has no private key") {
		t.Errorf("want no private key, got %v", err)
	}
	if _, err := api.CaCreateInternal(AuthorityInternal{Description: "sub", Issuer: "0000000000000"}); !coreapi.IsNotFound(err) {
		t.Errorf("want unknown issuer, got %v", err)
	}
	fake.wantNoPosts()
}

func TestCaCreateWrapsCertificateErrors(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.onStatus("POST", caTestAddPath, 500, `{"errorMessage":"missing CA key","errorTitle":"Certificate error"}`)

	var _, err = api.CaCreateInternal(AuthorityInternal{Description: "x"})
	if err == nil || !strings.Contains(err.Error(), "missing CA key") {
		t.Errorf("want the certificate error, got %v", err)
	}
	fake.on("POST", caTestAddPath, `{"result":"failed","validations":{"ca.key_type":"Option [] not in list."}}`)
	var validation *coreapi.ValidationError
	if _, err := api.CaCreateInternal(AuthorityInternal{Description: "x", KeyType: "999"}); !errors.As(err, &validation) {
		t.Errorf("want a validation error, got %v", err)
	}
	if _, err := api.CaCreateInternal(AuthorityInternal{}); err == nil {
		t.Error("an empty description must fail")
	}
}

func TestCaImport(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.on("POST", caTestAddPath, `{"result":"saved","uuid":"imp-uuid"}`)
	var certificate, key = caTestPair(t, "Imported CA", true)

	var uuid, err = api.CaImport(AuthorityImport{Description: "imp", Certificate: certificate, PrivateKey: key})
	if err != nil || uuid != "imp-uuid" {
		t.Fatalf("import: %q %v", uuid, err)
	}
	var want = map[string]any{"action": "existing", "descr": "imp", "caref": "", "crt_payload": certificate, "prv_payload": key}
	if got := fake.onePost(caTestAddPath); !reflect.DeepEqual(got, want) {
		t.Errorf("body\n got  %v\n want %v", got, want)
	}
}

func TestCaImportWithoutKeyClearsPrv(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.on("POST", caTestAddPath, `{"result":"saved","uuid":"imp-uuid"}`)
	var certificate, _ = caTestPair(t, "Imported CA", true)

	if _, err := api.CaImport(AuthorityImport{Description: "imp", Certificate: certificate}); err != nil {
		t.Fatal(err)
	}
	var body = fake.onePost(caTestAddPath)
	if body["prv"] != "" || body["prv_payload"] != "" {
		t.Errorf("want prv and prv_payload empty, got %v", body)
	}
}

func TestCaImportRejectsInvalidInputLocally(t *testing.T) {
	var api, fake = caTestApi(t)
	var certificate, key = caTestPair(t, "A", true)
	var _, otherKey = caTestPair(t, "B", true)
	var leaf, leafKey = caTestPair(t, "leaf", false)

	for name, test := range map[string]struct {
		spec AuthorityImport
		want string
	}{
		"garbage":     {AuthorityImport{Description: "x", Certificate: "garbage"}, "no PEM certificate"},
		"bad key":     {AuthorityImport{Description: "x", Certificate: certificate, PrivateKey: "garbage"}, "no PEM private key"},
		"wrong key":   {AuthorityImport{Description: "x", Certificate: certificate, PrivateKey: otherKey}, "does not belong"},
		"not a CA":    {AuthorityImport{Description: "x", Certificate: leaf, PrivateKey: leafKey}, "not a certificate authority"},
		"no descr":    {AuthorityImport{Certificate: certificate, PrivateKey: key}, "description"},
		"key as cert": {AuthorityImport{Description: "x", Certificate: key}, "no PEM certificate"},
		"encrypted": {AuthorityImport{Description: "x", Certificate: certificate,
			PrivateKey: "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"}, "encrypted"},
	} {
		if _, err := api.CaImport(test.spec); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: want %q, got %v", name, test.want, err)
		}
	}
	fake.wantNoPosts()
}

func TestCaUpdate(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.on("GET", caTestSearchPath, caTestSearch(caTestRows...))
	fake.on("POST", "/api/trust/ca/set/u-root", `{"result":"saved"}`)

	var description = "renamed"
	var serial = 7
	if err := api.CaUpdate("u-root", AuthorityPatch{Description: &description, Serial: &serial}); err != nil {
		t.Fatal(err)
	}
	if got := fake.onePost("/api/trust/ca/set/u-root"); !reflect.DeepEqual(got, map[string]any{"descr": "renamed", "serial": "7"}) {
		t.Errorf("body %v", got)
	}
}

func TestCaUpdateUnknownIsNotFoundWithoutSet(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.on("GET", caTestSearchPath, caTestSearch(caTestRows...))

	var description = "x"
	// set/<unknown uuid> would create a new CA on OPNsense
	if err := api.CaUpdate("00000000-0000-4000-8000-000000000000", AuthorityPatch{Description: &description}); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if err := api.CaUpdate("u-root", AuthorityPatch{}); err == nil {
		t.Error("an empty patch must fail")
	}
	var empty = ""
	if err := api.CaUpdate("u-root", AuthorityPatch{Description: &empty}); err == nil {
		t.Error("an empty description must fail")
	}
	fake.wantNoPosts()
}

func TestCaUpdateCertificateMustMatchStoredKey(t *testing.T) {
	var api, fake = caTestApi(t)
	var certificate, key = caTestPair(t, "A", true)
	var other, _ = caTestPair(t, "B", true)
	var row = caTestRow("u-a", "6ade1470bafcb", "a", "", "0", true)
	row["crt_payload"] = certificate
	fake.on("GET", caTestSearchPath, caTestSearch(row))
	var keyAnswer, _ = json.Marshal(map[string]string{"status": "ok", "descr": "a", "payload": key})
	fake.on("POST", "/api/trust/ca/generate_file/u-a/prv", string(keyAnswer))
	fake.on("POST", "/api/trust/ca/set/u-a", `{"result":"saved"}`)

	if err := api.CaUpdate("u-a", AuthorityPatch{Certificate: &other}); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("want mismatch, got %v", err)
	}
	for _, request := range fake.posts() {
		if strings.Contains(request.path, "/set/") {
			t.Errorf("nothing must be set, got %+v", request)
		}
	}

	// a renewed certificate of the same key is fine
	var renewed = caTestRenew(t, key, "A renewed")
	if err := api.CaUpdate("u-a", AuthorityPatch{Certificate: &renewed}); err != nil {
		t.Fatal(err)
	}
	var sets = 0
	for _, request := range fake.posts() {
		if request.path == "/api/trust/ca/set/u-a" {
			sets++
			if !strings.Contains(request.body, `"action":"existing"`) || !strings.Contains(request.body, "crt_payload") {
				t.Errorf("unexpected body %s", request.body)
			}
		}
	}
	if sets != 1 {
		t.Errorf("want one set, got %d", sets)
	}
}

func TestCaUpdatePrivateKeyMustMatchCertificate(t *testing.T) {
	var api, fake = caTestApi(t)
	var certificate, key = caTestPair(t, "A", true)
	var _, otherKey = caTestPair(t, "B", true)
	var row = caTestRow("u-a", "6ade1470bafcb", "a", "", "0", false)
	row["crt_payload"] = certificate
	fake.on("GET", caTestSearchPath, caTestSearch(row))
	fake.on("POST", "/api/trust/ca/set/u-a", `{"result":"saved"}`)

	if err := api.CaUpdate("u-a", AuthorityPatch{PrivateKey: &otherKey}); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("want mismatch, got %v", err)
	}
	var empty = ""
	if err := api.CaUpdate("u-a", AuthorityPatch{PrivateKey: &empty}); err == nil || !strings.Contains(err.Error(), "can not be removed") {
		t.Errorf("want can not be removed, got %v", err)
	}
	fake.wantNoPosts()
	if err := api.CaUpdate("u-a", AuthorityPatch{PrivateKey: &key}); err != nil {
		t.Fatal(err)
	}
	var body = fake.onePost("/api/trust/ca/set/u-a")
	if body["prv_payload"] != key {
		t.Errorf("unexpected body %v", body)
	}
}

// caTestRenew issues a new self-signed certificate for the PEM key
func caTestRenew(t *testing.T, keyPem string, commonName string) string {
	t.Helper()
	var signer, err = caParsePrivateKey(keyPem)
	if err != nil {
		t.Fatal(err)
	}
	var template = &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCaReplace(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.on("GET", caTestSearchPath, caTestSearch(caTestRows...))
	fake.on("POST", "/api/trust/ca/set/u-nokey", `{"result":"saved"}`)

	if err := api.CaReplaceInternal("u-nokey", AuthorityInternal{Description: "imported", Subject: AuthoritySubject{CommonName: "new"}}); err != nil {
		t.Fatal(err)
	}
	var body = fake.onePost("/api/trust/ca/set/u-nokey")
	if body["action"] != "internal" || body["commonname"] != "new" || body["caref"] != "" {
		t.Errorf("unexpected body %v", body)
	}
	if err := api.CaReplaceInternal("unknown", AuthorityInternal{Description: "x"}); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	var certificate, _ = caTestPair(t, "A", true)
	if err := api.CaReplaceImport("unknown", AuthorityImport{Description: "x", Certificate: certificate}); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
}

func TestCaRemove(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.on("GET", caTestSearchPath, caTestSearch(caTestRows...))
	fake.on("POST", "/api/trust/ca/del/u-inter", `{"result":"deleted"}`)

	if err := api.CaRemove("u-inter"); err != nil {
		t.Fatal(err)
	}
	fake.onePost("/api/trust/ca/del/u-inter")
	if err := api.CaRemove("unknown"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
}

func TestCaRemoveInUseIsRefused(t *testing.T) {
	var api, fake = caTestApi(t)
	fake.on("GET", caTestSearchPath, caTestSearch(caTestRows...))
	fake.on("GET", "/api/trust/cert/search", `{"rows":[{"uuid":"c1","descr":"web","caref":"6ade13e520da0"},`+
		`{"uuid":"c2","descr":"other","caref":"6ade14086671b"}],"rowCount":2,"total":2,"current":1}`)

	var err = api.CaRemove("u-root")
	var inUse *AuthorityInUseError
	if !errors.As(err, &inUse) {
		t.Fatalf("want in use, got %v", err)
	}
	if !reflect.DeepEqual(inUse.Authorities, []string{"inter"}) || !reflect.DeepEqual(inUse.Certificates, []string{"web"}) {
		t.Errorf("unexpected users %+v", inUse)
	}
	if !strings.Contains(err.Error(), `"root" is in use (2 reference(s)`) || !strings.Contains(err.Error(), `"inter"`) {
		t.Errorf("unexpected message %v", err)
	}
	fake.wantNoPosts()
}

func TestCaCheckPairFormats(t *testing.T) {
	var key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var template = &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	ecDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	// SEC 1 keys, after other PEM blocks, work; legacy certificates without basicConstraints are accepted
	var keyPem = "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n" +
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDer}))
	if err := CaCheckPair(certificate, keyPem); err != nil {
		t.Error(err)
	}
	var cert, _ = CaParseCertificate(certificate)
	if fingerprint := CaFingerprint(cert); len(fingerprint) != 95 || strings.ToUpper(fingerprint) != fingerprint {
		t.Errorf("fingerprint %q", fingerprint)
	}
}
