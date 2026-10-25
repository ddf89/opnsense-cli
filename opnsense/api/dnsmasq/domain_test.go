package dnsmasq

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"strings"
	"testing"
)

const domainOverrideTestRows = `{"rows":[
	{"uuid":"u1","sequence":"1","domain":"corp.lan","ipset":"","srcip":"","port":"5353","ip":"10.0.0.53","descr":"corp dns"},
	{"uuid":"u2","sequence":"2","domain":"CORP.lan","ipset":"","srcip":"","port":"","ip":"fd00::53","descr":""},
	{"uuid":"u3","sequence":"1","domain":"sub.corp.lan","ipset":"","srcip":"","port":"","ip":"10.0.0.53","descr":""},
	{"uuid":"u4","sequence":"1","domain":"local.lan","ipset":"","srcip":"","port":"","ip":"","descr":""}
],"rowCount":4,"total":4,"current":1}`

// domainOverrideTestRequest is a request the fake OPNsense received
type domainOverrideTestRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   string
}

// domainOverrideTestServer answers search_domain with the test rows, every other endpoint with responses[path].
// Received requests are appended to requests
func domainOverrideTestServer(t *testing.T, responses map[string]string, requests *[]domainOverrideTestRequest) *DnsmasqApi {
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		*requests = append(*requests, domainOverrideTestRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Body: string(body)})

		if r.URL.Path == "/api/dnsmasq/settings/search_domain" {
			_, _ = w.Write([]byte(domainOverrideTestRows))
			return
		}
		if response, found := responses[r.URL.Path]; found {
			_, _ = w.Write([]byte(response))
			return
		}
		// OPNsense answers unknown endpoints with an empty 200
	}))
	t.Cleanup(server.Close)

	var baseUrl, _ = url.Parse(server.URL)
	return &DnsmasqApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}
}

func TestDomainOverrideFindExactMatch(t *testing.T) {
	var requests []domainOverrideTestRequest
	var api = domainOverrideTestServer(t, nil, &requests)

	// sub.corp.lan must not match, case and trailing dot are ignored
	var matches, err = api.DomainOverrideFindAll("Corp.LAN.", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 || matches[0].Uuid != "u1" || matches[1].Uuid != "u2" {
		t.Fatalf("expected u1 and u2, got %+v", matches)
	}
	if requests[0].Query.Get("searchPhrase") != "corp.lan" {
		t.Errorf("expected searchPhrase corp.lan, got %q", requests[0].Query.Get("searchPhrase"))
	}

	found, err := api.DomainOverrideFind("local.lan", "")
	if err != nil || found.Uuid != "u4" {
		t.Fatalf("expected u4, got %+v, %v", found, err)
	}
}

func TestDomainOverrideFindIpFilter(t *testing.T) {
	var requests []domainOverrideTestRequest
	var api = domainOverrideTestServer(t, nil, &requests)

	var found, err = api.DomainOverrideFind("corp.lan", "10.0.0.53")
	if err != nil || found.Uuid != "u1" || found.Port != "5353" || found.Description != "corp dns" {
		t.Fatalf("expected u1, got %+v, %v", found, err)
	}

	// IPv6 is compared semantically
	found, err = api.DomainOverrideFind("corp.lan", "FD00:0::53")
	if err != nil || found.Uuid != "u2" {
		t.Fatalf("expected u2, got %+v, %v", found, err)
	}

	_, err = api.DomainOverrideFind("corp.lan", "10.9.9.9")
	if !coreapi.IsNotFound(err) {
		t.Fatalf("expected NotFoundError, got %v", err)
	}
}

func TestDomainOverrideFindAmbiguous(t *testing.T) {
	var requests []domainOverrideTestRequest
	var api = domainOverrideTestServer(t, nil, &requests)

	var _, err = api.DomainOverrideFind("corp.lan", "")
	var tooMany *coreapi.TooManyFoundError
	if !errors.As(err, &tooMany) {
		t.Fatalf("expected TooManyFoundError, got %v", err)
	}
	if !strings.Contains(tooMany.Name, "u1") || !strings.Contains(tooMany.Name, "u2") {
		t.Errorf("expected candidate uuids in the error, got %q", tooMany.Name)
	}
}

func TestDomainOverrideUpdateSendsOnlyGivenFields(t *testing.T) {
	var requests []domainOverrideTestRequest
	var api = domainOverrideTestServer(t, map[string]string{
		"/api/dnsmasq/settings/get_domain/u1": `{"domainoverride":{"domain":"corp.lan","ip":"10.0.0.53"}}`,
		"/api/dnsmasq/settings/set_domain/u1": `{"result":"saved"}`,
	}, &requests)

	var port, description = "53", ""
	var err = api.DomainOverrideUpdate("u1", DomainOverrideFields{Port: &port, Description: &description})
	if err != nil {
		t.Fatal(err)
	}

	// the existence check comes first, set_domain would create an unknown uuid
	if len(requests) != 2 || requests[0].Method != "GET" || requests[0].Path != "/api/dnsmasq/settings/get_domain/u1" {
		t.Fatalf("expected GET get_domain/u1 before the update, got %v", requests)
	}
	var set = requests[1]
	var body map[string]map[string]string
	if err := json.Unmarshal([]byte(set.Body), &body); err != nil {
		t.Fatal(err)
	}
	var expected = map[string]string{"port": "53", "descr": ""}
	if set.Method != "POST" || set.Path != "/api/dnsmasq/settings/set_domain/u1" || len(body["domainoverride"]) != len(expected) {
		t.Fatalf("expected POST with only port and descr, got %s %s %s", set.Method, set.Path, set.Body)
	}
	for key, value := range expected {
		if actual, found := body["domainoverride"][key]; !found || actual != value {
			t.Errorf("expected %s=%q, got %q (present: %v)", key, value, actual, found)
		}
	}
}

func TestDomainOverrideUpdateUnknownUuid(t *testing.T) {
	var requests []domainOverrideTestRequest
	// OPNsense 26.7 creates the entry when set_domain is called with a well-formed unknown uuid
	var api = domainOverrideTestServer(t, map[string]string{
		"/api/dnsmasq/settings/get_domain/0b3c6a1e-2f4d-4e5a-9b7c-8d9e0f1a2b3c": `[]`,
		"/api/dnsmasq/settings/set_domain/0b3c6a1e-2f4d-4e5a-9b7c-8d9e0f1a2b3c": `{"result":"saved"}`,
	}, &requests)

	var port = "53"
	if err := api.DomainOverrideUpdate("0b3c6a1e-2f4d-4e5a-9b7c-8d9e0f1a2b3c", DomainOverrideFields{Port: &port}); !coreapi.IsNotFound(err) {
		t.Fatalf("expected NotFoundError, got %v", err)
	}
	for _, request := range requests {
		if request.Method != "GET" {
			t.Errorf("an unknown uuid must not be written: %s %s", request.Method, request.Path)
		}
	}
}

func TestDomainOverrideUpdateBareFailureIsNotFound(t *testing.T) {
	var requests []domainOverrideTestRequest
	// deleted between the existence check and the write (or a malformed uuid)
	var api = domainOverrideTestServer(t, map[string]string{
		"/api/dnsmasq/settings/get_domain/u1": `{"domainoverride":{"domain":"corp.lan"}}`,
		"/api/dnsmasq/settings/set_domain/u1": `{"result":"failed"}`,
	}, &requests)

	var port = "53"
	if err := api.DomainOverrideUpdate("u1", DomainOverrideFields{Port: &port}); !coreapi.IsNotFound(err) {
		t.Fatalf("expected NotFoundError, got %v", err)
	}
}

func TestDomainOverrideCreateValidationError(t *testing.T) {
	var requests []domainOverrideTestRequest
	var api = domainOverrideTestServer(t, map[string]string{
		"/api/dnsmasq/settings/add_domain": `{"result":"failed","validations":{"domainoverride.port":"Please specify a valid port number (1-65535)."}}`,
	}, &requests)

	var _, err = api.DomainOverrideCreate(DomainOverride{Uuid: "ignored", Domain: "corp.lan", Port: "70000"})
	var validationErr *coreapi.ValidationError
	if !errors.As(err, &validationErr) || !strings.Contains(err.Error(), "domainoverride.port") {
		t.Fatalf("expected ValidationError for the port, got %v", err)
	}

	var body map[string]map[string]any
	if err := json.Unmarshal([]byte(requests[0].Body), &body); err != nil {
		t.Fatal(err)
	}
	if _, found := body["domainoverride"]["uuid"]; found {
		t.Errorf("uuid must not be sent on create: %s", requests[0].Body)
	}
	if _, found := body["domainoverride"]["sequence"]; found {
		t.Errorf("empty sequence must be omitted to use the OPNsense default: %s", requests[0].Body)
	}
}

func TestDomainOverrideCreateOrUpdate(t *testing.T) {
	var requests []domainOverrideTestRequest
	var api = domainOverrideTestServer(t, map[string]string{
		"/api/dnsmasq/settings/add_domain":    `{"result":"saved","uuid":"new"}`,
		"/api/dnsmasq/settings/set_domain/u4": `{"result":"saved"}`,
	}, &requests)

	// same domain, other ip: a second server for the domain is created
	var uuid, created, err = api.DomainOverrideCreateOrUpdate(DomainOverride{Domain: "corp.lan", Ip: "10.0.0.54"})
	if err != nil || !created || uuid != "new" {
		t.Fatalf("expected create, got %s %v %v", uuid, created, err)
	}

	// same domain and (empty) ip: updated
	uuid, created, err = api.DomainOverrideCreateOrUpdate(DomainOverride{Domain: "local.lan", Description: "x"})
	if err != nil || created || uuid != "u4" {
		t.Fatalf("expected update of u4, got %s %v %v", uuid, created, err)
	}
	var last = requests[len(requests)-1]
	if last.Path != "/api/dnsmasq/settings/set_domain/u4" || strings.Contains(last.Body, "sequence") || strings.Contains(last.Body, "ipset") {
		t.Errorf("unexpected update request %s %s", last.Path, last.Body)
	}
}

func TestDomainOverrideGet(t *testing.T) {
	var requests []domainOverrideTestRequest
	var api = domainOverrideTestServer(t, map[string]string{
		"/api/dnsmasq/settings/get_domain/u1": `{"domainoverride":{"sequence":"1","domain":"corp.lan",
			"ipset":{"":{"value":"None","selected":0},"myalias":{"value":"myalias","selected":1}},
			"srcip":"","port":"5353","ip":"10.0.0.53","descr":"corp dns"}}`,
		"/api/dnsmasq/settings/get_domain/nope": `[]`,
	}, &requests)

	var domainOverride, err = api.DomainOverrideGet("u1")
	if err != nil {
		t.Fatal(err)
	}
	if domainOverride.Uuid != "u1" || domainOverride.Ipset != "myalias" || domainOverride.Port != "5353" {
		t.Errorf("unexpected %+v", domainOverride)
	}

	if _, err = api.DomainOverrideGet("nope"); !coreapi.IsNotFound(err) {
		t.Fatalf("expected NotFoundError, got %v", err)
	}
}
