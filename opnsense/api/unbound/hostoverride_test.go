package unbound

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"testing"
)

// newTestApi returns an UnboundApi talking to a test server which answers with handler
func newTestApi(t *testing.T, handler http.HandlerFunc) *UnboundApi {
	t.Helper()
	var server = httptest.NewServer(handler)
	t.Cleanup(server.Close)

	var serverUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &UnboundApi{OPNsense: &coreapi.OPNsense{BaseUrl: *serverUrl, ApiKey: "key", ApiSecret: "secret"}}
}

func writeJSON(t *testing.T, w http.ResponseWriter, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Fatal(err)
	}
}

func searchHandler(t *testing.T, rows []HostOverride) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/unbound/settings/search_host_override" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		writeJSON(t, w, map[string]any{"rows": rows, "rowCount": len(rows), "total": len(rows), "current": 1})
	}
}

func TestHostEntryGetByFQDNMatchesHostExactly(t *testing.T) {
	var searchPhrase string
	var rows = []HostOverride{
		{Uuid: "1", Host: "foobar", Domain: "example.com", Rr: "A"},
		{Uuid: "2", Host: "FOO", Domain: "Example.com", Rr: "A"},
		{Uuid: "3", Host: "foo", Domain: "other.com", Rr: "A"},
		{Uuid: "4", Host: "barfoo", Domain: "example.com", Rr: "A"},
	}
	var api = newTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		searchPhrase = r.URL.Query().Get("searchPhrase")
		searchHandler(t, rows)(w, r)
	})

	var found, err = api.HostEntryGetByFQDN("foo", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if found.Uuid != "2" {
		t.Errorf("expected uuid 2, got %q", found.Uuid)
	}
	if searchPhrase != "foo" {
		t.Errorf("expected searchPhrase foo, got %q", searchPhrase)
	}

	if _, err = api.HostEntryGetByFQDN("fo", "example.com"); !coreapi.IsNotFound(err) {
		t.Errorf("expected not found for a host prefix, got %v", err)
	}
	if exists, err := api.HostEntryExists("oo", "example.com"); exists || err != nil {
		t.Errorf("expected not existing without error, got %v, %v", exists, err)
	}
}

func TestHostOverrideGetByFQDNAndRr(t *testing.T) {
	var api = newTestApi(t, searchHandler(t, []HostOverride{
		{Uuid: "a", Host: "foo", Domain: "example.com", Rr: "A"},
		{Uuid: "aaaa", Host: "foo", Domain: "example.com", Rr: "AAAA"},
	}))

	var tooMany *coreapi.TooManyFoundError
	if _, err := api.HostEntryGetByFQDN("foo", "example.com"); !errors.As(err, &tooMany) {
		t.Errorf("expected TooManyFoundError, got %v", err)
	}

	var found, err = api.HostOverrideGetByFQDNAndRr("foo", "example.com", "AAAA")
	if err != nil {
		t.Fatal(err)
	}
	if found.Uuid != "aaaa" {
		t.Errorf("expected uuid aaaa, got %q", found.Uuid)
	}

	if _, err = api.HostOverrideGetByFQDNAndRr("foo", "example.com", "MX"); !coreapi.IsNotFound(err) {
		t.Errorf("expected not found, got %v", err)
	}
}

func TestHostOverrideGet(t *testing.T) {
	var api = newTestApi(t, searchHandler(t, []HostOverride{
		{Uuid: "a", Host: "foo", Domain: "example.com", Rr: "A"},
		{Uuid: "b", Host: "bar", Domain: "example.com", Rr: "TXT", Txtdata: "hello"},
	}))

	var found, err = api.HostOverrideGet("b")
	if err != nil {
		t.Fatal(err)
	}
	if found.Host != "bar" || found.Txtdata != "hello" {
		t.Errorf("unexpected entry %+v", found)
	}
	if _, err = api.HostOverrideGet("c"); !coreapi.IsNotFound(err) {
		t.Errorf("expected not found, got %v", err)
	}
}

func TestHostOverrideCreateSurfacesValidationError(t *testing.T) {
	var api = newTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/unbound/settings/add_host_override" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		writeJSON(t, w, map[string]any{"result": "failed", "validations": map[string]string{"host.rr": "Option [] not in list."}})
	})

	var uuid, err = api.HostOverrideCreate(HostOverride{Host: "foo", Domain: "example.com", Rr: "BOGUS"})
	var validationErr *coreapi.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected ValidationError, got %v", err)
	}
	if validationErr.Validations["host.rr"] == "" {
		t.Errorf("expected validation message for host.rr, got %v", validationErr.Validations)
	}
	if uuid != "" {
		t.Errorf("expected no uuid, got %q", uuid)
	}
}

func TestHostOverrideCreateReturnsUuid(t *testing.T) {
	var api = newTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		var host = body["host"]
		if host["hostname"] != "foo" || host["txtdata"] != "v=spf1 -all" || host["rr"] != "TXT" {
			t.Errorf("unexpected body %v", body)
		}
		// empty enabled / addptr are not sent, so OPNsense uses its defaults
		if _, sent := host["addptr"]; sent {
			t.Errorf("expected addptr to be omitted, got %v", body)
		}
		writeJSON(t, w, map[string]string{"result": "saved", "uuid": "new-uuid"})
	})

	var uuid, err = api.HostOverrideCreate(HostOverride{Host: "foo", Domain: "example.com", Rr: "TXT", Txtdata: "v=spf1 -all"})
	if err != nil {
		t.Fatal(err)
	}
	if uuid != "new-uuid" {
		t.Errorf("expected new-uuid, got %q", uuid)
	}
}

func TestHostOverrideUpdateReturnsUuid(t *testing.T) {
	var requests []string
	var api = newTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/unbound/settings/search_host_override":
			// the existence check, set_host_override would create an unknown uuid
			writeJSON(t, w, map[string]any{"rows": []HostOverride{{Uuid: "existing-uuid", Host: "foo", Domain: "example.com"}}})
		case r.Method == "POST" && r.URL.Path == "/api/unbound/settings/set_host_override/existing-uuid":
			// set_* does not answer with the uuid
			writeJSON(t, w, map[string]string{"result": "saved"})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	var uuid, err = api.HostOverrideUpdate(HostOverride{Uuid: "existing-uuid", Host: "foo", Domain: "example.com", Ip: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if uuid != "existing-uuid" {
		t.Errorf("expected existing-uuid, got %q", uuid)
	}
	if len(requests) != 2 || requests[0] != "GET /api/unbound/settings/search_host_override" {
		t.Errorf("expected the existence check before the update, got %v", requests)
	}
}

func TestHostOverrideUpdateUnknownUuid(t *testing.T) {
	// OPNsense 26.7 creates the entry when set_host_override is called with a well-formed unknown uuid
	var api = newTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("an unknown uuid must not be written: %s %s", r.Method, r.URL.Path)
		}
		writeJSON(t, w, map[string]any{"rows": []HostOverride{{Uuid: "other", Host: "foo", Domain: "example.com"}}})
	})

	var unknown = HostOverride{Uuid: "0b3c6a1e-2f4d-4e5a-9b7c-8d9e0f1a2b3c", Host: "foo", Domain: "example.com", Ip: "10.0.0.1"}
	if _, err := api.HostOverrideUpdate(unknown); !coreapi.IsNotFound(err) {
		t.Errorf("expected not found, got %v", err)
	}
	if _, err := api.HostOverrideCreateOrUpdate(unknown); !coreapi.IsNotFound(err) {
		t.Errorf("expected not found from create or update with a stale uuid, got %v", err)
	}
}

func TestHostOverrideUpdateBareFailureIsNotFound(t *testing.T) {
	// deleted between the existence check and the write
	var api = newTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			writeJSON(t, w, map[string]any{"rows": []HostOverride{{Uuid: "gone", Host: "foo", Domain: "example.com"}}})
			return
		}
		writeJSON(t, w, map[string]string{"result": "failed"})
	})

	if _, err := api.HostOverrideUpdate(HostOverride{Uuid: "gone", Host: "foo", Domain: "example.com"}); !coreapi.IsNotFound(err) {
		t.Errorf("expected not found, got %v", err)
	}
}

func TestHostOverrideCreateOrUpdate(t *testing.T) {
	var requests []string
	var api = newTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/api/unbound/settings/search_host_override":
			writeJSON(t, w, map[string]any{"rows": []HostOverride{
				{Uuid: "a", Host: "foo", Domain: "example.com", Rr: "A"},
				{Uuid: "other", Host: "foobar", Domain: "example.com", Rr: "AAAA"},
			}})
		case "/api/unbound/settings/set_host_override/a":
			writeJSON(t, w, map[string]string{"result": "saved"})
		case "/api/unbound/settings/add_host_override":
			writeJSON(t, w, map[string]string{"result": "saved", "uuid": "created"})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	// same FQDN and record type: update
	var uuid, err = api.HostOverrideCreateOrUpdate(HostOverride{Host: "foo", Domain: "example.com", Rr: "A", Ip: "10.0.0.2"})
	if err != nil || uuid != "a" {
		t.Errorf("expected update of a, got %q, %v", uuid, err)
	}
	// same FQDN, other record type (and no exact match for foobar): create
	uuid, err = api.HostOverrideCreateOrUpdate(HostOverride{Host: "foo", Domain: "example.com", Rr: "AAAA", Ip: "::1"})
	if err != nil || uuid != "created" {
		t.Errorf("expected create, got %q, %v", uuid, err)
	}

	var expected = []string{
		"GET /api/unbound/settings/search_host_override",
		"POST /api/unbound/settings/set_host_override/a",
		"GET /api/unbound/settings/search_host_override",
		"POST /api/unbound/settings/add_host_override",
	}
	if len(requests) != len(expected) {
		t.Fatalf("expected requests %v, got %v", expected, requests)
	}
	for i := range expected {
		if requests[i] != expected[i] {
			t.Errorf("expected request %q, got %q", expected[i], requests[i])
		}
	}
}

func TestHostEntryRemove(t *testing.T) {
	var api = newTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method %s", r.Method)
		}
		switch r.URL.Path {
		case "/api/unbound/settings/del_host_override/existing":
			writeJSON(t, w, map[string]string{"result": "deleted"})
		default:
			writeJSON(t, w, map[string]string{"result": "not found"})
		}
	})

	if err := api.HostEntryRemove("existing"); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if err := api.HostEntryRemove("unknown"); !coreapi.IsNotFound(err) {
		t.Errorf("expected not found, got %v", err)
	}
	if err := api.HostEntryRemove(""); err == nil {
		t.Errorf("expected an error for an empty uuid")
	}
}

func TestServiceRestartAndReconfigure(t *testing.T) {
	var answers = map[string]string{}
	var api = newTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method %s for %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, answers[r.URL.Path])
	})

	answers["/api/unbound/service/restart"] = `{"response":"OK"}`
	answers["/api/unbound/service/reconfigure"] = `{"status":"ok"}`
	if err := api.ServiceRestart(); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if err := api.ServiceReconfigure(); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	answers["/api/unbound/service/restart"] = `{"response":"Error (1)"}`
	answers["/api/unbound/service/reconfigure"] = `{"status":"failed"}`
	if err := api.ServiceRestart(); err == nil {
		t.Errorf("expected restart error")
	}
	if err := api.ServiceReconfigure(); err == nil {
		t.Errorf("expected reconfigure error")
	}
}
