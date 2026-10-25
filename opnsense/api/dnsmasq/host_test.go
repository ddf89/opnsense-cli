package dnsmasq

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

type hostTestRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   map[string]map[string]string
}

// newHostTestApi starts a fake OPNsense answering every request with handler, all requests are recorded
func newHostTestApi(t *testing.T, handler func(r hostTestRequest) any) (*DnsmasqApi, *[]hostTestRequest) {
	t.Helper()
	var requests []hostTestRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var recorded = hostTestRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query()}
		var raw, _ = io.ReadAll(r.Body)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &recorded.Body); err != nil {
				t.Errorf("invalid request body %q: %v", raw, err)
			}
		}
		requests = append(requests, recorded)
		_ = json.NewEncoder(w).Encode(handler(recorded))
	}))
	t.Cleanup(server.Close)

	var baseUrl, _ = url.Parse(server.URL)
	return &DnsmasqApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, &requests
}

func searchAnswer(hosts ...Host) any {
	return map[string]any{"rows": hosts, "rowCount": len(hosts), "total": len(hosts), "current": 1}
}

var hostTestRows = []Host{
	{Uuid: "u-foo", Host: "foo", Domain: "bar.lan", Ip: "10.0.0.1"},
	{Uuid: "u-foobar", Host: "foobar", Domain: "bar.lan", Ip: "10.0.0.2"},
	{Uuid: "u-foo-sub", Host: "foo", Domain: "sub.bar.lan", Ip: "10.0.0.3"},
	{Uuid: "u-foo-nodomain", Host: "foo", Domain: "", Hwaddr: "aa:bb:cc:dd:ee:ff"},
}

func TestHostGetByFQDNExactMatch(t *testing.T) {
	var api, requests = newHostTestApi(t, func(r hostTestRequest) any {
		// the real search is a substring match, so every row containing "foo" is returned
		return searchAnswer(hostTestRows...)
	})

	var host, err = api.HostGetByFQDN("FOO", "Bar.Lan")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host.Uuid != "u-foo" {
		t.Errorf("expected u-foo, got %s", host.Uuid)
	}
	if got := (*requests)[0]; got.Path != "/api/dnsmasq/settings/search_host" || got.Query.Get("searchPhrase") != "FOO" {
		t.Errorf("unexpected search request %+v", got)
	}

	host, err = api.HostGetByFQDN("foo", "")
	if err != nil || host.Uuid != "u-foo-nodomain" {
		t.Errorf("expected u-foo-nodomain, got %+v / %v", host, err)
	}
}

func TestHostGetByFQDNSubstringIsNotFound(t *testing.T) {
	var api, _ = newHostTestApi(t, func(r hostTestRequest) any {
		return searchAnswer(hostTestRows...)
	})

	for _, fqdn := range [][2]string{{"fo", "bar.lan"}, {"foo", "lan"}, {"oobar", "bar.lan"}} {
		var _, err = api.HostGetByFQDN(fqdn[0], fqdn[1])
		if !coreapi.IsNotFound(err) {
			t.Errorf("%v: expected NotFoundError, got %v", fqdn, err)
		}
	}
}

func TestHostGetByFQDNDuplicates(t *testing.T) {
	var api, _ = newHostTestApi(t, func(r hostTestRequest) any {
		return searchAnswer(
			Host{Uuid: "u-2", Host: "dup", Domain: "bar.lan"},
			Host{Uuid: "u-1", Host: "DUP", Domain: "bar.lan"},
		)
	})

	var _, err = api.HostGetByFQDN("dup", "bar.lan")
	var tooMany *coreapi.TooManyFoundError
	if !errors.As(err, &tooMany) {
		t.Fatalf("expected TooManyFoundError, got %v", err)
	}
	if !strings.Contains(err.Error(), "u-1, u-2") {
		t.Errorf("expected candidate uuids in error, got %q", err.Error())
	}

	// create must not add yet another duplicate
	if _, _, err = api.HostCreateOrUpdate(Host{Host: "dup", Domain: "bar.lan", Ip: "10.0.0.1"}); !errors.As(err, &tooMany) {
		t.Errorf("expected TooManyFoundError from create or update, got %v", err)
	}
}

func TestHostUpdateSendsOnlyGivenFields(t *testing.T) {
	var api, requests = newHostTestApi(t, func(r hostTestRequest) any {
		if strings.HasSuffix(r.Path, "/search_host") {
			return searchAnswer(hostTestRows...)
		}
		return map[string]string{"result": "saved"}
	})

	if err := api.HostUpdate("u-foo", HostFields{"descr": "new", "cnames": ""}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// the existence check comes first, set_host would create an unknown uuid
	if len(*requests) != 2 || (*requests)[0].Path != "/api/dnsmasq/settings/search_host" {
		t.Fatalf("expected search_host before set_host, got %+v", *requests)
	}
	var got = (*requests)[1]
	if got.Method != "POST" || got.Path != "/api/dnsmasq/settings/set_host/u-foo" {
		t.Errorf("unexpected request %s %s", got.Method, got.Path)
	}
	var sent = got.Body["host"]
	if len(sent) != 2 || sent["descr"] != "new" || sent["cnames"] != "" {
		t.Errorf("expected only descr and cnames to be sent, got %v", sent)
	}

	if err := api.HostUpdate("u-foo", HostFields{"description": "typo"}); err == nil {
		t.Errorf("expected error for unknown field")
	}
	if len(*requests) != 2 {
		t.Errorf("unknown field must not be sent")
	}
}

func TestHostUpdateUnknownUuid(t *testing.T) {
	// OPNsense 26.7 creates the host when set_host is called with a well-formed unknown uuid
	var api, requests = newHostTestApi(t, func(r hostTestRequest) any {
		if strings.HasSuffix(r.Path, "/search_host") {
			return searchAnswer(hostTestRows...)
		}
		return map[string]string{"result": "saved"}
	})

	var unknown = "0b3c6a1e-2f4d-4e5a-9b7c-8d9e0f1a2b3c"
	if err := api.HostUpdate(unknown, HostFields{"host": "ghost", "ip": "10.6.9.9"}); !coreapi.IsNotFound(err) {
		t.Errorf("expected NotFoundError, got %v", err)
	}
	// a stale uuid given to create or update must not resurrect the entry either
	if _, _, err := api.HostCreateOrUpdate(Host{Uuid: unknown, Host: "ghost", Ip: "10.6.9.9"}); !coreapi.IsNotFound(err) {
		t.Errorf("expected NotFoundError from create or update, got %v", err)
	}
	for _, request := range *requests {
		if request.Method != "GET" {
			t.Errorf("an unknown uuid must not be written: %s %s", request.Method, request.Path)
		}
	}
}

func TestHostUpdateBareFailureIsNotFound(t *testing.T) {
	// deleted between the existence check and the write
	var api, _ = newHostTestApi(t, func(r hostTestRequest) any {
		if strings.HasSuffix(r.Path, "/search_host") {
			return searchAnswer(hostTestRows...)
		}
		return map[string]string{"result": "failed"}
	})

	if err := api.HostUpdate("u-foo", HostFields{"descr": "x"}); !coreapi.IsNotFound(err) {
		t.Errorf("expected NotFoundError, got %v", err)
	}
}

func TestHostValidationErrorSurfaced(t *testing.T) {
	var api, _ = newHostTestApi(t, func(r hostTestRequest) any {
		if strings.HasSuffix(r.Path, "/search_host") {
			return searchAnswer()
		}
		return map[string]any{"result": "failed", "validations": map[string]string{
			"host.ip": "Please specify a valid network segment or IP address.",
		}}
	})

	var _, updated, err = api.HostCreateOrUpdate(Host{Host: "foo", Domain: "bar.lan", Ip: "bogus"})
	var validationErr *coreapi.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected ValidationError, got %v", err)
	}
	if updated || !strings.Contains(err.Error(), "host.ip: Please specify a valid") {
		t.Errorf("unexpected error message %q", err.Error())
	}
}

func TestHostCreateOrUpdate(t *testing.T) {
	var existing []Host
	var api, requests = newHostTestApi(t, func(r hostTestRequest) any {
		switch {
		case strings.HasSuffix(r.Path, "/search_host"):
			return searchAnswer(existing...)
		case strings.HasSuffix(r.Path, "/add_host"):
			return map[string]string{"result": "saved", "uuid": "u-new"}
		default:
			return map[string]string{"result": "saved"}
		}
	})

	var uuid, updated, err = api.HostCreateOrUpdate(Host{Host: "foo", Domain: "bar.lan", Ip: "10.0.0.1,fd00::1"})
	if err != nil || uuid != "u-new" || updated {
		t.Fatalf("expected create, got %s %v %v", uuid, updated, err)
	}
	var add = (*requests)[1]
	if add.Path != "/api/dnsmasq/settings/add_host" || add.Body["host"]["ip"] != "10.0.0.1,fd00::1" ||
		add.Body["host"]["local"] != "0" || add.Body["host"]["ignore"] != "0" {
		t.Errorf("unexpected add request %+v", add)
	}
	if _, hasUuid := add.Body["host"]["uuid"]; hasUuid {
		t.Errorf("uuid must not be sent")
	}

	existing = []Host{{Uuid: "u-old", Host: "foo", Domain: "bar.lan", Description: "old"}}
	uuid, updated, err = api.HostCreateOrUpdate(Host{Host: "foo", Domain: "bar.lan", Ip: "10.0.0.2"})
	if err != nil || uuid != "u-old" || !updated {
		t.Fatalf("expected update, got %s %v %v", uuid, updated, err)
	}
	var set = (*requests)[3]
	if set.Path != "/api/dnsmasq/settings/set_host/u-old" || set.Body["host"]["ip"] != "10.0.0.2" {
		t.Errorf("unexpected set request %+v", set)
	}
}

func TestHostRemove(t *testing.T) {
	var api, requests = newHostTestApi(t, func(r hostTestRequest) any {
		if strings.HasSuffix(r.Path, "/u-foo") {
			return map[string]string{"result": "deleted"}
		}
		return map[string]string{"result": "not found"}
	})

	if err := api.HostRemove("u-foo"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got := (*requests)[0]; got.Method != "POST" || got.Path != "/api/dnsmasq/settings/del_host/u-foo" {
		t.Errorf("unexpected request %s %s", got.Method, got.Path)
	}
	if err := api.HostRemove("missing"); !coreapi.IsNotFound(err) {
		t.Errorf("expected NotFoundError, got %v", err)
	}
}
