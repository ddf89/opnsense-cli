//go:build integration

package integration

import (
	"errors"
	"net/http"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dnsmasq"
	"opnsense-cli/opnsense/api/unbound"
)

func TestCoreBadCredentials(t *testing.T) {
	var good = coreApi(t)
	var bad = &api.OPNsense{BaseUrl: good.BaseUrl, ApiKey: "invalid-key", ApiSecret: "invalid-secret", NoSslVerify: good.NoSslVerify}

	var check = func(name string, err error) {
		t.Helper()
		var httpErr *api.HttpError
		if !errors.As(err, &httpErr) {
			t.Fatalf("%s: want *api.HttpError, got %T: %v", name, err, err)
		}
		if httpErr.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: want status 401, got %d (%s)", name, httpErr.StatusCode, httpErr.Message)
		}
	}

	var _, err = (&dnsmasq.DnsmasqApi{OPNsense: bad}).ServiceStatus()
	check("dnsmasq ServiceStatus", err)
	_, err = (&dnsmasq.DnsmasqApi{OPNsense: bad}).HostList("")
	check("dnsmasq HostList", err)
	_, err = (&unbound.UnboundApi{OPNsense: bad}).HostOverrideList()
	check("unbound HostOverrideList", err)
	_, err = (&dnsmasq.DnsmasqApi{OPNsense: bad}).HostCreate(dnsmasq.Host{Host: "never", Domain: testDomain("badcred")})
	check("dnsmasq HostCreate", err)
}

func TestCoreUnknownEndpoint(t *testing.T) {
	var core = coreApi(t)

	var endpoints = []string{
		core.EndpointForPluginControllerMethod("dnsmasq", "settings", "does_not_exist"),
		core.EndpointForPluginControllerMethod("doesnotexist", "settings", "search_item"),
	}
	for _, endpoint := range endpoints {
		var out map[string]any
		var err = core.DoJSON("GET", endpoint, nil, &out)
		if err == nil {
			t.Errorf("GET %s: want an error, got success with %v", endpoint, out)
			continue
		}
		var httpErr *api.HttpError
		if errors.As(err, &httpErr) && httpErr.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: want status 404, got %d", endpoint, httpErr.StatusCode)
		}

		if rows, err := api.Search[map[string]any](core, endpoint, "x"); err == nil {
			t.Errorf("Search %s: want an error, got %d rows", endpoint, len(rows))
		}
		if _, err := core.Mutate(endpoint, map[string]any{}); err == nil {
			t.Errorf("Mutate %s: want an error, got success", endpoint)
		}
	}
}

// TestCoreSearchPhraseEncoding checks that search phrases with special characters are url encoded and simply match nothing
func TestCoreSearchPhraseEncoding(t *testing.T) {
	var core = coreApi(t)
	var rows, err = api.Search[map[string]any](core, core.EndpointForPluginControllerMethod("dnsmasq", "settings", "search_host"), runDomain+" &x=1#?%")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("want no rows, got %v", rows)
	}
}
