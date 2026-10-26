//go:build integration

package integrationfirewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/firewall"
)

// The GeoIP URL is a setting of the alias model: the tests snapshot it, set documentation URLs carrying this run's
// prefix (example.com, a fake license key) and restore it. A disabled alias of this run checks that setting the URL
// keeps every alias. Nothing is downloaded (update/geoip only runs against the unit test fakes) and nothing is
// applied, so the URL never reaches the GeoIP updater

var (
	// geoipOriginal is the URL before the first change of this run, the sweep restores it when a test could not
	geoipOriginal    string
	geoipOriginalSet bool
	geoipOriginalMu  sync.Mutex
)

// geoipRawModel reads firewall/alias/get with the raw API: the geoip URL and the aliases by uuid without their
// statistics (AliasVolatileFields change with every packet)
func geoipRawModel(core *api.OPNsense) (string, map[string]map[string]json.RawMessage, error) {
	var container struct {
		Alias struct {
			GeoIP struct {
				Url string `json:"url"`
			} `json:"geoip"`
			Aliases struct {
				Alias map[string]map[string]json.RawMessage `json:"alias"`
			} `json:"aliases"`
		} `json:"alias"`
	}
	if err := core.DoJSON("GET", core.EndpointForModule("firewall/alias/get"), nil, &container); err != nil {
		return "", nil, err
	}
	for _, alias := range container.Alias.Aliases.Alias {
		for _, field := range firewall.AliasVolatileFields {
			delete(alias, field)
		}
	}
	return container.Alias.GeoIP.Url, container.Alias.Aliases.Alias, nil
}

func geoipRawSetUrl(core *api.OPNsense, url string) error {
	var _, err = core.Mutate(core.EndpointForModule("firewall/alias/set"), map[string]any{"alias": map[string]any{"geoip": map[string]string{"url": url}}})
	return err
}

// geoipSnapshot records the URL (once per run), registers its restore and returns it with the aliases
func geoipSnapshot(t *testing.T) (string, map[string]map[string]json.RawMessage) {
	t.Helper()
	var core = coreApi(t)
	var url, aliases, err = geoipRawModel(core)
	if err != nil {
		t.Fatalf("raw read of the alias model: %v", err)
	}
	if strings.Contains(url, runPrefix) {
		t.Fatalf("the GeoIP URL %q is still set by this run", url)
	}
	geoipOriginalMu.Lock()
	if !geoipOriginalSet {
		geoipOriginal, geoipOriginalSet = url, true
	}
	geoipOriginalMu.Unlock()
	t.Cleanup(func() {
		if err := geoipRawSetUrl(core, url); err != nil {
			t.Errorf("restoring the GeoIP URL failed: %v", err)
		}
		if restored, _, err := geoipRawModel(core); err != nil || restored != url {
			t.Errorf("GeoIP URL after the restore: %q (want %q) %v", restored, url, err)
		}
	})
	return url, aliases
}

// geoipTestUrl is a documentation URL with a fake license key, tagged with this run
func geoipTestUrl(label string) (url string, key string) {
	key = strings.ReplaceAll(runPrefix, "-", "") + "fakekey" + label
	return fmt.Sprintf("https://example.com/%s-%s.zip?edition_id=GeoLite2-Country-CSV&license_key=%s&suffix=zip", runPrefix, label, key), key
}

// geoipWantAliasesUnchanged compares the aliases (uuids and stored fields) with a snapshot
func geoipWantAliasesUnchanged(t *testing.T, before map[string]map[string]json.RawMessage, own string) {
	t.Helper()
	var _, after, err = geoipRawModel(coreApi(t))
	if err != nil {
		t.Fatalf("raw read of the alias model: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("%d aliases before, %d after", len(before), len(after))
	}
	if _, found := after[own]; !found {
		t.Errorf("the test alias %s is gone", own)
	}
	for uuid, fields := range before {
		if !reflect.DeepEqual(after[uuid], fields) {
			t.Errorf("alias %s changed:\n before %v\n after  %v", uuid, fields, after[uuid])
		}
	}
}

// geoipTestAlias creates a disabled geoip alias of this run (so geoip usages count it) and returns its uuid
func geoipTestAlias(t *testing.T, label string) string {
	t.Helper()
	var uuid, err = aliasFirewallApi(t).AliasCreate(firewall.AliasFields{
		"name": aliasTestName("geo" + label), "type": "geoip", "content": "NL", "proto": "IPv4", "enabled": "0",
		"description": testDescription("alias-geoip-" + label),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	aliasCleanup(t, uuid)
	return uuid
}

func TestAliasGeoIPSettings(t *testing.T) {
	var fw = aliasFirewallApi(t)
	var own = geoipTestAlias(t, "lib")
	var original, aliases = geoipSnapshot(t)

	var before, err = fw.AliasGeoIPGet()
	if err != nil || before.Url != original || before.Usages < 1 {
		t.Fatalf("get: %+v %v (want url %q and at least the test alias as usage)", before, err, original)
	}

	var url, _ = geoipTestUrl("lib")
	if err := fw.AliasGeoIPSetUrl(url); err != nil {
		t.Fatalf("set: %v", err)
	}
	var after, getErr = fw.AliasGeoIPGet()
	if getErr != nil || after.Url != url || after.Usages != before.Usages || after.AddressCount != before.AddressCount {
		t.Errorf("after set: %+v %v", after, getErr)
	}
	if raw, _, rawErr := geoipRawModel(coreApi(t)); rawErr != nil || raw != url {
		t.Errorf("raw url %q %v", raw, rawErr)
	}
	geoipWantAliasesUnchanged(t, aliases, own)

	t.Run("an invalid URL is refused and nothing changes", func(t *testing.T) {
		var err = fw.AliasGeoIPSetUrl("not a url")
		var validation *api.ValidationError
		if !errors.As(err, &validation) || validation.Validations["url"] == "" {
			t.Errorf("want a url validation error, got %v", err)
		}
		if geoip, err := fw.AliasGeoIPGet(); err != nil || geoip.Url != url {
			t.Errorf("url after the refused set: %q %v", geoip.Url, err)
		}
	})

	if err := fw.AliasGeoIPSetUrl(""); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if geoip, err := fw.AliasGeoIPGet(); err != nil || geoip.Url != "" {
		t.Errorf("url after clear: %q %v", geoip.Url, err)
	}
	geoipWantAliasesUnchanged(t, aliases, own)
}

func TestCliAliasGeoIP(t *testing.T) {
	var own = geoipTestAlias(t, "cli")
	var _, aliases = geoipSnapshot(t)

	var url, key = geoipTestUrl("cli")
	requireNoStdout(t, mustOpn(t, "/firewall/alias/geoip", "set", "url="+url))

	var result = mustOpn(t, "/firewall/alias/geoip", "print")
	var masked = "https://example.com/" + runPrefix + "-cli.zip?edition_id=***&license_key=***&suffix=***"
	requireContains(t, result, result.stdout, masked, "aliases:", "addresses:", "updated:")
	if strings.Contains(result.stdout+result.stderr, key) {
		t.Errorf("print shows the license key:\n%s", result)
	}
	result = mustOpn(t, "/firewall/alias/geoip", "print", "json")
	requireContains(t, result, result.stdout, `"url":"`+masked+`"`, `"usages":`)
	if strings.Contains(result.stdout, key) {
		t.Errorf("print json shows the license key:\n%s", result)
	}
	// the library reads the URL unmasked
	if geoip, err := aliasFirewallApi(t).AliasGeoIPGet(); err != nil || geoip.Url != url {
		t.Errorf("unmasked url %q %v", geoip.Url, err)
	}
	geoipWantAliasesUnchanged(t, aliases, own)

	result = mustFailOpn(t, "/firewall/alias/geoip", "set", "url=ftp://example.com/"+key)
	requireContains(t, result, result.stderr, "http")
	if strings.Contains(result.stderr, key) {
		t.Errorf("the error repeats the URL:\n%s", result)
	}

	requireNoStdout(t, mustOpn(t, "/firewall/alias/geoip", "set", "url="))
	result = mustOpn(t, "/firewall/alias/geoip", "print")
	requireContains(t, result, result.stdout, "(none)")
	geoipWantAliasesUnchanged(t, aliases, own)
}

// geoipSweep restores the GeoIP URL when it still carries this run's prefix and reports it
func geoipSweep(core *api.OPNsense) []string {
	var url, _, err = geoipRawModel(core)
	if err != nil || !strings.Contains(url, runPrefix) {
		return nil
	}
	if err := geoipRawSetUrl(core, geoipOriginal); err != nil {
		fmt.Fprintf(os.Stderr, "integration/firewall: sweep could not restore the GeoIP URL: %v\n", err)
		return nil
	}
	return []string{"geoip url"}
}
