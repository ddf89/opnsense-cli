package cli

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

// Answers are shaped like OPNsense 26.7.7 (AliasController::getGeoIPAction, setAction, updateAction)

const (
	firewallAliasGeoipGetPath    = "/api/firewall/alias/get_geo_ip"
	firewallAliasGeoipSetPath    = "/api/firewall/alias/set"
	firewallAliasGeoipUpdatePath = "/api/firewall/alias/update/geoip"
	firewallAliasGeoipKey        = "Sup3rS3cretLicense"
	firewallAliasGeoipEmpty      = `{"alias":{"geoip":{"url":"","usages":0,"address_count":0,"file_count":0,"timestamp":null,` +
		`"locations_filename":null,"address_sources":{"IPv4":null,"IPv6":null}}}}`
	firewallAliasGeoipLoaded = `{"alias":{"geoip":{"url":"https:\/\/download.maxmind.com\/app\/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=` +
		firewallAliasGeoipKey + `&suffix=zip","usages":2,"address_count":412345,"file_count":498,"timestamp":"2026-10-20T12:00:00",` +
		`"locations_filename":"GeoLite2-Country-Locations-en.csv","address_sources":{"IPv4":"GeoLite2-Country-Blocks-IPv4.csv","IPv6":"GeoLite2-Country-Blocks-IPv6.csv"}}}}`
	// a URL saved but never downloaded, used by two geoip aliases
	firewallAliasGeoipPending = `{"alias":{"geoip":{"url":"https:\/\/ipinfo.example\/data\/country.csv.gz?token=` + firewallAliasGeoipKey +
		`","usages":2,"address_count":0,"file_count":0,"timestamp":null,"locations_filename":null,"address_sources":{"IPv4":null,"IPv6":null}}}}`
)

// firewallAliasGeoipWantFields asserts "name: value" lines of c.Fields output (aligned with any spaces)
func firewallAliasGeoipWantFields(t *testing.T, out string, fields ...string) {
	t.Helper()
	for _, field := range fields {
		var name, value, _ = strings.Cut(field, ": ")
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `: +` + regexp.QuoteMeta(value) + `$`).MatchString(out) {
			t.Errorf("want field %q in:\n%s", field, out)
		}
	}
}

func TestFirewallAliasGeoipMaskUrl(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		"": "",
		"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=K3y&suffix=zip": "https://download.maxmind.com/app/geoip_download?edition_id=***&license_key=***&suffix=***",
		"https://123456:K3y@download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip":           "https://***@download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=***",
		"https://opnsense-update.deciso.com/0a1b2c3d4e5f60718293a4b5c6d7e8f9/ipinfo_lite.csv.gz":                     "https://opnsense-update.deciso.com/***/ipinfo_lite.csv.gz",
		"http://example.com:8080/geo.zip?S3cret#frag":                                                                "http://example.com:8080/geo.zip?***#***",
		"https://example.com/geo.zip": "https://example.com/geo.zip",
		"not a url with K3y":          "***",
		"://broken":                   "***",
	} {
		if got := firewallAliasGeoipMaskUrl(raw); got != want {
			t.Errorf("mask %q: got %q, want %q", raw, got, want)
		}
	}
}

func TestFirewallAliasGeoipPrint(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", firewallAliasGeoipGetPath, 200, firewallAliasGeoipLoaded)
	var r = f.run("/firewall/alias/geoip", "print")
	wantExit(t, r, 0)
	firewallAliasGeoipWantFields(t, r.stdout,
		"url: https://download.maxmind.com/app/geoip_download?edition_id=***&license_key=***&suffix=***",
		"subscription: no", "aliases: 2", "addresses: 412345", "files: 498",
		"updated: 2026-10-20 12:00:00", "ipv6-file: GeoLite2-Country-Blocks-IPv6.csv")
	wantNotContains(t, "output", r.stdout+r.stderr, firewallAliasGeoipKey)

	r = f.run("/firewall/alias/geoip", "print", "json")
	wantExit(t, r, 0)
	wantNotContains(t, "json", r.stdout, firewallAliasGeoipKey)
	var object map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &object); err != nil || strings.Count(r.stdout, "\n") != 1 ||
		object["url"] != "https://download.maxmind.com/app/geoip_download?edition_id=***&license_key=***&suffix=***" ||
		object["address_count"] != float64(412345) || object["timestamp"] != "2026-10-20T12:00:00" {
		t.Errorf("json %v %q", err, r.stdout)
	}
	wantNoMutations(t, f)
}

func TestFirewallAliasGeoipPrintHints(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", firewallAliasGeoipGetPath, 200, firewallAliasGeoipEmpty)
	var r = f.run("/firewall/alias/geoip", "print")
	wantExit(t, r, 0)
	firewallAliasGeoipWantFields(t, r.stdout, "url: (none)", "aliases: 0", "updated: never")
	if r.stderr != "" {
		t.Errorf("no hint without geoip aliases: %q", r.stderr)
	}

	f.on("GET", firewallAliasGeoipGetPath, 200, `{"alias":{"geoip":{"url":"","usages":1,"address_count":0}}}`)
	r = f.run("/firewall/alias/geoip", "print")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "no data", "set url=")

	f.on("GET", firewallAliasGeoipGetPath, 200, firewallAliasGeoipPending)
	r = f.run("/firewall/alias/geoip", "print")
	wantExit(t, r, 0)
	firewallAliasGeoipWantFields(t, r.stdout, "url: https://ipinfo.example/data/country.csv.gz?token=***")
	wantContains(t, "stderr", r.stderr, `run "update"`)
	wantNotContains(t, "output", r.stdout+r.stderr, firewallAliasGeoipKey)
	wantNoMutations(t, f)
}

func TestFirewallAliasGeoipSet(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", firewallAliasGeoipSetPath, 200, `{"result":"saved"}`)
	var target = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=" + firewallAliasGeoipKey + "&suffix=zip"
	var r = f.run("/firewall/alias/geoip", "set", "url="+target)
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("set must be silent: %q", r.stdout)
	}
	// only the geoip node, never the aliases
	wantJSON(t, wantOneMutation(t, f, "POST", firewallAliasGeoipSetPath), map[string]any{"alias": map[string]any{"geoip": map[string]any{"url": target}}})

	f = newFakeOPN(t)
	f.on("POST", firewallAliasGeoipSetPath, 200, `{"result":"saved"}`)
	r = f.run("/firewall/alias/geoip", "set", "url=")
	wantExit(t, r, 0)
	wantJSON(t, wantOneMutation(t, f, "POST", firewallAliasGeoipSetPath), map[string]any{"alias": map[string]any{"geoip": map[string]any{"url": ""}}})
}

func TestFirewallAliasGeoipSetRefused(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	for _, args := range [][]string{
		{"set"},
		{"set", "url=ftp://example.com/" + firewallAliasGeoipKey},
		{"set", "url=example.com/geo.zip?key=" + firewallAliasGeoipKey},
		{"set", "url=https:///geo.zip?key=" + firewallAliasGeoipKey},
	} {
		var r = f.run(append([]string{"/firewall/alias/geoip"}, args...)...)
		wantFailure(t, r)
		// the URL usually contains a license key: never repeated in errors
		wantNotContains(t, "output", r.stdout+r.stderr, firewallAliasGeoipKey)
	}
	wantNoCalls(t, f)

	f.on("POST", firewallAliasGeoipSetPath, 200, `{"result":"failed","validations":{"alias.geoip.url":"Invalid URL."}}`)
	var r = f.run("/firewall/alias/geoip", "set", "url=https://bad_host.example/"+firewallAliasGeoipKey)
	wantFailure(t, r, "url: Invalid URL.")
	wantNotContains(t, "output", r.stdout+r.stderr, firewallAliasGeoipKey)
}

func TestFirewallAliasGeoipUpdate(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var updated atomic.Bool
	f.onFunc("GET", firewallAliasGeoipGetPath, func(w http.ResponseWriter, _ *http.Request) {
		if updated.Load() {
			_, _ = w.Write([]byte(firewallAliasGeoipLoaded))
		} else {
			_, _ = w.Write([]byte(firewallAliasGeoipPending))
		}
	})
	f.onFunc("POST", firewallAliasGeoipUpdatePath, func(w http.ResponseWriter, _ *http.Request) {
		updated.Store(true)
		_, _ = w.Write([]byte(`{"status":"ok","message":"Update completed"}`))
	})
	var r = f.run("/firewall/alias/geoip", "update")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "412345 networks in 498 country files")
	wantJSON(t, wantOneMutation(t, f, "POST", firewallAliasGeoipUpdatePath), map[string]any{})
}

func TestFirewallAliasGeoipUpdateFailures(t *testing.T) {
	t.Parallel()
	// no source: refused before anything is downloaded
	var f = newFakeOPN(t)
	f.on("GET", firewallAliasGeoipGetPath, 200, firewallAliasGeoipEmpty)
	wantFailure(t, f.run("/firewall/alias/geoip", "update"), "no GeoIP source", "set url=")
	wantNoMutations(t, f)

	// a business subscription is a source even without URL; OPNsense answers ok when nothing was downloaded
	f = newFakeOPN(t)
	f.on("GET", firewallAliasGeoipGetPath, 200, `{"alias":{"geoip":{"url":"","usages":1,"subscription":true,"address_count":0}}}`)
	f.on("POST", firewallAliasGeoipUpdatePath, 200, `{"status":"ok","message":"Update completed"}`)
	var r = f.run("/firewall/alias/geoip", "update")
	wantFailure(t, r, "brought no networks", "system log")
	wantOneMutation(t, f, "POST", firewallAliasGeoipUpdatePath)

	f = newFakeOPN(t)
	f.on("GET", firewallAliasGeoipGetPath, 200, firewallAliasGeoipPending)
	f.on("POST", firewallAliasGeoipUpdatePath, 200, `{"status":"failed","message":"Error updating action"}`)
	r = f.run("/firewall/alias/geoip", "update")
	wantFailure(t, r, "Error updating action")
	wantNotContains(t, "output", r.stdout+r.stderr, firewallAliasGeoipKey)
}
