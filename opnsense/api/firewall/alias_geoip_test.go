package firewall

import (
	"errors"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

// Answers are shaped like OPNsense 26.7.7 (AliasController::getGeoIPAction, setAction, updateAction)

const (
	aliasGeoIPEmpty = `{"alias":{"geoip":{"url":"","usages":0,"address_count":0,"file_count":0,"timestamp":null,` +
		`"locations_filename":null,"address_sources":{"IPv4":null,"IPv6":null}}}}`
	aliasGeoIPLoaded = `{"alias":{"geoip":{"url":"https:\/\/download.example.com\/geo.zip?license_key=K","usages":2,` +
		`"subscription":false,"address_count":412345,"file_count":498,"timestamp":"2026-10-20T12:00:00",` +
		`"locations_filename":"GeoLite2-Country-Locations-en.csv","address_sources":{"IPv4":"GeoLite2-Country-Blocks-IPv4.csv","IPv6":"GeoLite2-Country-Blocks-IPv6.csv"}}}}`
)

func TestAliasGeoIPGet(t *testing.T) {
	var api, _ = aliasTestApi(t, map[string]aliasTestAnswer{"GET /api/firewall/alias/get_geo_ip": aliasTestOk(aliasGeoIPLoaded)})
	var geoip, err = api.AliasGeoIPGet()
	if err != nil {
		t.Fatal(err)
	}
	if geoip.Url != "https://download.example.com/geo.zip?license_key=K" || geoip.Usages != 2 || geoip.AddressCount != 412345 ||
		geoip.FileCount != 498 || geoip.Timestamp != "2026-10-20T12:00:00" || geoip.Subscription == nil || *geoip.Subscription ||
		geoip.AddressSources.IPv6 != "GeoLite2-Country-Blocks-IPv6.csv" || geoip.LocationsFilename != "GeoLite2-Country-Locations-en.csv" {
		t.Errorf("geoip %+v", geoip)
	}

	api, _ = aliasTestApi(t, map[string]aliasTestAnswer{"GET /api/firewall/alias/get_geo_ip": aliasTestOk(aliasGeoIPEmpty)})
	if geoip, err = api.AliasGeoIPGet(); err != nil || geoip.Url != "" || geoip.Timestamp != "" || geoip.Subscription != nil {
		t.Errorf("geoip %+v %v", geoip, err)
	}

	// without statistics (no download yet) only usages and address_count are there
	api, _ = aliasTestApi(t, map[string]aliasTestAnswer{"GET /api/firewall/alias/get_geo_ip": aliasTestOk(`{"alias":{"geoip":{"url":"","usages":1,"address_count":0}}}`)})
	if geoip, err = api.AliasGeoIPGet(); err != nil || geoip.Usages != 1 {
		t.Errorf("geoip %+v %v", geoip, err)
	}

	api, _ = aliasTestApi(t, map[string]aliasTestAnswer{"GET /api/firewall/alias/get_geo_ip": aliasTestOk(`[]`)})
	if _, err = api.AliasGeoIPGet(); err == nil {
		t.Error("want an error for an answer without alias.geoip")
	}
}

func TestAliasGeoIPSetUrl(t *testing.T) {
	var api, calls = aliasTestApi(t, map[string]aliasTestAnswer{"POST /api/firewall/alias/set": aliasTestOk(`{"result":"saved"}`)})
	if err := api.AliasGeoIPSetUrl("https://example.com/geo.zip?k=1"); err != nil {
		t.Fatal(err)
	}
	if err := api.AliasGeoIPSetUrl(""); err != nil {
		t.Fatal(err)
	}
	var posts = aliasTestPosts(calls())
	if len(posts) != 2 || posts[0].Body != `{"alias":{"geoip":{"url":"https://example.com/geo.zip?k=1"}}}`+"\n" ||
		posts[1].Body != `{"alias":{"geoip":{"url":""}}}`+"\n" {
		t.Errorf("only the geoip node may be sent: %+v", posts)
	}

	api, _ = aliasTestApi(t, map[string]aliasTestAnswer{
		"POST /api/firewall/alias/set": aliasTestOk(`{"result":"failed","validations":{"alias.geoip.url":"Invalid URL."}}`),
	})
	var err = api.AliasGeoIPSetUrl("https://x")
	var validation *coreapi.ValidationError
	if !errors.As(err, &validation) || validation.Validations["url"] != "Invalid URL." {
		t.Errorf("want a validation error keyed url, got %v", err)
	}
}

func TestAliasGeoIPUpdate(t *testing.T) {
	var api, calls = aliasTestApi(t, map[string]aliasTestAnswer{
		"POST /api/firewall/alias/update/geoip": aliasTestOk(`{"status":"ok","message":"Update completed"}`),
		"GET /api/firewall/alias/get_geo_ip":    aliasTestOk(aliasGeoIPLoaded),
	})
	var geoip, err = api.AliasGeoIPUpdate()
	if err != nil || geoip.AddressCount != 412345 {
		t.Errorf("update %+v %v", geoip, err)
	}
	var all = calls()
	if len(all) != 2 || all[0].Method != "POST" || all[0].Path != "/api/firewall/alias/update/geoip" || all[0].Body != "{}\n" {
		t.Errorf("calls %+v", all)
	}

	api, calls = aliasTestApi(t, map[string]aliasTestAnswer{
		"POST /api/firewall/alias/update/geoip": aliasTestOk(`{"status":"failed","message":"Error updating action"}`),
	})
	if _, err = api.AliasGeoIPUpdate(); err == nil || len(calls()) != 1 {
		t.Errorf("want a failure without reading the statistics, got %v %+v", err, calls())
	}
}
