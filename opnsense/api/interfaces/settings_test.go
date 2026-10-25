package interfaces

import (
	"reflect"
	"strings"
	"testing"
)

// testSettingsGet is interfaces/settings/get of OPNsense 26.7: disablevlanhwfilter is an option list, not a map
const testSettingsGet = `{"settings":{"disablechecksumoffloading":"1","disablesegmentationoffloading":"0",` +
	`"disablelargereceiveoffloading":"1","disablevlanhwfilter":[{"value":"Enable VLAN Hardware Filtering","selected":0},` +
	`{"value":"Disable VLAN Hardware Filtering","selected":0},{"value":"Leave default","selected":1}],"disableipv6":"0",` +
	`"dhcp6_norelease":"0","dhcp6_debug":"1","dhcp6_duid":"","dhcp6_ratimeout":"10"},` +
	`"duids":{"llt":"00:01:00:01:32:70:DE:DD:46:3D:2F:23:D3:E8","current":"00:01:00:01:32:70:DC:61:52:54:00:12:34:56"}}`

func TestSettingsGet(t *testing.T) {
	var api, requests = newTestApi(t, func(r testRequest) (int, string) { return 200, testSettingsGet })
	var settings, err = api.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	if (*requests)[0].Path != "/api/interfaces/settings/get" {
		t.Errorf("unexpected request %+v", (*requests)[0])
	}
	var want = Settings{DisableChecksumOffloading: "1", DisableSegmentationOffloading: "0", DisableLargeReceiveOffloading: "1",
		DisableVlanHwFilter: "2", DisableIpv6: "0", Dhcp6NoRelease: "0", Dhcp6Debug: "1", Dhcp6Duid: "", Dhcp6RaTimeout: "10",
		Duids: map[string]string{"llt": "00:01:00:01:32:70:DE:DD:46:3D:2F:23:D3:E8", "current": "00:01:00:01:32:70:DC:61:52:54:00:12:34:56"}}
	if !reflect.DeepEqual(settings, want) {
		t.Errorf("got  %+v\nwant %+v", settings, want)
	}

	var broken, _ = newTestApi(t, func(r testRequest) (int, string) { return 200, `{"other":{}}` })
	if _, err := broken.SettingsGet(); err == nil {
		t.Error("want an error without settings")
	}
}

func TestSettingsSetAndReconfigure(t *testing.T) {
	var answer = `{"result":"saved"}`
	var api, requests = newTestApi(t, func(r testRequest) (int, string) { return 200, answer })
	var on, timeout = "1", "30"
	if err := api.SettingsSet(SettingsFields{Dhcp6Debug: &on, Dhcp6RaTimeout: &timeout}); err != nil {
		t.Fatal(err)
	}
	var got = (*requests)[0]
	if got.Method != "POST" || got.Path != "/api/interfaces/settings/set" ||
		!reflect.DeepEqual(got.Body, map[string]any{"settings": map[string]any{"dhcp6_debug": "1", "dhcp6_ratimeout": "30"}}) {
		t.Errorf("unexpected request %+v", got)
	}
	var bad = "zz"
	if err := api.SettingsSet(SettingsFields{Dhcp6Duid: &bad}); err == nil || len(*requests) != 1 {
		t.Errorf("an invalid DUID must fail before any call: %v", err)
	}

	answer = `{"status":"ok"}`
	if err := api.SettingsReconfigure(); err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[1]; got.Method != "POST" || got.Path != "/api/interfaces/settings/reconfigure" {
		t.Errorf("unexpected request %+v", got)
	}
	answer = `{"status":"failed"}`
	if err := api.SettingsReconfigure(); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Errorf("want an error, got %v", err)
	}
}

func TestSettingsValidateDuid(t *testing.T) {
	for _, duid := range []string{"", "00:01:00:01:32:70:DE:DD:46:3D:2F:23:D3:E8", "00:03:00:01:46:3D:2F:23:D3:E8",
		"00:04:0A:75:73:5A:40:0D:F3:FF:90:06:80:E5:C5:7F:64:D5", "00:02:00:00:D2:6D", "00:00:00:04:aa:bb"} {
		if err := SettingsValidateDuid(duid); err != nil {
			t.Errorf("%q: %v", duid, err)
		}
	}
	for _, duid := range []string{"zz", "00:01:00:01:32", "00:05:00:01:32:70", "00:01:00:02:32:70", "00-01-00-01-32-70", "000:01:00:01:32:70"} {
		if err := SettingsValidateDuid(duid); err == nil {
			t.Errorf("%q: want an error", duid)
		}
	}
}
