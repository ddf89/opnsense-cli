package system

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// haSyncTestGet is a core/hasync/get answer of OPNsense 26.7 (sync items shortened, a password set)
const haSyncTestGet = `{"hasync":{"disablepreempt":"0","disconnectppps":"1","pfsyncinterface":{"":{"value":"Disabled","selected":0},` +
	`"lan":{"value":"LAN","selected":0},"opt2":{"value":"SYNC","selected":1}},"pfsyncpeerip":"10.99.0.2",` +
	`"pfsyncversion":{"1301":{"value":"OPNsense 24.1 or below","selected":0},"1400":{"value":"OPNsense 24.7 or above","selected":1}},` +
	`"pfsyncdefer":"0","synchronizetoip":"10.99.0.2","verifypeer":"0","username":"root","password":"s3cret",` +
	`"syncitems":{"aliases":{"value":"Aliases","selected":1},"cron":{"value":"Cron","selected":0},"rules":{"value":"Firewall Rules","selected":1}}}}`

func TestHaSyncSettings(t *testing.T) {
	var api, server = newCoreTestApi(t, map[string]string{
		"GET /api/core/hasync/get":          haSyncTestGet,
		"POST /api/core/hasync/set":         `{"result":"saved"}`,
		"POST /api/core/hasync/reconfigure": `{"status":"ok"}`,
	})
	var settings, err = api.HaSyncSettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	if settings.DisconnectPpps != "1" || settings.PfsyncInterface != "opt2" || settings.PfsyncVersion != "1400" ||
		settings.SyncItems != "aliases,rules" || settings.Password != "s3cret" || settings.Username != "root" ||
		settings.SynchronizeToIp != "10.99.0.2" || settings.PfsyncPeerIp != "10.99.0.2" {
		t.Errorf("unexpected settings %+v", settings)
	}
	var wantInterfaces = []HaSyncOption{{Key: "", Name: "Disabled"}, {Key: "lan", Name: "LAN"}, {Key: "opt2", Name: "SYNC", Selected: true}}
	if !reflect.DeepEqual(settings.Options["pfsyncinterface"], wantInterfaces) || len(settings.Options["syncitems"]) != 3 {
		t.Errorf("unexpected options %+v", settings.Options)
	}
	if encoded, _ := json.Marshal(settings); strings.Contains(string(encoded), "s3cret") {
		t.Errorf("the password must not be marshalled: %s", encoded)
	}

	var on, items = "1", "aliases,nat"
	if err := api.HaSyncSettingsUpdate(HaSyncSettingsPatch{PfsyncDefer: &on, SyncItems: &items}); err != nil {
		t.Fatal(err)
	}
	if err := api.HaSyncReconfigure(); err != nil {
		t.Fatal(err)
	}
	var posts = server.posts()
	if len(posts) != 2 || posts[0].Path != "/api/core/hasync/set" || posts[1].Path != "/api/core/hasync/reconfigure" || posts[1].Body != "" {
		t.Fatalf("unexpected posts %+v", posts)
	}
	var body map[string]map[string]string
	if err := json.Unmarshal([]byte(posts[0].Body), &body); err != nil ||
		!reflect.DeepEqual(body, map[string]map[string]string{"hasync": {"pfsyncdefer": "1", "syncitems": "aliases,nat"}}) {
		t.Errorf("unexpected set body %s", posts[0].Body)
	}

	server.set("POST /api/core/hasync/set", `{"result":"failed","validations":{"hasync.pfsyncpeerip":"Please specify a valid network address."}}`)
	coreTestWantError(t, api.HaSyncSettingsUpdate(HaSyncSettingsPatch{PfsyncDefer: &on}), "valid network address")
	server.set("POST /api/core/hasync/reconfigure", `{"status":"failed"}`)
	coreTestWantError(t, api.HaSyncReconfigure(), `status "failed"`)
	coreTestWantError(t, api.HaSyncSettingsUpdate(HaSyncSettingsPatch{}), "no HA setting")
	if len(server.posts()) != 4 {
		t.Errorf("an empty patch must not be sent: %v", server.posts())
	}
}

func TestHaPeerVersion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer string
		want   HaPeerVersion
	}{
		{"no peer", `{"response":false}`, HaPeerVersion{Message: "no backup node configured (synchronize-to-ip) or it did not answer"}},
		{"error", `{"status":"error","message":"Connection refused"}`, HaPeerVersion{Message: "Connection refused"}},
		{"peer", `{"response":{"firmware":{"version":"26.7.6","_my_version":"26.7.7\n"},"base":{"version":"26.7.6"},` +
			`"kernel":{"version":"26.7.6"}}}`,
			HaPeerVersion{Reachable: true, Firmware: "26.7.6", Base: "26.7.6", Kernel: "26.7.6", Local: "26.7.7"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var api, _ = newCoreTestApi(t, map[string]string{"GET /api/core/hasync_status/version": tc.answer})
			var version, err = api.HaPeerVersionGet()
			if err != nil || version != tc.want {
				t.Errorf("got %+v %v, want %+v", version, err, tc.want)
			}
		})
	}
}

func TestHaRemoteServices(t *testing.T) {
	var api, server = newCoreTestApi(t, map[string]string{
		"GET /api/core/hasync_status/services": `{"total":2,"rowCount":2,"current":1,"rows":[` +
			`{"name":"unbound","description":"Unbound DNS","status":true,"uid":"unbound"},` +
			`{"name":"openvpn","id":1,"description":"OpenVPN","status":false,"nocheck":true,"uid":"openvpn_1"}]}`,
		"POST /api/core/hasync_status/restart/unbound": `{"response":true,"status":"ok"}`,
		"POST /api/core/hasync_status/start/openvpn/1": `{"status":"error","message":"Connection refused"}`,
		"POST /api/core/hasync_status/stop/unbound":    `null`,
		"POST /api/core/hasync_status/restart_all":     `{"status":"ok","count":7}`,
	})
	var services, raw, err = api.HaRemoteServiceListRaw()
	if err != nil {
		t.Fatal(err)
	}
	var want = []HaRemoteService{
		{Uid: "unbound", Name: "unbound", Description: "Unbound DNS", Running: true},
		{Uid: "openvpn_1", Name: "openvpn", Id: "1", Description: "OpenVPN", NoCheck: true},
	}
	if !reflect.DeepEqual(services, want) || len(raw) != 2 {
		t.Errorf("got  %+v\nwant %+v", services, want)
	}
	coreTestWantError(t, api.HaRemoteServiceAction("restart", "unbound", ""), "")
	coreTestWantError(t, api.HaRemoteServiceAction("start", "openvpn", "1"), "Connection refused")
	coreTestWantError(t, api.HaRemoteServiceAction("stop", "unbound", ""), "is a backup node configured")
	if count, err := api.HaSync(); err != nil || count != 7 {
		t.Errorf("HaSync %d %v", count, err)
	}
	var sent = len(server.posts())
	coreTestWantError(t, api.HaRemoteServiceAction("reload", "unbound", ""), "unknown remote service action")
	coreTestWantError(t, api.HaRemoteServiceAction("stop", " ", ""), "without name")
	if sent != 4 || len(server.posts()) != sent {
		t.Errorf("unexpected posts %v", server.posts())
	}
	server.set("POST /api/core/hasync_status/restart_all", `{"status":"failed"}`)
	if _, err := api.HaSync(); err == nil {
		t.Error("want an error for a failed sync")
	}
}
