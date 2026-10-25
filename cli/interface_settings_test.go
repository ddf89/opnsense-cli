package cli

import (
	"reflect"
	"strings"
	"testing"
)

const (
	interfaceSettingsGetPath = "/api/interfaces/settings/get"
	interfaceSettingsSetPath = "/api/interfaces/settings/set"
	interfaceSettingsGet     = `{"settings":{"disablechecksumoffloading":"1","disablesegmentationoffloading":"1",` +
		`"disablelargereceiveoffloading":"0","disablevlanhwfilter":[{"value":"Enable VLAN Hardware Filtering","selected":0},` +
		`{"value":"Disable VLAN Hardware Filtering","selected":1},{"value":"Leave default","selected":0}],"disableipv6":"0",` +
		`"dhcp6_norelease":"0","dhcp6_debug":"0","dhcp6_duid":"","dhcp6_ratimeout":"10"},` +
		`"duids":{"llt":"00:01:00:01:32:70:DE:DD:46:3D:2F:23:D3:E8","current":"00:01:00:01:32:70:DC:61:52:54:00:12:34:56"}}`
)

func TestInterfaceSettingsPrint(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", interfaceSettingsGetPath, 200, interfaceSettingsGet)
	var r = f.run("/interface/settings", "print")
	wantExit(t, r, 0)
	var want = []string{"disable-checksum-offload:|yes", "disable-segmentation-offload:|yes", "disable-large-receive-offload:|no",
		"vlan-hw-filter:|disable", "disable-ipv6:|no", "dhcp6-no-release:|no", "dhcp6-debug:|no", "dhcp6-duid:", "dhcp6-ra-timeout:|10"}
	if got := interfaceLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	var detail = f.run("/interface/settings", "print", "detail")
	wantContains(t, "stdout", detail.stdout, "duid-current:", "00:01:00:01:32:70:DC:61:52:54:00:12:34:56", "duid-llt:")
	var asJSON = f.run("/interface/settings", "print", "json")
	wantContains(t, "stdout", asJSON.stdout, `"disablevlanhwfilter":"1"`, `"dhcp6_ratimeout":"10"`)
	wantNoMutations(t, f)
}

func TestInterfaceSettingsSet(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", interfaceSettingsSetPath, 200, answerSaved)
	var r = f.run("/interface/settings", "set", "disable-checksum-offload=no", "vlan-hw-filter=Default", "dhcp6-ra-timeout=0",
		"dhcp6-duid=00:03:00:01:46:3D:2F:23:D3:E8")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("set must be silent: %q", r.stdout)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", interfaceSettingsSetPath), map[string]any{"settings": map[string]any{
		"disablechecksumoffloading": "0", "disablevlanhwfilter": "2", "dhcp6_ratimeout": "0", "dhcp6_duid": "00:03:00:01:46:3D:2F:23:D3:E8"}})

	for _, args := range [][]string{{}, {"vlan-hw-filter=off"}, {"dhcp6-ra-timeout=-1"}, {"dhcp6-duid=zz"}, {"disable-ipv6=maybe"}} {
		var refused = newFakeOPN(t)
		wantFailure(t, refused.run(append([]string{"/interface/settings", "set"}, args...)...))
		wantNoCalls(t, refused)
	}
	var invalid = newFakeOPN(t)
	invalid.on("POST", interfaceSettingsSetPath, 200, answerValidation("settings.dhcp6_ratimeout", "Invalid integer value."))
	wantFailure(t, invalid.run("/interface/settings", "set", "dhcp6-ra-timeout=5"), "Invalid integer value")
}

func TestInterfaceSettingsApply(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", "/api/interfaces/settings/reconfigure", 200, `{"status":"ok"}`)
	// all interfaces are reconfigured: confirmation needed, nothing is sent without it
	wantFailure(t, f.run("/interface/settings", "apply"), "every interface", "confirm=yes")
	wantFailure(t, f.run("/interface/settings", "apply", "confirm=no"), "confirm")
	wantNoCalls(t, f)
	wantExit(t, f.run("/interface/settings", "apply", "confirm=yes"), 0)
	if got := wantOneMutation(t, f, "POST", "/api/interfaces/settings/reconfigure"); strings.TrimSpace(got.Body) != "{}" {
		t.Errorf("want a {} body, got %q", got.Body)
	}
}
