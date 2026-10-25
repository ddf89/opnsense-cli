package cli

import (
	"reflect"
	"testing"
)

const (
	dhcrelayDestPath  = "/api/dhcrelay/settings/search_dest"
	dhcrelayRelayPath = "/api/dhcrelay/settings/search_relay"
	dhcrelayDestUuid  = "cc0f4cfe-8627-4109-b870-1d0c53147f0f"
	dhcrelayRelayUuid = "1a288696-da01-4942-ac1f-874b2c237d6f"
)

func dhcrelayFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(dhcrelayDestPath,
		map[string]any{"uuid": dhcrelayDestUuid, "name": "servers", "server": "198.51.100.67,198.51.100.68"},
		map[string]any{"uuid": "d6", "name": "servers6", "server": "2001:db8::67"})
	f.search(dhcrelayRelayPath, map[string]any{"uuid": dhcrelayRelayUuid, "enabled": "0", "interface": "lan", "%interface": "LAN",
		"destination": dhcrelayDestUuid, "%destination": "servers", "agent_info": "1", "carp_depend_on": "", "status": "grey"})
	return f
}

func TestDhcrelayDestination(t *testing.T) {
	t.Parallel()
	var f = dhcrelayFake(t)
	f.on("POST", "/api/dhcrelay/settings/add_dest", 200, answerAdded("d2"))
	f.on("POST", "/api/dhcrelay/settings/set_dest/"+dhcrelayDestUuid, 200, answerSaved)
	var r = f.run("/dhcrelay/destination", "print")
	wantExit(t, r, 0)
	if got := keaTestLines(r.stdout); !reflect.DeepEqual(got, []string{"#|NAME|SERVERS", "0|servers|198.51.100.67,198.51.100.68", "1|servers6|2001:db8::67"}) {
		t.Errorf("print %q", got)
	}
	wantExit(t, f.run("/dhcrelay/destination", "add", "name=other", "servers=192.0.2.67, 192.0.2.68"), 0)
	wantJSON(t, f.mutations()[0], map[string]any{"destination": map[string]any{"name": "other", "server": "192.0.2.67,192.0.2.68"}})
	wantExit(t, f.run("/dhcrelay/destination", "set", "servers", "servers=192.0.2.1"), 0)
	wantJSON(t, f.mutations()[1], map[string]any{"destination": map[string]any{"server": "192.0.2.1"}})

	var refused = dhcrelayFake(t)
	wantFailure(t, refused.run("/dhcrelay/destination", "add", "name=x", "servers=192.0.2.1,2001:db8::1"), "not both")
	wantFailure(t, refused.run("/dhcrelay/destination", "add", "name=x"), "servers")
	wantFailure(t, refused.run("/dhcrelay/destination", "add", "name=servers", "servers=192.0.2.1"), "exists already", dhcrelayDestUuid)
	refused.on("POST", "/api/dhcrelay/settings/del_dest/"+dhcrelayDestUuid, 500,
		`{"errorMessage":"DHCRelay -  {DHCRelay.relays.`+dhcrelayRelayUuid+`}\n","errorTitle":"Item destinations {servers} in use by:"}`)
	wantFailure(t, refused.run("/dhcrelay/destination", "remove", "servers"), "in use by", dhcrelayRelayUuid)
}

func TestDhcrelayRelay(t *testing.T) {
	t.Parallel()
	var f = dhcrelayFake(t)
	f.on("POST", "/api/dhcrelay/settings/add_relay", 200, answerAdded("r2"))
	var r = f.run("/dhcrelay/relay", "print")
	wantExit(t, r, 0)
	if got := keaTestLines(r.stdout); !reflect.DeepEqual(got, []string{"#|DISABLED|INTERFACE|DESTINATION|AGENT-INFO|STATUS", "0|yes|lan|servers|yes|disabled"}) {
		t.Errorf("print %q", got)
	}
	var show = f.run("/dhcrelay/relay", "show", "lan")
	wantExit(t, show, 0)
	if got := keaTestLines(show.stdout); !reflect.DeepEqual(got, []string{"uuid:|" + dhcrelayRelayUuid, "interface:|lan", "destination:|servers",
		"disabled:|yes", "agent-info:|yes", "carp-depend-on:"}) {
		t.Errorf("show %q", got)
	}

	// add is enabled unless disabled is given, the destination is given by name
	wantExit(t, f.run("/dhcrelay/relay", "add", "interface=lan", "destination=servers6"), 0)
	wantJSON(t, f.mutations()[0], map[string]any{"relay": map[string]any{"interface": "lan", "destination": "d6", "enabled": "1"}})
	wantExit(t, f.run("/dhcrelay/relay", "add", "interface=opt1", "destination=SERVERS", "disabled", "agent-info"), 0)
	wantJSON(t, f.mutations()[1], map[string]any{"relay": map[string]any{"interface": "opt1", "destination": dhcrelayDestUuid, "enabled": "0", "agent_info": "1"}})
	wantFailure(t, f.run("/dhcrelay/relay", "add", "interface=lan", "destination=servers"), "exists already")
	wantFailure(t, f.run("/dhcrelay/relay", "add", "interface=lan", "destination=nope"), "destination", `"servers"`, `"servers6"`)
	wantFailure(t, f.run("/dhcrelay/relay", "add", "interface=lan"), "destination")
	if len(f.mutations()) != 2 {
		t.Errorf("mutations %v", f.mutations())
	}
}

func TestDhcrelayToggleAndService(t *testing.T) {
	t.Parallel()
	var f = dhcrelayFake(t)
	f.on("POST", "/api/dhcrelay/settings/toggle_relay/"+dhcrelayRelayUuid+"/1", 200, `{"result":"Enabled","changed":true}`)
	f.on("POST", "/api/dhcrelay/settings/toggle_relay/"+dhcrelayRelayUuid+"/0", 200, `{"result":"Disabled","changed":false}`)
	f.on("POST", "/api/dhcrelay/service/reconfigure", 200, `{"status":"ok"}`)
	wantExit(t, f.run("/dhcrelay/relay", "enable", "0"), 0)
	var disable = f.run("/dhcrelay/relay", "disable", "lan")
	wantExit(t, disable, 0)
	wantContains(t, "stderr", disable.stderr, "already disabled")
	wantExit(t, f.run("/dhcrelay/service", "reconfigure"), 0)
	var paths []string
	for _, call := range f.mutations() {
		paths = append(paths, call.Path)
	}
	if !reflect.DeepEqual(paths, []string{"/api/dhcrelay/settings/toggle_relay/" + dhcrelayRelayUuid + "/1",
		"/api/dhcrelay/settings/toggle_relay/" + dhcrelayRelayUuid + "/0", "/api/dhcrelay/service/reconfigure"}) {
		t.Errorf("mutations %q", paths)
	}
	var help = f.run("/dhcrelay/destination", "?")
	wantNotContains(t, "help", help.stdout, "enable")
}
