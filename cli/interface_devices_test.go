package cli

import (
	"reflect"
	"strings"
	"testing"
)

// Tests of /interface/lagg, bridge, gif, gre, loopback and vxlan: their field mapping and apply

func interfaceDeviceFake(t *testing.T, controller string, rows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search("/api/interfaces/"+controller+"/search_item", rows...)
	f.search(interfaceAssignmentPath)
	return f
}

func TestInterfaceLagg(t *testing.T) {
	t.Parallel()
	const path = "/api/interfaces/lagg_settings/"
	var row = map[string]any{"uuid": "l1", "laggif": "lagg0", "members": "igb2,igb3", "%members": "igb2 (00:..), igb3 (00:..)",
		"primary_member": "", "proto": "lacp", "lacp_fast_timeout": "0", "use_flowid": "", "lagghash": "l2,l3", "lacp_strict": "1",
		"mtu": "", "descr": "uplink"}
	var f = interfaceDeviceFake(t, "lagg_settings", row)
	f.on("POST", path+"add_item", 200, answerAdded("l2"))
	var printed = f.run("/interface/lagg", "print")
	wantExit(t, printed, 0)
	var want = []string{"#|DEVICE|MEMBERS|PROTOCOL|MTU|DESCRIPTION", "0|lagg0|igb2,igb3|lacp|-|uplink"}
	if got := interfaceLines(printed.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	var shown = f.run("/interface/lagg", "show", "lagg0")
	wantExit(t, shown, 0)
	wantContains(t, "stdout", shown.stdout, "use-flowid:         default", "hash:               l2,l3", "lacp-strict:        yes",
		"lacp-fast-timeout:  no")

	wantExit(t, f.run("/interface/lagg", "add", "members=igb4, igb5", "protocol=FAILOVER", "primary=igb5", "use-flowid=no",
		"lacp-fast-timeout", "hash=l3,l4", "mtu=9000", "description=storage"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", path+"add_item"), map[string]any{"lagg": map[string]any{
		"members": "igb4,igb5", "proto": "failover", "primary_member": "igb5", "use_flowid": "0", "lacp_fast_timeout": "1",
		"lagghash": "l3,l4", "mtu": "9000", "descr": "storage"}})

	for _, args := range [][]string{{}, {"members=igb4", "protocol=bond"}, {"members=igb4", "mtu=500"}, {"members=igb4", "hash=l5"},
		{"members=igb4", "use-flowid=maybe"}} {
		var refused = interfaceDeviceFake(t, "lagg_settings")
		wantFailure(t, refused.run(append([]string{"/interface/lagg", "add"}, args...)...))
		wantNoCalls(t, refused)
	}

	// the device name is fixed: set does not send it
	var set = interfaceDeviceFake(t, "lagg_settings", row)
	set.on("POST", path+"set_item/l1", 200, answerSaved)
	wantExit(t, set.run("/interface/lagg", "set", "uplink", "use-flowid=default", "mtu="), 0)
	wantJSON(t, wantOneMutation(t, set, "POST", path+"set_item/l1"), map[string]any{"lagg": map[string]any{"use_flowid": "", "mtu": ""}})

	// apply reattaches members: confirmation needed, nothing is sent without it
	var apply = interfaceDeviceFake(t, "lagg_settings")
	apply.on("POST", path+"reconfigure", 200, `{"status":"ok"}`)
	wantFailure(t, apply.run("/interface/lagg", "apply"), "reattaches their members", "confirm=yes")
	wantNoCalls(t, apply)
	wantExit(t, apply.run("/interface/lagg", "apply", "confirm=yes"), 0)
	wantOneMutation(t, apply, "POST", path+"reconfigure")
}

func TestInterfaceBridge(t *testing.T) {
	t.Parallel()
	const path = "/api/interfaces/bridge_settings/"
	var row = map[string]any{"uuid": "b1", "bridgeif": "bridge0", "members": "opt1,opt2", "%members": "OPT1, OPT2", "linklocal": "0",
		"enablestp": "1", "proto": "rstp", "stp": "opt1", "maxage": "", "fwdelay": "", "holdcnt": "", "maxaddr": "", "timeout": "0",
		"span": "", "edge": "", "autoedge": "", "ptp": "", "autoptp": "", "static": "opt2", "private": "", "descr": "lab"}
	var f = interfaceDeviceFake(t, "bridge_settings", row)
	f.on("POST", path+"add_item", 200, answerAdded("b2"))
	var printed = f.run("/interface/bridge", "print")
	wantExit(t, printed, 0)
	var want = []string{"#|DEVICE|MEMBERS|STP|DESCRIPTION", "0|bridge0|opt1,opt2|yes|lab"}
	if got := interfaceLines(printed.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	var shown = f.run("/interface/bridge", "show", "0")
	wantExit(t, shown, 0)
	wantContains(t, "stdout", shown.stdout, "stp-members:", "sticky:", "opt2", "cache-timeout:")

	wantExit(t, f.run("/interface/bridge", "add", "members=opt3,opt4", "stp", "protocol=stp", "stp-members=opt3", "max-age=10",
		"forward-delay=5", "hold-count=2", "cache-size=100", "cache-timeout=0", "span=opt5", "edge=opt4", "private=opt3,opt4"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", path+"add_item"), map[string]any{"bridge": map[string]any{
		"members": "opt3,opt4", "enablestp": "1", "proto": "stp", "stp": "opt3", "maxage": "10", "fwdelay": "5", "holdcnt": "2",
		"maxaddr": "100", "timeout": "0", "span": "opt5", "edge": "opt4", "private": "opt3,opt4"}})

	for _, args := range [][]string{{}, {"members=opt3", "max-age=5"}, {"members=opt3", "forward-delay=31"}, {"members=opt3", "protocol=mstp"},
		{"members=opt3", "hold-count=0"}} {
		var refused = interfaceDeviceFake(t, "bridge_settings")
		wantFailure(t, refused.run(append([]string{"/interface/bridge", "add"}, args...)...))
		wantNoCalls(t, refused)
	}

	var apply = interfaceDeviceFake(t, "bridge_settings")
	apply.on("POST", path+"reconfigure", 200, `{"status":"ok"}`)
	wantFailure(t, apply.run("/interface/bridge", "apply"), "every bridge", "confirm=yes")
	wantNoCalls(t, apply)
	wantExit(t, apply.run("/interface/bridge", "apply", "confirm=yes"), 0)
	wantOneMutation(t, apply, "POST", path+"reconfigure")
}

func TestInterfaceGifGre(t *testing.T) {
	t.Parallel()
	var gifRow = map[string]any{"uuid": "g1", "local-addr": "wan", "if": "wan", "ipaddr": "", "gifif": "gif0", "remote-addr": "198.51.100.1",
		"tunnel-local-addr": "10.255.0.1", "tunnel-remote-addr": "10.255.0.2", "tunnel-remote-net": "30", "descr": "he.net",
		"link1": "0", "link2": "1"}
	var f = interfaceDeviceFake(t, "gif_settings", gifRow)
	f.on("POST", "/api/interfaces/gif_settings/add_item", 200, answerAdded("g2"))
	var printed = f.run("/interface/gif", "print")
	wantExit(t, printed, 0)
	var want = []string{"#|DEVICE|LOCAL|REMOTE|TUNNEL|DESCRIPTION", "0|gif0|wan|198.51.100.1|10.255.0.1 -> 10.255.0.2/30|he.net"}
	if got := interfaceLines(printed.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	// no-clamp only exists in newer releases: not shown when the record lacks it
	var shown = f.run("/interface/gif", "show", "gif0")
	wantExit(t, shown, 0)
	wantContains(t, "stdout", shown.stdout, "ecn:", "no-ingress-filter:      yes", "tunnel-prefix:          30")
	wantNotContains(t, "stdout", shown.stdout, "no-clamp")

	wantExit(t, f.run("/interface/gif", "add", "local-address=192.0.2.1", "remote-address=2001:db8::1", "tunnel-prefix=64",
		"ecn", "no-clamp", "description=v6"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/interfaces/gif_settings/add_item"), map[string]any{"gif": map[string]any{
		"local-addr": "192.0.2.1", "remote-addr": "2001:db8::1", "tunnel-remote-net": "64", "link1": "1", "noclamp": "1", "descr": "v6"}})

	var gre = interfaceDeviceFake(t, "gre_settings")
	gre.on("POST", "/api/interfaces/gre_settings/add_item", 200, answerAdded("r1"))
	wantFailure(t, gre.run("/interface/gre", "add", "local-address=wan", "remote-address=198.51.100.1", "ecn=yes"), "unknown argument")
	wantExit(t, gre.run("/interface/gre", "add", "local-address=wan_vip1", "remote-address=198.51.100.1",
		"tunnel-local-address=10.0.0.1", "tunnel-remote-address=10.0.0.2"), 0)
	wantJSON(t, wantOneMutation(t, gre, "POST", "/api/interfaces/gre_settings/add_item"), map[string]any{"gre": map[string]any{
		"local-addr": "wan_vip1", "remote-addr": "198.51.100.1", "tunnel-local-addr": "10.0.0.1", "tunnel-remote-addr": "10.0.0.2"}})

	for _, args := range [][]string{{"local-address=wan"}, {"remote-address=198.51.100.1"}, {"local-address=w an", "remote-address=198.51.100.1"},
		{"local-address=wan", "remote-address=host"}, {"local-address=wan", "remote-address=198.51.100.1", "tunnel-prefix=129"}} {
		var refused = interfaceDeviceFake(t, "gre_settings")
		wantFailure(t, refused.run(append([]string{"/interface/gre", "add"}, args...)...))
		wantNoCalls(t, refused)
	}

	// tunnel apply needs no confirmation
	var apply = interfaceDeviceFake(t, "gre_settings")
	apply.on("POST", "/api/interfaces/gre_settings/reconfigure", 200, `{"status":"ok"}`)
	wantExit(t, apply.run("/interface/gre", "apply"), 0)
	wantOneMutation(t, apply, "POST", "/api/interfaces/gre_settings/reconfigure")
}

func TestInterfaceLoopback(t *testing.T) {
	t.Parallel()
	const path = "/api/interfaces/loopback_settings/"
	var f = interfaceDeviceFake(t, "loopback_settings", map[string]any{"uuid": "lo-1", "deviceId": "1", "description": "router id"},
		map[string]any{"uuid": "lo-2", "deviceId": "4", "description": "anycast"})
	f.on("POST", path+"add_item", 200, answerAdded("lo-2"))
	f.on("POST", path+"set_item/lo-2", 200, answerSaved)
	f.on("POST", path+"del_item/lo-1", 200, answerDeleted)
	var printed = f.run("/interface/loopback", "print")
	wantExit(t, printed, 0)
	var want = []string{"#|DEVICE|DESCRIPTION", "0|lo1|router id", "1|lo4|anycast"}
	if got := interfaceLines(printed.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	var added = f.run("/interface/loopback", "add", "description=new")
	wantExit(t, added, 0)
	if added.stdout != "lo-2\n" || !strings.Contains(added.stderr, "device lo4") {
		t.Errorf("add:\n%s", added)
	}
	wantFailure(t, f.run("/interface/loopback", "add"), "description")
	wantExit(t, f.run("/interface/loopback", "set", "lo4", "description=x"), 0)
	wantExit(t, f.run("/interface/loopback", "remove", "router id"), 0)
	var mutations = f.mutations()
	if len(mutations) != 3 || mutations[1].Path != path+"set_item/lo-2" || mutations[2].Path != path+"del_item/lo-1" {
		t.Errorf("unexpected mutations %v", mutations)
	}
	wantJSON(t, mutations[1], map[string]any{"loopback": map[string]any{"description": "x"}})
}

func TestInterfaceVxlan(t *testing.T) {
	t.Parallel()
	const path = "/api/interfaces/vxlan_settings/"
	var f = interfaceDeviceFake(t, "vxlan_settings",
		map[string]any{"uuid": "x1", "deviceId": "1", "vxlanid": "100", "vxlanlocal": "203.0.113.1", "vxlanlocalport": "",
			"vxlanremote": "198.51.100.7", "vxlanremoteport": "", "vxlangroup": "", "vxlandev": "", "%vxlandev": "None"},
		map[string]any{"uuid": "x2", "deviceId": "2", "vxlanid": "200", "vxlanlocal": "192.168.1.1", "vxlanlocalport": "",
			"vxlanremote": "", "vxlanremoteport": "", "vxlangroup": "239.1.1.200", "vxlandev": "lan", "%vxlandev": "LAN"})
	f.on("POST", path+"add_item", 200, answerAdded("x3"))
	var printed = f.run("/interface/vxlan", "print")
	wantExit(t, printed, 0)
	var want = []string{"#|DEVICE|VNI|LOCAL|REMOTE|INTERFACE", "0|vxlan1|100|203.0.113.1|198.51.100.7|-", "1|vxlan2|200|192.168.1.1|239.1.1.200|lan"}
	if got := interfaceLines(printed.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	wantExit(t, f.run("/interface/vxlan", "add", "vni=300", "local-address=192.168.1.1", "group=ff05::300", "interface=lan", "local-port=4790"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", path+"add_item"), map[string]any{"vxlan": map[string]any{
		"vxlanid": "300", "vxlanlocal": "192.168.1.1", "vxlangroup": "ff05::300", "vxlandev": "lan", "vxlanlocalport": "4790"}})

	for _, args := range [][]string{
		{"vni=1", "local-address=192.0.2.1"},
		{"vni=1", "local-address=192.0.2.1", "remote-address=198.51.100.1", "group=239.1.1.1", "interface=lan"},
		{"vni=1", "local-address=192.0.2.1", "group=239.1.1.1"},
		{"vni=1", "local-address=192.0.2.1", "remote-address=198.51.100.1", "interface=lan"},
		{"vni=1", "local-address=192.0.2.1", "group=192.0.2.9", "interface=lan"},
		{"vni=16777216", "local-address=192.0.2.1", "remote-address=198.51.100.1"},
		{"local-address=192.0.2.1", "remote-address=198.51.100.1"},
	} {
		var refused = interfaceDeviceFake(t, "vxlan_settings")
		wantFailure(t, refused.run(append([]string{"/interface/vxlan", "add"}, args...)...))
		wantNoCalls(t, refused)
	}
	wantFailure(t, f.run("/interface/vxlan", "set", "vxlan2", "remote-address=198.51.100.1", "group=239.1.1.1"), "not both")
}
