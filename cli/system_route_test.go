package cli

import (
	"reflect"
	"strings"
	"testing"
)

const (
	systemRouteSearchPath   = "/api/routes/routes/searchroute"
	systemRouteGetPath      = "/api/routes/routes/getroute"
	systemRouteAddPath      = "/api/routes/routes/addroute"
	systemRouteSetPath      = "/api/routes/routes/setroute/"
	systemRouteDelPath      = "/api/routes/routes/delroute/"
	systemRouteTogglePath   = "/api/routes/routes/toggleroute/"
	systemRouteReconfigPath = "/api/routes/routes/reconfigure"
)

// systemRouteRow is a searchroute row as OPNsense 26.7 returns it
func systemRouteRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "network": "198.51.100.0/24", "gateway": "LAN_GW", "%gateway": "LAN_GW - 192.168.1.230",
		"descr": "", "enabled": "1",
	}, overrides)
}

// systemRouteGetRoute is getroute without uuid: the defaults of a new route with the gateway options
const systemRouteGetRoute = `{"route":{"network":"","gateway":{` +
	`"Null4":{"value":"Null4 - 127.0.0.1","selected":0},"Null6":{"value":"Null6 - ::1","selected":0},` +
	`"WAN_DHCP":{"value":"WAN_DHCP - 10.0.2.2","selected":0},"WAN_DHCP6":{"value":"WAN_DHCP6 - fe80::2","selected":0},` +
	`"LAN_GW":{"value":"LAN_GW - 192.168.1.230","selected":0}},"descr":"","enabled":"1"}}`

// systemRouteRows: r-doc (enabled), r-v6 (disabled), r-host (stored with host bits) and two routes for the same network
func systemRouteRows() []map[string]any {
	return []map[string]any{
		systemRouteRow(map[string]any{"uuid": "r-doc", "descr": "doc net"}),
		systemRouteRow(map[string]any{"uuid": "r-v6", "network": "2001:db8:1::/48", "gateway": "WAN_DHCP6",
			"%gateway": "WAN_DHCP6 - fe80::2", "descr": "v6 net", "enabled": "0"}),
		systemRouteRow(map[string]any{"uuid": "r-host", "network": "203.0.113.5/25", "descr": "host bits"}),
		systemRouteRow(map[string]any{"uuid": "r-d1", "network": "192.0.2.0/24", "descr": "dup"}),
		systemRouteRow(map[string]any{"uuid": "r-d2", "network": "192.0.2.0/24", "gateway": "Null4", "%gateway": "Null4 - 127.0.0.1"}),
	}
}

// systemRouteFake serves searchroute with rows and getroute with the gateway options
func systemRouteFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(systemRouteSearchPath, rows...)
	f.on("GET", systemRouteGetPath, 200, systemRouteGetRoute)
	return f
}

var systemRouteHeader = []string{"#", "DISABLED", "NETWORK", "GATEWAY", "GATEWAY-IP", "DESCRIPTION"}

func TestSystemRoutePrint(t *testing.T) {
	t.Parallel()
	var f = systemRouteFake(t, systemRouteRows()...)
	var r = f.run("/system/route", "print")
	wantExit(t, r, 0)
	var rows = systemCronWantTable(t, r.stdout, systemRouteHeader, 2,
		"198.51.100.0/24", "2001:db8:1::/48", "203.0.113.5/25", "192.0.2.0/24", "192.0.2.0/24")
	if len(rows) == 6 {
		if got := strings.Join(rows[1], "|"); got != "0|no|198.51.100.0/24|LAN_GW|192.168.1.230|doc net" {
			t.Errorf("row r-doc: %q", got)
		}
		if got := strings.Join(rows[2], "|"); got != "1|yes|2001:db8:1::/48|WAN_DHCP6|fe80::2|v6 net" {
			t.Errorf("row r-v6: %q", got)
		}
		if got := strings.Join(rows[5], "|"); got != "4|no|192.0.2.0/24|Null4|127.0.0.1|-" {
			t.Errorf("row r-d2: %q", got)
		}
	}
	wantSearchPhrases(t, f, systemRouteSearchPath, "")
	wantNoMutations(t, f)

	t.Run("search phrase is passed on", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		var r = f.run("/system/route", "print", "search=v6 net")
		wantExit(t, r, 0)
		systemCronWantTable(t, r.stdout, systemRouteHeader, 2, "2001:db8:1::/48")
		wantSearchPhrases(t, f, systemRouteSearchPath, "v6 net")
	})
	t.Run("detail", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		var r = f.run("/system/route", "print", "detail")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "0\n  uuid:", "r-doc", "network:      198.51.100.0/24", "gateway:      LAN_GW",
			"gateway-ip:   192.168.1.230", "description:  doc net", "\n1\n", "disabled:     yes", "\n4\n")
	})
	t.Run("json is the raw API rows", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		var r = f.run("/system/route", "print", "json")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != 5 || !strings.Contains(lines[0], `"uuid":"r-doc"`) || !strings.Contains(lines[0], `"%gateway":"LAN_GW - 192.168.1.230"`) {
			t.Errorf("json output:\n%s", r.stdout)
		}
	})
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t)
		var r = f.run("/system/route", "print")
		wantExit(t, r, 0)
		systemCronWantTable(t, r.stdout, systemRouteHeader, 2)
	})
	t.Run("the # of a filtered print selects in a script", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		f.on("POST", systemRouteSetPath+"r-v6", 200, answerSaved)
		var r = f.runScript("/system/route\nprint search=v6\nset 0 description=x\n")
		wantExit(t, r, 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemRouteSetPath+"r-v6"),
			map[string]any{"route": map[string]any{"network": "2001:db8:1::/48", "descr": "x"}})
	})
}

func TestSystemRouteShow(t *testing.T) {
	t.Parallel()
	for _, selector := range []string{"r-doc", "R-DOC", "198.51.100.0/24", "198.51.100.77/24", "0"} {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()
			var f = systemRouteFake(t, systemRouteRows()...)
			var r = f.run("/system/route", "show", selector)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, "uuid:         r-doc\n", "disabled:     no\n", "network:      198.51.100.0/24\n",
				"gateway:      LAN_GW\n", "gateway-ip:   192.168.1.230\n", "description:  doc net\n")
			wantNoMutations(t, f)
		})
	}
	for _, tc := range []struct{ selector, uuid string }{
		{"203.0.113.5/25", "r-host"},  // as stored
		{"203.0.113.0/25", "r-host"},  // canonical
		{"2001:DB8:1:0::/48", "r-v6"}, // other IPv6 notation
		{"2001:db8:1::1/48", "r-v6"},  // host bits
		{"item=2001:db8:1::/48", "r-v6"},
	} {
		t.Run(tc.selector, func(t *testing.T) {
			t.Parallel()
			var f = systemRouteFake(t, systemRouteRows()...)
			var r = f.run("/system/route", "show", tc.selector)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, "uuid:         "+tc.uuid+"\n")
		})
	}

	t.Run("network of several routes is an error listing the candidates", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		wantFailure(t, f.run("/system/route", "show", "192.0.2.0/24"), "r-d1", "r-d2")
	})
	t.Run("description is no name", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		wantFailure(t, f.run("/system/route", "show", "doc net"), "not found")
	})
	t.Run("unknown network", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		wantFailure(t, f.run("/system/route", "show", "198.51.100.0/25"), "not found")
	})
	t.Run("index out of range", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		wantFailure(t, f.run("/system/route", "show", "5"), "not found", "#5")
	})
	t.Run("item required, no API call", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t)
		wantFailure(t, f.run("/system/route", "show"), "item")
		wantNoCalls(t, f)
	})
}

func TestSystemRouteAdd(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		args []string
		want map[string]any
	}{
		{"defaults", []string{"network=203.0.113.0/24", "gateway=LAN_GW"},
			map[string]any{"network": "203.0.113.0/24", "gateway": "LAN_GW", "enabled": "1"}},
		{"all arguments", []string{"network=203.0.113.0/24", "gateway=LAN_GW", "description=to the lab", "disabled"},
			map[string]any{"network": "203.0.113.0/24", "gateway": "LAN_GW", "descr": "to the lab", "enabled": "0"}},
		{"host bits are cleared, the gateway name is matched case-insensitively", []string{"network=203.0.113.9/24", "gateway=lan_gw"},
			map[string]any{"network": "203.0.113.0/24", "gateway": "LAN_GW", "enabled": "1"}},
		{"IPv6 is canonical", []string{"network=2001:DB8:0:5:0::/64", "gateway=WAN_DHCP6", "disabled=no"},
			map[string]any{"network": "2001:db8:0:5::/64", "gateway": "WAN_DHCP6", "enabled": "1"}},
		{"an IPv4 network via an IPv6 gateway (RFC 5549)", []string{"network=203.0.113.0/24", "gateway=Null6"},
			map[string]any{"network": "203.0.113.0/24", "gateway": "Null6", "enabled": "1"}},
		{"another network than the existing routes", []string{"network=198.51.100.0/25", "gateway=LAN_GW"},
			map[string]any{"network": "198.51.100.0/25", "gateway": "LAN_GW", "enabled": "1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = systemRouteFake(t, systemRouteRows()...)
			f.on("POST", systemRouteAddPath, 200, answerAdded("r-new"))
			var r = f.run(append([]string{"/system/route", "add"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != "r-new\n" {
				t.Errorf("stdout must be the uuid: %q", r.stdout)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", systemRouteAddPath), map[string]any{"route": tc.want})
		})
	}

	t.Run("existing network fails without replace", func(t *testing.T) {
		t.Parallel()
		for _, network := range []string{"198.51.100.0/24", "198.51.100.1/24", "203.0.113.0/25"} {
			var f = systemRouteFake(t, systemRouteRows()...)
			var r = f.run("/system/route", "add", "network="+network, "gateway=Null4")
			wantFailure(t, r, "exists already", "replace")
			wantNoMutations(t, f)
		}
	})

	t.Run("replace replaces the route completely", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		f.on("POST", systemRouteSetPath+"r-host", 200, answerSaved)
		var r = f.run("/system/route", "add", "network=203.0.113.0/25", "gateway=Null4", "disabled", "replace")
		wantExit(t, r, 0)
		if r.stdout != "r-host\n" {
			t.Errorf("stdout must be the uuid: %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, "replaced the existing route for 203.0.113.0/25")
		wantJSON(t, wantOneMutation(t, f, "POST", systemRouteSetPath+"r-host"), map[string]any{"route": map[string]any{
			"network": "203.0.113.0/25", "gateway": "Null4", "descr": "", "enabled": "0",
		}})
	})

	t.Run("several routes for the network", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		wantFailure(t, f.run("/system/route", "add", "network=192.0.2.0/24", "gateway=LAN_GW", "replace"), "r-d1", "r-d2")
		wantNoMutations(t, f)
	})

	t.Run("unknown gateway lists the gateways", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		var r = f.run("/system/route", "add", "network=203.0.113.0/24", "gateway=nope")
		wantFailure(t, r, `unknown gateway "nope"`, "LAN_GW, Null4, Null6, WAN_DHCP, WAN_DHCP6", "20 seconds")
		wantNoMutations(t, f)
	})

	t.Run("an IPv6 network needs an IPv6 gateway", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		var r = f.run("/system/route", "add", "network=2001:db8:2::/48", "gateway=WAN_DHCP")
		wantFailure(t, r, "IPv6 network 2001:db8:2::/48 needs an IPv6 gateway", "WAN_DHCP is IPv4 (10.0.2.2)")
		wantNoMutations(t, f)
	})

	t.Run("no gateways", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.search(systemRouteSearchPath)
		f.on("GET", systemRouteGetPath, 200, `{"route":{"network":"","gateway":[],"descr":"","enabled":"1"}}`)
		wantFailure(t, f.run("/system/route", "add", "network=203.0.113.0/24", "gateway=LAN_GW"), `unknown gateway "LAN_GW"`)
		wantNoMutations(t, f)
	})

	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"network is required", []string{"gateway=LAN_GW"}, []string{"network"}},
		{"gateway is required", []string{"network=203.0.113.0/24"}, []string{"gateway"}},
		{"empty gateway", []string{"network=203.0.113.0/24", "gateway="}, []string{"gateway must not be empty"}},
		{"network without prefix length", []string{"network=203.0.113.1", "gateway=LAN_GW"}, []string{"network must be a network in CIDR notation", `"203.0.113.1"`}},
		{"network is no network", []string{"network=lan", "gateway=LAN_GW"}, []string{"network must be a network"}},
		{"prefix too long", []string{"network=203.0.113.0/33", "gateway=LAN_GW"}, []string{"network must be a network"}},
		{"empty network", []string{"network=", "gateway=LAN_GW"}, []string{"network must be a network"}},
		{"description with a newline", []string{"network=203.0.113.0/24", "gateway=LAN_GW", "description=a\nb"}, []string{"description must not contain control characters"}},
		{"description too long", []string{"network=203.0.113.0/24", "gateway=LAN_GW", "description=" + strings.Repeat("x", 256)}, []string{"description must be at most 255 characters"}},
		{"disabled is yes or no", []string{"network=203.0.113.0/24", "gateway=LAN_GW", "disabled=2"}, []string{"disabled must be yes or no"}},
		{"positional args are rejected", []string{"network=203.0.113.0/24", "gateway=LAN_GW", "extra"}, []string{"extra"}},
	} {
		t.Run(tc.name+", no API call", func(t *testing.T) {
			t.Parallel()
			var f = systemRouteFake(t)
			wantFailure(t, f.run(append([]string{"/system/route", "add"}, tc.args...)...), tc.wants...)
			wantNoCalls(t, f)
		})
	}

	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t)
		f.on("POST", systemRouteAddPath, 200,
			answerValidation("route.gateway", "Specify a valid gateway from the list matching the networks ip protocol."))
		wantFailure(t, f.run("/system/route", "add", "network=203.0.113.0/24", "gateway=LAN_GW"),
			"route.gateway", "Specify a valid gateway")
	})
}

func TestSystemRouteSet(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		args []string
		uuid string
		want map[string]any
	}{
		{"by uuid, the network is always sent", []string{"r-doc", "description=new"}, "r-doc",
			map[string]any{"network": "198.51.100.0/24", "descr": "new"}},
		{"by network", []string{"198.51.100.0/24", "disabled"}, "r-doc", map[string]any{"network": "198.51.100.0/24", "enabled": "0"}},
		{"by index", []string{"1", "disabled=no"}, "r-v6", map[string]any{"network": "2001:db8:1::/48", "enabled": "1"}},
		{"the stored network is sent unchanged", []string{"r-host", "description="}, "r-host",
			map[string]any{"network": "203.0.113.5/25", "descr": ""}},
		{"gateway", []string{"r-doc", "gateway=null4"}, "r-doc", map[string]any{"network": "198.51.100.0/24", "gateway": "Null4"}},
		{"move to another network", []string{"r-doc", "network=203.0.113.130/25"}, "r-doc", map[string]any{"network": "203.0.113.128/25"}},
		{"the same network in another notation", []string{"r-host", "network=203.0.113.0/25"}, "r-host", map[string]any{"network": "203.0.113.0/25"}},
		{"IPv4 network and IPv6 gateway", []string{"r-doc", "gateway=WAN_DHCP6"}, "r-doc",
			map[string]any{"network": "198.51.100.0/24", "gateway": "WAN_DHCP6"}},
		{"IPv6 network and gateway together", []string{"r-doc", "network=2001:db8:5::/48", "gateway=Null6"}, "r-doc",
			map[string]any{"network": "2001:db8:5::/48", "gateway": "Null6"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = systemRouteFake(t, systemRouteRows()...)
			f.on("POST", systemRouteSetPath+tc.uuid, 200, answerSaved)
			var r = f.run(append([]string{"/system/route", "set"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("set must be silent: %q", r.stdout)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", systemRouteSetPath+tc.uuid), map[string]any{"route": tc.want})
		})
	}

	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"nothing to change", []string{"r-doc"}, []string{"nothing to change"}},
		{"unknown gateway", []string{"r-doc", "gateway=nope"}, []string{`unknown gateway "nope"`}},
		{"IPv6 network with the IPv4 gateway of the route", []string{"r-doc", "network=2001:db8:5::/48"},
			[]string{"needs an IPv6 gateway", "LAN_GW is IPv4", "give a gateway= as well"}},
		{"IPv4 gateway for an IPv6 route", []string{"r-v6", "gateway=WAN_DHCP"}, []string{"IPv6 network 2001:db8:1::/48 needs an IPv6 gateway"}},
		{"network of another route", []string{"r-doc", "network=192.0.2.7/24"}, []string{"another route for 192.0.2.0/24", "r-d1, r-d2"}},
		{"network of several routes", []string{"192.0.2.0/24", "description=x"}, []string{"r-d1", "r-d2"}},
		{"unknown item", []string{"r-nope", "description=x"}, []string{"not found"}},
		{"invalid network", []string{"r-doc", "network=10.0.0.1"}, []string{"network must be a network"}},
		{"empty network", []string{"r-doc", "network="}, []string{"network must be a network"}},
		{"empty gateway", []string{"r-doc", "gateway="}, []string{"gateway must not be empty"}},
	} {
		t.Run(tc.name+", no change", func(t *testing.T) {
			t.Parallel()
			var f = systemRouteFake(t, systemRouteRows()...)
			wantFailure(t, f.run(append([]string{"/system/route", "set"}, tc.args...)...), tc.wants...)
			wantNoMutations(t, f)
		})
	}

	t.Run("nothing to change and argument errors need no API call", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		wantFailure(t, f.run("/system/route", "set", "r-doc"), "nothing to change")
		wantFailure(t, f.run("/system/route", "set", "description=x"), "item")
		wantNoCalls(t, f)
	})
	t.Run("removed meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		f.on("POST", systemRouteSetPath+"r-doc", 200, answerFailedBare)
		wantFailure(t, f.run("/system/route", "set", "r-doc", "description=x"), "not found")
	})
	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		f.on("POST", systemRouteSetPath+"r-doc", 200, answerValidation("route.network", "Specify a valid network matching the gateways ip protocol."))
		wantFailure(t, f.run("/system/route", "set", "r-doc", "description=x"), "route.network", "Specify a valid network")
	})
}

func TestSystemRouteRemove(t *testing.T) {
	t.Parallel()
	for _, selector := range []string{"r-doc", "198.51.100.0/24", "0"} {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()
			var f = systemRouteFake(t, systemRouteRows()...)
			f.on("POST", systemRouteDelPath+"r-doc", 200, answerDeleted)
			var r = f.run("/system/route", "remove", selector)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("remove must be silent: %q", r.stdout)
			}
			wantOneMutation(t, f, "POST", systemRouteDelPath+"r-doc")
		})
	}

	t.Run("network of several routes", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		wantFailure(t, f.run("/system/route", "remove", "192.0.2.0/24"), "r-d1", "r-d2")
		wantNoMutations(t, f)
	})
	t.Run("not found", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		wantFailure(t, f.run("/system/route", "remove", "r-nope"), "not found")
		wantNoMutations(t, f)
	})
	t.Run("removed meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		f.on("POST", systemRouteDelPath+"r-doc", 200, answerNotFound)
		wantFailure(t, f.run("/system/route", "remove", "r-doc"), "not found")
	})
	t.Run("no item, no API call", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		wantFailure(t, f.run("/system/route", "remove"), "item")
		wantNoCalls(t, f)
	})
}

func TestSystemRouteEnableDisable(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args     []string
		answer   string
		path     string
		wantInfo string
	}{
		{[]string{"enable", "r-v6"}, `{"result":"Enabled","changed":true}`, systemRouteTogglePath + "r-v6/1", ""},
		{[]string{"enable", "198.51.100.0/24"}, `{"result":"Enabled","changed":false}`, systemRouteTogglePath + "r-doc/1",
			"the route for 198.51.100.0/24 is already enabled"},
		{[]string{"disable", "0"}, `{"result":"Disabled","changed":true}`, systemRouteTogglePath + "r-doc/0", ""},
		{[]string{"disable", "2001:db8:1::/48"}, `{"result":"Disabled","changed":false}`, systemRouteTogglePath + "r-v6/0", "already disabled"},
	} {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			t.Parallel()
			var f = systemRouteFake(t, systemRouteRows()...)
			f.on("POST", tc.path, 200, tc.answer)
			var r = f.run(append([]string{"/system/route"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("%s must be silent: %q", tc.args[0], r.stdout)
			}
			if tc.wantInfo != "" {
				wantContains(t, "stderr", r.stderr, tc.wantInfo)
			} else if r.stderr != "" {
				t.Errorf("stderr: %q", r.stderr)
			}
			wantOneMutation(t, f, "POST", tc.path)
		})
	}

	t.Run("unknown item", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		wantFailure(t, f.run("/system/route", "enable", "r-nope"), "not found")
		wantNoMutations(t, f)
	})
	t.Run("removed meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t, systemRouteRows()...)
		f.on("POST", systemRouteTogglePath+"r-doc/0", 200, `{"result":"failed"}`)
		wantFailure(t, f.run("/system/route", "disable", "r-doc"), "not found")
	})
	t.Run("no item, no API call", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t)
		wantFailure(t, f.run("/system/route", "disable"), "item")
		wantNoCalls(t, f)
	})
}

func TestSystemRouteApply(t *testing.T) {
	t.Parallel()
	var f = systemRouteFake(t)
	f.on("POST", systemRouteReconfigPath, 200, `{"status":"ok"}`)
	var r = f.run("/system/route", "apply")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("apply must be silent: %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", systemRouteReconfigPath)

	t.Run("failure status", func(t *testing.T) {
		t.Parallel()
		var f = systemRouteFake(t)
		f.on("POST", systemRouteReconfigPath, 200, `{"status":"error reloading routes (oops)"}`)
		wantFailure(t, f.run("/system/route", "apply"), "error reloading routes (oops)")
	})
}

func TestSystemRouteHelp(t *testing.T) {
	t.Parallel()
	var f = systemRouteFake(t)
	var r = f.run("/system/route", "add", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "network=<string>", "gateway=<string>", "description=<string>", "disabled[=yes|no]",
		"default no", "replace", "/system/route apply")
	var apply = f.run("/system/route", "apply", "?")
	wantExit(t, apply, 0)
	wantContains(t, "stdout", apply.stdout, "apply the static route changes")
	wantNoCalls(t, f)
}

func TestSystemRouteCompletion(t *testing.T) {
	t.Parallel()
	var f = systemRouteFake(t, systemRouteRows()...)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/system/route set 198.5":            {"198.51.100.0/24"},
		"/system/route remove 2001":          {"2001:db8:1::/48"},
		"/system/route add gateway=WAN_":     {"gateway=WAN_DHCP", "gateway=WAN_DHCP6"},
		"/system/route set r-doc gateway=Nu": {"gateway=Null4", "gateway=Null6"},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}
