package cli

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	systemGatewaySearchPath   = "/api/routing/settings/search_gateway"
	systemGatewayGetPath      = "/api/routing/settings/get_gateway"
	systemGatewayAddPath      = "/api/routing/settings/add_gateway"
	systemGatewaySetPath      = "/api/routing/settings/set_gateway/"
	systemGatewayDelPath      = "/api/routing/settings/del_gateway/"
	systemGatewayTogglePath   = "/api/routing/settings/toggle_gateway/"
	systemGatewayReconfigPath = "/api/routing/settings/reconfigure"
	systemGatewayStatusPath   = "/api/routes/gateway/status"

	systemGatewayLanUuid      = "3afca08c-7f2a-48b9-a6a6-d70f6b65c762"
	systemGatewayV6Uuid       = "5b0d7e2a-0000-4000-8000-000000000002"
	systemGatewayOverrideUuid = "9d6e1c1a-1111-4222-8333-444455556666"
)

// systemGatewayDynamicRow is a generated gateway of a dynamic interface as search_gateway returns it in 26.7
func systemGatewayDynamicRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"interface": "wan", "weight": "1", "ipprotocol": "inet", "name": "WAN_DHCP", "descr": "Interface WAN_DHCP Gateway",
		"monitor_disable": "1", "monitor_noroute": "0", "gateway_interface": false, "if": "vtnet1", "dynamic": true,
		"virtual": true, "priority": 254, "gateway": "10.0.2.2", "uuid": "WAN_DHCP", "disabled": false, "upstream": false,
		"defaultgw": true, "interface_descr": "WAN", "status": "Online", "delay": "~", "stddev": "~", "loss": "~",
		"label_class": "fa fa-plug text-success",
	}, overrides)
}

// systemGatewayConfiguredRow is a configured gateway as search_gateway returns it in 26.7
func systemGatewayConfiguredRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"disabled": false, "name": "lan_gw", "descr": "LAN router", "interface": "lan", "ipprotocol": "inet",
		"gateway": "192.168.1.240", "defaultgw": false, "fargw": "0", "monitor_disable": "1", "monitor_noroute": "0",
		"monitor_killstates": "0", "monitor_killstates_priority": "0", "monitor": "", "force_down": "0", "nosync": "0",
		"priority": "255", "weight": "1", "latencylow": "", "current_latencylow": "200", "latencyhigh": "",
		"current_latencyhigh": "500", "losslow": "", "current_losslow": "10", "losshigh": "", "current_losshigh": "20",
		"interval": "", "current_interval": "1", "time_period": "", "current_time_period": "60", "loss_interval": "",
		"current_loss_interval": "4", "data_length": "", "current_data_length": "1", "uuid": systemGatewayLanUuid,
		"if": "vtnet0", "attribute": 0, "virtual": false, "upstream": false, "interface_descr": "LAN", "status": "Online",
		"delay": "~", "stddev": "~", "loss": "~", "label_class": "fa fa-plug text-success",
	}, overrides)
}

// systemGatewayRows: a generated dynamic gateway, a configured IPv4 and a configured IPv6 gateway
func systemGatewayRows() []map[string]any {
	return []map[string]any{
		systemGatewayDynamicRow(nil),
		systemGatewayConfiguredRow(nil),
		systemGatewayConfiguredRow(map[string]any{"uuid": systemGatewayV6Uuid, "name": "v6_gw", "descr": "backup line",
			"ipprotocol": "inet6", "gateway": "fd00::1", "priority": "10", "interface": "opt1", "interface_descr": "DMZ", "upstream": true, "disabled": true, "force_down": "1",
			"latencyhigh": "800", "status": "Offline"}),
	}
}

// systemGatewayGetNew is get_gateway without uuid: the defaults of a new gateway with the interface options
const systemGatewayGetNew = `{"gateway_item":{"disabled":"0","name":"","descr":"",` +
	`"interface":{"lan":{"value":"LAN","selected":0},"opt1":{"value":"DMZ","selected":0},"wan":{"value":"WAN","selected":1}},` +
	`"ipprotocol":{"inet":{"value":"IPv4","selected":1},"inet6":{"value":"IPv6","selected":0}},"gateway":"","defaultgw":"0",` +
	`"fargw":"0","monitor_disable":"1","monitor_noroute":"0","monitor_killstates":"0","monitor_killstates_priority":"0",` +
	`"monitor":"","force_down":"0","nosync":"0","priority":"255","weight":"1","latencylow":"","latencyhigh":"","losslow":"",` +
	`"losshigh":"","interval":"","time_period":"","loss_interval":"","data_length":""}}`

// systemGatewayGetDynamic is get_gateway/WAN_DHCP: the complete record of the generated gateway
var systemGatewayGetDynamic = strings.NewReplacer(`"name":""`, `"name":"WAN_DHCP"`,
	`"descr":""`, `"descr":"Interface WAN_DHCP Gateway"`, `"priority":"255"`, `"priority":"254"`).Replace(systemGatewayGetNew)

func systemGatewayFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(systemGatewaySearchPath, rows...)
	f.on("GET", systemGatewayGetPath, 200, systemGatewayGetNew)
	f.on("GET", systemGatewayGetPath+"/WAN_DHCP", 200, systemGatewayGetDynamic)
	return f
}

// systemGatewayFakeOverride serves the rows until set_gateway/WAN_DHCP was called, then WAN_DHCP is configured
// with systemGatewayOverrideUuid
func systemGatewayFakeOverride(t *testing.T) *fakeOPN {
	t.Helper()
	var f = systemGatewayFake(t)
	var overridden atomic.Bool
	var rows = systemGatewayRows()
	var after = append([]map[string]any{systemGatewayDynamicRow(map[string]any{"uuid": systemGatewayOverrideUuid, "virtual": false})}, rows[1:]...)
	f.onFunc("GET", systemGatewaySearchPath, func(w http.ResponseWriter, _ *http.Request) {
		var current = rows
		if overridden.Load() {
			current = after
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": current, "rowCount": len(current), "total": len(current), "current": 1})
	})
	f.onFunc("POST", systemGatewaySetPath+"WAN_DHCP", func(w http.ResponseWriter, _ *http.Request) {
		overridden.Store(true)
		_, _ = w.Write([]byte(answerSaved))
	})
	return f
}

// systemGatewayFullBody is the body add sends for a gateway with only the required arguments
func systemGatewayFullBody(overrides map[string]any) map[string]any {
	return map[string]any{"gateway_item": withFields(map[string]any{
		"name": "new_gw", "interface": "lan", "ipprotocol": "inet", "gateway": "", "descr": "", "disabled": "0",
		"defaultgw": "0", "fargw": "0", "priority": "255", "weight": "1", "monitor_disable": "1", "monitor": "",
		"monitor_noroute": "0", "monitor_killstates": "0", "monitor_killstates_priority": "0", "force_down": "0",
		"nosync": "0", "latencylow": "", "latencyhigh": "", "losslow": "", "losshigh": "", "interval": "",
		"time_period": "", "loss_interval": "", "data_length": "",
	}, overrides)}
}

var systemGatewayHeader = []string{"#", "DISABLED", "NAME", "INTERFACE", "PROTOCOL", "ADDRESS", "PRIORITY", "FLAGS", "STATUS", "DESCRIPTION"}

func TestSystemGatewayPrint(t *testing.T) {
	t.Parallel()
	var f = systemGatewayFake(t, systemGatewayRows()...)
	var r = f.run("/system/gateway", "print")
	wantExit(t, r, 0)
	var rows = systemCronWantTable(t, r.stdout, systemGatewayHeader, 2, "WAN_DHCP", "lan_gw", "v6_gw")
	if len(rows) == 4 {
		var want = [][]string{
			{"0", "no", "WAN_DHCP", "wan", "ipv4", "10.0.2.2", "254", "default,dynamic,generated", "Online", "Interface WAN_DHCP Gateway"},
			{"1", "no", "lan_gw", "lan", "ipv4", "192.168.1.240", "255", "-", "Online", "LAN router"},
			{"2", "yes", "v6_gw", "opt1", "ipv6", "fd00::1", "10", "upstream,down", "Offline", "backup line"},
		}
		if !reflect.DeepEqual(rows[1:], want) {
			t.Errorf("rows:\n got  %q\n want %q", rows[1:], want)
		}
	}
	wantNoMutations(t, f)

	t.Run("search filters over all values", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		for phrase, want := range map[string][]string{"vtnet1": {"WAN_DHCP"}, "BACKUP": {"v6_gw"}, "254": {"WAN_DHCP"}, "nothing": nil} {
			var r = f.run("/system/gateway", "print", "search="+phrase)
			wantExit(t, r, 0)
			systemCronWantTable(t, r.stdout, systemGatewayHeader, 2, want...)
		}
	})
	t.Run("json prints the raw rows", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		var r = f.run("/system/gateway", "print", "json")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != 3 {
			t.Fatalf("want 3 lines:\n%s", r.stdout)
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &row); err != nil || row["priority"] != float64(254) || row["label_class"] == nil {
			t.Errorf("want the raw row, got %q (%v)", lines[0], err)
		}
	})
	t.Run("detail", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		var r = f.run("/system/gateway", "print", "detail")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "0\n  uuid:", "configured:            no, generated for a dynamic interface",
			"latency-high:          800\n", "latency-low:           200 (default)", "interface:             opt1 (DMZ)", "interface:             lan\n")
	})
}

func TestSystemGatewayShow(t *testing.T) {
	t.Parallel()
	var f = systemGatewayFake(t, systemGatewayRows()...)
	for _, selector := range []string{"LAN_GW", "1", systemGatewayLanUuid} {
		var r = f.run("/system/gateway", "show", selector)
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "uuid:                  "+systemGatewayLanUuid, "name:                  lan_gw",
			"protocol:              ipv4", "address:               192.168.1.240", "configured:            yes",
			"monitor-disabled:      yes", "time-period:           60 (default)", "status:                Online")
	}
	var r = f.run("/system/gateway", "show", "wan_dhcp")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "uuid:                  WAN_DHCP", "dynamic:               yes", "default:               yes",
		"interface:             wan\n", "device:                vtnet1")
	wantFailure(t, f.run("/system/gateway", "show", "nope"), "not found")
	wantNoMutations(t, f)
}

func TestSystemGatewayAdd(t *testing.T) {
	t.Parallel()

	t.Run("new gateway sends all fields", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		f.on("POST", systemGatewayAddPath, 200, answerAdded("u-new"))
		var r = f.run("/system/gateway", "add", "name=new_gw", "interface=LAN")
		wantExit(t, r, 0)
		if r.stdout != "u-new\n" || r.stderr != "" {
			t.Errorf("want only the uuid on stdout: %s", r)
		}
		wantJSON(t, wantOneMutation(t, f, "POST", systemGatewayAddPath), systemGatewayFullBody(nil))
	})
	t.Run("all arguments", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		f.on("POST", systemGatewayAddPath, 200, answerAdded("u-new"))
		wantExit(t, f.run("/system/gateway", "add", "name=new_gw", "interface=opt1", "protocol=IPv6", "address=fd00::9",
			"description=dmz", "disabled", "upstream", "far-gateway", "priority=0", "weight=10", "monitor-disabled=no",
			"monitor=2001:db8::1", "monitor-no-route", "kill-states", "kill-states-failback", "force-down", "no-sync",
			"latency-low=100", "latency-high=300", "loss-low=5", "loss-high=50", "interval=2", "time-period=30",
			"loss-interval=5", "data-length=0"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemGatewayAddPath), systemGatewayFullBody(map[string]any{
			"interface": "opt1", "ipprotocol": "inet6", "gateway": "fd00::9", "descr": "dmz", "disabled": "1", "defaultgw": "1",
			"fargw": "1", "priority": "0", "weight": "10", "monitor_disable": "0", "monitor": "2001:db8::1", "monitor_noroute": "1",
			"monitor_killstates": "1", "monitor_killstates_priority": "1", "force_down": "1", "nosync": "1", "latencylow": "100",
			"latencyhigh": "300", "losslow": "5", "losshigh": "50", "interval": "2", "time_period": "30", "loss_interval": "5",
			"data_length": "0",
		}))
	})
	t.Run("interface by its name", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t)
		f.on("POST", systemGatewayAddPath, 200, answerAdded("u-new"))
		wantExit(t, f.run("/system/gateway", "add", "name=new_gw", "interface=dmz", "address=dynamic"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemGatewayAddPath),
			systemGatewayFullBody(map[string]any{"interface": "opt1", "gateway": "dynamic"}))
	})
	t.Run("unknown interface", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t)
		wantFailure(t, f.run("/system/gateway", "add", "name=new_gw", "interface=opt9"), `unknown interface "opt9"`, "lan, opt1, wan")
		wantNoMutations(t, f)
	})
	t.Run("existing name fails without replace", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		wantFailure(t, f.run("/system/gateway", "add", "name=LAN_GW", "interface=lan"), "exists already", systemGatewayLanUuid, "replace")
		wantNoMutations(t, f)
	})
	t.Run("replace replaces a configured gateway completely", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		f.on("POST", systemGatewaySetPath+systemGatewayLanUuid, 200, answerSaved)
		var r = f.run("/system/gateway", "add", "name=lan_gw", "interface=lan", "address=192.168.1.241", "replace")
		wantExit(t, r, 0)
		if r.stdout != systemGatewayLanUuid+"\n" {
			t.Errorf("stdout must be the uuid: %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, "replaced the existing gateway lan_gw")
		wantJSON(t, wantOneMutation(t, f, "POST", systemGatewaySetPath+systemGatewayLanUuid),
			systemGatewayFullBody(map[string]any{"name": "lan_gw", "gateway": "192.168.1.241"}))
	})
	t.Run("replace can not rename by case", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		wantFailure(t, f.run("/system/gateway", "add", "name=LAN_GW", "interface=lan", "replace"), "can not be renamed")
		wantNoMutations(t, f)
	})
	t.Run("replace of a generated gateway stores an override", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFakeOverride(t)
		var r = f.run("/system/gateway", "add", "name=WAN_DHCP", "interface=wan", "priority=1", "replace")
		wantExit(t, r, 0)
		if r.stdout != systemGatewayOverrideUuid+"\n" {
			t.Errorf("stdout must be the new uuid: %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, "stored an override of the generated gateway WAN_DHCP")
		wantJSON(t, wantOneMutation(t, f, "POST", systemGatewaySetPath+"WAN_DHCP"),
			systemGatewayFullBody(map[string]any{"name": "WAN_DHCP", "interface": "wan", "priority": "1"}))
	})
	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t)
		f.on("POST", systemGatewayAddPath, 200, answerValidation("gateway_item.gateway", "This gateway IP address already exists."))
		wantFailure(t, f.run("/system/gateway", "add", "name=new_gw", "interface=lan", "address=192.168.1.1"),
			"gateway_item.gateway", "This gateway IP address already exists.")
	})

	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"name is required", []string{"interface=lan"}, []string{"name"}},
		{"interface is required", []string{"name=x"}, []string{"interface"}},
		{"name with a space", []string{"name=a b", "interface=lan"}, []string{"name must be 1-32 characters"}},
		{"name too long", []string{"name=" + strings.Repeat("a", 33), "interface=lan"}, []string{"name must be 1-32 characters"}},
		{"bad address", []string{"name=x", "interface=lan", "address=192.168.1"}, []string{"address must be an IPv4 or IPv6 address"}},
		{"IPv6 address for the default IPv4", []string{"name=x", "interface=lan", "address=fd00::1"}, []string{`does not match protocol=ipv4`}},
		{"IPv4 monitor for IPv6", []string{"name=x", "interface=lan", "protocol=ipv6", "monitor=10.0.0.1"}, []string{"monitor", "protocol=ipv6"}},
		{"bad protocol", []string{"name=x", "interface=lan", "protocol=inet"}, []string{"protocol must be one of ipv4, ipv6"}},
		{"weight out of range", []string{"name=x", "interface=lan", "weight=11"}, []string{"weight must be a number from 1 to 10"}},
		{"priority out of range", []string{"name=x", "interface=lan", "priority=256"}, []string{"priority must be a number from 0 to 255"}},
		{"loss-low out of range", []string{"name=x", "interface=lan", "loss-low=100"}, []string{"loss-low must be a number from 1 to 99"}},
		{"latency low above high", []string{"name=x", "interface=lan", "latency-low=500", "latency-high=100"}, []string{"latency-low must be lower than latency-high"}},
		{"description with a newline", []string{"name=x", "interface=lan", "description=a\nb"}, []string{"control characters"}},
	} {
		t.Run(tc.name+", no API call", func(t *testing.T) {
			t.Parallel()
			var f = systemGatewayFake(t, systemGatewayRows()...)
			wantFailure(t, f.run(append([]string{"/system/gateway", "add"}, tc.args...)...), tc.wants...)
			wantNoCalls(t, f)
		})
	}
}

func TestSystemGatewaySet(t *testing.T) {
	t.Parallel()

	t.Run("only the given fields", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		f.on("POST", systemGatewaySetPath+systemGatewayLanUuid, 200, answerSaved)
		var r = f.run("/system/gateway", "set", "lan_gw", "priority=5", "description=", "monitor-disabled=no", "latency-high=")
		wantExit(t, r, 0)
		if r.stdout != "" || r.stderr != "" {
			t.Errorf("set must be silent: %s", r)
		}
		wantJSON(t, wantOneMutation(t, f, "POST", systemGatewaySetPath+systemGatewayLanUuid),
			map[string]any{"gateway_item": map[string]any{"priority": "5", "descr": "", "monitor_disable": "0", "latencyhigh": ""}})
	})
	t.Run("a generated gateway is overridden with its complete record", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFakeOverride(t)
		var r = f.run("/system/gateway", "set", "0", "monitor-disabled=no", "monitor=10.0.2.3")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "stored an override of the generated gateway WAN_DHCP, uuid "+systemGatewayOverrideUuid)
		var get = false
		for _, call := range f.calls() {
			get = get || call.Method == "GET" && call.Path == systemGatewayGetPath+"/WAN_DHCP"
		}
		if !get {
			t.Errorf("the record of WAN_DHCP was not loaded: %v", f.calls())
		}
		wantJSON(t, wantOneMutation(t, f, "POST", systemGatewaySetPath+"WAN_DHCP"), systemGatewayFullBody(map[string]any{
			"name": "WAN_DHCP", "descr": "Interface WAN_DHCP Gateway", "interface": "wan", "priority": "254",
			"monitor_disable": "0", "monitor": "10.0.2.3",
		}))
	})
	t.Run("the address must match the protocol of the gateway", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		wantFailure(t, f.run("/system/gateway", "set", "v6_gw", "address=192.168.1.9"), "IPv6")
		wantNoMutations(t, f)
	})
	t.Run("unknown gateway", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		wantFailure(t, f.run("/system/gateway", "set", "00000000-0000-4000-8000-000000000000", "priority=1"), "not found")
		wantNoMutations(t, f)
	})
	t.Run("removed meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		f.on("POST", systemGatewaySetPath+systemGatewayLanUuid, 200, answerFailedBare)
		wantFailure(t, f.run("/system/gateway", "set", "lan_gw", "priority=1"), "not found")
	})
	t.Run("name can not be changed, no API call", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		wantFailure(t, f.run("/system/gateway", "set", "lan_gw", "name=other"), "name can not be changed", "renaming")
		wantNoCalls(t, f)
	})
	t.Run("nothing to change, no API call", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		wantFailure(t, f.run("/system/gateway", "set", "lan_gw"), "nothing to change")
		wantNoCalls(t, f)
	})
}

func TestSystemGatewayRemove(t *testing.T) {
	t.Parallel()

	t.Run("configured gateway", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		f.on("POST", systemGatewayDelPath+systemGatewayLanUuid, 200, answerDeleted)
		var r = f.run("/system/gateway", "remove", "lan_gw")
		wantExit(t, r, 0)
		if r.stdout != "" || r.stderr != "" {
			t.Errorf("remove must be silent: %s", r)
		}
		wantOneMutation(t, f, "POST", systemGatewayDelPath+systemGatewayLanUuid)
	})
	t.Run("the override of a dynamic gateway", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayDynamicRow(map[string]any{"uuid": systemGatewayOverrideUuid, "virtual": false}))
		f.on("POST", systemGatewayDelPath+systemGatewayOverrideUuid, 200, answerDeleted)
		var r = f.run("/system/gateway", "remove", "WAN_DHCP")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "the gateway WAN_DHCP generated for the dynamic interface wan applies again")
		wantOneMutation(t, f, "POST", systemGatewayDelPath+systemGatewayOverrideUuid)
	})
	t.Run("a generated gateway is refused", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		wantFailure(t, f.run("/system/gateway", "remove", "WAN_DHCP"), "generated by OPNsense", "disable it instead")
		wantNoMutations(t, f)
	})
	t.Run("in use", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		f.on("POST", systemGatewayDelPath+systemGatewayLanUuid, 500,
			`{"errorMessage":"Gateway lan_gw cannot be deleted because it is in use on Gateway Group(s) 'grp'","errorTitle":""}`)
		var r = f.run("/system/gateway", "remove", "lan_gw")
		wantExit(t, r, 1)
		wantContains(t, "stderr", r.stderr, "error: Gateway lan_gw cannot be deleted because it is in use on Gateway Group(s) 'grp'")
		wantNotContains(t, "stderr", r.stderr, "HTTP 500")
	})
	t.Run("removed meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		f.on("POST", systemGatewayDelPath+systemGatewayLanUuid, 200, answerFailedBare)
		wantFailure(t, f.run("/system/gateway", "remove", "lan_gw"), "not found")
	})
}

func TestSystemGatewayEnableDisable(t *testing.T) {
	t.Parallel()

	t.Run("configured gateway", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		f.on("POST", systemGatewayTogglePath+systemGatewayLanUuid+"/0", 200, `{"result":"Disabled","changed":true}`)
		var r = f.run("/system/gateway", "disable", "lan_gw")
		wantExit(t, r, 0)
		if r.stdout != "" || r.stderr != "" {
			t.Errorf("disable must be silent: %s", r)
		}
		wantOneMutation(t, f, "POST", systemGatewayTogglePath+systemGatewayLanUuid+"/0")
	})
	t.Run("already enabled", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		f.on("POST", systemGatewayTogglePath+systemGatewayLanUuid+"/1", 200, `{"result":"Enabled","changed":false}`)
		var r = f.run("/system/gateway", "enable", "1")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "gateway lan_gw is already enabled")
	})
	t.Run("removed meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		f.on("POST", systemGatewayTogglePath+systemGatewayV6Uuid+"/1", 200, `{"result":"failed"}`)
		wantFailure(t, f.run("/system/gateway", "enable", "v6_gw"), "not found")
	})
	t.Run("a generated gateway which is enabled", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t, systemGatewayRows()...)
		var r = f.run("/system/gateway", "enable", "WAN_DHCP")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "gateway WAN_DHCP is already enabled")
		wantNoMutations(t, f)
	})
	t.Run("disabling a generated gateway stores an override", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFakeOverride(t)
		var r = f.run("/system/gateway", "disable", "WAN_DHCP")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "stored an override of the generated gateway WAN_DHCP")
		wantJSON(t, wantOneMutation(t, f, "POST", systemGatewaySetPath+"WAN_DHCP"), systemGatewayFullBody(map[string]any{
			"name": "WAN_DHCP", "descr": "Interface WAN_DHCP Gateway", "interface": "wan", "priority": "254", "disabled": "1",
		}))
	})
}

func TestSystemGatewayApply(t *testing.T) {
	t.Parallel()
	var f = systemGatewayFake(t)
	f.on("POST", systemGatewayReconfigPath, 200, `{"status":"ok"}`)
	var r = f.run("/system/gateway", "apply")
	wantExit(t, r, 0)
	if r.stdout != "" || r.stderr != "" {
		t.Errorf("apply must be silent: %s", r)
	}
	wantOneMutation(t, f, "POST", systemGatewayReconfigPath)

	t.Run("failure status", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayFake(t)
		f.on("POST", systemGatewayReconfigPath, 200, `{"status":"failed"}`)
		wantFailure(t, f.run("/system/gateway", "apply"), "failed")
	})
}

const systemGatewayStatusAnswer = `{"items":[` +
	`{"name":"WAN_DHCP","address":"10.0.2.2","status":"none","loss":"0.0 %","delay":"0.4 ms","stddev":"0.1 ms","monitor":"10.0.2.2","status_translated":"Online"},` +
	`{"name":"lan_gw","address":"192.168.1.240","status":"none","loss":"~","delay":"~","stddev":"~","monitor":"~","status_translated":"Online"}],"status":"ok"}`

func TestSystemGatewayMonitor(t *testing.T) {
	t.Parallel()

	t.Run("once", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", systemGatewayStatusPath, 200, systemGatewayStatusAnswer)
		var r = f.run("/system/gateway", "monitor", "once")
		wantExit(t, r, 0)
		var want = [][]string{
			{"NAME", "ADDRESS", "STATUS", "LOSS", "DELAY", "STDDEV", "MONITOR"},
			{"WAN_DHCP", "10.0.2.2", "Online", "0.0 %", "0.4 ms", "0.1 ms", "10.0.2.2"},
			{"lan_gw", "192.168.1.240", "Online", "~", "~", "~", "~"},
		}
		if got := systemCronTable(r.stdout); !reflect.DeepEqual(got, want) {
			t.Errorf("table:\n got  %q\n want %q", got, want)
		}
		if strings.Contains(r.stdout, "---") {
			t.Errorf("once prints no separator:\n%s", r.stdout)
		}
		wantNoMutations(t, f)
	})
	t.Run("once json", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", systemGatewayStatusPath, 200, systemGatewayStatusAnswer)
		var r = f.run("/system/gateway", "monitor", "once", "json")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != 2 || !strings.HasPrefix(lines[0], `{"name":"WAN_DHCP","address":"10.0.2.2"`) {
			t.Errorf("want one raw object per gateway:\n%s", r.stdout)
		}
	})
	t.Run("follows until Ctrl-C", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", systemGatewayStatusPath, 200, systemGatewayStatusAnswer)
		var p = f.start("/system/gateway", "monitor", "interval=20ms")
		// the polls are sequential: query 4 is only sent after refresh 3 was printed, so this waits for 3 refreshes
		// (waiting for 3 queries raced with printing the third answer under load)
		f.waitForConnections(systemGatewayStatusPath, 4)
		p.waitFor("lan_gw")
		var r = p.interrupt()
		wantExit(t, r, 0)
		var refreshes = strings.Count(r.stdout, "lan_gw")
		if refreshes < 3 || strings.Count(r.stdout, "--- ") != refreshes {
			t.Errorf("want at least 3 refreshes, each with a separator (not a terminal):\n%s", r.stdout)
		}
	})
	t.Run("error stops polling", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", systemGatewayStatusPath, 403, `{"status":403,"message":"Forbidden"}`)
		var r = f.start("/system/gateway", "monitor", "interval=20ms").wait()
		wantFailure(t, r, "HTTP 403")
		if n := f.streamConnections(systemGatewayStatusPath); n != 1 {
			t.Errorf("want no polling after an error, got %d queries", n)
		}
	})
	t.Run("bad interval, no API call", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		wantFailure(t, f.run("/system/gateway", "monitor", "interval=0"), "interval")
		wantNoCalls(t, f)
	})
}

func TestSystemGatewayComplete(t *testing.T) {
	t.Parallel()
	var f = systemGatewayFake(t, systemGatewayRows()...)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/system/gateway remove W":             {"WAN_DHCP"},
		"/system/gateway show l":               {"lan_gw"},
		"/system/gateway set 0 interface=":     {"interface=lan", "interface=opt1", "interface=wan"},
		"/system/gateway add interface=o":      {"interface=opt1"},
		"/system/gateway set 0 protocol=":      {"protocol=ipv4", "protocol=ipv6"},
		"/system/gateway set 0 kill-states-f":  {"kill-states-failback"},
		"/system/gateway monitor in":           {"interval="},
		"/system/gateway set lan_gw monitor-d": {"monitor-disabled"},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}

func TestSystemGatewayHelp(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var r = f.run("/system/gateway", "set", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "name=<string>", "can not be changed", "protocol=ipv4|ipv6", "address=<string>",
		"upstream[=yes|no]", "kill-states-failback[=yes|no]", "override", "/system/gateway apply")
	r = f.run("/system/gateway", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "monitor", "apply", "print")
	wantNoCalls(t, f)
}
