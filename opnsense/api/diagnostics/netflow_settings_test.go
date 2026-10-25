package diagnostics

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

// netflowTestConfig is a getconfig answer of 26.7 with capture on lan (egress only on wan) to a collector
const netflowTestConfig = `{"netflow":{"capture":{"interfaces":{"lan":{"value":"LAN","selected":1},"wan":{"value":"WAN","selected":0},` +
	`"opt1":{"value":"DMZ","selected":1}},"egress_only":{"lan":{"value":"LAN","selected":0},"wan":{"value":"WAN","selected":1}},` +
	`"version":{"v5":{"value":"v5","selected":0},"v9":{"value":"v9","selected":1}},` +
	`"targets":{"192.0.2.10:2055":{"value":"192.0.2.10:2055","selected":1},"127.0.0.1:2056":{"value":"127.0.0.1:2056","selected":1}}},` +
	`"collect":{"enable":"1"},"activeTimeout":"1800","inactiveTimeout":"15"}}`

// netflowTestDefaults is getconfig of a fresh 26.7 (nothing configured)
const netflowTestDefaults = `{"netflow":{"capture":{"interfaces":{"lan":{"value":"LAN","selected":0},"wan":{"value":"WAN","selected":0}},` +
	`"egress_only":{"lan":{"value":"LAN","selected":0},"wan":{"value":"WAN","selected":0}},"version":{"v5":{"value":"v5","selected":0},` +
	`"v9":{"value":"v9","selected":1}},"targets":{"":{"value":"","selected":1}}},"collect":{"enable":"0"},"activeTimeout":"1800","inactiveTimeout":"15"}}`

func TestNetflowSettings(t *testing.T) {
	var api, _ = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/netflow/getconfig": healthTestJSON(netflowTestConfig),
	})
	var settings, err = api.NetflowSettings()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(settings.Interfaces, []string{"lan", "opt1"}) || !reflect.DeepEqual(settings.EgressOnly, []string{"wan"}) ||
		settings.Version != "v9" || !reflect.DeepEqual(settings.Targets, []string{"127.0.0.1:2056", "192.0.2.10:2055"}) ||
		!settings.LocalCollection || settings.ActiveTimeout != "1800" || settings.InactiveTimeout != "15" ||
		!reflect.DeepEqual(settings.Versions, []string{"v5", "v9"}) ||
		!reflect.DeepEqual(settings.InterfaceOptions, map[string]string{"lan": "LAN", "wan": "WAN", "opt1": "DMZ"}) {
		t.Errorf("got %+v", settings)
	}

	var defaults, _ = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/netflow/getconfig": healthTestJSON(netflowTestDefaults),
	})
	settings, err = defaults.NetflowSettings()
	if err != nil || len(settings.Interfaces) != 0 || len(settings.Targets) != 0 || settings.LocalCollection || settings.Version != "v9" {
		t.Errorf("defaults: %+v, %v", settings, err)
	}

	var broken, _ = healthTestApi(t, map[string]http.HandlerFunc{"GET /api/diagnostics/netflow/getconfig": healthTestJSON(`[]`)})
	if _, err := broken.NetflowSettings(); err == nil {
		t.Error("want an error for an unexpected answer")
	}
}

func TestNetflowSetSettings(t *testing.T) {
	var api, calls = healthTestApi(t, map[string]http.HandlerFunc{
		"POST /api/diagnostics/netflow/setconfig": healthTestJSON(`{"result":"saved"}`),
	})
	var interfaces = []string{"lan", "opt1"}
	var targets = []string{}
	var local = true
	var timeout = "60"
	if err := api.NetflowSetSettings(NetflowSettingsFields{Interfaces: &interfaces, Targets: &targets, LocalCollection: &local,
		InactiveTimeout: &timeout}); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(calls()[0].Body), &body); err != nil {
		t.Fatal(err)
	}
	var want = map[string]any{"netflow": map[string]any{
		"capture": map[string]any{"interfaces": "lan,opt1", "targets": ""},
		"collect": map[string]any{"enable": "1"}, "inactiveTimeout": "60",
	}}
	if !reflect.DeepEqual(body, want) {
		t.Errorf("body %v, want %v", body, want)
	}

	if err := api.NetflowSetSettings(NetflowSettingsFields{}); err == nil {
		t.Error("want an error without fields")
	}
	if len(calls()) != 1 {
		t.Errorf("nothing to change must not send anything: %v", calls())
	}

	var failing, _ = healthTestApi(t, map[string]http.HandlerFunc{
		"POST /api/diagnostics/netflow/setconfig": healthTestJSON(`{"result":"failed","validations":{"netflow.capture.targets":"Please specify a valid ip:port."}}`),
	})
	var validation *coreapi.ValidationError
	if err := failing.NetflowSetSettings(NetflowSettingsFields{Targets: &[]string{"bad"}}); !errors.As(err, &validation) ||
		validation.Validations["netflow.capture.targets"] == "" {
		t.Errorf("want a validation error, got %v", err)
	}
}

func TestNetflowStatusAndCache(t *testing.T) {
	var api, calls = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/netflow/isEnabled":    healthTestJSON(`{"netflow":1,"local":0}`),
		"GET /api/diagnostics/netflow/status":       healthTestJSON(`{"status":"active","collectors":"2"}`),
		"GET /api/diagnostics/netflow/cacheStats":   healthTestJSON(`{"netflow_vtnet1":{"Pkts":7,"if":"vtnet1","SrcIPaddresses":1,"DstIPaddresses":2},"netflow_vtnet0":{"Pkts":1234,"if":"vtnet0","SrcIPaddresses":3,"DstIPaddresses":5}}`),
		"POST /api/diagnostics/netflow/reconfigure": healthTestJSON(`{"status":"ok"}`),
		"POST /api/diagnostics/netflow/reset":       healthTestJSON(`{"status":"OK\n"}`),
	})
	if capture, local, err := api.NetflowEnabled(); err != nil || !capture || local {
		t.Errorf("enabled: %v %v %v", capture, local, err)
	}
	if status, err := api.NetflowStatus(); err != nil || !status.Active || status.Collectors != "2" {
		t.Errorf("status: %+v, %v", status, err)
	}
	var nodes, err = api.NetflowCache()
	if err != nil || len(nodes) != 2 {
		t.Fatalf("cache: %+v, %v", nodes, err)
	}
	if nodes[0].Node != "netflow_vtnet0" || nodes[0].Interface != "vtnet0" || nodes[0].Packets != 1234 || nodes[0].Sources != 3 ||
		nodes[0].Destinations != 5 || nodes[1].Node != "netflow_vtnet1" {
		t.Errorf("cache: %+v", nodes)
	}
	if err := api.NetflowReconfigure(); err != nil {
		t.Error(err)
	}
	if err := api.NetflowReset(); err != nil {
		t.Error(err)
	}
	for _, call := range calls() {
		if (strings.HasSuffix(call.Path, "/reconfigure") || strings.HasSuffix(call.Path, "/reset")) && call.Method != "POST" {
			t.Errorf("actions must be POSTed: %+v", call)
		}
	}

	var idle, _ = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/netflow/status":       healthTestJSON(`{"status":"inactive"}`),
		"GET /api/diagnostics/netflow/cacheStats":   healthTestJSON(`[]`),
		"POST /api/diagnostics/netflow/reconfigure": healthTestJSON(`{"status":"error"}`),
		"POST /api/diagnostics/netflow/reset":       healthTestJSON(`{"status":"failed"}`),
		"GET /api/diagnostics/netflow/isEnabled":    healthTestJSON(`{}`),
	})
	if status, err := idle.NetflowStatus(); err != nil || status.Active {
		t.Errorf("status: %+v, %v", status, err)
	}
	if nodes, err := idle.NetflowCache(); err != nil || len(nodes) != 0 {
		t.Errorf("cache: %+v, %v", nodes, err)
	}
	if err := idle.NetflowReconfigure(); err == nil {
		t.Error("want an error for status error")
	}
	if err := idle.NetflowReset(); err == nil {
		t.Error("want an error for status failed")
	}
	if _, _, err := idle.NetflowEnabled(); err == nil {
		t.Error("want an error for an unexpected answer")
	}
}
