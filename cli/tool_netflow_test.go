package cli

import (
	"strings"
	"testing"
)

const (
	toolNetflowGetPath = "/api/diagnostics/netflow/getconfig"
	toolNetflowSetPath = "/api/diagnostics/netflow/setconfig"
)

// toolNetflowTestConfig is a getconfig answer of 26.7: capture on lan, egress only on wan, one collector and the
// local one
const toolNetflowTestConfig = `{"netflow":{"capture":{"interfaces":{"lan":{"value":"LAN","selected":1},"wan":{"value":"Uplink","selected":0},` +
	`"opt1":{"value":"DMZ","selected":0}},"egress_only":{"lan":{"value":"LAN","selected":0},"wan":{"value":"Uplink","selected":1},` +
	`"opt1":{"value":"DMZ","selected":0}},"version":{"v5":{"value":"v5","selected":0},"v9":{"value":"v9","selected":1}},` +
	`"targets":{"192.0.2.10:2055":{"value":"192.0.2.10:2055","selected":1},"127.0.0.1:2056":{"value":"127.0.0.1:2056","selected":1}}},` +
	`"collect":{"enable":"1"},"activeTimeout":"1800","inactiveTimeout":"15"}}`

func TestToolNetflowPrint(t *testing.T) {
	var f = newFakeOPN(t)
	f.on("GET", toolNetflowGetPath, 200, toolNetflowTestConfig)
	var r = f.run("/tool/netflow", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout,
		"interfaces:        lan\n",
		"egress-only:       wan\n",
		"version:           v9\n",
		"targets:           127.0.0.1:2056,192.0.2.10:2055\n",
		"collect:           yes\n",
		"active-timeout:    1800\n",
		"inactive-timeout:  15\n")

	r = f.run("/tool/netflow", "print", "json")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, `{"netflow":{"capture":`)
	wantNoMutations(t, f)
}

func TestToolNetflowSet(t *testing.T) {
	var f = newFakeOPN(t)
	f.on("GET", toolNetflowGetPath, 200, toolNetflowTestConfig)
	f.on("POST", toolNetflowSetPath, 200, answerSaved)

	// interfaces by name or description, the lists replace the old ones
	var r = f.run("/tool/netflow", "set", "interfaces=lan,dmz", "egress-only=", "targets=192.0.2.20:9995,[2001:db8::1]:2055",
		"version=v5", "collect=no", "active-timeout=600", "inactive-timeout=30")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("set must be silent: %q", r.stdout)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", toolNetflowSetPath), map[string]any{"netflow": map[string]any{
		"capture": map[string]any{"interfaces": "lan,opt1", "egress_only": "", "version": "v5", "targets": "192.0.2.20:9995,[2001:db8::1]:2055"},
		"collect": map[string]any{"enable": "0"}, "activeTimeout": "600", "inactiveTimeout": "30",
	}})

	// only the given settings are sent, without interface lists no getconfig is needed
	var g = newFakeOPN(t)
	g.on("POST", toolNetflowSetPath, 200, answerSaved)
	wantExit(t, g.run("/tool/netflow", "set", "collect", "targets="), 0)
	wantJSON(t, wantOneMutation(t, g, "POST", toolNetflowSetPath), map[string]any{"netflow": map[string]any{
		"capture": map[string]any{"targets": ""}, "collect": map[string]any{"enable": "1"},
	}})
	if len(g.calls()) != 1 {
		t.Errorf("want only the setconfig call, got %v", g.calls())
	}
}

func TestToolNetflowSetErrors(t *testing.T) {
	var f = newFakeOPN(t)
	f.on("GET", toolNetflowGetPath, 200, toolNetflowTestConfig)
	for _, args := range [][]string{
		{"set"},
		{"set", "targets=192.0.2.1"},
		{"set", "targets=host.example:2055"},
		{"set", "targets=192.0.2.1:0"},
		{"set", "version=v10"},
		{"set", "active-timeout=0"},
		{"set", "inactive-timeout=86401"},
	} {
		wantFailure(t, f.run(append([]string{"/tool/netflow"}, args...)...))
	}
	wantNoCalls(t, f)

	wantFailure(t, f.run("/tool/netflow", "set", "interfaces=lan,nope"), `interface "nope"`, "lan, opt1, wan")
	wantNoMutations(t, f)

	var g = newFakeOPN(t)
	g.on("POST", toolNetflowSetPath, 200, answerValidation("netflow.capture.targets", "Please specify a valid ip:port."))
	wantFailure(t, g.run("/tool/netflow", "set", "targets=192.0.2.1:2055"), "netflow.capture.targets", "valid ip:port")
}

func TestToolNetflowStatus(t *testing.T) {
	var f = newFakeOPN(t)
	f.on("GET", "/api/diagnostics/netflow/status", 200, `{"status":"active","collectors":"2"}`)
	f.on("GET", "/api/diagnostics/netflow/isEnabled", 200, `{"netflow":1,"local":1}`)
	f.on("GET", "/api/diagnostics/networkinsight/getMetadata", 200, `{"last_sync":1792936000,"aggregators":{"FlowInterfaceTotals":{"resolutions":[30,300]}}}`)
	var r = f.run("/tool/netflow", "status")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "status:              active (2 collectors)", "capture-configured:  yes", "collect:             yes",
		"last-aggregation:    2026-10-25 13:46:40")

	r = f.run("/tool/netflow", "status", "json")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, `"status":{"status":"active","collectors":"2"}`, `"netflow":"1"`, `"local":"1"`, `"metadata":{"last_sync":1792936000`)

	var g = newFakeOPN(t)
	g.on("GET", "/api/diagnostics/netflow/status", 200, `{"status":"inactive"}`)
	g.on("GET", "/api/diagnostics/netflow/isEnabled", 200, `{"netflow":0,"local":0}`)
	g.on("GET", "/api/diagnostics/networkinsight/getMetadata", 200, `{"last_sync":0,"aggregators":{}}`)
	r = g.run("/tool/netflow", "status")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "status:              inactive", "capture-configured:  no", "last-aggregation:    never")
	wantNoMutations(t, g)
}

func TestToolNetflowCache(t *testing.T) {
	var f = newFakeOPN(t)
	f.on("GET", "/api/diagnostics/netflow/cacheStats", 200,
		`{"netflow_vtnet0":{"Pkts":1234,"if":"vtnet0","SrcIPaddresses":3,"DstIPaddresses":5},"netflow_vtnet1":{"Pkts":7,"if":"vtnet1","SrcIPaddresses":1,"DstIPaddresses":2}}`)
	f.on("GET", "/api/diagnostics/networkinsight/getInterfaces", 200, `{"vtnet0":"lan","vtnet1":"Uplink"}`)
	var r = f.run("/tool/netflow/cache", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "DEVICE  INTERFACE  PACKETS  SOURCES  DESTINATIONS", "vtnet0  lan        1234     3        5",
		"vtnet1  Uplink     7        1        2")

	r = f.run("/tool/netflow/cache", "print", "json")
	wantExit(t, r, 0)
	if lines := strings.Split(strings.TrimSpace(r.stdout), "\n"); len(lines) != 2 || lines[0] != `{"Pkts":1234,"if":"vtnet0","SrcIPaddresses":3,"DstIPaddresses":5}` {
		t.Errorf("json: %s", r.stdout)
	}

	var g = newFakeOPN(t)
	g.on("GET", "/api/diagnostics/netflow/cacheStats", 200, `[]`)
	r = g.run("/tool/netflow/cache", "print")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != "DEVICE  INTERFACE  PACKETS  SOURCES  DESTINATIONS" {
		t.Errorf("empty: %q", r.stdout)
	}
	wantNoMutations(t, f)
}

func TestToolNetflowReconfigureAndReset(t *testing.T) {
	var f = newFakeOPN(t)
	f.on("POST", "/api/diagnostics/netflow/reconfigure", 200, `{"status":"ok"}`)
	var r = f.run("/tool/netflow", "reconfigure")
	wantExit(t, r, 0)
	wantOneMutation(t, f, "POST", "/api/diagnostics/netflow/reconfigure")

	var g = newFakeOPN(t)
	g.on("POST", "/api/diagnostics/netflow/reconfigure", 200, `{"status":"error"}`)
	wantFailure(t, g.run("/tool/netflow", "apply"), "netflow reconfigure failed")

	var h = newFakeOPN(t)
	h.on("POST", "/api/diagnostics/netflow/reset", 200, `{"status":"OK\n"}`)
	wantFailure(t, h.run("/tool/netflow", "reset-data"), "deletes all locally collected NetFlow data", "confirm=yes")
	wantNoCalls(t, h)
	wantExit(t, h.run("/tool/netflow", "reset-data", "confirm=yes"), 0)
	wantOneMutation(t, h, "POST", "/api/diagnostics/netflow/reset")
}
