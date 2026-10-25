package diagnostics

import (
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const ifdiagTestArp = `[{"mac":"52:54:00:12:34:56","ip":"192.168.1.1","intf":"vtnet0","expired":false,"expires":-1,"permanent":true,"type":"ethernet","manufacturer":"","hostname":"","intf_description":"LAN"},` +
	`{"mac":"82:a3:6e:c6:fc:1c","ip":"192.168.1.2","intf":"vtnet0","expired":false,"expires":842,"permanent":false,"type":"ethernet","manufacturer":"Acme","hostname":"client.lan","intf_description":"LAN"}]`

func TestArpAndNdp(t *testing.T) {
	var api, calls = toolsTestApi(t, map[string]any{
		"GET /api/diagnostics/interface/get_arp": ifdiagTestArp,
		"GET /api/diagnostics/interface/get_ndp": `[{"mac":"52:56:00:00:00:02","ip":"fe80::2%vtnet1","intf":"vtnet1","manufacturer":"","intf_description":"WAN"}]`,
	})
	var arp, err = api.ArpList(false)
	if err != nil || len(arp) != 2 {
		t.Fatalf("arp %+v, %v", arp, err)
	}
	if arp[1].Hostname != "client.lan" || arp[1].Expires != 842 || arp[1].Permanent || !arp[0].Permanent || arp[0].InterfaceDescription != "LAN" ||
		!strings.Contains(string(arp[1].Raw), `"manufacturer":"Acme"`) {
		t.Errorf("arp %+v", arp)
	}
	if _, err := api.ArpList(true); err != nil {
		t.Fatal(err)
	}
	if calls()[0].Query != "" || calls()[1].Query != "resolve=yes" {
		t.Errorf("resolve query: %+v", calls())
	}
	ndp, err := api.NdpList()
	if err != nil || len(ndp) != 1 || ndp[0].Ip != "fe80::2%vtnet1" || ndp[0].InterfaceDescription != "WAN" {
		t.Errorf("ndp %+v, %v", ndp, err)
	}

	var broken, _ = toolsTestApi(t, map[string]any{"GET /api/diagnostics/interface/get_arp": `null`, "GET /api/diagnostics/interface/get_ndp": `{"x":1}`})
	if _, err := broken.ArpList(false); err == nil {
		t.Error("want an error for null")
	}
	if _, err := broken.NdpList(); err == nil {
		t.Error("want an error for an object")
	}
}

func TestArpFlush(t *testing.T) {
	var api, calls = toolsTestApi(t, map[string]any{
		"POST /api/diagnostics/interface/flush_arp": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			_, _ = io.WriteString(w, "192.168.1.2 (192.168.1.2) deleted\n10.0.2.2 (10.0.2.2) deleted\n")
		},
	})
	var deleted, err = api.ArpFlush()
	if err != nil || !reflect.DeepEqual(deleted, []string{"192.168.1.2 (192.168.1.2) deleted", "10.0.2.2 (10.0.2.2) deleted"}) {
		t.Errorf("flush: %q, %v", deleted, err)
	}
	if call := calls()[0]; call.Method != "POST" || call.Body != "{}" || call.Type != "application/json" {
		t.Errorf("flush must POST {}: %+v", call)
	}

	var quoted, _ = toolsTestApi(t, map[string]any{"POST /api/diagnostics/interface/flush_arp": `"192.168.1.2 (192.168.1.2) deleted\n"`})
	if deleted, err := quoted.ArpFlush(); err != nil || len(deleted) != 1 {
		t.Errorf("JSON string answer: %q, %v", deleted, err)
	}
	var refused, _ = toolsTestApi(t, map[string]any{"POST /api/diagnostics/interface/flush_arp": `{"message":"error"}`})
	if _, err := refused.ArpFlush(); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("want a refusal, got %v", err)
	}
	var missing, _ = toolsTestApi(t, map[string]any{})
	if _, err := missing.ArpFlush(); err == nil || !strings.Contains(err.Error(), "HTTP 404: Endpoint not found") {
		t.Errorf("want the HTTP error, got %v", err)
	}
}

func TestNetstat(t *testing.T) {
	var api, _ = toolsTestApi(t, map[string]any{
		"GET /api/diagnostics/interface/get_interface_statistics": `{"statistics":{` +
			`"[LAN] (vtnet0) \/ 192.168.1.1":{"name":"vtnet0","flags":"0x8843","network":"192.168.1.0\/24","address":"192.168.1.1","received-packets":21122,"received-bytes":2919298,"sent-packets":30340,"sent-bytes":17327368},` +
			`"[LAN] (vtnet0) \/ 52:54:00:12:34:56":{"name":"vtnet0","flags":"0x8843","mtu":1500,"network":"<Link#1>","address":"52:54:00:12:34:56","received-packets":21132,"received-errors":1,"dropped-packets":2,"received-bytes":3215650,"sent-packets":30352,"send-errors":3,"sent-bytes":17753384,"collisions":4},` +
			`"[enc0] \/ enc0":{"name":"enc0","flags":"0x0","mtu":1536,"network":"<Link#4>","address":"enc0"}}}`,
		"GET /api/diagnostics/interface/get_socket_statistics": `{"statistics":{"Active Internet connections":{` +
			`"tcp4\/[192.168.1.1:443-192.168.1.2:48578]":{"protocol":"tcp4","receive-bytes-waiting":0,"send-bytes-waiting":5,"local":{"address":"192.168.1.1","port":"443","0":"192.168.1.1:443"},"remote":{"address":"192.168.1.2","port":"48578","0":"192.168.1.2:48578"},"user":"root","command":"lighttpd","pid":"13877","fd":"13","proto":"tcp4"},` +
			`"udp6\/[fe80::1%lo0:123-*:*]":{"protocol":"udp6","local":{"address":"fe80::1%lo0","port":"123"},"remote":{"address":"*","port":"*"}},` +
			`"tcp4\/[*:53-*:*]":{"protocol":"tcp4","local":{"address":"*","port":"53"},"remote":{"address":"*","port":"*"},"user":["unbound","unbound"],"command":"unbound","pid":17923}},` +
			`"Active UNIX domain sockets":{"fffff80007473280":{"address":"fffff80007473280","type":"stream","receive-bytes-waiting":0,"send-bytes-waiting":0,"connection":"fffff80007472a00"},` +
			`"fffff80007472a00 - \/var\/run\/configd.socket":{"address":"fffff80007472a00","type":"stream","path":"\/var\/run\/configd.socket"}}}}`,
		"GET /api/diagnostics/interface/get_protocol_statistics": `{"statistics":{"tcp":{"sent-packets":38532,"syncache":{"entries-added":785,"dropped":0},"histogram":[1,2]},"udp":{"received-datagrams":5},"carp":{}}}`,
		"GET /api/diagnostics/interface/get_memory_statistics":   `{"mbuf-statistics":{"mbuf-current":2671,"mbuf-cache":644,"sendfile-syscalls":6}}`,
		"GET /api/diagnostics/interface/get_bpf_statistics": `{"bpf-statistics":{"bpf-entry":[{"pid":81972,"interface-name":"pflog0","header-complete":true,"direction":"bidirectional","received-packets":696,"dropped-packets":0,"filter-packets":696,"store-buffer-length":164,"hold-buffer-length":0,"process":"filterlog"},` +
			`{"pid":93927,"interface-name":"lo0","promiscuous":true,"immediate":true,"locked":true,"direction":"bidirectional","received-packets":18,"process":"tcpdump"}]}}`,
		"GET /api/diagnostics/interface/get_netisr_statistics": `{"netisr":{"protocol":[{"name":"ip","protocol":1,"queue-limit":1000,"policy-type":"flow","policy":"default","flags":"---"}],` +
			`"workstream":[{"work":[{"workstream":0,"cpu":0,"name":"ip","length":0,"watermark":1,"dispatched":21499,"hybrid-dispatched":0,"queue-drops":0,"queued":8227,"handled":29726}]},{"work":[{"workstream":1,"cpu":1,"name":"ip","handled":5}]}]}}`,
	})

	var interfaces, raw, err = api.NetstatInterfaces()
	if err != nil || len(interfaces) != 3 || len(raw) == 0 {
		t.Fatalf("interfaces %+v, %v", interfaces, err)
	}
	if interfaces[0].Name != "enc0" || interfaces[1].Label != "[LAN] (vtnet0) / 192.168.1.1" || interfaces[2].Mtu != 1500 ||
		interfaces[2].ReceivedErrors != 1 || interfaces[2].DroppedPackets != 2 || interfaces[2].SendErrors != 3 || interfaces[2].Collisions != 4 ||
		interfaces[1].SentBytes != 17327368 {
		t.Errorf("interfaces %+v", interfaces)
	}

	sockets, _, err := api.NetstatSocketList()
	if err != nil || len(sockets.Internet) != 3 || len(sockets.Unix) != 2 {
		t.Fatalf("sockets %+v, %v", sockets, err)
	}
	var first, second, third = sockets.Internet[0], sockets.Internet[1], sockets.Internet[2]
	if first.Local.String() != "*:53" || first.User != "unbound" || first.Pid != "17923" || second.Local.String() != "192.168.1.1:443" ||
		second.Remote.String() != "192.168.1.2:48578" || second.SendBytesWaiting != 5 || second.Command != "lighttpd" ||
		third.Local.String() != "[fe80::1%lo0]:123" || third.Remote.String() != "*:*" {
		t.Errorf("internet sockets %+v", sockets.Internet)
	}
	if sockets.Unix[0].Path != "/var/run/configd.socket" || sockets.Unix[1].Connection != "fffff80007472a00" {
		t.Errorf("unix sockets %+v", sockets.Unix)
	}

	protocols, _, err := api.NetstatProtocols()
	var wantProtocols = []NetstatSection{
		{Name: "tcp", Values: []NetstatValue{{"sent-packets", "38532"}, {"syncache.entries-added", "785"}, {"syncache.dropped", "0"}, {"histogram", "[1,2]"}}},
		{Name: "udp", Values: []NetstatValue{{"received-datagrams", "5"}}},
		{Name: "carp"},
	}
	if err != nil || !reflect.DeepEqual(protocols, wantProtocols) {
		t.Errorf("protocols in answer order:\n got  %+v\n want %+v (%v)", protocols, wantProtocols, err)
	}

	memory, _, err := api.NetstatMemory()
	if err != nil || memory.Name != "mbuf-statistics" || !reflect.DeepEqual(memory.Values, []NetstatValue{{"mbuf-current", "2671"}, {"mbuf-cache", "644"}, {"sendfile-syscalls", "6"}}) {
		t.Errorf("memory %+v, %v", memory, err)
	}

	bpf, _, err := api.NetstatBpf()
	if err != nil || len(bpf) != 2 || bpf[0].Process != "filterlog" || !bpf[0].HeaderComplete || bpf[0].Pid != "81972" ||
		!bpf[1].Promiscuous || !bpf[1].Immediate || !bpf[1].Locked || bpf[1].ReceivedPackets != 18 {
		t.Errorf("bpf %+v, %v", bpf, err)
	}

	netisr, _, err := api.NetstatNetisrGet()
	if err != nil || len(netisr.Protocols) != 1 || netisr.Protocols[0].QueueLimit != 1000 || len(netisr.Work) != 2 ||
		netisr.Work[0].Handled != 29726 || netisr.Work[1].Cpu != 1 {
		t.Errorf("netisr %+v, %v", netisr, err)
	}
}

func TestNetstatErrors(t *testing.T) {
	var api, _ = toolsTestApi(t, map[string]any{
		"GET /api/diagnostics/interface/get_interface_statistics": `null`,
		"GET /api/diagnostics/interface/get_protocol_statistics":  `{"statistics":{"tcp":{"a":1}`,
		"GET /api/diagnostics/interface/get_memory_statistics":    `[]`,
		"GET /api/diagnostics/interface/get_socket_statistics":    `{"statistics":{"Active Internet connections":{"x":{"local":"bad"}}}}`,
	})
	if _, _, err := api.NetstatInterfaces(); err == nil {
		t.Error("want an error for null")
	}
	if _, _, err := api.NetstatProtocols(); err == nil {
		t.Error("want an error for broken JSON")
	}
	if _, _, err := api.NetstatMemory(); err == nil {
		t.Error("want an error for []")
	}
	if _, _, err := api.NetstatSocketList(); err == nil {
		t.Error("want an error for a bad endpoint")
	}
	if _, _, err := api.NetstatBpf(); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("want the HTTP error, got %v", err)
	}
}

func TestVipStatus(t *testing.T) {
	var api, calls = toolsTestApi(t, map[string]any{
		"GET /api/diagnostics/interface/get_vip_status": `{"total":2,"rowCount":2,"current":1,"rows":[` +
			`{"interface":"LAN","vhid":"1","advbase":"1","advskew":"0","subnet":"192.168.1.250","status":"MASTER","mode":"carp","status_txt":"MASTER","vhid_txt":"1 (freq. 1\/0)"},` +
			`{"vhid":3,"advbase":1,"advskew":100,"subnet":"fd00::250","mode":"ipalias","interface":"OPT1","status":"DISABLED","status_txt":"DISABLED","vhid_txt":"3"}],` +
			`"carp":{"demotion":"0","allow":"1","maintenancemode":false,"status_msg":"CARP has detected a problem.<br />Check link status."}}`,
		"POST /api/diagnostics/interface/carp_status/maintenance": `{"status":"ok","action":"enter_maintenance"}`,
		"POST /api/diagnostics/interface/carp_status/disable":     `{"message":"error"}`,
		"GET /api/diagnostics/interface/get_pfsync_nodes":         `{"total":2,"rowCount":2,"current":1,"rows":[{"creatorid":"bc91ed6e","this":1},{"creatorid":"0a0b0c0d","this":0}]}`,
	})
	var entries, status, raw, err = api.VipStatusGet()
	if err != nil || len(entries) != 2 || len(raw) == 0 {
		t.Fatalf("vip status %+v, %v", entries, err)
	}
	if entries[0].Status != "MASTER" || entries[1].Vhid != "3" || entries[1].AdvSkew != "100" || entries[1].Mode != "ipalias" ||
		!strings.Contains(string(entries[0].Raw), "vhid_txt") {
		t.Errorf("entries %+v", entries)
	}
	if !status.Enabled() || status.MaintenanceMode || status.Demotion != "0" || status.Message != "CARP has detected a problem. Check link status." {
		t.Errorf("status %+v", status)
	}

	action, err := api.CarpSetStatus("maintenance")
	if err != nil || action != "enter_maintenance" {
		t.Errorf("maintenance: %q, %v", action, err)
	}
	var last = calls()[len(calls())-1]
	if last.Method != "POST" || last.Body != "{}\n" {
		t.Errorf("carp_status must POST {}: %+v", last)
	}
	if _, err := api.CarpSetStatus("disable"); err == nil || !strings.Contains(err.Error(), "error") {
		t.Errorf("want a failure, got %v", err)
	}
	var before = len(calls())
	if _, err := api.CarpSetStatus("reboot"); err == nil || len(calls()) != before {
		t.Errorf("unknown action must not be sent: %v", err)
	}

	nodes, err := api.PfsyncNodes()
	if err != nil || len(nodes) != 2 || !nodes[0].IsThis() || nodes[1].IsThis() || nodes[1].CreatorId != "0a0b0c0d" {
		t.Errorf("nodes %+v, %v", nodes, err)
	}

	var broken, _ = toolsTestApi(t, map[string]any{"GET /api/diagnostics/interface/get_vip_status": `[]`})
	if _, _, _, err := broken.VipStatusGet(); err == nil {
		t.Error("want an error for []")
	}
}
