package cli

import (
	"strings"
	"testing"
)

// /interface/arp, /interface/ndp, /interface/netstat, /interface/vip-status

const interfaceDiagTestArp = `[{"mac":"52:54:00:12:34:56","ip":"192.168.1.1","intf":"vtnet0","expired":false,"expires":-1,"permanent":true,"type":"ethernet","manufacturer":"","hostname":"","intf_description":"LAN"},` +
	`{"mac":"82:a3:6e:c6:fc:1c","ip":"192.168.1.2","intf":"vtnet0","expired":false,"expires":842,"permanent":false,"type":"ethernet","manufacturer":"Acme","hostname":"client.lan","intf_description":"LAN"},` +
	`{"mac":"52:55:0a:00:02:02","ip":"10.0.2.2","intf":"vtnet1","expired":false,"expires":550,"permanent":false,"type":"ethernet","manufacturer":"","hostname":"","intf_description":"WAN"}]`

func TestInterfaceDiagArpPrint(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/diagnostics/interface/get_arp", 200, interfaceDiagTestArp)
	var r = f.run("/interface/arp", "print")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[1], "0  192.168.1.1") {
		t.Fatalf("want 3 entries in API order:\n%s", r.stdout)
	}
	wantContains(t, "stdout", r.stdout, "ADDRESS", "MAC-ADDRESS", "INTERFACE", "HOSTNAME", "MANUFACTURER", "EXPIRES",
		"LAN (vtnet0)", "permanent", "client.lan", "Acme", "14m2s", "WAN (vtnet1)", "9m10s")

	r = f.run("/interface/arp", "print", "interface=wan")
	wantExit(t, r, 0)
	if strings.Count(r.stdout, "\n") != 2 || !strings.Contains(r.stdout, "10.0.2.2") {
		t.Errorf("want only the WAN entry:\n%s", r.stdout)
	}
	r = f.run("/interface/arp", "print", "search=acme", "detail")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "address:", "192.168.1.2", "device:", "vtnet0", "permanent:", "no")
	wantNotContains(t, "stdout", r.stdout, "192.168.1.1")
	r = f.run("/interface/arp", "print", "resolve", "json", "interface=vtnet1")
	wantExit(t, r, 0)
	if strings.Count(r.stdout, "\n") != 1 || !strings.HasPrefix(r.stdout, `{"mac":"52:55:0a:00:02:02"`) {
		t.Errorf("want the raw WAN entry: %q", r.stdout)
	}
	if calls := f.calls(); calls[len(calls)-1].Query.Get("resolve") != "yes" {
		t.Errorf("resolve must be sent: %v", calls[len(calls)-1])
	}
	wantNoMutations(t, f)
}

func TestInterfaceDiagArpFlush(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", "/api/diagnostics/interface/flush_arp", 200, "192.168.1.2 (192.168.1.2) deleted\n10.0.2.2 (10.0.2.2) deleted\n")
	wantFailure(t, f.run("/interface/arp", "flush"), "confirm=yes")
	wantNoCalls(t, f)
	var r = f.run("/interface/arp", "flush", "confirm=yes")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "deleted 2 ARP entries")
	if r.stdout != "" {
		t.Errorf("want no output: %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", "/api/diagnostics/interface/flush_arp")

	var refused = newFakeOPN(t)
	refused.on("POST", "/api/diagnostics/interface/flush_arp", 200, `{"message":"error"}`)
	wantFailure(t, refused.run("/interface/arp", "flush", "confirm=yes"), "refused")
}

func TestInterfaceDiagNdpPrint(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/diagnostics/interface/get_ndp", 200, `[{"mac":"52:54:00:12:34:56","ip":"fe80::5054:ff:fe12:3456%vtnet0","intf":"vtnet0","manufacturer":"","intf_description":"LAN"},`+
		`{"mac":"52:56:00:00:00:02","ip":"fec0::2","intf":"vtnet1","manufacturer":"QEMU","intf_description":"WAN"}]`)
	var r = f.run("/interface/ndp", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "ADDRESS", "MAC-ADDRESS", "fe80::5054:ff:fe12:3456%vtnet0", "LAN (vtnet0)", "fec0::2", "QEMU")
	r = f.run("/interface/ndp", "print", "search=qemu")
	wantExit(t, r, 0)
	if strings.Count(r.stdout, "\n") != 2 || !strings.Contains(r.stdout, "0  fec0::2") {
		t.Errorf("want only the QEMU entry:\n%s", r.stdout)
	}
	r = f.run("/interface/ndp", "print", "json", "interface=lan")
	wantExit(t, r, 0)
	if strings.Count(r.stdout, "\n") != 1 || !strings.Contains(r.stdout, `"intf":"vtnet0"`) {
		t.Errorf("want the raw LAN entry: %q", r.stdout)
	}
	var broken = newFakeOPN(t)
	broken.on("GET", "/api/diagnostics/interface/get_ndp", 200, `null`)
	wantFailure(t, broken.run("/interface/ndp", "print"), "NDP table")
}

func interfaceDiagTestNetstat(t *testing.T) *fakeOPN {
	var f = newFakeOPN(t)
	f.on("GET", "/api/diagnostics/interface/get_interface_statistics", 200, `{"statistics":{`+
		`"[LAN] (vtnet0) \/ 192.168.1.1":{"name":"vtnet0","flags":"0x8843","network":"192.168.1.0\/24","address":"192.168.1.1","received-packets":21122,"received-bytes":2919298,"sent-packets":30340,"sent-bytes":17327368},`+
		`"[WAN] (vtnet1) \/ 52:54:00:12:34:57":{"name":"vtnet1","flags":"0x8843","mtu":1500,"network":"<Link#2>","address":"52:54:00:12:34:57","received-packets":407,"received-errors":7,"dropped-packets":0,"received-bytes":86468,"sent-packets":426,"send-errors":0,"sent-bytes":39930,"collisions":0},`+
		`"[enc0] \/ enc0":{"name":"enc0","mtu":1536,"network":"<Link#4>","address":"enc0"}}}`)
	f.on("GET", "/api/diagnostics/interface/get_socket_statistics", 200, `{"statistics":{"Active Internet connections":{`+
		`"tcp4\/[192.168.1.1:443-192.168.1.2:48578]":{"protocol":"tcp4","receive-bytes-waiting":0,"send-bytes-waiting":5,"local":{"address":"192.168.1.1","port":"443"},"remote":{"address":"192.168.1.2","port":"48578"},"user":"root","command":"lighttpd","pid":"13877"},`+
		`"udp6\/[*:546-*:*]":{"protocol":"udp6","local":{"address":"*","port":"546"},"remote":{"address":"*","port":"*"},"user":"root","command":"dhcp6c","pid":"1234"},`+
		`"tcp4\/[*:53-*:*]":{"protocol":"tcp4","local":{"address":"*","port":"53"},"remote":{"address":"*","port":"*"},"user":"unbound","command":"unbound","pid":"17923"}},`+
		`"Active UNIX domain sockets":{"fffff80007472a00 - \/var\/run\/configd.socket":{"address":"fffff80007472a00","type":"stream","path":"\/var\/run\/configd.socket"}}}}`)
	f.on("GET", "/api/diagnostics/interface/get_protocol_statistics", 200, `{"statistics":{"tcp":{"sent-packets":38532,"sent-urg-only-packets":0,"syncache":{"entries-added":785}},"udp":{"received-datagrams":5},"carp":{"received-inet-packets":0}}}`)
	f.on("GET", "/api/diagnostics/interface/get_memory_statistics", 200, `{"mbuf-statistics":{"mbuf-current":2671,"mbuf-failures":0}}`)
	f.on("GET", "/api/diagnostics/interface/get_bpf_statistics", 200, `{"bpf-statistics":{"bpf-entry":[{"pid":93927,"interface-name":"lo0","promiscuous":true,"immediate":true,"direction":"bidirectional","received-packets":18,"dropped-packets":1,"filter-packets":17,"process":"tcpdump"}]}}`)
	f.on("GET", "/api/diagnostics/interface/get_netisr_statistics", 200, `{"netisr":{"protocol":[{"name":"ip","protocol":1,"queue-limit":1000,"policy-type":"flow","policy":"default","flags":"---"}],`+
		`"workstream":[{"work":[{"workstream":0,"cpu":0,"name":"ip","length":0,"watermark":1,"dispatched":21499,"hybrid-dispatched":0,"queue-drops":3,"queued":8227,"handled":29726}]}]}}`)
	return f
}

func TestInterfaceDiagNetstat(t *testing.T) {
	t.Parallel()
	var f = interfaceDiagTestNetstat(t)
	var r = f.run("/interface/netstat", "interfaces")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[1], "enc0") || !strings.HasPrefix(lines[2], "LAN (vtnet0)") || !strings.HasPrefix(lines[3], "WAN (vtnet1)") {
		t.Fatalf("want the addresses sorted by device:\n%s", r.stdout)
	}
	wantContains(t, "stdout", lines[3], "<Link#2>", "52:54:00:12:34:57", "1500", "407", "7", "86468", "39930")
	r = f.run("/interface/netstat", "interfaces", "interface=lan")
	wantExit(t, r, 0)
	if strings.Count(r.stdout, "\n") != 2 {
		t.Errorf("want only LAN:\n%s", r.stdout)
	}

	r = f.run("/interface/netstat", "sockets")
	wantExit(t, r, 0)
	lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[1], "tcp4   *:53") || !strings.HasPrefix(lines[3], "udp6") {
		t.Errorf("want 3 sockets sorted by protocol:\n%s", r.stdout)
	}
	wantContains(t, "stdout", r.stdout, "PROTO", "LOCAL", "REMOTE", "RECV-Q", "SEND-Q", "USER", "COMMAND", "PID", "192.168.1.2:48578", "lighttpd", "13877")
	r = f.run("/interface/netstat", "sockets", "protocol=tcp", "listening")
	wantExit(t, r, 0)
	if strings.Count(r.stdout, "\n") != 2 || !strings.Contains(r.stdout, "unbound") {
		t.Errorf("want only the listening TCP socket:\n%s", r.stdout)
	}
	r = f.run("/interface/netstat", "sockets", "unix")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "ADDRESS", "TYPE", "PATH", "/var/run/configd.socket", "stream")

	r = f.run("/interface/netstat", "protocols")
	wantExit(t, r, 0)
	if r.stdout != "tcp:\n  sent-packets:            38532\n  syncache.entries-added:  785\n\nudp:\n  received-datagrams:  5\n" {
		t.Errorf("want the non-zero counters, all-zero sections left out: %q", r.stdout)
	}
	r = f.run("/interface/netstat", "protocols", "protocol=carp,TCP", "zero")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "tcp:", "sent-urg-only-packets:", "carp:", "received-inet-packets:")
	wantNotContains(t, "stdout", r.stdout, "udp:")
	r = f.run("/interface/netstat", "protocols", "protocol=ospf")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "no statistics for ospf", "tcp, udp, carp")

	r = f.run("/interface/netstat", "memory")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "mbuf-current:", "2671", "mbuf-failures:")
	r = f.run("/interface/netstat", "bpf")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "PID", "PROCESS", "93927", "tcpdump", "lo0", "promiscuous,immediate", "18", "17")
	r = f.run("/interface/netstat", "netisr")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "PROTOCOL", "QUEUE-LIMIT", "1000", "flow", "WORKSTREAM", "DISPATCHED", "21499", "29726")

	for _, command := range []string{"interfaces", "sockets", "protocols", "memory", "bpf", "netisr"} {
		r = f.run("/interface/netstat", command, "json")
		wantExit(t, r, 0)
		if !strings.HasPrefix(r.stdout, "{") || strings.Count(r.stdout, "\n") != 1 {
			t.Errorf("%s json: want one raw object: %q", command, r.stdout)
		}
	}
	wantNoMutations(t, f)

	var failing = newFakeOPN(t)
	failing.on("GET", "/api/diagnostics/interface/get_bpf_statistics", 403, `{"status":403,"message":"Forbidden"}`)
	wantFailure(t, failing.run("/interface/netstat", "bpf"), "HTTP 403")
}

const interfaceDiagTestVip = `{"total":2,"rowCount":2,"current":1,"rows":[` +
	`{"interface":"LAN","vhid":"1","advbase":"1","advskew":"0","subnet":"192.168.1.250","status":"MASTER","mode":"carp","status_txt":"MASTER","vhid_txt":"1 (freq. 1\/0)"},` +
	`{"vhid":"3","advbase":"1","advskew":"100","subnet":"fd00::250","mode":"ipalias","interface":"OPT1","status":"DISABLED","status_txt":"DISABLED","vhid_txt":"3"}],` +
	`"carp":{"demotion":"0","allow":"1","maintenancemode":MAINTENANCE,"status_msg":"CARP has detected a problem.<br />Check link status."}}`

func interfaceDiagTestVipFake(t *testing.T, maintenance bool) *fakeOPN {
	var f = newFakeOPN(t)
	f.on("GET", "/api/diagnostics/interface/get_vip_status", 200, strings.Replace(interfaceDiagTestVip, "MAINTENANCE", map[bool]string{true: "true", false: "false"}[maintenance], 1))
	f.on("POST", "/api/diagnostics/interface/carp_status/maintenance", 200, `{"status":"ok","action":"enter_maintenance"}`)
	f.on("POST", "/api/diagnostics/interface/carp_status/enable", 200, `{"status":"ok","action":"enable"}`)
	f.on("POST", "/api/diagnostics/interface/carp_status/disable", 200, `{"status":"ok","action":"disable"}`)
	return f
}

func TestInterfaceDiagVipStatusPrint(t *testing.T) {
	t.Parallel()
	var f = interfaceDiagTestVipFake(t, false)
	var r = f.run("/interface/vip-status", "print")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[1], "0  LAN") {
		t.Fatalf("want 2 VIPs:\n%s", r.stdout)
	}
	wantContains(t, "stdout", r.stdout, "VHID", "ADDRESS", "MODE", "STATUS", "ADVSKEW", "192.168.1.250", "MASTER", "carp", "fd00::250", "DISABLED", "100")
	r = f.run("/interface/vip-status", "print", "json")
	wantExit(t, r, 0)
	if strings.Count(r.stdout, "\n") != 2 || !strings.Contains(r.stdout, `"vhid_txt":"1 (freq. 1\/0)"`) {
		t.Errorf("want the raw rows: %q", r.stdout)
	}

	r = f.run("/interface/vip-status", "status")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "carp:", "enabled", "maintenance-mode:", "no", "demotion:", "0", "message:", "CARP has detected a problem. Check link status.")
	r = f.run("/interface/vip-status", "status", "json")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, `"maintenancemode":false`)

	var pfsync = newFakeOPN(t)
	pfsync.on("GET", "/api/diagnostics/interface/get_pfsync_nodes", 200, `{"rows":[{"creatorid":"bc91ed6e","this":1},{"creatorid":"0a0b0c0d","this":0}]}`)
	r = pfsync.run("/interface/vip-status", "pfsync-nodes")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "CREATOR-ID", "THIS-NODE", "bc91ed6e    yes", "0a0b0c0d    no")
	wantNoMutations(t, f)
	wantNoMutations(t, pfsync)
}

func TestInterfaceDiagVipStatusChanges(t *testing.T) {
	t.Parallel()
	// nothing is sent without confirmation, not even the status read
	for _, args := range [][]string{
		{"/interface/vip-status", "maintenance", "enter"},
		{"/interface/vip-status", "enable"},
		{"/interface/vip-status", "disable"},
	} {
		var f = interfaceDiagTestVipFake(t, false)
		wantFailure(t, f.run(args...), "confirm=yes")
		wantNoCalls(t, f)
	}
	var invalid = interfaceDiagTestVipFake(t, false)
	wantFailure(t, invalid.run("/interface/vip-status", "maintenance", "toggle", "confirm=yes"))
	wantNoCalls(t, invalid)

	var enter = interfaceDiagTestVipFake(t, false)
	var r = enter.run("/interface/vip-status", "maintenance", "enter", "confirm=yes")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("want no output: %q", r.stdout)
	}
	wantOneMutation(t, enter, "POST", "/api/diagnostics/interface/carp_status/maintenance")
	// already in the requested mode: no toggle
	r = enter.run("/interface/vip-status", "maintenance", "leave", "confirm=yes")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "not in CARP maintenance mode")
	wantOneMutation(t, enter, "POST", "/api/diagnostics/interface/carp_status/maintenance")

	var leave = interfaceDiagTestVipFake(t, true)
	wantExit(t, leave.run("/interface/vip-status", "maintenance", "leave", "confirm=yes"), 0)
	wantOneMutation(t, leave, "POST", "/api/diagnostics/interface/carp_status/maintenance")
	r = leave.run("/interface/vip-status", "maintenance", "enter", "confirm=yes")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "already is in CARP maintenance mode")

	for _, action := range []string{"enable", "disable"} {
		var f = interfaceDiagTestVipFake(t, false)
		wantExit(t, f.run("/interface/vip-status", action, "confirm=yes"), 0)
		wantOneMutation(t, f, "POST", "/api/diagnostics/interface/carp_status/"+action)
	}

	var failing = newFakeOPN(t)
	failing.on("POST", "/api/diagnostics/interface/carp_status/disable", 200, `{"message":"error"}`)
	wantFailure(t, failing.run("/interface/vip-status", "disable", "confirm=yes"), "CARP disable failed: error")
}
