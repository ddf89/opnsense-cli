//go:build integration

package integrationtools

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/diagnostics"
)

func TestPingJob(t *testing.T) {
	var diag = diagApi(t)
	var id, err = diag.PingCreate(diagnostics.PingSettings{Hostname: "127.0.0.1", Description: runPrefix + "-lib"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = diag.PingRemove(id) }()

	job, err := diag.PingJob(id)
	if err != nil || job.Running() || job.Sent != nil || job.Hostname != "127.0.0.1" || job.Family != "ip" {
		t.Fatalf("a created job is stopped without statistics: %+v, %v", job, err)
	}
	if err := diag.PingStart(id); err != nil {
		t.Fatal(err)
	}
	if err := diag.PingStart(id); err == nil || !strings.Contains(err.Error(), "already active") {
		t.Errorf("starting a running job: want already active, got %v", err)
	}
	// statistics appear after a SIGINFO, i.e. one listing later
	var deadline = time.Now().Add(15 * time.Second)
	for {
		job, err = diag.PingJob(id)
		if err != nil {
			t.Fatal(err)
		}
		if job.Sent != nil && *job.Sent >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no statistics after 15s: %+v", job)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !job.Running() || job.Received == nil || *job.Received < 1 || job.Avg == nil || job.LastError != nil {
		t.Errorf("job %+v", job)
	}
	if err := diag.PingStop(id); err != nil {
		t.Fatal(err)
	}
	if job, err = diag.PingJob(id); err != nil || job.Running() || job.Sent == nil {
		t.Errorf("a stopped job keeps its statistics: %+v, %v", job, err)
	}
	if err := diag.PingRemove(id); err != nil {
		t.Fatal(err)
	}
	if _, err := diag.PingJob(id); !api.IsNotFound(err) {
		t.Errorf("removed job: want not found, got %v", err)
	}
	if err := diag.PingRemove(id); !api.IsNotFound(err) {
		t.Errorf("removing again: want not found, got %v", err)
	}

	_, err = diag.PingCreate(diagnostics.PingSettings{Hostname: "", Interval: 500})
	if err == nil || !strings.Contains(err.Error(), "ping.settings.hostname") || !strings.Contains(err.Error(), "ping.settings.interval") {
		t.Errorf("want validations, got %v", err)
	}
}

func TestTracerouteAndPortProbe(t *testing.T) {
	var diag = diagApi(t)
	var trace, err = diag.Traceroute(diagnostics.TracerouteOptions{Hostname: "127.0.0.1"})
	if err != nil || len(trace.Hops) != 1 || trace.Hops[0].Address != "127.0.0.1" || trace.Hops[0].TTL != "1" ||
		!strings.HasPrefix(trace.Notice, "traceroute to 127.0.0.1") {
		t.Errorf("traceroute %+v, %v", trace, err)
	}
	if _, err := diag.Traceroute(diagnostics.TracerouteOptions{Hostname: "bad host!"}); err == nil || !strings.Contains(err.Error(), "traceroute.settings.hostname") {
		t.Errorf("want a validation error, got %v", err)
	}

	probe, err := diag.PortProbe(diagnostics.PortProbeOptions{Hostname: "127.0.0.1", Port: 443})
	if err != nil || !probe.Succeeded() {
		t.Errorf("the web GUI port: %+v, %v", probe, err)
	}
	probe, err = diag.PortProbe(diagnostics.PortProbeOptions{Hostname: "127.0.0.1", Port: 9})
	if err != nil || probe.Succeeded() || !strings.Contains(probe.Message, "Connection refused") {
		t.Errorf("a closed port: %+v, %v", probe, err)
	}
}

func TestDnsLookup(t *testing.T) {
	var diag = diagApi(t)
	var result, err = diag.DnsLookup("localhost", "127.0.0.1")
	if err != nil || result.Error != "" {
		t.Fatalf("%+v, %v", result, err)
	}
	var found = false
	for _, answer := range result.Answers() {
		if answer.Type == "A" && answer.Data == "127.0.0.1" && answer.Name == "localhost." {
			found = true
		}
	}
	if !found || result.Records["A"].Server != "127.0.0.1" {
		t.Errorf("no A record 127.0.0.1: %+v", result)
	}
	reverse, err := diag.DnsLookup("127.0.0.1", "127.0.0.1")
	if err != nil || len(reverse.Answers()) == 0 || reverse.Answers()[0].Type != "PTR" || reverse.Answers()[0].Data != "localhost." {
		t.Errorf("reverse %+v, %v", reverse, err)
	}
	// nothing listens on 127.0.0.2
	failing, err := diag.DnsLookup("localhost", "127.0.0.2")
	if err != nil || failing.Error == "" {
		t.Errorf("want the resolver error, got %+v, %v", failing, err)
	}
}

func TestPacketCapture(t *testing.T) {
	var diag = diagApi(t)
	var options, err = diag.PacketCaptureOptions()
	if err != nil {
		t.Fatal(err)
	}
	var hasLoopback = false
	for _, iface := range options.Interfaces {
		if iface.Device == "lo0" {
			hasLoopback = true
		}
	}
	if !hasLoopback || options.Protocols[0] != "any" || len(options.Protocols) < 10 {
		t.Fatalf("options %+v", options)
	}

	id, err := diag.PacketCaptureCreate(diagnostics.PacketCaptureSettings{
		Interfaces: []string{"lo0"}, Description: runPrefix + "-lib", Family: "ip", Protocol: "TCP", Host: "127.0.0.1", Port: 443, Count: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = diag.PacketCaptureRemove(id) }()
	if err := diag.PacketCaptureStart(id); err != nil {
		t.Fatal(err)
	}
	job, err := diag.PacketCaptureJob(id)
	if err != nil || !job.Running() || job.Interface != "lo0" || job.Protocol != "TCP" || job.Count != "50" {
		t.Errorf("job %+v, %v", job, err)
	}

	// generate traffic until packets show up (tcpdump starts and the bpf buffer is flushed with a delay)
	var view diagnostics.PacketCaptureViewResult
	var deadline = time.Now().Add(20 * time.Second)
	for {
		time.Sleep(time.Second)
		if _, err := diag.PortProbe(diagnostics.PortProbeOptions{Hostname: "127.0.0.1", Port: 443}); err != nil {
			t.Fatal(err)
		}
		if view, err = diag.PacketCaptureView(id, "normal"); err != nil {
			t.Fatal(err)
		}
		if len(view.Interfaces["lo0"].Packets) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no packets after 20s: %+v", view)
		}
	}
	var packet = view.Interfaces["lo0"].Packets[0]
	if !strings.Contains(packet.Text, "127.0.0.1") || !strings.Contains(packet.Text, ".443") || packet.SourceMac != nil || packet.Family != "ip" {
		t.Errorf("packet %+v", packet)
	}
	high, err := diag.PacketCaptureView(id, "high")
	if err != nil || len(high.Interfaces["lo0"].Packets) == 0 || !strings.Contains(high.Interfaces["lo0"].Packets[0].Text, "Flags") {
		t.Errorf("high detail %+v, %v", high, err)
	}

	if err := diag.PacketCaptureStop(id); err != nil {
		t.Fatal(err)
	}
	if job, err = diag.PacketCaptureJob(id); err != nil || job.Running() {
		t.Errorf("stopped job %+v, %v", job, err)
	}
	content, filename, err := diag.PacketCaptureDownload(id)
	if err != nil || filename != id+".zip" {
		t.Fatalf("download %q, %v", filename, err)
	}
	archive, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, file := range archive.File {
		names = append(names, file.Name)
	}
	if strings.Join(names, ",") != id+".json,"+id+"_lo0.pcap" && strings.Join(names, ",") != id+"_lo0.pcap,"+id+".json" {
		t.Errorf("archive files %v", names)
	}

	if err := diag.PacketCaptureRemove(id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := diag.PacketCaptureDownload(id); !api.IsNotFound(err) {
		t.Errorf("download of a removed capture: want not found, got %v", err)
	}
	if _, err := diag.PacketCaptureView(id, "normal"); !api.IsNotFound(err) {
		t.Errorf("view of a removed capture: want not found, got %v", err)
	}

	if _, err := diag.PacketCaptureCreate(diagnostics.PacketCaptureSettings{Interfaces: []string{"a7nonexist0"}, Description: runPrefix}); err == nil ||
		!strings.Contains(err.Error(), "not in list") {
		t.Errorf("unknown interface: want a validation error, got %v", err)
	}
}

func TestNeighborsNetstatCarp(t *testing.T) {
	var diag = diagApi(t)
	var arp, err = diag.ArpList(false)
	if err != nil {
		t.Fatal(err)
	}
	var own = false
	for _, entry := range arp {
		if entry.Ip == "192.168.1.1" && entry.Permanent && entry.Interface != "" {
			own = true
		}
	}
	if !own {
		t.Errorf("the LAN address of the firewall is missing in the ARP table: %+v", arp)
	}
	if _, err := diag.NdpList(); err != nil {
		t.Error(err)
	}

	interfaces, _, err := diag.NetstatInterfaces()
	if err != nil || len(interfaces) == 0 {
		t.Errorf("interfaces %v", err)
	}
	var loopback = false
	for _, entry := range interfaces {
		if entry.Name == "lo0" && entry.Address == "127.0.0.1" && entry.ReceivedPackets > 0 {
			loopback = true
		}
	}
	if !loopback {
		t.Errorf("no lo0 127.0.0.1 counters: %+v", interfaces)
	}
	sockets, _, err := diag.NetstatSocketList()
	var webgui = false
	for _, socket := range sockets.Internet {
		if strings.HasPrefix(socket.Protocol, "tcp") && socket.Local.Port == "443" && socket.Remote.Address == "*" {
			webgui = true
		}
	}
	if err != nil || !webgui || len(sockets.Unix) == 0 {
		t.Errorf("sockets: listening 443 %v, %d unix sockets, %v", webgui, len(sockets.Unix), err)
	}
	protocols, _, err := diag.NetstatProtocols()
	if err != nil || len(protocols) < 3 || protocols[0].Name != "tcp" || len(protocols[0].Values) < 10 {
		t.Errorf("protocols %v", err)
	}
	memory, _, err := diag.NetstatMemory()
	if err != nil || memory.Name != "mbuf-statistics" || len(memory.Values) == 0 {
		t.Errorf("memory %+v, %v", memory, err)
	}
	bpf, _, err := diag.NetstatBpf()
	if err != nil || len(bpf) == 0 {
		t.Errorf("bpf %+v, %v (filterlog listens on pflog0)", bpf, err)
	}
	netisr, _, err := diag.NetstatNetisrGet()
	if err != nil || len(netisr.Protocols) == 0 || len(netisr.Work) == 0 {
		t.Errorf("netisr %+v, %v", netisr, err)
	}

	_, status, _, err := diag.VipStatusGet()
	if err != nil || status.Allow == "" || status.Demotion == "" {
		t.Errorf("carp status %+v, %v", status, err)
	}
	nodes, err := diag.PfsyncNodes()
	if err != nil || len(nodes) == 0 || !nodes[0].IsThis() {
		t.Errorf("pfsync nodes %+v, %v", nodes, err)
	}
}
