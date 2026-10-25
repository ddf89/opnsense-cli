package diagnostics

import (
	"errors"
	"io"
	"net/http"
	coreapi "opnsense-cli/opnsense/api"
	"reflect"
	"strings"
	"testing"
)

const toolsTestCaptureGet = `{"packetcapture":{"settings":{"interface":{"vtnet0":{"value":"vtnet0 [LAN]","selected":0},` +
	`"vtnet1":{"value":"vtnet1 [WAN]","selected":0},"lo0":{"value":"lo0 [Loopback]","selected":0},"enc0":{"value":"enc0","selected":0}},` +
	`"description":"","promiscuous":"0","fam":{"any":{"value":"Any","selected":0},"ip":{"value":"IPv4 only","selected":0}},"protocol_not":"0",` +
	`"protocol":{"any":{"value":"any","selected":1},"TCP":{"value":"TCP","selected":0},"UDP":{"value":"UDP","selected":0},"ICMP":{"value":"ICMP","selected":0}},` +
	`"host":"","port_not":"0","port":"","snaplen":"","count":"100"}}}`

const toolsTestCaptureJobs = `{"total":1,"rowCount":1,"current":1,"rows":[{"interface":"lo0,vtnet0","description":"probe","promiscuous":"0","fam":"ip",` +
	`"protocol_not":"1","protocol":"TCP","host":"127.0.0.1","port_not":"0","port":"443","snaplen":"","count":"20","id":"` + toolsTestJobId + `","status":"running"}]}`

const toolsTestCaptureView = `{"settings":{"interface":"lo0,vtnet0"},"status":"ok","interfaces":{` +
	`"vtnet0":{"rows":[{"timestamp":"2026-10-25T15:40:38.000001","esrc":"52:54:00:12:34:56","edst":"82:a3:6e:c6:fc:1c","raw":"ethertype IPv4 (0x0800), length 98: 192.168.1.1 > 192.168.1.2: ICMP echo request\n","fam":"ip"}],"name":"LAN"},` +
	`"lo0":{"rows":[{"timestamp":"2026-10-25T15:40:37.803032","esrc":null,"edst":null,"raw":"length 64: 127.0.0.1.48552 > 127.0.0.1.443: tcp 0\n","fam":"ip"}],"name":"Loopback"}}}`

func TestPacketCaptureOptions(t *testing.T) {
	var api, _ = toolsTestApi(t, map[string]any{"GET /api/diagnostics/packet_capture/get": toolsTestCaptureGet})
	var options, err = api.PacketCaptureOptions()
	if err != nil {
		t.Fatal(err)
	}
	var want = []PacketCaptureInterface{{"enc0", "enc0"}, {"lo0", "lo0 [Loopback]"}, {"vtnet0", "vtnet0 [LAN]"}, {"vtnet1", "vtnet1 [WAN]"}}
	if !reflect.DeepEqual(options.Interfaces, want) || !reflect.DeepEqual(options.Protocols, []string{"any", "ICMP", "TCP", "UDP"}) {
		t.Errorf("options %+v", options)
	}
	if options.Interfaces[2].Description() != "LAN" || options.Interfaces[0].Description() != "" {
		t.Errorf("descriptions %q %q", options.Interfaces[2].Description(), options.Interfaces[0].Description())
	}
	var broken, _ = toolsTestApi(t, map[string]any{"GET /api/diagnostics/packet_capture/get": `{"packetcapture":{"settings":{}}}`})
	if _, err := broken.PacketCaptureOptions(); err == nil {
		t.Error("want an error without interfaces")
	}
}

func TestPacketCaptureJobLifecycle(t *testing.T) {
	var api, calls = toolsTestApi(t, map[string]any{
		"POST /api/diagnostics/packet_capture/set":                      `{"result":"ok","uuid":"` + toolsTestJobId + `"}`,
		"POST /api/diagnostics/packet_capture/start/" + toolsTestJobId:  `{"status":"ok","started_processes":2}`,
		"POST /api/diagnostics/packet_capture/stop/" + toolsTestJobId:   `{"status":"ok","stopped_processes":2}`,
		"POST /api/diagnostics/packet_capture/remove/" + toolsTestJobId: `{"status":"ok","stopped_processes":0}`,
		"GET /api/diagnostics/packet_capture/search_jobs":               toolsTestCaptureJobs,
	})
	var id, err = api.PacketCaptureCreate(PacketCaptureSettings{
		Interfaces: []string{"lo0", "vtnet0"}, Description: "probe", Family: "ip", Protocol: "TCP", ProtocolInvert: true,
		Host: "127.0.0.1", Port: 443, Count: 20,
	})
	if err != nil || id != toolsTestJobId {
		t.Fatalf("create: %q, %v", id, err)
	}
	var settings = toolsTestSettings(t, calls()[0], "packetcapture")
	var want = map[string]any{"interface": "lo0,vtnet0", "description": "probe", "promiscuous": "0", "fam": "ip", "protocol_not": "1",
		"protocol": "TCP", "host": "127.0.0.1", "port_not": "0", "port": "443", "snaplen": "", "count": "20"}
	if !reflect.DeepEqual(settings, want) {
		t.Errorf("settings:\n got  %v\n want %v", settings, want)
	}
	if err := api.PacketCaptureStart(id); err != nil {
		t.Fatal(err)
	}
	job, err := api.PacketCaptureJob(id)
	if err != nil || !job.Running() || !reflect.DeepEqual(job.Interfaces(), []string{"lo0", "vtnet0"}) || job.ProtocolInvert != "1" ||
		job.Port != "443" || !strings.Contains(string(job.Raw), `"status":"running"`) {
		t.Errorf("job %+v, %v", job, err)
	}
	if _, err := api.PacketCaptureJob("bbbb"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if err := api.PacketCaptureStop(id); err != nil {
		t.Error(err)
	}
	if err := api.PacketCaptureRemove(id); err != nil {
		t.Error(err)
	}

	// defaults
	var defaults, defaultCalls = toolsTestApi(t, map[string]any{"POST /api/diagnostics/packet_capture/set": `{"result":"ok","uuid":"` + toolsTestJobId + `"}`})
	if _, err := defaults.PacketCaptureCreate(PacketCaptureSettings{Interfaces: []string{"lo0"}, Snaplen: 96}); err != nil {
		t.Fatal(err)
	}
	settings = toolsTestSettings(t, defaultCalls()[0], "packetcapture")
	if settings["fam"] != "any" || settings["protocol"] != "any" || settings["count"] != "0" || settings["snaplen"] != "96" || settings["port"] != "" {
		t.Errorf("defaults %v", settings)
	}

	var failing, _ = toolsTestApi(t, map[string]any{
		"POST /api/diagnostics/packet_capture/set": `{"result":"failed","validations":{"packetcapture.settings.interface":"Option [a7nonexist0] not in list."}}`,
	})
	var validation *coreapi.ValidationError
	if _, err := failing.PacketCaptureCreate(PacketCaptureSettings{Interfaces: []string{"a7nonexist0"}}); !errors.As(err, &validation) {
		t.Errorf("want a validation error, got %v", err)
	}
}

func TestPacketCaptureView(t *testing.T) {
	var api, calls = toolsTestApi(t, map[string]any{
		"GET /api/diagnostics/packet_capture/view/" + toolsTestJobId + "/high":   toolsTestCaptureView,
		"GET /api/diagnostics/packet_capture/view/" + toolsTestJobId + "/normal": `{"settings":{},"status":"ok","interfaces":[]}`,
		"GET /api/diagnostics/packet_capture/view/bbbb/normal":                   `{"status":"failed"}`,
	})
	var view, err = api.PacketCaptureView(toolsTestJobId, "high")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(view.Devices(), []string{"lo0", "vtnet0"}) || view.Interfaces["vtnet0"].Name != "LAN" {
		t.Fatalf("view %+v", view)
	}
	var lan = view.Interfaces["vtnet0"].Packets[0]
	var lo = view.Interfaces["lo0"].Packets[0]
	if *lan.SourceMac != "52:54:00:12:34:56" || *lan.DestinationMac != "82:a3:6e:c6:fc:1c" || lan.Family != "ip" ||
		!strings.Contains(lan.Text, "ICMP echo request") || lo.SourceMac != nil || lo.Timestamp != "2026-10-25T15:40:37.803032" {
		t.Errorf("packets %+v %+v", lan, lo)
	}
	if !strings.Contains(string(view.Raw), `"status":"ok"`) {
		t.Errorf("raw %s", view.Raw)
	}
	empty, err := api.PacketCaptureView(toolsTestJobId, "")
	if err != nil || len(empty.Devices()) != 0 {
		t.Errorf("empty view %+v, %v", empty, err)
	}
	if _, err := api.PacketCaptureView("bbbb", "normal"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	var before = len(calls())
	if _, err := api.PacketCaptureView(toolsTestJobId, "verbose"); err == nil {
		t.Error("want an error for an unknown detail")
	}
	if _, err := api.PacketCaptureView("../x", "normal"); err == nil {
		t.Error("want an error for an invalid id")
	}
	if len(calls()) != before {
		t.Errorf("nothing must be sent for invalid arguments: %+v", calls()[before:])
	}
}

func TestPacketCaptureDownload(t *testing.T) {
	var api, _ = toolsTestApi(t, map[string]any{
		"GET /api/diagnostics/packet_capture/download/" + toolsTestJobId: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", "attachment; filename=../"+toolsTestJobId+".zip")
			_, _ = io.WriteString(w, "PK\x03\x04zip")
		},
		"GET /api/diagnostics/packet_capture/download/aaaa": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, "PK")
		},
		"GET /api/diagnostics/packet_capture/download/bbbb": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		},
		"GET /api/diagnostics/packet_capture/download/cccc": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"status":403,"message":"Forbidden"}`)
		},
	})
	var content, name, err = api.PacketCaptureDownload(toolsTestJobId)
	if err != nil || string(content) != "PK\x03\x04zip" || name != toolsTestJobId+".zip" {
		t.Errorf("download: %q %q %v", content, name, err)
	}
	if _, name, err := api.PacketCaptureDownload("aaaa"); err != nil || name != "aaaa.zip" {
		t.Errorf("without disposition: %q %v", name, err)
	}
	if _, _, err := api.PacketCaptureDownload("bbbb"); !coreapi.IsNotFound(err) {
		t.Errorf("empty answer: want not found, got %v", err)
	}
	if _, _, err := api.PacketCaptureDownload("cccc"); err == nil || !strings.Contains(err.Error(), "HTTP 403: Forbidden") {
		t.Errorf("want the HTTP error, got %v", err)
	}
}
