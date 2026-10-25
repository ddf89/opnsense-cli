package diagnostics

import (
	"net/http"
	"strings"
	"testing"
)

var systemResourceTestAnswers = map[string]string{
	"system_information": `{"name":"OPNsense.internal","versions":["OPNsense 26.7-amd64","FreeBSD 15.1-RELEASE-p1","OpenSSL 3.5.7"],"updates":"Click to check for updates."}`,
	"system_time":        `{"uptime":"00:42:37","datetime":"Sun Oct 25 0:06:33 UTC 2026","boottime":"Sat Oct 24 23:23:56 UTC 2026","config":"Sun Oct 25 0:03:51 UTC 2026","loadavg":"0.48, 0.58, 0.56"}`,
	"system_resources":   `{"memory":{"total":"2102894592","total_frmt":"2005","used":599127070,"used_frmt":"571","arc":104857600,"arc_frmt":"100"}}`,
	"system_disk":        `{"devices":[{"device":"\/dev\/ufs\/OPNsense_Nano","type":"ufs","blocks":"2.8G","used":"2.0G","available":"540M","used_pct":80,"mountpoint":"\/"},{"device":"zroot","type":"zfs","blocks":"10G","total":"10G","total_bytes":10737418240,"used":"1G","used_bytes":1073741824,"available":"9G","available_bytes":9663676416,"used_pct":10,"mountpoint":"\/zroot"}]}`,
	"system_swap":        `{"swap":[{"device":"\/dev\/gpt\/swapfs","total":"1048576","used":"2048"}]}`,
	"system_mbuf":        `{"mbuf-statistics":{"mbuf-current":2691,"cluster-total":254,"cluster-max":125514,"mbuf-failures":0}}`,
	"system_temperature": `[{"device":"dev.cpu.0.temperature","device_seq":0,"temperature":"45.0","type_translated":"CPU","type":"cpu"},{"device":"hw.acpi.thermal.tz0.temperature","device_seq":0,"temperature":"27.9","type_translated":"Zone","type":"zone"}]`,
}

func systemResourceTestApi(t *testing.T, answers map[string]string) (*DiagnosticsApi, func() []trafficTestCall) {
	var routes = map[string]http.HandlerFunc{}
	for method, answer := range answers {
		routes["GET /api/diagnostics/system/"+method] = trafficTestJSON(200, answer)
	}
	return trafficTestApi(t, routes)
}

func TestSystemResources(t *testing.T) {
	var api, calls = systemResourceTestApi(t, systemResourceTestAnswers)

	var info, raw, err = api.SystemResourceInformation()
	if err != nil || info.Name != "OPNsense.internal" || len(info.Versions) != 3 || string(raw) != systemResourceTestAnswers["system_information"] {
		t.Errorf("information: %+v, %v", info, err)
	}
	times, _, err := api.SystemResourceTime()
	if err != nil || times.Uptime != "00:42:37" || times.Loadavg != "0.48, 0.58, 0.56" || times.Boottime == "" || times.Config == "" {
		t.Errorf("time: %+v, %v", times, err)
	}
	memory, _, err := api.SystemResourceMemory()
	if err != nil || memory.Total != (SystemResourceNumber{2102894592, true}) || memory.Used != (SystemResourceNumber{599127070, true}) ||
		memory.Arc != (SystemResourceNumber{104857600, true}) {
		t.Errorf("memory: %+v, %v", memory, err)
	}
	disks, _, err := api.SystemResourceDisks()
	if err != nil || len(disks) != 2 || disks[0].Blocks != "2.8G" || disks[0].UsedPercent.Value != 80 || disks[0].TotalBytes.Valid ||
		disks[0].Mountpoint != "/" || !disks[1].TotalBytes.Valid || disks[1].Total != "10G" {
		t.Errorf("disks: %+v, %v", disks, err)
	}
	swap, _, err := api.SystemResourceSwap()
	if err != nil || len(swap) != 1 || swap[0].Total.Value != 1048576 || swap[0].Used.Value != 2048 {
		t.Errorf("swap: %+v, %v", swap, err)
	}
	mbuf, _, err := api.SystemResourceMbuf()
	if err != nil || mbuf["cluster-total"].Value != 254 || mbuf["cluster-max"].Value != 125514 || len(mbuf) != 4 {
		t.Errorf("mbuf: %+v, %v", mbuf, err)
	}
	sensors, _, err := api.SystemResourceTemperatures()
	if err != nil || len(sensors) != 2 || sensors[0].Temperature.Value != 45 || sensors[1].Type != "zone" {
		t.Errorf("temperatures: %+v, %v", sensors, err)
	}
	for _, call := range calls() {
		if call.Method != "GET" {
			t.Errorf("unexpected %s %s", call.Method, call.Path)
		}
	}
	if len(calls()) != 7 {
		t.Errorf("want 7 requests, got %d", len(calls()))
	}
}

func TestSystemResourcesEmpty(t *testing.T) {
	var api, _ = systemResourceTestApi(t, map[string]string{
		"system_resources":   `{"memory":{"used":"N/A"}}`,
		"system_disk":        `[]`,
		"system_swap":        `{"swap":[]}`,
		"system_temperature": `[]`,
	})
	if memory, _, err := api.SystemResourceMemory(); err != nil || memory.Used.Valid || memory.Total.Valid {
		t.Errorf("memory: %+v, %v", memory, err)
	}
	if disks, _, err := api.SystemResourceDisks(); err != nil || len(disks) != 0 {
		t.Errorf("disks: %+v, %v", disks, err)
	}
	if swap, _, err := api.SystemResourceSwap(); err != nil || len(swap) != 0 {
		t.Errorf("swap: %+v, %v", swap, err)
	}
	if sensors, _, err := api.SystemResourceTemperatures(); err != nil || len(sensors) != 0 {
		t.Errorf("temperatures: %+v, %v", sensors, err)
	}
}

func TestSystemResourcesErrors(t *testing.T) {
	var api, _ = systemResourceTestApi(t, map[string]string{
		"system_information": `{}`,
		"system_time":        `{"datetime":"x"}`,
		"system_resources":   `{}`,
		"system_swap":        `{}`,
		"system_mbuf":        `{"other":1}`,
		"system_temperature": `{"x":1}`,
		"system_disk":        `{"devices":"x"}`,
	})
	var check = func(name string, err error, want string) {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want error containing %q, got %v", name, want, err)
		}
	}
	var _, _, err = api.SystemResourceInformation()
	check("information", err, "system_information")
	_, _, err = api.SystemResourceTime()
	check("time", err, "system_time")
	_, _, err = api.SystemResourceMemory()
	check("memory", err, "system_resources")
	_, _, err = api.SystemResourceSwap()
	check("swap", err, "system_swap")
	_, _, err = api.SystemResourceMbuf()
	check("mbuf", err, "system_mbuf")
	_, _, err = api.SystemResourceTemperatures()
	check("temperature", err, "system_temperature")
	_, _, err = api.SystemResourceDisks()
	check("disk", err, "system_disk")

	var api404, _ = systemResourceTestApi(t, nil)
	_, _, err = api404.SystemResourceTime()
	check("404", err, "HTTP 404")
}
