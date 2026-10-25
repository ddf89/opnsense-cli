package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

var systemResourceTestAnswers = map[string]string{
	"/api/diagnostics/system/system_information": `{"name":"fw.example.com","versions":["OPNsense 26.7-amd64","FreeBSD 15.1-RELEASE-p1","OpenSSL 3.5.7"],"updates":"Click to check for updates."}`,
	"/api/diagnostics/system/system_time":        `{"uptime":"1 day, 00:42:37","datetime":"Sun Oct 25 0:06:33 UTC 2026","boottime":"Sat Oct 24 23:23:56 UTC 2026","config":"Sun Oct 25 0:03:51 UTC 2026","loadavg":"0.48, 0.58, 0.56"}`,
	"/api/diagnostics/cpu_usage/getCPUType":      `["Intel(R) Core(TM) Ultra 7 165U (1 cores, 1 threads)"]`,
	"/api/diagnostics/system/system_resources":   `{"memory":{"total":"2147483648","total_frmt":"2048","used":536870912,"used_frmt":"512","arc":104857600,"arc_frmt":"100"}}`,
	"/api/diagnostics/system/system_swap":        `{"swap":[{"device":"\/dev\/gpt\/swapfs","total":"1048576","used":"262144"}]}`,
	"/api/diagnostics/system/system_mbuf":        `{"mbuf-statistics":{"cluster-total":254,"cluster-max":127000,"mbuf-failures":0,"cluster-failures":3}}`,
	"/api/diagnostics/system/system_temperature": `[{"device":"dev.cpu.1.temperature","device_seq":1,"temperature":"47.0","type_translated":"CPU","type":"cpu"},{"device":"dev.cpu.0.temperature","device_seq":0,"temperature":"45.0","type_translated":"CPU","type":"cpu"}]`,
	"/api/diagnostics/system/system_disk":        `{"devices":[{"device":"\/dev\/ufs\/OPNsense_Nano","type":"ufs","blocks":"2.8G","used":"2.0G","available":"540M","used_pct":80,"mountpoint":"\/"},{"device":"tmpfs","type":"tmpfs","blocks":"1.0G","total":"1.0G","used":"3.8M","available":"999M","used_pct":0,"mountpoint":"\/var\/log"}]}`,
}

// systemResourceTestFake answers all parts, the paths in forbidden with a 403
func systemResourceTestFake(t *testing.T, forbidden ...string) *fakeOPN {
	var f = newFakeOPN(t)
	for path, answer := range systemResourceTestAnswers {
		f.on("GET", path, 200, answer)
	}
	for _, path := range forbidden {
		f.on("GET", path, 403, `{"status":403,"message":"Forbidden"}`)
	}
	return f
}

func TestSystemResourcePrint(t *testing.T) {
	t.Parallel()
	var f = systemResourceTestFake(t)
	var r = f.run("/system", "resource", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout,
		"host:", "fw.example.com",
		"versions:", "OPNsense 26.7-amd64, FreeBSD 15.1-RELEASE-p1, OpenSSL 3.5.7",
		"cpu:", "Ultra 7 165U",
		"uptime:", "1 day, 00:42:37 (since Sat Oct 24 23:23:56 UTC 2026)",
		"load-average:", "0.48, 0.58, 0.56",
		"memory:", "512 MiB of 2048 MiB used (25%), ZFS ARC 100 MiB",
		"swap:", "256 MiB of 1024 MiB used (25%)",
		"mbuf-clusters:", "254 of 127000 (0%), 3 allocation failures",
		"temperature:", "CPU 0: 45.0 °C, CPU 1: 47.0 °C",
		"FILESYSTEM", "/dev/ufs/OPNsense_Nano", "2.8G", "80%", "/var/log")
	if r.stderr != "" {
		t.Errorf("unexpected stderr %q", r.stderr)
	}
	wantNoMutations(t, f)
	if len(f.calls()) != len(systemResourceTestAnswers) {
		t.Errorf("want %d requests, got %d", len(systemResourceTestAnswers), len(f.calls()))
	}
}

func TestSystemResourcePrintJSON(t *testing.T) {
	t.Parallel()
	var r = systemResourceTestFake(t).run("/system/resource", "print", "json")
	wantExit(t, r, 0)
	if lines := ifaceTestLines(r.stdout); len(lines) != 1 {
		t.Fatalf("want one JSON line:\n%s", r.stdout)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal([]byte(r.stdout), &decoded); err != nil {
		t.Fatalf("no JSON: %v\n%s", err, r.stdout)
	}
	for _, part := range []string{"information", "time", "cpu", "memory", "swap", "mbuf", "temperature", "disk"} {
		if len(decoded[part]) == 0 {
			t.Errorf("part %s missing", part)
		}
	}
	if string(decoded["cpu"]) != `"Intel(R) Core(TM) Ultra 7 165U (1 cores, 1 threads)"` {
		t.Errorf("unexpected cpu %s", decoded["cpu"])
	}
}

func TestSystemResourcePrintPartialFailure(t *testing.T) {
	t.Parallel()
	var f = systemResourceTestFake(t, "/api/diagnostics/system/system_mbuf", "/api/diagnostics/system/system_disk")
	var r = f.run("/system/resource", "print")
	wantFailure(t, r, "mbuf: HTTP 403", "disk: HTTP 403", "could not read mbuf, disk")
	wantContains(t, "stdout", r.stdout, "fw.example.com", "memory:")
	wantNotContains(t, "stdout", r.stdout, "mbuf-clusters", "FILESYSTEM", "403")

	r = f.run("/system/resource", "print", "json")
	wantFailure(t, r, "could not read mbuf, disk")
	wantContains(t, "stdout", r.stdout, `"information":`)
	wantNotContains(t, "stdout", r.stdout, `"mbuf":`, `"disk":`)
}

func TestSystemResourcePrintFormatting(t *testing.T) {
	t.Parallel()
	var f = systemResourceTestFake(t)
	f.on("GET", "/api/diagnostics/system/system_resources", 200, `{"memory":{"used":"N/A"}}`)
	f.on("GET", "/api/diagnostics/system/system_swap", 200, `{"swap":[]}`)
	f.on("GET", "/api/diagnostics/system/system_temperature", 200, `[]`)
	f.on("GET", "/api/diagnostics/system/system_mbuf", 200, `{"mbuf-statistics":{"cluster-total":10}}`)
	f.on("GET", "/api/diagnostics/system/system_disk", 200, `[]`)
	var r = f.run("/system/resource", "print")
	wantExit(t, r, 0)
	var normalized = strings.Join(strings.Fields(r.stdout), " ")
	wantContains(t, "stdout", normalized, "memory: unknown", "swap: none", "mbuf-clusters: unknown", "temperature: no sensors")
	if strings.Contains(r.stdout, "FILESYSTEM") {
		t.Errorf("no disk table without disks:\n%s", r.stdout)
	}
}

// --- monitor

const (
	systemResourceTestStream = "/api/diagnostics/cpu_usage/stream"
	systemResourceTestType   = "/api/diagnostics/cpu_usage/getCPUType"
	systemResourceTestBoot   = `{"total":5,"user":4,"nice":0,"sys":1,"intr":0,"idle":95}`
	systemResourceTestBusy   = `{"total":83,"user":64,"nice":1,"sys":17,"intr":1,"idle":17}`
)

func TestSystemResourceMonitorOnce(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", systemResourceTestType, 200, `["Intel(R) Core(TM) Ultra 7 165U (1 cores, 1 threads)"]`)
	f.stream(systemResourceTestStream, ifaceTestEvents(systemResourceTestBoot, systemResourceTestBusy))
	var r = f.run("/system/resource", "monitor", "once")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "model:", "Ultra 7 165U", "total:      83%", "user:       64%", "nice:       1%",
		"system:     17%", "interrupt:  1%", "idle:       17%")
	wantNotContains(t, "stdout", r.stdout, "95%") // the average since boot is skipped

	r = f.run("/system/resource", "monitor", "once", "json")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != systemResourceTestBusy {
		t.Errorf("want the raw 2nd event, got %q", r.stdout)
	}
}

func TestSystemResourceMonitorErrors(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", systemResourceTestType, 403, `{"status":403,"message":"Forbidden"}`)
	wantFailure(t, f.run("/system/resource", "monitor", "once"), "HTTP 403")
	if n := ifaceTestCount(f, systemResourceTestStream); n != 0 {
		t.Errorf("want no stream after the failed type query, got %d", n)
	}

	var f2 = newFakeOPN(t)
	f2.on("GET", systemResourceTestType, 200, `["cpu"]`)
	f2.on("GET", systemResourceTestStream, 404, `{"errorMessage":"Endpoint not found"}`)
	wantFailure(t, f2.run("/system/resource", "monitor", "once"), "HTTP 404")
	if n := ifaceTestCount(f2, systemResourceTestStream); n != 1 {
		t.Errorf("want no retry of a 404, got %d connections", n)
	}
}

func TestSystemResourceMonitorFollow(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.stream(systemResourceTestStream, ifaceTestEvents(systemResourceTestBoot, systemResourceTestBusy, `{"total":0,"user":0,"nice":0,"sys":0,"intr":0,"idle":100}`))
	var p = f.start("/system/resource", "monitor")
	p.waitFor("100%")
	var r = p.interrupt()
	wantExit(t, r, 0)
	var lines = ifaceTestLines(r.stdout)
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "TIME") {
		t.Fatalf("want a header and 2 lines:\n%s", r.stdout)
	}
	wantContains(t, "output", lines[1], "83%", "64%", "17%")
	wantContains(t, "output", lines[2], "0%", "100%")
	if n := ifaceTestCount(f, systemResourceTestType); n != 0 {
		t.Errorf("monitor must not query the CPU type, got %d", n)
	}
}

func TestSystemResourceArgValidation(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"/system/resource", "print", "now"},
		{"/system/resource", "monitor", "now"},
		{"/system/resource", "monitor", "interval=1"},
	} {
		var f = newFakeOPN(t)
		wantFailure(t, f.run(args...))
		wantNoCalls(t, f)
	}
}

func TestSystemResourceMonitorStreams(t *testing.T) {
	t.Parallel()
	ifaceStreamSuite(t, []ifaceStreamCase{
		{
			name: "monitor", args: []string{"/system/resource", "monitor"}, path: systemResourceTestStream,
			events: []string{sseData(`{"total":3,"user":2,"nice":0,"sys":1,"intr":0,"idle":97}`), sseData(`{"total":42,"user":30,"nice":0,"sys":10,"intr":2,"idle":58}`)},
			want:   "42%",
		},
		{
			name: "monitor json", args: []string{"/system/resource", "monitor", "json"}, path: systemResourceTestStream,
			events: []string{sseData(`{"total":3,"user":2,"nice":0,"sys":1,"intr":0,"idle":97}`), sseData(`{"total":42,"user":30,"nice":0,"sys":10,"intr":2,"idle":58}`)},
			want:   `"total":42`,
		},
	})
}
