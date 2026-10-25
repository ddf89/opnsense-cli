package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

var diagSystemTestAnswers = map[string]string{
	"/api/diagnostics/system/system_information": `{"name":"fw.example.com","versions":["OPNsense 26.7-amd64","FreeBSD 15.1-RELEASE-p1","OpenSSL 3.5.7"],"updates":"Click to check for updates."}`,
	"/api/diagnostics/system/system_time":        `{"uptime":"1 day, 00:42:37","datetime":"Sun Oct 25 0:06:33 UTC 2026","boottime":"Sat Oct 24 23:23:56 UTC 2026","config":"Sun Oct 25 0:03:51 UTC 2026","loadavg":"0.48, 0.58, 0.56"}`,
	"/api/diagnostics/cpu_usage/getCPUType":      `["Intel(R) Core(TM) Ultra 7 165U (1 cores, 1 threads)"]`,
	"/api/diagnostics/system/system_resources":   `{"memory":{"total":"2147483648","total_frmt":"2048","used":536870912,"used_frmt":"512","arc":104857600,"arc_frmt":"100"}}`,
	"/api/diagnostics/system/system_swap":        `{"swap":[{"device":"\/dev\/gpt\/swapfs","total":"1048576","used":"262144"}]}`,
	"/api/diagnostics/system/system_mbuf":        `{"mbuf-statistics":{"cluster-total":254,"cluster-max":127000,"mbuf-failures":0,"cluster-failures":3}}`,
	"/api/diagnostics/system/system_temperature": `[{"device":"dev.cpu.1.temperature","device_seq":1,"temperature":"47.0","type_translated":"CPU","type":"cpu"},{"device":"dev.cpu.0.temperature","device_seq":0,"temperature":"45.0","type_translated":"CPU","type":"cpu"}]`,
	"/api/diagnostics/system/system_disk":        `{"devices":[{"device":"\/dev\/ufs\/OPNsense_Nano","type":"ufs","blocks":"2.8G","used":"2.0G","available":"540M","used_pct":80,"mountpoint":"\/"},{"device":"tmpfs","type":"tmpfs","blocks":"1.0G","total":"1.0G","used":"3.8M","available":"999M","used_pct":0,"mountpoint":"\/var\/log"}]}`,
}

func diagSystemTestFake(t *testing.T, overrides map[string]string) *fakeOPN {
	var f = newFakeOPN(t)
	for path, answer := range diagSystemTestAnswers {
		if override, found := overrides[path]; found {
			f.on("GET", path, 403, override)
			continue
		}
		f.on("GET", path, 200, answer)
	}
	return f
}

func TestDiagSystem(t *testing.T) {
	t.Parallel()
	var f = diagSystemTestFake(t, nil)
	var r = f.run("diag", "system")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout,
		"host:", "fw.example.com",
		"versions:", "OPNsense 26.7-amd64, FreeBSD 15.1-RELEASE-p1, OpenSSL 3.5.7",
		"cpu:", "Ultra 7 165U",
		"uptime:", "1 day, 00:42:37 (since Sat Oct 24 23:23:56 UTC 2026)",
		"load average:", "0.48, 0.58, 0.56",
		"memory:", "512 MiB of 2048 MiB used (25%), ZFS ARC 100 MiB",
		"swap:", "256 MiB of 1024 MiB used (25%)",
		"mbuf clusters:", "254 of 127000 (0%), 3 allocation failures",
		"temperature:", "CPU 0: 45.0 °C, CPU 1: 47.0 °C",
		"FILESYSTEM", "/dev/ufs/OPNsense_Nano", "2.8G", "80%", "/var/log")
	if r.stderr != "" {
		t.Errorf("unexpected stderr %q", r.stderr)
	}
	for _, call := range f.calls() {
		if call.Method != "GET" {
			t.Errorf("unexpected %s", call)
		}
	}
	if len(f.calls()) != len(diagSystemTestAnswers) {
		t.Errorf("want %d requests, got %d", len(diagSystemTestAnswers), len(f.calls()))
	}
}

func TestDiagSystemJson(t *testing.T) {
	t.Parallel()
	var r = diagSystemTestFake(t, nil).run("diag", "system", "--json")
	wantExit(t, r, 0)
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

func TestDiagSystemPartialFailure(t *testing.T) {
	t.Parallel()
	var f = diagSystemTestFake(t, map[string]string{
		"/api/diagnostics/system/system_mbuf": `{"status":403,"message":"Forbidden"}`,
		"/api/diagnostics/system/system_disk": `{"status":403,"message":"Forbidden"}`,
	})
	var r = f.run("diag", "system")
	wantFailure(t, r, "mbuf: HTTP 403", "disk: HTTP 403", "could not read mbuf, disk")
	wantContains(t, "stdout", r.stdout, "fw.example.com", "memory:")
	wantNotContains(t, "stdout", r.stdout, "mbuf clusters", "FILESYSTEM")
}

func TestDiagSystemFormatting(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	for path, answer := range diagSystemTestAnswers {
		f.on("GET", path, 200, answer)
	}
	f.on("GET", "/api/diagnostics/system/system_resources", 200, `{"memory":{"used":"N/A"}}`)
	f.on("GET", "/api/diagnostics/system/system_swap", 200, `{"swap":[]}`)
	f.on("GET", "/api/diagnostics/system/system_temperature", 200, `[]`)
	f.on("GET", "/api/diagnostics/system/system_mbuf", 200, `{"mbuf-statistics":{"cluster-total":10}}`)
	f.on("GET", "/api/diagnostics/system/system_disk", 200, `[]`)
	var r = f.run("diag", "system")
	wantExit(t, r, 0)
	var normalized = strings.Join(strings.Fields(r.stdout), " ")
	wantContains(t, "stdout", normalized, "memory: unknown", "swap: none", "mbuf clusters: unknown", "temperature: no sensors")
	if strings.Contains(r.stdout, "FILESYSTEM") {
		t.Errorf("no disk table without disks:\n%s", r.stdout)
	}
}
