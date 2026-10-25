package cli

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	toolSnifferTestId   = "5ce3e3bc-80e5-4b2b-b353-8b945ca242a3"
	toolSnifferTestId2  = "0a7e3bc0-80e5-4b2b-b353-8b945ca242a3"
	toolSnifferTestGet  = "/api/diagnostics/packet_capture/get"
	toolSnifferTestJobs = "/api/diagnostics/packet_capture/search_jobs"
	toolSnifferTestSet  = "/api/diagnostics/packet_capture/set"
)

const toolSnifferTestGetAnswer = `{"packetcapture":{"settings":{"interface":{"vtnet0":{"value":"vtnet0 [LAN]","selected":0},` +
	`"vtnet1":{"value":"vtnet1 [WAN]","selected":0},"lo0":{"value":"lo0 [Loopback]","selected":0},"enc0":{"value":"enc0","selected":0}},` +
	`"description":"","promiscuous":"0","protocol_not":"0",` +
	`"protocol":{"any":{"value":"any","selected":1},"TCP":{"value":"TCP","selected":0},"UDP":{"value":"UDP","selected":0},"ICMP":{"value":"ICMP","selected":0},"IPV6-ICMP":{"value":"IPV6-ICMP","selected":0}},` +
	`"host":"","port_not":"0","port":"","snaplen":"","count":"100"}}}`

func toolSnifferTestJob(id string, description string, status string) string {
	return `{"interface":"lo0,vtnet0","description":"` + description + `","promiscuous":"0","fam":"ip","protocol_not":"1","protocol":"TCP",` +
		`"host":"127.0.0.1","port_not":"0","port":"443","snaplen":"","count":"20","id":"` + id + `","status":"` + status + `"}`
}

func toolSnifferTestFake(t *testing.T) *fakeOPN {
	var f = newFakeOPN(t)
	f.on("GET", toolSnifferTestGet, 200, toolSnifferTestGetAnswer)
	f.on("GET", toolSnifferTestJobs, 200, `{"total":2,"rowCount":2,"current":1,"rows":[`+
		toolSnifferTestJob(toolSnifferTestId, "web", "running")+","+toolSnifferTestJob(toolSnifferTestId2, "dns", "stopped")+`]}`)
	for _, action := range []string{"start", "stop", "remove"} {
		for _, id := range []string{toolSnifferTestId, toolSnifferTestId2} {
			f.on("POST", "/api/diagnostics/packet_capture/"+action+"/"+id, 200, `{"status":"ok"}`)
		}
	}
	return f
}

func TestToolSnifferPrint(t *testing.T) {
	t.Parallel()
	var f = toolSnifferTestFake(t)
	var r = f.run("/tool/sniffer", "print")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	// sorted by job id: the "dns" job (0a7e...) first
	if len(lines) != 3 || !strings.HasPrefix(lines[1], "0  dns") || !strings.HasPrefix(lines[2], "1  web") {
		t.Fatalf("want 2 jobs sorted by id:\n%s", r.stdout)
	}
	wantContains(t, "stdout", lines[2], "lo0,vtnet0", "ip", "!tcp", "127.0.0.1", "443", "20", "running")
	wantContains(t, "stdout", lines[0], "DESCRIPTION", "INTERFACE", "FAMILY", "PROTOCOL", "HOST", "PORT", "COUNT", "STATUS")

	r = f.run("/tool/sniffer", "print", "detail")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "id:", toolSnifferTestId, "protocol:", "!tcp", "snaplen:")

	r = f.run("/tool/sniffer", "print", "json")
	wantExit(t, r, 0)
	if lines := strings.Split(strings.TrimSpace(r.stdout), "\n"); len(lines) != 2 || !strings.Contains(lines[0], toolSnifferTestId2) {
		t.Errorf("want the raw jobs:\n%s", r.stdout)
	}
	wantNoMutations(t, f)
}

func TestToolSnifferStart(t *testing.T) {
	t.Parallel()
	var f = toolSnifferTestFake(t)
	f.on("GET", ifaceTestInterfaces, 200, ifaceTestInterfacesAnswer)
	f.on("POST", toolSnifferTestSet, 200, `{"result":"ok","uuid":"`+toolSnifferTestId+`"}`)
	// lan by interface name (via the traffic totals), Loopback by description, vtnet0 twice
	var r = f.run("/tool/sniffer", "start", "interface=lan,Loopback,vtnet0", "family=ip6", "protocol=ipv6-icmp", "protocol-invert",
		"host=fd00::1 and not fd00::2", "port=546", "port-invert", "snaplen=96", "count=10", "description=a7 test")
	wantExit(t, r, 0)
	if r.stdout != toolSnifferTestId+"\n" {
		t.Errorf("want the job id on stdout, got %q", r.stdout)
	}
	var calls = f.mutations()
	if len(calls) != 2 || calls[0].Path != toolSnifferTestSet || calls[1].Path != "/api/diagnostics/packet_capture/start/"+toolSnifferTestId {
		t.Fatalf("want set and start, got %v", calls)
	}
	wantJSON(t, calls[0], map[string]any{"packetcapture": map[string]any{"settings": map[string]any{
		"interface": "vtnet0,lo0", "description": "a7 test", "promiscuous": "0", "fam": "ip6", "protocol_not": "1", "protocol": "IPV6-ICMP",
		"host": "fd00::1 and not fd00::2", "port_not": "1", "port": "546", "snaplen": "96", "count": "10"}}})

	// defaults, device names need no traffic lookup
	var defaults = toolSnifferTestFake(t)
	defaults.on("POST", toolSnifferTestSet, 200, `{"result":"ok","uuid":"`+toolSnifferTestId+`"}`)
	wantExit(t, defaults.run("/tool/sniffer", "start", "interface=lo0"), 0)
	wantJSON(t, defaults.mutations()[0], map[string]any{"packetcapture": map[string]any{"settings": map[string]any{
		"interface": "lo0", "description": "opn sniffer", "promiscuous": "0", "fam": "any", "protocol_not": "0", "protocol": "any",
		"host": "", "port_not": "0", "port": "", "snaplen": "", "count": "100"}}})
	if n := ifaceTestCount(defaults, ifaceTestInterfaces); n != 0 {
		t.Errorf("want no traffic lookup for device names, got %d", n)
	}
}

func TestToolSnifferStartFailures(t *testing.T) {
	t.Parallel()
	var f = toolSnifferTestFake(t)
	f.on("GET", ifaceTestInterfaces, 200, ifaceTestInterfacesAnswer)
	wantFailure(t, f.run("/tool/sniffer", "start", "interface=opt7"), `unknown interface "opt7"`, "vtnet0 [LAN]")
	wantFailure(t, f.run("/tool/sniffer", "start", "interface=lo0", "protocol=bogus"), `unknown protocol "bogus"`)
	wantNoMutations(t, f)

	var invalid = toolSnifferTestFake(t)
	invalid.on("POST", toolSnifferTestSet, 200, `{"result":"failed","validations":{"packetcapture.settings.host":"invalid host"}}`)
	wantFailure(t, invalid.run("/tool/sniffer", "start", "interface=lo0", "host=x"), "invalid host")
	if len(invalid.mutations()) != 1 {
		t.Errorf("want only the set: %v", invalid.mutations())
	}

	// a failed start removes the job again
	var start = toolSnifferTestFake(t)
	start.on("POST", toolSnifferTestSet, 200, `{"result":"ok","uuid":"`+toolSnifferTestId+`"}`)
	start.on("POST", "/api/diagnostics/packet_capture/start/"+toolSnifferTestId, 200, `{"status":"failed","status_msg":"already active (pids: 1)"}`)
	wantFailure(t, start.run("/tool/sniffer", "start", "interface=lo0"), "already active")
	if calls := start.mutations(); len(calls) != 3 || calls[2].Path != "/api/diagnostics/packet_capture/remove/"+toolSnifferTestId {
		t.Errorf("want set, start, remove: %v", calls)
	}

	for _, args := range [][]string{
		{"/tool/sniffer", "start"},
		{"/tool/sniffer", "start", "interface=lo0", "family=ipx"},
		{"/tool/sniffer", "start", "interface=lo0", "protocol-invert"},
		{"/tool/sniffer", "start", "interface=lo0", "port-invert"},
		{"/tool/sniffer", "start", "interface=lo0", "port=0"},
		{"/tool/sniffer", "start", "interface=lo0", "count=-1"},
		{"/tool/sniffer", "start", "interface=lo0", "duration=0s"},
	} {
		var none = newFakeOPN(t)
		wantFailure(t, none.run(args...))
		wantNoCalls(t, none)
	}
}

func TestToolSnifferStartDuration(t *testing.T) {
	t.Parallel()
	// the capture ends by itself (count reached) during the wait: no stop
	var f = newFakeOPN(t)
	f.on("GET", toolSnifferTestGet, 200, toolSnifferTestGetAnswer)
	f.on("POST", toolSnifferTestSet, 200, `{"result":"ok","uuid":"`+toolSnifferTestId+`"}`)
	f.on("POST", "/api/diagnostics/packet_capture/start/"+toolSnifferTestId, 200, `{"status":"ok"}`)
	f.on("GET", toolSnifferTestJobs, 200, `{"rows":[`+toolSnifferTestJob(toolSnifferTestId, "web", "stopped")+`]}`)
	var r = f.run("/tool/sniffer", "start", "interface=lo0", "duration=10s")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "capturing for 10s", "capture "+toolSnifferTestId+" stopped")
	if calls := f.mutations(); len(calls) != 2 {
		t.Errorf("want set and start only: %v", calls)
	}

	// Ctrl-C stops the capture
	var running = toolSnifferTestFake(t)
	running.on("POST", toolSnifferTestSet, 200, `{"result":"ok","uuid":"`+toolSnifferTestId+`"}`)
	var p = running.start("/tool/sniffer", "start", "interface=lo0", "duration=1m")
	p.waitFor(toolSnifferTestId)
	r = p.interrupt()
	wantExit(t, r, 0)
	if calls := running.mutations(); len(calls) != 3 || calls[2].Path != "/api/diagnostics/packet_capture/stop/"+toolSnifferTestId {
		t.Errorf("want set, start, stop: %v", calls)
	}

	// the duration passes
	var elapsed = toolSnifferTestFake(t)
	elapsed.on("POST", toolSnifferTestSet, 200, `{"result":"ok","uuid":"`+toolSnifferTestId+`"}`)
	wantExit(t, elapsed.run("/tool/sniffer", "start", "interface=lo0", "duration=100ms"), 0)
	if calls := elapsed.mutations(); len(calls) != 3 || calls[2].Path != "/api/diagnostics/packet_capture/stop/"+toolSnifferTestId {
		t.Errorf("want set, start, stop: %v", calls)
	}
}

func TestToolSnifferStopRemove(t *testing.T) {
	t.Parallel()
	var f = toolSnifferTestFake(t)
	wantExit(t, f.run("/tool/sniffer", "stop", "web"), 0)
	wantOneMutation(t, f, "POST", "/api/diagnostics/packet_capture/stop/"+toolSnifferTestId)

	var byIndex = toolSnifferTestFake(t)
	var r = byIndex.runScript("/tool/sniffer\nprint\nremove 1\n")
	wantExit(t, r, 0)
	wantOneMutation(t, byIndex, "POST", "/api/diagnostics/packet_capture/remove/"+toolSnifferTestId)

	var byId = toolSnifferTestFake(t)
	wantExit(t, byId.run("/tool/sniffer", "remove", toolSnifferTestId2), 0)
	wantOneMutation(t, byId, "POST", "/api/diagnostics/packet_capture/remove/"+toolSnifferTestId2)

	var unknown = toolSnifferTestFake(t)
	wantFailure(t, unknown.run("/tool/sniffer", "remove", "nothing"), "not found")
	wantFailure(t, unknown.run("/tool/sniffer", "stop", "5"), "not found")
	wantNoMutations(t, unknown)

	var gone = toolSnifferTestFake(t)
	gone.on("POST", "/api/diagnostics/packet_capture/stop/"+toolSnifferTestId, 200, `{"status":"failed"}`)
	wantFailure(t, gone.run("/tool/sniffer", "stop", "web"), "not found: capture job "+toolSnifferTestId)
}

func TestToolSnifferView(t *testing.T) {
	t.Parallel()
	var f = toolSnifferTestFake(t)
	f.on("GET", "/api/diagnostics/packet_capture/view/"+toolSnifferTestId+"/normal", 200, `{"settings":{},"status":"ok","interfaces":{`+
		`"vtnet0":{"rows":[{"timestamp":"2026-10-25T15:40:38.000001","esrc":"52:54:00:12:34:56","edst":"82:a3:6e:c6:fc:1c","raw":"ethertype IPv4 (0x0800), length 98: 192.168.1.1 > 192.168.1.2: ICMP echo request\n","fam":"ip"}],"name":"LAN"},`+
		`"lo0":{"rows":[{"timestamp":"2026-10-25T15:40:37.803032","esrc":null,"edst":null,"raw":"length 64: 127.0.0.1.48552 > 127.0.0.1.443: tcp 0\n","fam":"ip"},`+
		`{"timestamp":"2026-10-25T15:40:39.100000","esrc":null,"edst":null,"raw":"length 64: 127.0.0.1.443 > 127.0.0.1.48552: tcp 0\n","fam":"ip"}],"name":"Loopback"}}}`)
	f.on("GET", "/api/diagnostics/packet_capture/view/"+toolSnifferTestId+"/high", 200, `{"settings":{},"status":"ok","interfaces":{`+
		`"lo0":{"rows":[{"timestamp":"2026-10-25T15:40:37.803032","esrc":null,"edst":null,"raw":"length 64: (tos 0x0, ttl 64)\n    127.0.0.1.48552 > 127.0.0.1.443: Flags [S]\n","fam":"ip"}],"name":"Loopback"}}}`)
	f.on("GET", "/api/diagnostics/packet_capture/view/"+toolSnifferTestId2+"/normal", 200, `{"settings":{},"status":"ok","interfaces":{"lo0":{"rows":[],"name":"Loopback"}}}`)

	var r = f.run("/tool/sniffer", "view", "web")
	wantExit(t, r, 0)
	var want = "2026-10-25T15:40:37.803032 lo0 length 64: 127.0.0.1.48552 > 127.0.0.1.443: tcp 0\n" +
		"2026-10-25T15:40:38.000001 vtnet0 52:54:00:12:34:56 > 82:a3:6e:c6:fc:1c ethertype IPv4 (0x0800), length 98: 192.168.1.1 > 192.168.1.2: ICMP echo request\n" +
		"2026-10-25T15:40:39.100000 lo0 length 64: 127.0.0.1.443 > 127.0.0.1.48552: tcp 0\n"
	if r.stdout != want {
		t.Errorf("want the packets of all interfaces in time order:\n got %q\nwant %q", r.stdout, want)
	}

	r = f.run("/tool/sniffer", "view", "web", "interface=LAN")
	wantExit(t, r, 0)
	if strings.Count(r.stdout, "\n") != 1 || !strings.Contains(r.stdout, "vtnet0") {
		t.Errorf("want only the LAN packet:\n%s", r.stdout)
	}
	wantFailure(t, f.run("/tool/sniffer", "view", "web", "interface=wan"), "not found", "lo0, vtnet0")

	r = f.run("/tool/sniffer", "view", "web", "verbosity=high")
	wantExit(t, r, 0)
	if r.stdout != "2026-10-25T15:40:37.803032 lo0 length 64: (tos 0x0, ttl 64)\n        127.0.0.1.48552 > 127.0.0.1.443: Flags [S]\n" {
		t.Errorf("want continuation lines indented: %q", r.stdout)
	}

	r = f.run("/tool/sniffer", "view", "web", "json")
	wantExit(t, r, 0)
	if !strings.HasPrefix(r.stdout, `{"settings":{},"status":"ok"`) {
		t.Errorf("want the raw answer: %q", r.stdout)
	}

	r = f.run("/tool/sniffer", "view", "dns")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "no packets captured")
	wantFailure(t, f.run("/tool/sniffer", "view", "web", "verbosity=max"))
	wantNoMutations(t, f)
}

func TestToolSnifferDownload(t *testing.T) {
	t.Parallel()
	var f = toolSnifferTestFake(t)
	var mu sync.Mutex
	var content = "PK\x03\x04first"
	f.onFunc("GET", "/api/diagnostics/packet_capture/download/"+toolSnifferTestId, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename="+toolSnifferTestId+".zip")
		_, _ = io.WriteString(w, content)
	})
	f.on("GET", "/api/diagnostics/packet_capture/download/"+toolSnifferTestId2, 200, "")

	var dir = t.TempDir()
	var r = runOpnIn(t, dir, f.env(), "/tool/sniffer", "download", "web")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "saved "+toolSnifferTestId+".zip")
	var path = filepath.Join(dir, toolSnifferTestId+".zip")
	if data, err := os.ReadFile(path); err != nil || string(data) != content {
		t.Fatalf("file %q, %v", data, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode())
	}

	mu.Lock()
	content = "PK\x03\x04second"
	mu.Unlock()
	wantFailure(t, runOpnIn(t, dir, f.env(), "/tool/sniffer", "download", "web"), "already exists, add overwrite")
	if data, _ := os.ReadFile(path); string(data) != "PK\x03\x04first" {
		t.Errorf("the file must not be changed without overwrite")
	}
	wantExit(t, runOpnIn(t, dir, f.env(), "/tool/sniffer", "download", "web", "overwrite"), 0)
	if data, _ := os.ReadFile(path); string(data) != "PK\x03\x04second" {
		t.Errorf("overwrite did not replace the file: %q", data)
	}

	var custom = filepath.Join(dir, "capture.zip")
	wantExit(t, f.run("/tool/sniffer", "download", "1", "file="+custom), 0) // # 1 is the web job
	if data, _ := os.ReadFile(custom); string(data) != "PK\x03\x04second" {
		t.Errorf("file= content %q", data)
	}
	wantFailure(t, f.run("/tool/sniffer", "download", "dns", "file="+custom), "not found: capture job "+toolSnifferTestId2)

	r = f.run("/tool/sniffer", "download", "web", "file=-")
	wantExit(t, r, 0)
	if r.stdout != "PK\x03\x04second" {
		t.Errorf("stdout %q", r.stdout)
	}
	wantFailure(t, f.run("/tool/sniffer", "download", "web", "file=-", "overwrite"), "overwrite has no effect")
	wantNoMutations(t, f)
}
