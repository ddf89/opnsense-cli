package cli

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	toolInsightBase = "/api/diagnostics/networkinsight/"
	// toolInsightRange is the path part of from=1792850000 to=1792936000 (2026-10-24 13:53:20 to 2026-10-25 13:46:40 UTC)
	toolInsightRange = "1792850000/1792936000"
)

const toolInsightTestMetadata = `{"last_sync":1792936000,"aggregators":{"FlowInterfaceTotals":{"resolutions":[30,300,3600,86400]},` +
	`"FlowDstPortTotals":{"resolutions":[300,3600,86400]},"FlowSourceAddrDetails":{"resolutions":[86400]},` +
	`"FlowSourceAddrTotals":{"resolutions":[300,3600,86400]}}}`

func toolInsightFake(t *testing.T) *fakeOPN {
	var f = newFakeOPN(t)
	f.on("GET", toolInsightBase+"getInterfaces", 200, `{"vtnet1":"Uplink","vtnet0":"lan","lo0":"Loopback"}`)
	f.on("GET", toolInsightBase+"getProtocols", 200, `{"0":"ip","1":"icmp","6":"tcp","17":"udp"}`)
	f.on("GET", toolInsightBase+"getMetadata", 200, toolInsightTestMetadata)
	return f
}

func TestToolInsightPrintInterfaces(t *testing.T) {
	var f = toolInsightFake(t)
	f.on("GET", toolInsightBase+"top/FlowInterfaceTotals/"+toolInsightRange+"/if,direction/octets/25", 200,
		`[{"if":"vtnet1","direction":"in","total":5000000,"last_seen":1792935000},{"if":"vtnet0","direction":"out","total":4000,"last_seen":1792935000}]`)
	f.on("GET", toolInsightBase+"top/FlowInterfaceTotals/"+toolInsightRange+"/if,direction/packets/25", 200,
		`[{"if":"vtnet0","direction":"out","total":40,"last_seen":1792935000},{"if":"vtnet1","direction":"in","total":4500,"last_seen":1792935000}]`)

	var r = f.run("/tool/insight", "print", "from=1792850000", "to=1792936000")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout,
		"INTERFACE  DEVICE  DIRECTION  BYTES   PACKETS",
		"Uplink     vtnet1  in         5.0 MB  4500",
		"lan        vtnet0  out        4.0 kB  40")

	r = f.run("/tool/insight", "print", "from=1792850000", "to=1792936000", "json")
	wantExit(t, r, 0)
	if lines := strings.Split(strings.TrimSpace(r.stdout), "\n"); len(lines) != 2 || !strings.HasPrefix(lines[0], `{"if":"vtnet1"`) {
		t.Errorf("json: %s", r.stdout)
	}

	// filters: interface by name, description or device
	for _, name := range []string{"uplink", "vtnet1"} {
		var g = toolInsightFake(t)
		g.on("GET", toolInsightBase+"top/FlowInterfaceTotals/"+toolInsightRange+"/if,direction/octets/3", 200, `[]`)
		g.on("GET", toolInsightBase+"top/FlowInterfaceTotals/"+toolInsightRange+"/if,direction/packets/3", 200, `[]`)
		r = g.run("/tool/insight", "print", "interface="+name, "direction=in", "from=1792850000", "to=1792936000", "limit=3")
		wantExit(t, r, 0)
		var found = false
		for _, call := range g.calls() {
			if strings.Contains(call.Path, "/top/FlowInterfaceTotals/") {
				found = true
				if !strings.HasSuffix(call.Path, "/3") || call.Query.Get("filter_field") != "if,direction" || call.Query.Get("filter_value") != "vtnet1,in" {
					t.Errorf("query: %v", call)
				}
			}
		}
		if !found {
			t.Errorf("no top query: %v", g.calls())
		}
		wantContains(t, "stderr", r.stderr, "no traffic from 2026-10-24 13:53 to 2026-10-25 13:46")
	}
	wantNoMutations(t, f)
}

func TestToolInsightPrintViews(t *testing.T) {
	var f = toolInsightFake(t)
	f.on("GET", toolInsightBase+"top/FlowDstPortTotals/"+toolInsightRange+"/dst_port,protocol/octets/2", 200,
		`[{"dst_port":443,"protocol":6,"total":7500,"last_seen":1792935000,"label":"https (tcp)","last_seen_str":"2026-10-25 13:30:00"},`+
			`{"dst_port":53,"protocol":17,"total":1500,"last_seen":1792934000,"label":"domain (udp)","last_seen_str":"2026-10-25 13:13:20"},`+
			`{"total":1000,"dst_port":"","protocol":"","last_seen":"","label":"","last_seen_str":""}]`)
	f.on("GET", toolInsightBase+"top/FlowDstPortTotals/"+toolInsightRange+"/protocol/packets/25", 200,
		`[{"protocol":6,"total":90,"last_seen":1792935000},{"protocol":17,"total":10,"last_seen":1792934000}]`)
	f.on("GET", toolInsightBase+"top/FlowSourceAddrTotals/"+toolInsightRange+"/src_addr/octets/25", 200,
		`[{"src_addr":"192.168.1.10","total":3000,"last_seen":1792935000},{"src_addr":"10.0.2.2","total":1000,"last_seen":1792935000}]`)
	f.on("GET", toolInsightBase+"top/FlowSourceAddrDetails/"+toolInsightRange+"/service_port,protocol,if,src_addr,dst_addr/octets/25", 200,
		`[{"service_port":443,"protocol":6,"if":"vtnet1","src_addr":"192.168.1.10","dst_addr":"198.51.100.7","total":2048,"last_seen":1792935000,"label":"https (tcp)"}]`)

	var r = f.run("/tool/insight", "print", "by=service", "limit=2", "from=1792850000", "to=1792936000")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout,
		"SERVICE       PORT  BYTES   SHARE  LAST-SEEN",
		"https (tcp)   443   7.5 kB  75.0%  2026-10-25 13:30:00",
		"domain (udp)  53    1.5 kB  15.0%  2026-10-25 13:13:20",
		"(other)       -     1.0 kB  10.0%  -")

	r = f.run("/tool/insight", "print", "by=protocol", "measure=packets", "from=1792850000", "to=1792936000")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "PROTOCOL  NUMBER  PACKETS  SHARE", "tcp       6       90       90.0%", "udp       17      10       10.0%")

	r = f.run("/tool/insight", "print", "by=talker", "from=1792850000", "to=1792936000")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "ADDRESS       BYTES   SHARE", "192.168.1.10  3.0 kB  75.0%", "10.0.2.2      1.0 kB  25.0%")

	r = f.run("/tool/insight", "print", "by=flow", "from=1792850000", "to=1792936000")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "SERVICE      INTERFACE  SOURCE        DESTINATION   BYTES   SHARE   LAST-SEEN",
		"https (tcp)  Uplink     192.168.1.10  198.51.100.7  2.0 kB  100.0%  2026-10-25 13:30:00")
	wantNoMutations(t, f)
}

func TestToolInsightPrintFilters(t *testing.T) {
	var f = toolInsightFake(t)
	f.on("GET", toolInsightBase+"top/FlowSourceAddrDetails/"+toolInsightRange+"/service_port,protocol,if,src_addr,dst_addr/octets/25", 200, `[]`)
	var r = f.run("/tool/insight", "print", "by=flow", "interface=lan", "direction=out", "port=443", "protocol=tcp",
		"source=192.168.1.10", "destination=198.51.100.7", "from=1792850000", "to=1792936000")
	wantExit(t, r, 0)
	var calls = f.calls()
	var top = calls[len(calls)-1]
	if !strings.Contains(top.Path, "/top/FlowSourceAddrDetails/") ||
		top.Query.Get("filter_field") != "if,direction,service_port,protocol,src_addr,dst_addr" ||
		top.Query.Get("filter_value") != "vtnet0,out,443,6,192.168.1.10,198.51.100.7" {
		t.Errorf("query: %v", top)
	}

	var g = toolInsightFake(t)
	g.on("GET", toolInsightBase+"top/FlowDstPortTotals/"+toolInsightRange+"/dst_port,protocol/octets/25", 200, `[]`)
	wantExit(t, g.run("/tool/insight", "print", "by=service", "port=53", "protocol=17", "from=1792850000", "to=1792936000"), 0)
	calls = g.calls()
	if top = calls[len(calls)-1]; top.Query.Get("filter_field") != "dst_port,protocol" || top.Query.Get("filter_value") != "53,17" {
		t.Errorf("query: %v", top)
	}

	var h = newFakeOPN(t)
	wantFailure(t, h.run("/tool/insight", "print", "port=443"), "by=interface can not filter by port")
	wantFailure(t, h.run("/tool/insight", "print", "by=talker", "destination=192.0.2.1"), "by=talker can not filter by destination")
	wantFailure(t, h.run("/tool/insight", "print", "by=service", "source=not-an-ip"), "source")
	wantFailure(t, h.run("/tool/insight", "print", "by=bogus"), "by")
	wantFailure(t, h.run("/tool/insight", "print", "from=1d", "to=2d"), "is after to")
	wantFailure(t, h.run("/tool/insight", "print", "by=flow", "protocol=tcp,udp"), "protocol")
	wantNoCalls(t, h)

	var i = toolInsightFake(t)
	wantFailure(t, i.run("/tool/insight", "print", "interface=nope"), `interface "nope"`, "Uplink (vtnet1)")
	wantFailure(t, i.run("/tool/insight", "print", "by=service", "protocol=nope"), `protocol "nope"`)
	for _, call := range i.calls() {
		if strings.Contains(call.Path, "/top/") {
			t.Errorf("an invalid filter must not query: %v", call)
		}
	}
}

func TestToolInsightHistory(t *testing.T) {
	var f = toolInsightFake(t)
	f.on("GET", toolInsightBase+"timeserie/FlowInterfaceTotals/bps/1792935400/1792936000/300/if,direction", 200,
		`[{"key":"vtnet1,in","values":[[1792935600000,2500000],[1792935900000,0]],"interface":"Uplink","direction":"in"},`+
			`{"key":"vtnet0,out","values":[[1792935600000,1200],[1792935900000,800.5]],"interface":"lan","direction":"out"},`+
			`{"key":"vtnet1,out","values":[[1792935600000,1000],[1792935900000,10]],"interface":"Uplink","direction":"out"}]`)
	f.on("GET", toolInsightBase+"timeserie/FlowInterfaceTotals/octets/1792935400/1792936000/300/if,direction", 200,
		`[{"key":"vtnet1,in","values":[[1792935600000,2500000]],"interface":"Uplink","direction":"in"}]`)

	var r = f.run("/tool/insight", "history", "from=1792935400", "to=1792936000")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout,
		"TIME              LAN-OUT     UPLINK-IN   UPLINK-OUT",
		"2026-10-25 13:40  1.2 kbit/s  2.5 Mbit/s  1.0 kbit/s",
		"2026-10-25 13:45  800 bit/s   0 bit/s     10 bit/s")

	r = f.run("/tool/insight", "history", "from=1792935400", "to=1792936000", "interface=uplink", "json")
	wantExit(t, r, 0)
	if lines := strings.Split(strings.TrimSpace(r.stdout), "\n"); len(lines) != 2 ||
		lines[0] != `{"time":"2026-10-25T13:40:00Z","values":{"vtnet1,in":2500000,"vtnet1,out":1000}}` {
		t.Errorf("json: %s", r.stdout)
	}

	r = f.run("/tool/insight", "history", "from=1792935400", "to=1792936000", "measure=bytes")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "UPLINK-IN", "2.5 MB")

	// the default range is 60 steps before to: 300s * 60
	var g = toolInsightFake(t)
	g.on("GET", toolInsightBase+"timeserie/FlowInterfaceTotals/bps/1792918000/1792936000/300/if,direction", 200, `[]`)
	wantExit(t, g.run("/tool/insight", "history", "to=1792936000"), 0)
	var calls = g.calls()
	if !strings.Contains(calls[len(calls)-1].Path, "/timeserie/FlowInterfaceTotals/bps/1792918000/1792936000/300/") {
		t.Errorf("query: %v", calls[len(calls)-1])
	}

	wantFailure(t, g.run("/tool/insight", "history", "resolution=10m"), "resolution 10m is not available", "30s, 5m, 1h, 1d")
	wantFailure(t, g.run("/tool/insight", "history", "resolution=x"), "resolution")
	wantFailure(t, g.run("/tool/insight", "history", "interface=nope"), `interface "nope"`)
	wantNoMutations(t, g)
}

func TestToolInsightExport(t *testing.T) {
	var f = toolInsightFake(t)
	var csv = "if,direction,octets,packets,mtime\nvtnet0,in,1200,10,2026/10/25 13:40:00\n"
	f.onFunc("GET", toolInsightBase+"export/FlowInterfaceTotals/"+toolInsightRange+"/30", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, csv)
	})
	f.onFunc("GET", toolInsightBase+"export/FlowSourceAddrDetails/"+toolInsightRange+"/86400", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, "\n\n")
	})

	var dir = t.TempDir()
	var r = runOpnIn(t, dir, f.env(), "/tool/insight", "export", "interfaces.csv", "from=1792850000", "to=1792936000")
	wantExit(t, r, 0)
	if content, err := os.ReadFile(filepath.Join(dir, "interfaces.csv")); err != nil || string(content) != csv {
		t.Errorf("file: %q, %v", content, err)
	}
	wantFailure(t, runOpnIn(t, dir, f.env(), "/tool/insight", "export", "interfaces.csv", "from=1792850000", "to=1792936000"), "already exists")
	wantExit(t, runOpnIn(t, dir, f.env(), "/tool/insight", "export", "interfaces.csv", "from=1792850000", "to=1792936000", "overwrite"), 0)

	r = f.run("/tool/insight", "export", "-", "resolution=30s", "from=1792850000", "to=1792936000")
	wantExit(t, r, 0)
	if r.stdout != csv {
		t.Errorf("stdout: %q", r.stdout)
	}

	r = runOpnIn(t, dir, f.env(), "/tool/insight", "export", "by=flow", "flows.csv", "from=1792850000", "to=1792936000")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "no flow data", "nothing exported")
	if _, err := os.Stat(filepath.Join(dir, "flows.csv")); !os.IsNotExist(err) {
		t.Errorf("no file must be written without data: %v", err)
	}

	wantFailure(t, f.run("/tool/insight", "export", "-", "by=flow", "resolution=1h"), "resolution 1h is not available", "use 1d")
	wantFailure(t, f.run("/tool/insight", "export", "-", "by=protocol"), "by")
	wantFailure(t, f.run("/tool/insight", "export", "-", "overwrite"), "overwrite has no effect")
	wantFailure(t, f.run("/tool/insight", "export"), "file")
	wantNoMutations(t, f)
}

func TestToolInsightParseResolution(t *testing.T) {
	for value, want := range map[string]int{"30": 30, "30s": 30, "5m": 300, "1h": 3600, "1d": 86400, "2d": 172800} {
		if got, err := toolInsightParseResolution(value); err != nil || got != want {
			t.Errorf("%s: got %d, %v", value, got, err)
		}
	}
	for _, value := range []string{"", "0", "-5", "1.5s", "500ms", "xd", "x"} {
		if _, err := toolInsightParseResolution(value); err == nil {
			t.Errorf("%q: want an error", value)
		}
	}
}
