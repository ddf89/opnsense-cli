package cli

import (
	"strings"
	"testing"
	"time"
)

const (
	firewallShaperStatisticsPath  = "/api/trafficshaper/service/statistics"
	firewallShaperReconfigurePath = "/api/trafficshaper/service/reconfigure"
	firewallShaperFlushPath       = "/api/trafficshaper/service/flushreload"
)

// firewallShaperTestStatistics is shaped like service/statistics of 26.7: a pipe, its automatic queue (traffic of
// rules targeting the pipe) and a queue of the pipe
const firewallShaperTestStatistics = `{"status":"ok","items":[` +
	`{"pipe":"10000","bw":"100.000 Mbit/s","delay":"0","burst":"0","flows":[],"flowset":{"flow_set_nr":"1","flows":"0"},` +
	`"scheduler":{"sched_nr":"10000","sched_type":"FQ_CODEL","sched_flags":"0x0","sched_buckets":"1","sched_active":"0"},` +
	`"description":"WAN down","uuid":"p-1","type":"pipe","id":10000,"rules":[]},` +
	`{"flow_set_nr":"1","queue_size":"50 sl.","buckets":"64","sched_nr":"10000","weight":"0","lmax":"0","pri":"0",` +
	`"queue_params":"droptail","type":"queue","template":true,"pipe":10000,"id":"10000.1","flows":[` +
	`{"BKT":"0","Prot":"tcp","Source":"192.0.2.10/51000","Destination":"198.51.100.1/443","pkt":1000,"bytes":1500000,"drop_pkt":3,"drop_bytes":4500}],` +
	`"rules":[{"rule":"60001","pkts":1000,"bytes":1500000,"accessed":"2026-10-25T14:00:00","accessed_epoch":1761400800,` +
	`"attached_to":"10000","rule_uuid":"r-1","description":"all web"}]},` +
	`{"flow_set_nr":"10000","queue_size":"50 sl.","buckets":"64","sched_nr":"10000","weight":"10","lmax":"0","pri":"0",` +
	`"queue_params":"","flows":[{"BKT":"1","Prot":"udp","flowid":"5","Source":"2001:db8::1/5060","Destination":"2001:db8::2/5060",` +
	`"pkt":5,"bytes":500,"drop_pkt":0,"drop_bytes":0}],"description":"voip","uuid":"q-1","type":"queue","id":"10000.10000","rules":[]}]}`

func TestFirewallShaperStatus(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", firewallShaperStatisticsPath, 200, firewallShaperTestStatistics)
	var r = f.run("/firewall/shaper", "status")
	wantExit(t, r, 0)
	var rows = dnsmasqTableRows(r.stdout)
	var want = [][]string{
		{"TYPE", "ID", "DESCRIPTION", "BANDWIDTH", "WEIGHT", "SCHEDULER", "FLOWS", "PACKETS", "BYTES", "DROPS"},
		{"pipe", "10000", "WAN down", "100.000 Mbit/s", "-", "FQ_CODEL", "0", "0", "0 B", "0"},
		{"queue", "10000.1", "WAN down (direct)", "-", "-", "-", "1", "1000", "1.5 MB", "3"},
		{"queue", "10000.10000", "voip", "-", "10", "-", "1", "5", "500 B", "0"},
	}
	if len(rows) != len(want) {
		t.Fatalf("want %d lines:\n%s", len(want), r.stdout)
	}
	for i := range want {
		if strings.Join(rows[i], "|") != strings.Join(want[i], "|") {
			t.Errorf("line %d: got %q, want %q", i, rows[i], want[i])
		}
	}

	r = f.run("/firewall/shaper", "status", "detail")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "uuid:", "p-1", "scheduler:", "FQ_CODEL", "flow:",
		"tcp 192.0.2.10/51000 -> 198.51.100.1/443, 1000 packets, 1.5 MB, 3 drops", "rule:", `60001 "all web", 1000 packets`,
		time.Unix(1761400800, 0).UTC().Format(time.DateTime), "weight:")

	r = f.run("/firewall/shaper", "status", "json")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"bw":"100.000 Mbit/s"`) || !strings.Contains(lines[1], `"template":true`) {
		t.Errorf("want 3 raw items:\n%s", r.stdout)
	}
	wantNoMutations(t, f)
}

func TestFirewallShaperStatusEmptyAndErrors(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", firewallShaperStatisticsPath, 200, `{"status":"ok","items":[]}`)
	var r = f.run("/firewall/shaper", "status")
	wantExit(t, r, 0)
	if len(dnsmasqTableRows(r.stdout)) != 1 {
		t.Errorf("want only the header:\n%s", r.stdout)
	}

	for _, tc := range []struct {
		status int
		body   string
		want   string
	}{
		{200, `{"status":"failed"}`, "failed"},
		{403, `{"status":403,"message":"Forbidden"}`, "HTTP 403"},
		{200, ``, "empty response"},
	} {
		var f = newFakeOPN(t)
		f.on("GET", firewallShaperStatisticsPath, tc.status, tc.body)
		wantFailure(t, f.run("/firewall/shaper", "status"), tc.want)
	}
}

func TestFirewallShaperStatusFollow(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", firewallShaperStatisticsPath, 200, firewallShaperTestStatistics)
	var p = f.start("/firewall/shaper", "status", "follow", "interval=20ms")
	f.waitForConnections(firewallShaperStatisticsPath, 4)
	p.waitFor("voip")
	var r = p.interrupt()
	wantExit(t, r, 0)
	if refreshes := strings.Count(r.stdout, "voip"); refreshes < 3 || strings.Count(r.stdout, "--- ") != refreshes {
		t.Errorf("want at least 3 refreshes with separators:\n%s", r.stdout)
	}
}

func TestFirewallShaperReconfigure(t *testing.T) {
	t.Parallel()
	for _, command := range []string{"reconfigure", "apply"} {
		var f = newFakeOPN(t)
		f.on("POST", firewallShaperReconfigurePath, 200, `{"status":"ok"}`)
		var r = f.run("/firewall/shaper", command)
		wantExit(t, r, 0)
		if r.stdout != "" {
			t.Errorf("%s must be silent, got %q", command, r.stdout)
		}
		if call := wantOneMutation(t, f, "POST", firewallShaperReconfigurePath); call.Body != "" {
			t.Errorf("want a POST without body, got %q", call.Body)
		}
	}

	var f = newFakeOPN(t)
	f.on("POST", firewallShaperReconfigurePath, 200, `{"status":"error reloading ipfw (Execute error)"}`)
	wantFailure(t, f.run("/firewall/shaper", "apply"), "error reloading ipfw")
}

func TestFirewallShaperFlushReload(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", firewallShaperFlushPath, 200, `{"status":"OK"}`)
	wantFailure(t, f.run("/firewall/shaper", "flush-reload"), "flushes all ipfw rules", "confirm=yes")
	wantFailure(t, f.run("/firewall/shaper", "flush-reload", "confirm=no"), "confirm")
	wantNoCalls(t, f)

	var r = f.run("/firewall/shaper", "flush-reload", "confirm=yes")
	wantExit(t, r, 0)
	wantOneMutation(t, f, "POST", firewallShaperFlushPath)

	f = newFakeOPN(t)
	f.on("POST", firewallShaperFlushPath, 200, `{"status":"Execute error"}`)
	wantFailure(t, f.run("/firewall/shaper", "flush-reload", "confirm"), "Execute error")
}

func TestFirewallShaperParseBandwidth(t *testing.T) {
	t.Parallel()
	for value, want := range map[string][2]string{
		"100Mbit": {"100", "Mbit"}, "100 Mbit/s": {"100", "Mbit"}, "100mbps": {"100", "Mbit"}, "100M": {"100", "Mbit"},
		"512kbit": {"512", "Kbit"}, "1G": {"1", "Gbit"}, "64000bit": {"64000", "bit"}, "100": {"100", ""}, "007k": {"7", "Kbit"},
	} {
		var number, unit, err = firewallShaperParseBandwidth(value)
		if err != nil || number != want[0] || unit != want[1] {
			t.Errorf("%q: got %q %q %v, want %v", value, number, unit, err, want)
		}
	}
	for _, value := range []string{"", "fast", "100Tbit", "-5M", "1.5M", "0", "100 MB/s/s"} {
		if _, _, err := firewallShaperParseBandwidth(value); err == nil {
			t.Errorf("%q: want an error", value)
		}
	}
}

func TestFirewallShaperValidatePort(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", "any", "ANY", "80", "1-65535", "1000-2000", "https", "ipsec-nat-t"} {
		if err := firewallShaperValidatePort(value); err != nil {
			t.Errorf("%q: %v", value, err)
		}
	}
	for _, value := range []string{"0", "70000", "80:90", "1000-", "-5", "1000-70000", "Http!", "80,443"} {
		if err := firewallShaperValidatePort(value); err == nil {
			t.Errorf("%q: want an error", value)
		}
	}
}
