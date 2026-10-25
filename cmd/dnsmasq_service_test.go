package cmd

import (
	"reflect"
	"testing"
)

func TestDnsmasqService(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		action  string
		method  string
		answer  string
		wantOk  bool
		wantOut string
	}{
		{"status", "GET", `{"status":"running","widget":{"caption_stop":"stop service","caption_start":"start service"}}`, true, "running"},
		{"status", "GET", `{"status":"stopped","widget":{}}`, true, "stopped"},
		{"status", "GET", `{"widget":{}}`, false, "status"},
		{"start", "POST", `{"response":"OK"}`, true, "started"},
		{"start", "POST", `{"response":"Execute error"}`, false, "Execute error"},
		{"stop", "POST", `{"response":"OK"}`, true, "stopped"},
		{"stop", "POST", `{"response":[]}`, false, "stop"},
		{"restart", "POST", `{"response":"OK"}`, true, "restarted"},
		{"restart", "POST", `{"response":"Execute error"}`, false, "Execute error"},
		{"reconfigure", "POST", `{"status":"ok"}`, true, "reconfigured"},
		{"reconfigure", "POST", `{"status":"failed","status_msg":"dnsmasq: syntax error at line 3"}`, false, "syntax error at line 3"},
		{"reconfigure", "POST", `{"status":"failed"}`, false, "failed"},
	} {
		t.Run(tc.action+"/"+tc.answer, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			var path = "/api/dnsmasq/service/" + tc.action
			f.on(tc.method, path, 200, tc.answer)
			var r = f.run("dnsmasq", "service", tc.action)
			if tc.wantOk {
				wantExit(t, r, 0)
			} else {
				wantExit(t, r, 1)
			}
			wantContains(t, "output", r.stdout+r.stderr, tc.wantOut)
			var calls = f.calls()
			if len(calls) != 1 || calls[0].Method != tc.method || calls[0].Path != path {
				t.Errorf("want one %s %s, got %v", tc.method, path, calls)
			}
		})
	}
}

func TestDnsmasqServiceRejectsArguments(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var r = f.run("dnsmasq", "service", "restart", "now")
	wantFailure(t, r, "now")
	wantNoCalls(t, f)
}

const dnsmasqLeasePath = "/api/dnsmasq/leases/search"

func TestDnsmasqLeasesList(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search(dnsmasqLeasePath,
		map[string]any{"expire": 1761350400, "hwaddr": "aa:bb:cc:dd:ee:ff", "iaid": "", "address": "192.168.1.10",
			"hostname": "laptop", "client_id": "01:aa:bb:cc:dd:ee:ff", "if": "igc1", "if_descr": "LAN", "if_name": "lan",
			"mac_info": "Vendor", "is_reserved": []string{"hwaddr"}, "lease_type": "static", "sort_address": "04.192.168.001.010"},
		map[string]any{"expire": 0, "hwaddr": "", "iaid": "12345", "address": "fd00::10", "hostname": "*",
			"client_id": "*", "is_reserved": []string{}, "lease_type": "dynamic"},
		map[string]any{"expire": 1761350400, "hwaddr": "aa:bb:cc:dd:ee:01", "address": "192.168.2.20",
			"hostname": "phone", "if": "igc2", "if_descr": "", "lease_type": "dynamic"},
	)

	var r = f.run("dnsmasq", "leases", "list")
	wantExit(t, r, 0)
	var want = [][]string{
		{"ADDRESS", "HWADDR", "HOSTNAME", "EXPIRES", "INTERFACE", "TYPE"},
		{"192.168.1.10", "aa:bb:cc:dd:ee:ff", "laptop", "2025-10-25 00:00:00", "LAN", "static"},
		{"fd00::10", "-", "-", "never", "-", "dynamic"},
		{"192.168.2.20", "aa:bb:cc:dd:ee:01", "phone", "2025-10-25 00:00:00", "igc2", "dynamic"},
	}
	if got := tableRows(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("table:\n got  %q\n want %q\n%s", got, want, r.stdout)
	}

	for _, args := range [][]string{
		{"dnsmasq", "leases", "list", "--search", "laptop"},
		{"dnsmasq", "lease", "list", "-s", "laptop"},
	} {
		r = f.run(args...)
		wantExit(t, r, 0)
		if rows := tableRows(r.stdout); len(rows) != 2 || rows[1][0] != "192.168.1.10" {
			t.Errorf("%v: want only the laptop lease:\n%s", args, r.stdout)
		}
	}
	wantSearchPhrases(t, f, dnsmasqLeasePath, "", "laptop", "laptop")
	wantNoMutations(t, f)
}
