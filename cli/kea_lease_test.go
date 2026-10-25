package cli

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

const keaLease4Path = "/api/kea/leases4/search"

func keaLeaseFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	// leases4/search rows of 26.7: numbers stay numbers, if is null for leases outside the interface networks
	f.onFunc("GET", keaLease4Path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var phrase = r.URL.Query().Get("searchPhrase")
		var rows = []string{
			`{"address":"192.168.1.100","prefix_len":128,"type":"","hwaddr":"02:00:5e:10:00:01","duid":"","client_id":"01:02","iaid":"",` +
				`"valid_lifetime":4000,"expire":1761400000,"hostname":"laptop","state":0,"if":"vtnet0","if_descr":"LAN","if_name":"lan",` +
				`"mac_info":"","lease_type":"dynamic","is_reserved":[],"sort_address":"192.168.001.100"}`,
			`{"address":"10.9.9.9","prefix_len":128,"type":"","hwaddr":"","duid":"","client_id":"01:aa","iaid":"","valid_lifetime":4000,` +
				`"expire":0,"hostname":"","state":2,"if":null,"if_descr":"","if_name":"","mac_info":"","lease_type":"static","is_reserved":["client_id"]}`,
		}
		var matching []string
		for _, row := range rows {
			if phrase == "" || strings.Contains(row, phrase) {
				matching = append(matching, row)
			}
		}
		_, _ = w.Write([]byte(`{"total":2,"rowCount":2,"current":1,"rows":[` + strings.Join(matching, ",") + `],"stats":{},"interfaces":{"lan":"LAN"}}`))
	})
	return f
}

func TestKeaLeasePrint(t *testing.T) {
	t.Parallel()
	var f = keaLeaseFake(t)
	var r = f.run("/kea/dhcp4/lease", "print")
	wantExit(t, r, 0)
	var expires = time.Unix(1761400000, 0).UTC().Format(time.DateTime) // the tests run with TZ=UTC
	var want = []string{
		"#|ADDRESS|MAC/CLIENT-ID|HOSTNAME|EXPIRES|STATE|INTERFACE|TYPE",
		"0|192.168.1.100|02:00:5e:10:00:01|laptop|" + expires + "|active|lan|dynamic",
		"1|10.9.9.9|01:aa|-|never|expired|-|static",
	}
	if got := keaTestLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	for _, iface := range []string{"lan", "LAN", "vtnet0"} {
		var filtered = f.run("/kea/dhcp4/lease", "print", "interface="+iface)
		if got := keaTestLines(filtered.stdout); len(got) != 2 || !strings.Contains(got[1], "laptop") {
			t.Errorf("interface=%s: %q", iface, got)
		}
	}
	var asJSON = f.run("/kea/dhcp4/lease", "print", "json", "interface=lan")
	wantExit(t, asJSON, 0)
	if lines := strings.Split(strings.TrimSpace(asJSON.stdout), "\n"); len(lines) != 1 || !strings.Contains(lines[0], `"valid_lifetime":4000`) {
		t.Errorf("json %q", asJSON.stdout)
	}
	var detail = f.run("/kea/dhcp4/lease", "print", "detail", "search=laptop")
	wantContains(t, "detail", detail.stdout, "client-id:", "01:02", "interface-description:", "LAN", "valid-lifetime:", "4000")
	wantNoMutations(t, f)
}

func TestKeaLeaseRemove(t *testing.T) {
	t.Parallel()
	var f = keaLeaseFake(t)
	f.on("POST", "/api/kea/leases4/del_lease/10.9.9.9", 200, `{"status":"ok"}`)
	f.on("POST", "/api/kea/leases4/del_lease/192.168.1.100", 500, `{"errorMessage":"Failed to delete lease(s): 192.168.1.100: not found","errorTitle":""}`)
	// by # without a print: the list position
	wantExit(t, f.run("/kea/dhcp4/lease", "remove", "1"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/kea/leases4/del_lease/10.9.9.9"), map[string]any{})
	wantFailure(t, f.run("/kea/dhcp4/lease", "remove", "192.168.1.100"), "Failed to delete lease(s): 192.168.1.100: not found")

	var refused = newFakeOPN(t)
	wantFailure(t, refused.run("/kea/dhcp4/lease", "remove", "2001:db8::1"), "IPv4")
	wantFailure(t, refused.run("/kea/dhcp6/lease", "remove", "192.0.2.1"), "IPv6")
	wantNoCalls(t, refused)
	var script = keaLeaseFake(t)
	wantFailure(t, script.runScript("/kea/dhcp4/lease print\n/kea/dhcp4/lease remove 5\n"), "#5", "2 items")
	wantNoMutations(t, script)
}
