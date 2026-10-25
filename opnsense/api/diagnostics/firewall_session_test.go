package diagnostics

import (
	"reflect"
	"strings"
	"testing"
)

func TestFirewallSessionList(t *testing.T) {
	var api, calls = firewallStateTestApi(t, map[string]string{"POST /api/diagnostics/firewall/query_pf_top": `{"total":2,"rowCount":2,"current":1,"rows":[` +
		`{"proto":"tcp","dir":"in","src_addr":"192.168.1.2","src_port":"55816","dst_addr":"192.168.1.1","dst_port":"443","gw_addr":null,"gw_port":null,"state":"TIME_WAIT:TIME_WAIT","age":87,"expire":3,"pkts":32,"bytes":8244,"avg":94,"rule":"86","label":"3345e04986bd5750d23b77cbbb21271f","descr":"anti-lockout rule"},` +
		`{"proto":"udp","dir":"out","src_addr":"10.0.2.15","src_port":"61000","dst_addr":"212.34.149.56","dst_port":"123","gw_addr":"192.168.1.50","gw_port":"40000","state":"MULTIPLE:SINGLE","age":30,"expire":30,"pkts":2,"bytes":152,"avg":5,"rule":"95"}]}`})
	var sessions, err = api.FirewallSessionList(FirewallSessionQuery{Search: "192.168.1.0/24", RuleId: "3345e04986bd5750d23b77cbbb21271f"})
	if err != nil || len(sessions) != 2 {
		t.Fatalf("got %+v, %v", sessions, err)
	}
	var nat = sessions[1]
	if nat.Proto != "udp" || nat.Dir != "out" || nat.GwAddr != "192.168.1.50" || nat.GwPort != "40000" || nat.Age != 30 ||
		nat.Expire != 30 || nat.Pkts != 2 || nat.Bytes != 152 || nat.Avg != 5 || nat.Rule != "95" || nat.Label != "" {
		t.Errorf("unexpected session %+v", nat)
	}
	if sessions[0].Descr != "anti-lockout rule" || !strings.HasPrefix(string(sessions[0].Raw), `{"proto":"tcp"`) {
		t.Errorf("unexpected session %+v", sessions[0])
	}
	var body = firewallStateTestBody(t, calls()[0])
	if !reflect.DeepEqual(body, map[string]any{"searchPhrase": "192.168.1.0/24", "ruleid": "3345e04986bd5750d23b77cbbb21271f"}) {
		t.Errorf("unexpected body %v (no rowCount: all rows)", body)
	}

	for _, answer := range []string{``, `null`, `{}`} {
		var failing, _ = firewallStateTestApi(t, map[string]string{"POST /api/diagnostics/firewall/query_pf_top": answer})
		if _, err := failing.FirewallSessionList(FirewallSessionQuery{}); err == nil {
			t.Errorf("answer %q: want an error", answer)
		}
	}
}
