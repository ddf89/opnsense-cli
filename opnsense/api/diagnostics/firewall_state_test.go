package diagnostics

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// firewallStateTestRows are trimmed query_states rows of OPNsense 26.7 (a NAT state added)
const firewallStateTestRows = `{"rows":[` +
	`{"label":"3345e04986bd5750d23b77cbbb21271f","descr":"anti-lockout rule","nat_addr":null,"nat_port":null,"gateway":null,"iface":"all","proto":"tcp","ipproto":"ipv4","flags":[],"direction":"in","dst_addr":"192.168.1.1","dst_port":"443","src_addr":"192.168.1.2","src_port":"55816","state":"TIME_WAIT:TIME_WAIT","age":"00:01:26","expires":"00:00:04","pkts":[15,17],"bytes":[2751,5493],"rule":"86","id":"6f14de6a00000000\/0449ade0","interface":"all"},` +
	`{"label":"d621e174-154f-4ebb-9465-6e2fac4b2bcb","descr":"Default allow LAN to any rule","nat_addr":"192.168.1.50","nat_port":"40000","gateway":null,"iface":"vtnet1","proto":"udp","ipproto":"ipv4","flags":["no-df"],"direction":"out","dst_addr":"212.34.149.56","dst_port":"123","src_addr":"10.0.2.15","src_port":"61000","state":"MULTIPLE:SINGLE","age":"00:00:30","expires":"00:00:30","pkts":[1,1],"bytes":[76,76],"rule":"95","id":"7714de6a00000000\/0449ade0","interface":"WAN"}` +
	`],"rowCount":2,"total":2,"current":1}`

type firewallStateTestCall struct {
	Method string
	Path   string
	Body   string
}

// firewallStateTestApi answers "METHOD /path" with the canned bodies (404 for others) and records the requests
func firewallStateTestApi(t *testing.T, routes map[string]string) (*DiagnosticsApi, func() []firewallStateTestCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []firewallStateTestCall
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, firewallStateTestCall{Method: r.Method, Path: r.URL.Path, Body: string(body)})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if answer, found := routes[r.Method+" "+r.URL.Path]; found {
			_, _ = io.WriteString(w, answer)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"errorMessage":"Endpoint not found"}`)
	}))
	t.Cleanup(server.Close)
	var serverUrl, _ = url.Parse(server.URL)
	return &DiagnosticsApi{OPNsense: &coreapi.OPNsense{BaseUrl: *serverUrl}}, func() []firewallStateTestCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]firewallStateTestCall(nil), calls...)
	}
}

func firewallStateTestBody(t *testing.T, call firewallStateTestCall) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal([]byte(call.Body), &body); err != nil {
		t.Fatalf("body of %s %s is not JSON: %q", call.Method, call.Path, call.Body)
	}
	return body
}

func TestFirewallStateList(t *testing.T) {
	var api, calls = firewallStateTestApi(t, map[string]string{"POST /api/diagnostics/firewall/query_states": firewallStateTestRows})
	var states, err = api.FirewallStateList(FirewallStateQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 {
		t.Fatalf("want 2 states, got %+v", states)
	}
	var nat = states[1]
	if nat.Id != "7714de6a00000000/0449ade0" || nat.Iface != "vtnet1" || nat.Interface != "WAN" || nat.Proto != "udp" ||
		nat.IpProto != "ipv4" || nat.Direction != "out" || nat.SrcAddr != "10.0.2.15" || nat.SrcPort != "61000" ||
		nat.DstAddr != "212.34.149.56" || nat.DstPort != "123" || nat.NatAddr != "192.168.1.50" || nat.NatPort != "40000" ||
		nat.Gateway != "" || nat.State != "MULTIPLE:SINGLE" || nat.Age != "00:00:30" || nat.Expires != "00:00:30" ||
		nat.Rule != "95" || nat.Label != "d621e174-154f-4ebb-9465-6e2fac4b2bcb" || nat.Descr != "Default allow LAN to any rule" ||
		!reflect.DeepEqual(nat.Flags, []string{"no-df"}) {
		t.Errorf("unexpected state %+v", nat)
	}
	if states[0].TotalPackets() != 32 || states[0].TotalBytes() != 8244 {
		t.Errorf("totals: %d packets, %d bytes", states[0].TotalPackets(), states[0].TotalBytes())
	}
	if !strings.HasPrefix(string(states[0].Raw), `{"label":"3345e04986bd5750d23b77cbbb21271f"`) {
		t.Errorf("raw state not kept: %s", states[0].Raw)
	}
	var body = firewallStateTestBody(t, calls()[0])
	if body["rowCount"] != float64(firewallStatesMaxRows) || body["current"] != float64(1) || len(body) != 2 {
		t.Errorf("unexpected body %v", body)
	}

	if _, err := api.FirewallStateList(FirewallStateQuery{Search: "192.168.1.0/24 tcp", RuleId: "3345e049"}); err != nil {
		t.Fatal(err)
	}
	body = firewallStateTestBody(t, calls()[1])
	if body["searchPhrase"] != "192.168.1.0/24 tcp" || body["ruleid"] != "3345e049" {
		t.Errorf("unexpected body %v", body)
	}
}

func TestFirewallStateListErrors(t *testing.T) {
	for _, answer := range []string{`{}`, ``, `[]`} {
		var api, _ = firewallStateTestApi(t, map[string]string{"POST /api/diagnostics/firewall/query_states": answer})
		if states, err := api.FirewallStateList(FirewallStateQuery{}); err == nil {
			t.Errorf("answer %q: want an error, got %+v", answer, states)
		}
	}
	var api, _ = firewallStateTestApi(t, map[string]string{"POST /api/diagnostics/firewall/query_states": `{"rows":[],"rowCount":0,"total":0,"current":0}`})
	if states, err := api.FirewallStateList(FirewallStateQuery{}); err != nil || states == nil || len(states) != 0 {
		t.Errorf("empty table: %+v, %v", states, err)
	}
}

func TestFirewallStateRemove(t *testing.T) {
	var path = "POST /api/diagnostics/firewall/del_state/6f14de6a00000000/0449ade0"
	for _, tc := range []struct {
		answer   string
		ok       bool
		notFound bool
	}{
		{`{"result":"killed 1 states from 1 specified\n"}`, true, false},
		{`{"result":"killed 1 states\n"}`, true, false},
		{`{"result":"killed 0 states\n"}`, false, true},
		{`{"result":""}`, false, false},
	} {
		var api, calls = firewallStateTestApi(t, map[string]string{path: tc.answer})
		var err = api.FirewallStateRemove("6f14de6a00000000/0449ade0")
		if tc.ok != (err == nil) || tc.notFound != coreapi.IsNotFound(err) {
			t.Errorf("answer %s: got %v", tc.answer, err)
		}
		if c := calls(); len(c) != 1 || c[0].Method != "POST" {
			t.Errorf("unexpected requests %+v", c)
		}
	}

	// malformed ids are refused without a request
	var api, calls = firewallStateTestApi(t, nil)
	for _, id := range []string{"", "6f14de6a00000000", "6f14/../x", "6f14de6a00000000/0449ade0/1", "zz/00"} {
		if err := api.FirewallStateRemove(id); err == nil {
			t.Errorf("id %q: want an error", id)
		}
	}
	if len(calls()) != 0 {
		t.Errorf("want no requests, got %+v", calls())
	}
}

func TestFirewallStateKill(t *testing.T) {
	var api, calls = firewallStateTestApi(t, map[string]string{
		"POST /api/diagnostics/firewall/kill_states": `{"result":"ok","dropped_states":3}`,
	})
	var dropped, err = api.FirewallStateKill("192.168.1.50", "b7cd97a164650b538506fb551a0369e7")
	if err != nil || dropped != 3 {
		t.Fatalf("got %d, %v", dropped, err)
	}
	var body = firewallStateTestBody(t, calls()[0])
	if !reflect.DeepEqual(body, map[string]any{"filter": "192.168.1.50", "ruleid": "b7cd97a164650b538506fb551a0369e7"}) {
		t.Errorf("unexpected body %v", body)
	}
	if _, err := api.FirewallStateKill("tcp", ""); err != nil {
		t.Fatal(err)
	}
	if body = firewallStateTestBody(t, calls()[1]); !reflect.DeepEqual(body, map[string]any{"filter": "tcp"}) {
		t.Errorf("unexpected body %v", body)
	}

	// without filter nothing is sent (OPNsense would refuse too, but never rely on it)
	if _, err := api.FirewallStateKill(" ", ""); err == nil || len(calls()) != 2 {
		t.Errorf("want a refusal without request, got %v, %+v", err, calls())
	}

	var failing, _ = firewallStateTestApi(t, map[string]string{"POST /api/diagnostics/firewall/kill_states": `{"result":"failed"}`})
	if _, err := failing.FirewallStateKill("x", ""); err == nil {
		t.Error("want an error for result failed")
	}
}

func TestFirewallStateFlush(t *testing.T) {
	var api, calls = firewallStateTestApi(t, map[string]string{
		"POST /api/diagnostics/firewall/flush_states":  `{"result":"ok"}`,
		"POST /api/diagnostics/firewall/flush_sources": `{"result":"ok"}`,
	})
	if err := api.FirewallStateFlush(); err != nil {
		t.Fatal(err)
	}
	if err := api.FirewallSourceFlush(); err != nil {
		t.Fatal(err)
	}
	var c = calls()
	if len(c) != 2 || c[0].Path != "/api/diagnostics/firewall/flush_states" || c[1].Path != "/api/diagnostics/firewall/flush_sources" ||
		strings.TrimSpace(c[0].Body) != "{}" {
		t.Errorf("unexpected requests %+v", c)
	}

	var failing, _ = firewallStateTestApi(t, map[string]string{"POST /api/diagnostics/firewall/flush_states": `{"result":"failed"}`})
	if err := failing.FirewallStateFlush(); err == nil {
		t.Error("want an error for result failed")
	}
}

func TestFirewallRuleIds(t *testing.T) {
	var api, _ = firewallStateTestApi(t, map[string]string{"GET /api/diagnostics/firewall/list_rule_ids": `{"items":[` +
		`{"id":"b7cd97a164650b538506fb551a0369e7","descr":"Block bogon IPv4 networks from WAN"},` +
		`{"id":"d621e174-154f-4ebb-9465-6e2fac4b2bcb","descr":"Default allow LAN to any rule"}]}`})
	var ids, err = api.FirewallRuleIds()
	if err != nil || len(ids) != 2 || ids[1] != (FirewallRuleId{Id: "d621e174-154f-4ebb-9465-6e2fac4b2bcb", Descr: "Default allow LAN to any rule"}) {
		t.Errorf("got %+v, %v", ids, err)
	}
	var empty, _ = firewallStateTestApi(t, map[string]string{"GET /api/diagnostics/firewall/list_rule_ids": `{"items":[]}`})
	if ids, err := empty.FirewallRuleIds(); err != nil || ids == nil || len(ids) != 0 {
		t.Errorf("empty: %+v, %v", ids, err)
	}
}

func TestFirewallStateCountGet(t *testing.T) {
	var api, _ = firewallStateTestApi(t, map[string]string{"GET /api/diagnostics/firewall/pf_states": `{"current":"33","limit":"200500"}`})
	var count, err = api.FirewallStateCountGet()
	if err != nil || count != (FirewallStateCount{Current: 33, Limit: 200500}) {
		t.Errorf("got %+v, %v", count, err)
	}
	var failing, _ = firewallStateTestApi(t, map[string]string{"GET /api/diagnostics/firewall/pf_states": `{"result":"failed"}`})
	if _, err := failing.FirewallStateCountGet(); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Errorf("want an error, got %v", err)
	}
}
