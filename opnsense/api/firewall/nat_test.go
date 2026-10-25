package firewall

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

type natTestCall struct {
	Method, Path, Body string
}

// natTestApi serves answers by "METHOD /path", recording every call; unknown paths fail the test
func natTestApi(t *testing.T, answers map[string]string) (*FirewallApi, func() []natTestCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []natTestCall
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, natTestCall{r.Method, r.URL.Path, strings.TrimSpace(string(body))})
		mu.Unlock()
		var answer, ok = answers[r.Method+" "+r.URL.Path]
		if !ok {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if strings.HasPrefix(answer, "@uuid") || answer == "" {
			w.Header().Set("Content-Type", "text/csv;charset=UTF-8")
		}
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(server.Close)
	var serverUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &FirewallApi{OPNsense: &coreapi.OPNsense{BaseUrl: *serverUrl, ApiKey: "key", ApiSecret: "secret"}}, func() []natTestCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]natTestCall(nil), calls...)
	}
}

func natTestMutations(calls []natTestCall) []natTestCall {
	var result []natTestCall
	for _, call := range calls {
		if call.Method != "GET" {
			result = append(result, call)
		}
	}
	return result
}

const natTestSnatSearch = `{"rows":[{"uuid":"automatic_wan","enabled":"1","sequence":"2","interface":"wan","description":"Auto created rule",` +
	`"is_automatic":true,"category_colors":[],"alias_meta_target":[{"value":"wanip"}]}],"rowCount":1}`

const natTestSnatCSV = "@uuid;enabled;sequence;interface;source_net;description\n" +
	"s2;0;200;wan;198.51.100.0/24;\"second; rule\"\n" +
	"s1;1;100;lan;any;first\n"

const natTestDnatSearch = `{"rows":[` +
	`{"uuid":"lockout_0","disabled":"0","nordr":"1","descr":"Anti-Lockout Rule","is_automatic":true},` +
	`{"uuid":"d1","sequence":"100","disabled":"1","destination.network":"wanip","destination.port":"8080","source.network":"","source.port":"","source.not":"0","destination.not":"1","descr":"web"},` +
	`{"uuid":"d2","sequence":"300","disabled":"0","destination.network":"wanip","destination.port":"22","source.network":"","source.port":"","source.not":"0","destination.not":"0","descr":"ssh"}` +
	`],"rowCount":2}`

func TestNatListMergesInactiveSourceNatRules(t *testing.T) {
	var api, _ = natTestApi(t, map[string]string{
		"GET /api/firewall/source_nat/search_rule":    natTestSnatSearch,
		"GET /api/firewall/source_nat/download_rules": natTestSnatCSV,
	})
	var rules = api.SourceNat()
	var list, err = rules.List()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, rule := range list {
		got = append(got, strings.Join([]string{rule.Uuid, rules.Description(rule), map[bool]string{true: "auto"}[rule.Automatic],
			map[bool]string{true: "inactive"}[rule.Inactive], map[bool]string{true: "disabled"}[rules.Disabled(rule)]}, "|"))
	}
	var want = []string{"automatic_wan|Auto created rule|auto||", "s1|first||inactive|", "s2|second; rule||inactive|disabled"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
	if list[0].Fields["is_automatic"] != "1" || list[0].Fields["alias_meta_target"] != "" {
		t.Errorf("flattened fields %v", list[0].Fields)
	}
	var raw map[string]string
	if err := json.Unmarshal(list[2].Raw, &raw); err != nil || raw["uuid"] != "s2" || raw["source_net"] != "198.51.100.0/24" {
		t.Errorf("raw of a CSV rule: %s, %v", list[2].Raw, err)
	}
}

func TestNatDestinationShape(t *testing.T) {
	var api, calls = natTestApi(t, map[string]string{
		"GET /api/firewall/d_nat/search_rule":       natTestDnatSearch,
		"POST /api/firewall/d_nat/add_rule":         `{"result":"saved","uuid":"d3"}`,
		"POST /api/firewall/d_nat/set_rule/d1":      `{"result":"saved"}`,
		"POST /api/firewall/d_nat/toggle_rule/d1/0": `{"result":"Enabled"}`,
		"POST /api/firewall/d_nat/toggle_rule/d2/0": `{"result":"Enabled"}`,
	})
	var rules = api.DestinationNat()
	if rules.DescriptionField() != "descr" || rules.DisabledField() != "disabled" || rules.DisabledValue(true) != "1" {
		t.Errorf("d_nat fields: %s %s %s", rules.DescriptionField(), rules.DisabledField(), rules.DisabledValue(true))
	}
	if _, err := rules.Create(NatRuleFields{"destination.port": "80", "destination.network": "wanip", "descr": "x", "disabled": "1"}); err != nil {
		t.Fatal(err)
	}
	if err := rules.Update("D1", NatRuleFields{"source.not": "1"}); err != nil {
		t.Fatal(err)
	}
	if changed, err := rules.SetEnabled("d1", true); err != nil || !changed {
		t.Errorf("enable d1 (disabled): %v, %v", changed, err)
	}
	if changed, err := rules.SetEnabled("d2", true); err != nil || changed {
		t.Errorf("enable d2 (enabled): %v, %v", changed, err)
	}
	var mutations = natTestMutations(calls())
	var bodies = []string{
		`{"rule":{"descr":"x","destination":{"network":"wanip","port":"80"},"disabled":"1"}}`,
		`{"rule":{"source":{"not":"1"}}}`,
	}
	for i, want := range bodies {
		if mutations[i].Body != want {
			t.Errorf("body %d: %s, want %s", i, mutations[i].Body, want)
		}
	}
}

func TestNatUnknownAndAutomaticRules(t *testing.T) {
	var api, calls = natTestApi(t, map[string]string{
		"GET /api/firewall/d_nat/search_rule":       natTestDnatSearch,
		"POST /api/firewall/d_nat/del_rule/nope":    `{"result":"not found"}`,
		"POST /api/firewall/d_nat/set_rule/d2":      `{"result":"failed"}`,
		"POST /api/firewall/d_nat/toggle_rule/d2/1": `{"result":"failed"}`,
	})
	var rules = api.DestinationNat()
	if err := rules.Update("00000000-0000-4000-8000-000000000001", NatRuleFields{"descr": "x"}); !coreapi.IsNotFound(err) {
		t.Errorf("update of an unknown uuid: %v", err)
	}
	if err := rules.Update("lockout_0", NatRuleFields{"descr": "x"}); err == nil || !strings.Contains(err.Error(), "generated by OPNsense") {
		t.Errorf("update of an automatic rule: %v", err)
	}
	if err := rules.Update("d2", NatRuleFields{"descr": "x"}); !coreapi.IsNotFound(err) {
		t.Errorf("removed meanwhile: %v", err)
	}
	if _, err := rules.SetEnabled("d2", false); !coreapi.IsNotFound(err) {
		t.Errorf("toggle removed meanwhile: %v", err)
	}
	if err := rules.Remove("nope"); !coreapi.IsNotFound(err) || !strings.Contains(err.Error(), "destination NAT rule nope") {
		t.Errorf("remove unknown: %v", err)
	}
	if _, err := rules.Get("nope"); !coreapi.IsNotFound(err) {
		t.Errorf("get unknown: %v", err)
	}
	if err := rules.MoveBefore("d2", "lockout_0"); err == nil || !strings.Contains(err.Error(), "generated by OPNsense") {
		t.Errorf("move before an automatic rule: %v", err)
	}
	if err := rules.MoveBefore("d2", "d2"); err == nil || !strings.Contains(err.Error(), "before itself") {
		t.Errorf("move before itself: %v", err)
	}
	for _, call := range natTestMutations(calls()) {
		if strings.Contains(call.Path, "00000000") || strings.Contains(call.Path, "lockout") || strings.Contains(call.Path, "move_rule_before") {
			t.Errorf("unexpected mutation %+v", call)
		}
	}
}

func TestNatMove(t *testing.T) {
	var api, calls = natTestApi(t, map[string]string{
		"GET /api/firewall/d_nat/search_rule":             natTestDnatSearch,
		"POST /api/firewall/d_nat/move_rule_before/d2/d1": `{"status":"ok"}`,
		"POST /api/firewall/d_nat/set_rule/d1":            `{"result":"saved"}`,
	})
	var rules = api.DestinationNat()
	if err := rules.MoveBefore("d2", "d1"); err != nil {
		t.Fatal(err)
	}
	if err := rules.MoveToEnd("d1"); err != nil {
		t.Fatal(err)
	}
	if err := rules.MoveToEnd("d2"); err != nil { // the last one already
		t.Fatal(err)
	}
	var mutations = natTestMutations(calls())
	if len(mutations) != 2 || mutations[1].Body != `{"rule":{"sequence":"400"}}` {
		t.Errorf("mutations %+v", mutations)
	}
}

func TestNatOptionsAndColumns(t *testing.T) {
	var api, _ = natTestApi(t, map[string]string{
		"GET /api/firewall/d_nat/get_rule": `{"rule":{"sequence":"200","interface":{"lan":{"value":"LAN","selected":0},"wan":{"value":"WAN","selected":1}},` +
			`"protocol":{"":{"value":"any","selected":1},"tcp":{"value":"TCP","selected":0}},` +
			`"source":{"network":"","port":"","not":"0"},"category":[],"descr":""}}`,
	})
	var rules = api.DestinationNat()
	var options, err = rules.Options()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(options, map[string][]string{"interface": {"lan", "wan"}, "protocol": {"", "tcp"}}) {
		t.Errorf("options %v", options)
	}
	columns, err := rules.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var want = []string{"@uuid", "category", "descr", "interface", "prio_group", "protocol", "sequence", "sort_order", "source",
		"source.network", "source.not", "source.port"}
	if !reflect.DeepEqual(columns, want) {
		t.Errorf("columns %q\nwant %q", columns, want)
	}
}

func TestNatExportExpandsDestinationNat(t *testing.T) {
	var api, _ = natTestApi(t, map[string]string{
		"GET /api/firewall/d_nat/search_rule":    natTestDnatSearch,
		"GET /api/firewall/d_nat/download_rules": "@uuid;disabled;source;destination;descr\nd1;1;;;\"web; site\"\n",
	})
	var content, err = api.DestinationNat().Export()
	if err != nil {
		t.Fatal(err)
	}
	var want = "@uuid;disabled;source.network;source.port;source.not;destination.network;destination.port;destination.not;descr\n" +
		"d1;1;;;0;wanip;8080;1;\"web; site\"\n"
	if string(content) != want {
		t.Errorf("export:\n%s\nwant:\n%s", content, want)
	}

	var empty, _ = natTestApi(t, map[string]string{"GET /api/firewall/d_nat/download_rules": ""})
	if content, err := empty.DestinationNat().Export(); err != nil || len(content) != 0 {
		t.Errorf("empty export: %q, %v", content, err)
	}
}

func TestNatImport(t *testing.T) {
	var api, calls = natTestApi(t, map[string]string{
		"POST /api/firewall/npt/upload_rules": `{"validations":[{"sequence":0,"field":"rule.source_net","message":"bad"},{"message":"general"}],` +
			`"inserted":1,"updated":0,"uuids":{"u1":1}}`,
	})
	var result, err = api.Npt().Import([]byte("@uuid;source_net\n;x\n"), "f.csv")
	if err != nil {
		t.Fatal(err)
	}
	if result.Inserted != 1 || result.Uuids["u1"] != 1 || len(result.Validations) != 2 || result.Validations[0].Row != 0 || result.Validations[1].Row != -1 {
		t.Errorf("result %+v", result)
	}
	if body := calls()[0].Body; body != `{"filename":"f.csv","payload":"@uuid;source_net\n;x\n"}` {
		t.Errorf("body %s", body)
	}

	var refused, _ = natTestApi(t, map[string]string{"POST /api/firewall/npt/upload_rules": `{"status":"failed"}`})
	if _, err := refused.Npt().Import([]byte("x"), "f.csv"); err == nil {
		t.Error("want an error for status failed")
	}
}

func TestNatApplyAndMode(t *testing.T) {
	var api, calls = natTestApi(t, map[string]string{
		"POST /api/firewall/one_to_one/apply": `{"status":"OK\n\n"}`,
		"GET /api/firewall/source_nat/get": `{"filter":{"general":{"snat_mode":{"automatic":{"value":"A","selected":0},` +
			`"advanced":{"value":"M","selected":1}}}}}`,
		"POST /api/firewall/source_nat/set": `{"result":"saved"}`,
	})
	if err := api.OneToOne().Apply(); err != nil {
		t.Fatal(err)
	}
	if mode, err := api.SourceNatMode(); err != nil || mode != SourceNatModeManual {
		t.Errorf("mode %q, %v", mode, err)
	}
	if err := api.SourceNatSetMode(SourceNatModeHybrid); err != nil {
		t.Fatal(err)
	}
	if err := api.SourceNatSetMode("manual"); err == nil {
		t.Error("want an error for the unknown mode manual (the API calls it advanced)")
	}
	var mutations = natTestMutations(calls())
	if len(mutations) != 2 || mutations[1].Body != `{"filter":{"general":{"snat_mode":"hybrid"}}}` {
		t.Errorf("mutations %+v", mutations)
	}

	var failing, _ = natTestApi(t, map[string]string{"POST /api/firewall/npt/apply": `{"status":"Execute error"}`})
	if err := failing.Npt().Apply(); err == nil || !strings.Contains(err.Error(), "Execute error") {
		t.Errorf("want the status in the error, got %v", err)
	}
}
