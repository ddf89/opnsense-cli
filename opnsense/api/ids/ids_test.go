package ids

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

type testRequest struct {
	Method string
	Path   string
	Body   map[string]any
}

// newTestApi answers every request with handler, keyed by "METHOD /path" ("" for unknown paths: an empty 200)
func newTestApi(t *testing.T, answers map[string]string) (*IdsApi, *[]testRequest) {
	t.Helper()
	var requests []testRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var recorded = testRequest{Method: r.Method, Path: r.URL.Path}
		var raw, _ = io.ReadAll(r.Body)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &recorded.Body); err != nil {
				t.Errorf("invalid request body %q: %v", raw, err)
			}
		}
		requests = append(requests, recorded)
		_, _ = io.WriteString(w, answers[r.Method+" "+r.URL.Path])
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &IdsApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, &requests
}

func mutations(requests []testRequest) []testRequest {
	var result []testRequest
	for _, request := range requests {
		if request.Method != "GET" {
			result = append(result, request)
		}
	}
	return result
}

const testSettings = `{"ids":{"general":{"enabled":"0","mode":{"pcap":{"value":"PCAP live mode (IDS)","selected":1},` +
	`"netmap":{"value":"Netmap (IPS)","selected":0}},"interfaces":{"lan":{"value":"LAN","selected":1},"wan":{"value":"WAN","selected":1}},` +
	`"homenet":{"10.0.0.0\/8":{"value":"10.0.0.0\/8","selected":1}},"defaultPacketSize":"","AlertSaveLogs":"4",` +
	`"MPMAlgo":{"":{"value":"Default","selected":1},"hs":{"value":"Hyperscan","selected":0}},` +
	`"detect":{"Profile":{"":{"value":"Default","selected":0},"low":{"value":"Low","selected":1}},"toclient_groups":""},` +
	`"eveLog":{"tls":{"enable":"1","custom":{"subject":{"value":"subject","selected":1},"sni":{"value":"sni","selected":1}}}},` +
	`"UpdateCron":{"":{"value":"None","selected":1}},"empty":[]}}}`

func TestSettings(t *testing.T) {
	var api, requests = newTestApi(t, map[string]string{
		"GET /api/ids/settings/get":  testSettings,
		"POST /api/ids/settings/set": `{"result":"saved"}`,
	})
	var settings, err = api.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"enabled": "0", "mode": "pcap", "interfaces": "lan,wan", "homenet": "10.0.0.0/8", "MPMAlgo": "",
		"detect.Profile": "low", "detect.toclient_groups": "", "eveLog.tls.enable": "1", "eveLog.tls.custom": "subject,sni",
		"UpdateCron": "", "AlertSaveLogs": "4", "empty": "",
	} {
		if got := settings[path].Value; got != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}
	if options := settings["mode"].Options; len(options) != 2 || options[0] != (SettingsOption{Key: "pcap", Display: "PCAP live mode (IDS)", Selected: true}) {
		t.Errorf("mode options in API order: %+v", options)
	}
	if !settings["empty"].IsOption() || settings["enabled"].IsOption() {
		t.Errorf("IsOption: empty %v enabled %v", settings["empty"].IsOption(), settings["enabled"].IsOption())
	}

	if err := api.SettingsSet(map[string]string{"detect.Profile": "high", "enabled": "1"}); err != nil {
		t.Fatal(err)
	}
	var want = map[string]any{"ids": map[string]any{"general": map[string]any{"enabled": "1", "detect": map[string]any{"Profile": "high"}}}}
	if got := (*requests)[1].Body; !reflect.DeepEqual(got, want) {
		t.Errorf("set body %v, want %v", got, want)
	}
	if err := api.SettingsSet(nil); err == nil {
		t.Error("an empty set must fail")
	}
}

const testRulesets = `{"total":2,"rowCount":2,"current":1,"rows":[` +
	`{"description":"abuse.ch\/Feodo Tracker","filename":"abuse.ch.feodotracker.rules","documentation_url":"https:\/\/x","modified_local":"2026\/10\/25 15:38","enabled":"1"},` +
	`{"description":"ET open\/botcc","filename":"botcc.rules","documentation_url":"","modified_local":null,"enabled":"0"}]}`

func TestRulesets(t *testing.T) {
	var api, requests = newTestApi(t, map[string]string{
		"GET /api/ids/settings/list_rulesets":                     testRulesets,
		"POST /api/ids/settings/toggle_ruleset/botcc.rules/1":     `{"status":"1"}`,
		"POST /api/ids/settings/toggle_ruleset/a.rules,b.rules/0": `{"status":"error"}`,
		"GET /api/ids/settings/get_rulesetproperties":             `{"properties":{"et.code":"x"}}`,
		"POST /api/ids/settings/set_rulesetproperties":            `{"result":"saved","fields":["et.code"]}`,
		"POST /api/ids/service/update_rules":                      `{"status":"OK\n\n"}`,
		"POST /api/ids/service/update_rules/1":                    `{"status":"2b91ffd6-a7e9\n"}`,
	})
	var rulesets, err = api.RulesetSearch("")
	if err != nil {
		t.Fatal(err)
	}
	var want = []Ruleset{
		{Filename: "abuse.ch.feodotracker.rules", Description: "abuse.ch/Feodo Tracker", DocumentationUrl: "https://x", ModifiedLocal: "2026/10/25 15:38", Enabled: true},
		{Filename: "botcc.rules", Description: "ET open/botcc"},
	}
	if !reflect.DeepEqual(rulesets, want) {
		t.Errorf("got %+v", rulesets)
	}
	if err := api.RulesetSetEnabled([]string{"botcc.rules"}, true); err != nil {
		t.Errorf("enable: %v", err)
	}
	// unknown names are refused before anything is sent
	if err := api.RulesetSetEnabled([]string{"botcc.rules", "nope.rules"}, false); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if got := mutations(*requests); len(got) != 1 {
		t.Errorf("want one toggle, got %+v", got)
	}

	if err := api.RulesetPropertiesSet(map[string]string{"bogus": "1"}); err == nil || !strings.Contains(err.Error(), "et.code") {
		t.Errorf("unknown property: %v", err)
	}
	if err := api.RulesetPropertiesSet(map[string]string{"et.code": "1"}); err != nil {
		t.Errorf("set property: %v", err)
	}
	if status, err := api.RulesUpdate(context.Background(), false); err != nil || status != "OK" {
		t.Errorf("update: %q %v", status, err)
	}
	if status, err := api.RulesUpdate(context.Background(), true); err != nil || status != "2b91ffd6-a7e9" {
		t.Errorf("background update: %q %v", status, err)
	}
}

const testRuleRow = `{"sid":900509159,"rev":1,"gid":null,"msg":"Feodo Tracker: Emotet","reference":"url, x","source":"abuse.ch.feodotracker.rules",` +
	`"enabled":"0","action":"Drop","status":"enabled","enabled_default":1,"action_default":"alert","matched_policy":"__manual__","classtype":"trojan-activity"}`

func TestRules(t *testing.T) {
	var api, requests = newTestApi(t, map[string]string{
		"POST /api/ids/settings/search_installed_rules": `{"rows":[` + testRuleRow + `],"rowCount":1,"total":5,"current":2}`,
		"GET /api/ids/settings/get_rule_info/900509159": `{"action":{"alert":{"value":"Alert","selected":0},"drop":{"value":"Drop","selected":1}},` +
			`"enabled":"1","sid":900509159,"msg":"m","signature_severity":"Major","reference_html":"<a>"}`,
		"GET /api/ids/settings/get_rule_info/1":          `[]`,
		"POST /api/ids/settings/toggle_rule/900509159/0": `{"result":"saved"}`,
		"POST /api/ids/settings/set_rule/900509159":      `{"result":"saved"}`,
		"GET /api/ids/settings/search_policy_rule":       `{"rows":[{"uuid":"u1","sid":"900509159","enabled":"0","action":"alert"}]}`,
		"POST /api/ids/settings/del_policy_rule/u1":      `{"result":"deleted"}`,
		"GET /api/ids/settings/list_rule_metadata":       `{"classtype":["b","a"],"matched_policy":["__manual__"]}`,
		"GET /api/ids/settings/get_rule_info/900509160":  `[]`,
	})
	var page, err = api.RuleSearch(RuleQuery{Search: "emotet", Filters: map[string]string{"classtype": "trojan-activity"}, Limit: 10, Page: 2})
	if err != nil {
		t.Fatal(err)
	}
	var want = Rule{Sid: 900509159, Rev: "1", Msg: "Feodo Tracker: Emotet", Reference: "url, x", Source: "abuse.ch.feodotracker.rules",
		Action: "drop", EnabledDefault: true, ActionDefault: "alert", MatchedPolicy: "__manual__", Classtype: "trojan-activity", Metadata: map[string]string{}}
	if page.Total != 5 || len(page.Rules) != 1 || !reflect.DeepEqual(page.Rules[0], want) {
		t.Errorf("got %+v", page)
	}
	var wantBody = map[string]any{"current": 2.0, "rowCount": 10.0, "searchPhrase": "emotet", "classtype": "trojan-activity"}
	if got := (*requests)[0].Body; !reflect.DeepEqual(got, wantBody) {
		t.Errorf("search body %v", got)
	}
	for _, query := range []RuleQuery{{Limit: 0}, {Limit: 1, Search: `a"b`}, {Limit: 1, Filters: map[string]string{"rowCount": "0"}}} {
		if _, err := api.RuleSearch(query); err == nil {
			t.Errorf("query %+v must be refused", query)
		}
	}

	var rule, _, getErr = api.RuleGet(900509159)
	if getErr != nil || rule.Action != "drop" || !rule.Enabled || rule.Metadata["signature_severity"] != "Major" || rule.Metadata["reference_html"] != "" {
		t.Errorf("RuleGet: %+v %v", rule, getErr)
	}
	if _, _, err := api.RuleGet(1); !coreapi.IsNotFound(err) {
		t.Errorf("unknown sid: %v", err)
	}

	*requests = nil
	if err := api.RuleSetEnabled([]int64{900509159}, false); err != nil {
		t.Errorf("disable: %v", err)
	}
	if err := api.RuleSetAction(900509159, "pass", nil); err == nil {
		t.Error("invalid action must be refused")
	}
	var enabled = true
	if err := api.RuleSetAction(900509159, "drop", &enabled); err != nil {
		t.Errorf("set action: %v", err)
	}
	if err := api.RuleSetEnabled([]int64{900509159, 900509160}, true); !coreapi.IsNotFound(err) {
		t.Errorf("unknown sid in list: %v", err)
	}
	var got = mutations(*requests)
	if len(got) != 2 || got[1].Path != "/api/ids/settings/set_rule/900509159" ||
		!reflect.DeepEqual(got[1].Body, map[string]any{"action": "drop", "enabled": "1"}) {
		t.Errorf("mutations %+v", got)
	}

	*requests = nil
	if err := api.RuleReset([]int64{1}); !coreapi.IsNotFound(err) {
		t.Errorf("reset without adjustment: %v", err)
	}
	if err := api.RuleReset([]int64{900509159}); err != nil {
		t.Errorf("reset: %v", err)
	}
	if got := mutations(*requests); len(got) != 1 || got[0].Path != "/api/ids/settings/del_policy_rule/u1" {
		t.Errorf("reset mutations %+v", got)
	}
	if metadata, err := api.RuleMetadata(); err != nil || !reflect.DeepEqual(metadata["classtype"], []string{"a", "b"}) {
		t.Errorf("metadata %v %v", metadata, err)
	}
}

func TestPolicyAndUserRule(t *testing.T) {
	const uuid = "8dec2583-63f1-4f49-b6bb-dad60dc16dff"
	var api, requests = newTestApi(t, map[string]string{
		"GET /api/ids/settings/search_policy": `{"rows":[{"uuid":"` + uuid + `","enabled":"0","prio":"5","action":"alert,drop",` +
			`"rulesets":"e8a2","%rulesets":"a.rules","content":"classtype.x","new_action":"drop","description":"p"}]}`,
		"POST /api/ids/settings/add_policy":            `{"result":"saved","uuid":"new"}`,
		"POST /api/ids/settings/set_policy/" + uuid:    `{"result":"saved"}`,
		"POST /api/ids/settings/del_policy/" + uuid:    `{"result":"not found"}`,
		"GET /api/ids/settings/get_policy":             `{"policy":{"enabled":"1","rulesets":{"e8a2":{"value":"a.rules","selected":0}},"content":[]}}`,
		"GET /api/ids/settings/search_user_rule":       `{"rows":[]}`,
		"POST /api/ids/settings/add_user_rule":         `{"result":"failed","validations":{"rule.description":"A value is required."}}`,
		"POST /api/ids/settings/set_user_rule/" + uuid: `{"result":"saved"}`,
	})
	var policies, _, err = api.PolicySearch("")
	if err != nil || len(policies) != 1 || policies[0].RulesetNames != "a.rules" || policies[0].NewAction != "drop" {
		t.Fatalf("search: %+v %v", policies, err)
	}
	var prio, empty = "7", ""
	if uuid, err := api.PolicyCreate(PolicyFields{Prio: &prio, Content: &empty}); err != nil || uuid != "new" {
		t.Errorf("create: %q %v", uuid, err)
	}
	if err := api.PolicyUpdate(uuid, PolicyFields{Prio: &prio}); err != nil {
		t.Errorf("update: %v", err)
	}
	if err := api.PolicyUpdate("00000000-0000-4000-8000-000000000000", PolicyFields{Prio: &prio}); !coreapi.IsNotFound(err) {
		t.Errorf("update of an unknown uuid must not be sent: %v", err)
	}
	if err := api.PolicyRemove(uuid); !coreapi.IsNotFound(err) {
		t.Errorf("remove: %v", err)
	}
	var got = mutations(*requests)
	if len(got) != 3 || !reflect.DeepEqual(got[0].Body, map[string]any{"policy": map[string]any{"prio": "7", "content": ""}}) ||
		!reflect.DeepEqual(got[1].Body, map[string]any{"policy": map[string]any{"prio": "7"}}) {
		t.Errorf("mutations %+v", got)
	}
	if options, err := api.PolicyOptions(); err != nil || options["rulesets"][0].Display != "a.rules" || options["content"] == nil {
		t.Errorf("options %+v %v", options, err)
	}

	var description = ""
	var validationErr *coreapi.ValidationError
	if _, err := api.UserRuleCreate(UserRuleFields{Description: &description}); !errors.As(err, &validationErr) {
		t.Errorf("want a validation error, got %v", err)
	}
	if err := api.UserRuleUpdate(uuid, UserRuleFields{Description: &description}); !coreapi.IsNotFound(err) {
		t.Errorf("unknown user rule: %v", err)
	}
}

func TestAlerts(t *testing.T) {
	const alert = `{"timestamp":"2026-10-25T15:38:01.1+0000","in_iface":"vtnet1 ","src_ip":"192.0.2.1","src_port":5555,` +
		`"dest_ip":"2001:db8::1","dest_port":80,"proto":"TCP","alert":"ET SCAN x","alert_sid":2010935,"alert_action":"allowed",` +
		`"filepos":1250,"fileid":""}`
	var api, requests = newTestApi(t, map[string]string{
		"POST /api/ids/service/query_alerts":         `{"filters":[],"rows":[` + alert + `],"origin":"eve.json","rowCount":1,"total":3,"current":1}`,
		"GET /api/ids/service/get_alert_info/12":     alert,
		"GET /api/ids/service/get_alert_info/1250/2": alert,
		"GET /api/ids/service/get_alert_logs": `[{"size":10,"modified":"2026\/10\/25 15:38","filename":"eve.json","sequence":null},` +
			`{"size":5,"modified":"2026\/10\/18 1:00","filename":"eve.json.1","sequence":1}]`,
		"POST /api/ids/service/drop_alert_log": `{"status":"ok"}`,
	})
	var page, err = api.AlertSearch(AlertQuery{Search: "scan", LogId: "1", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	var got = page.Alerts[0]
	if page.Total != 3 || page.Origin != "eve.json" || got.Sid != 2010935 || got.FilePos != 1250 || got.SrcPort != "5555" ||
		got.InIface != "vtnet1" || got.Signature != "ET SCAN x" || got.Action != "allowed" {
		t.Errorf("got %+v", page)
	}
	if body := (*requests)[0].Body; !reflect.DeepEqual(body, map[string]any{"current": 1.0, "rowCount": 5.0, "searchPhrase": "scan", "fileid": "1"}) {
		t.Errorf("body %v", body)
	}
	// the position is matched as a prefix by OPNsense: another alert is not found
	if _, err := api.AlertGet(12, ""); !coreapi.IsNotFound(err) {
		t.Errorf("prefix match: %v", err)
	}
	if alert, err := api.AlertGet(1250, "2"); err != nil || alert.FilePos != 1250 {
		t.Errorf("AlertGet: %+v %v", alert, err)
	}
	var logs, logsErr = api.AlertLogs()
	if logsErr != nil || len(logs) != 2 || logs[0].Id() != "" || logs[1].Id() != "1" {
		t.Errorf("logs %+v %v", logs, logsErr)
	}
	*requests = nil
	if err := api.AlertLogRemove("eve.json.9"); !coreapi.IsNotFound(err) {
		t.Errorf("unknown log: %v", err)
	}
	if err := api.AlertLogRemove("eve.json.1"); err != nil {
		t.Errorf("remove: %v", err)
	}
	if got := mutations(*requests); len(got) != 1 || got[0].Body["filename"] != "eve.json.1" {
		t.Errorf("mutations %+v", got)
	}
}

func TestService(t *testing.T) {
	var api, requests = newTestApi(t, map[string]string{
		"GET /api/ids/service/status":        `{"status":"disabled","widget":{}}`,
		"POST /api/ids/service/start":        `{"response":"OK"}`,
		"POST /api/ids/service/reconfigure":  `{"status":"error installing ids rules (x)"}`,
		"POST /api/ids/service/reload_rules": `{"status":"Error (1)\n\n"}`,
	})
	if status, err := api.ServiceStatus(); err != nil || status != ServiceDisabled {
		t.Errorf("status %q %v", status, err)
	}
	if err := api.ServiceStart(); err != nil {
		t.Errorf("start: %v", err)
	}
	if err := api.ServiceReconfigure(); err == nil || !strings.Contains(err.Error(), "error installing ids rules") {
		t.Errorf("reconfigure: %v", err)
	}
	if err := api.ServiceReloadRules(); err == nil || !strings.Contains(err.Error(), "Error (1)") {
		t.Errorf("reload: %v", err)
	}
	if err := api.ServiceStop(); err == nil {
		t.Error("an empty answer must fail")
	}
	for _, request := range mutations(*requests) {
		if request.Method != "POST" {
			t.Errorf("actions must be POSTed: %+v", request)
		}
	}
}
