package cli

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

const (
	idsSettingsGetPath  = "/api/ids/settings/get"
	idsSettingsSetPath  = "/api/ids/settings/set"
	idsRulesetsPath     = "/api/ids/settings/list_rulesets"
	idsRuleSearchPath   = "/api/ids/settings/search_installed_rules"
	idsPolicySearchPath = "/api/ids/settings/search_policy"
	idsAlertQueryPath   = "/api/ids/service/query_alerts"
	idsTestPolicyUuid   = "8dec2583-63f1-4f49-b6bb-dad60dc16dff"
)

const idsTestSettings = `{"ids":{"general":{"enabled":"0","mode":{"pcap":{"value":"PCAP live mode (IDS)","selected":1},` +
	`"netmap":{"value":"Netmap (IPS)","selected":0},"divert":{"value":"Divert (IPS)","selected":0}},` +
	`"interfaces":{"lan":{"value":"LAN","selected":0},"wan":{"value":"WAN","selected":1}},` +
	`"homenet":{"10.0.0.0\/8":{"value":"10.0.0.0\/8","selected":1}},"AlertLogrotate":{"W0D23":{"value":"Weekly","selected":0},"D0":{"value":"Daily","selected":1}},` +
	`"verbosity":{"":{"value":"DEFAULT (0)","selected":0},"vv":{"value":"PERF (2)","selected":1}},` +
	`"detect":{"Profile":{"":{"value":"Default","selected":1},"low":{"value":"Low","selected":0}}},` +
	`"eveLog":{"tls":{"enable":"1","custom":{"sni":{"value":"sni","selected":1},"ja3":{"value":"ja3","selected":1}}}}}}}`

// idsWantNoChanges is wantNoMutations for the IDS menus, whose rule and alert searches are POSTed
func idsWantNoChanges(t *testing.T, f *fakeOPN) {
	t.Helper()
	for _, call := range f.mutations() {
		if call.Path != idsRuleSearchPath && call.Path != idsAlertQueryPath {
			t.Errorf("want no changing API calls, got %v", call)
		}
	}
}

func idsFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", idsSettingsGetPath, 200, idsTestSettings)
	f.on("POST", idsSettingsSetPath, 200, answerSaved)
	return f
}

func TestIdsSettings(t *testing.T) {
	t.Parallel()
	var f = idsFake(t)
	var r = f.run("/ids/settings", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "mode:", "pcap", "interfaces:", "wan", "home-networks:", "10.0.0.0/8",
		"alert-log-rotate:", "daily", "verbosity:", "perf", "detect-profile:", "default", "eve-tls:", "yes", "eve-tls-custom:", "sni,ja3")

	var options = f.run("/ids/settings", "print", "options=interfaces")
	wantExit(t, options, 0)
	wantContains(t, "stdout", options.stdout, "KEY", "lan", "LAN", "wan")

	wantExit(t, f.run("/ids/settings", "set", "enabled", "mode=netmap", "interfaces=LAN,wan", "alert-log-rotate=weekly",
		"verbosity=default", "home-networks=", "eve-tls-custom=SNI"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", idsSettingsSetPath), map[string]any{"ids": map[string]any{"general": map[string]any{
		"enabled": "1", "mode": "netmap", "interfaces": "lan,wan", "AlertLogrotate": "W0D23", "verbosity": "", "homenet": "",
		"eveLog": map[string]any{"tls": map[string]any{"custom": "sni"}},
	}}})

	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		var f = idsFake(t)
		wantFailure(t, f.run("/ids/settings", "set", "interfaces=opt9"), "unknown value", "lan, wan")
		wantFailure(t, f.run("/ids/settings", "set", "mode=inline"), "must be one of")
		wantFailure(t, f.run("/ids/settings", "set", "mode=pcap,netmap"), "must be one of")
		wantFailure(t, f.run("/ids/settings", "set", "alert-log-keep=0"), "1 to 1000")
		wantFailure(t, f.run("/ids/settings", "set"), "nothing to change")
		wantNoMutations(t, f)
	})
}

func TestIdsService(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/ids/service/status", 200, `{"status":"stopped"}`)
	f.on("POST", "/api/ids/service/start", 200, `{"response":"OK"}`)
	f.on("POST", "/api/ids/service/reload_rules", 200, `{"status":"OK\n\n"}`)
	var r = f.run("/ids/service", "status")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "status:", "stopped")

	for _, command := range []string{"start", "restart", "reconfigure"} {
		wantFailure(t, f.run("/ids/service", command), "IPS mode", "confirm=yes")
	}
	wantNoMutations(t, f)
	wantExit(t, f.run("/ids/service", "start", "confirm=yes"), 0)
	wantOneMutation(t, f, "POST", "/api/ids/service/start")

	var reload = newFakeOPN(t)
	reload.on("POST", "/api/ids/service/reload_rules", 200, `{"status":"Error (1)\n\n"}`)
	wantFailure(t, reload.run("/ids/service", "reload-rules"), "Error (1)")
}

func idsRulesetFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(idsRulesetsPath,
		map[string]any{"description": "abuse.ch/Feodo Tracker", "filename": "abuse.ch.feodotracker.rules", "modified_local": "2026/10/25 15:38", "enabled": "1"},
		map[string]any{"description": "ET open/botcc", "filename": "botcc.rules", "modified_local": nil, "enabled": "0"},
		map[string]any{"description": "ET open/ciarmy", "filename": "ciarmy.rules", "modified_local": nil, "enabled": "0"},
	)
	return f
}

func TestIdsRuleset(t *testing.T) {
	t.Parallel()
	var f = idsRulesetFake(t)
	var r = f.run("/ids/ruleset", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "DISABLED", "FILENAME", "DOWNLOADED", "0  no        abuse.ch.feodotracker.rules", "2026/10/25 15:38", "botcc.rules")
	var enabled = f.run("/ids/ruleset", "print", "enabled")
	if strings.Contains(enabled.stdout, "botcc") || !strings.Contains(enabled.stdout, "feodotracker") {
		t.Errorf("print enabled:\n%s", enabled)
	}

	f.on("POST", "/api/ids/settings/toggle_ruleset/botcc.rules,ciarmy.rules/1", 200, `{"status":"1"}`)
	var enable = f.run("/ids/ruleset", "enable", "1,ET open/ciarmy,abuse.ch.feodotracker.rules")
	wantExit(t, enable, 0)
	wantContains(t, "stderr", enable.stderr, "already enabled")
	wantOneMutation(t, f, "POST", "/api/ids/settings/toggle_ruleset/botcc.rules,ciarmy.rules/1")

	var unknown = idsRulesetFake(t)
	wantFailure(t, unknown.run("/ids/ruleset", "disable", "abuse.ch.feodotracker.rules,nope.rules"), "not found")
	wantNoMutations(t, unknown)

	var update = newFakeOPN(t)
	update.on("POST", "/api/ids/service/update_rules", 200, `{"status":"OK\n\n"}`)
	update.on("POST", "/api/ids/service/update_rules/1", 200, `{"status":"2b91ffd6\n"}`)
	wantExit(t, update.run("/ids/ruleset", "update"), 0)
	var background = update.run("/ids/ruleset", "update", "background")
	wantExit(t, background, 0)
	wantContains(t, "stderr", background.stderr, "2b91ffd6")

	var properties = newFakeOPN(t)
	properties.on("GET", "/api/ids/settings/get_rulesetproperties", 200, `{"properties":{"et_pro.code":"secret123","x.y":""}}`)
	properties.on("POST", "/api/ids/settings/set_rulesetproperties", 200, answerSaved)
	var printed = properties.run("/ids/ruleset/property", "print")
	wantExit(t, printed, 0)
	wantContains(t, "stdout", printed.stdout, "et_pro.code:", "(set)")
	wantNotContains(t, "stdout", printed.stdout, "secret123")
	wantFailure(t, properties.run("/ids/ruleset/property", "set", "name=bogus", "value=1"), "unknown rule set property")
	wantNoMutations(t, properties)
	wantExit(t, properties.run("/ids/ruleset/property", "set", "name=x.y", "value=abc"), 0)
	wantJSON(t, wantOneMutation(t, properties, "POST", "/api/ids/settings/set_rulesetproperties"),
		map[string]any{"properties": map[string]any{"x.y": "abc"}})
}

const idsTestRule = `{"sid":900509159,"rev":1,"gid":null,"msg":"Feodo Tracker: potential Emotet CnC","reference":"url, x",` +
	`"source":"abuse.ch.feodotracker.rules","enabled":1,"action":"alert","status":"enabled","enabled_default":1,` +
	`"action_default":"alert","matched_policy":null,"classtype":"trojan-activity"}`

func idsRuleFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("POST", idsRuleSearchPath, 200, `{"rows":[`+idsTestRule+`],"rowCount":1,"total":250,"current":2}`)
	f.on("GET", "/api/ids/settings/get_rule_info/900509159", 200, `{"action":{"alert":{"value":"Alert","selected":1},`+
		`"drop":{"value":"Drop","selected":0}},"enabled":1,"sid":900509159,"msg":"Feodo Tracker","source":"abuse.ch.feodotracker.rules",`+
		`"signature_severity":"Major"}`)
	f.on("GET", "/api/ids/settings/get_rule_info/1", 200, `[]`)
	return f
}

func TestIdsRule(t *testing.T) {
	t.Parallel()
	var f = idsRuleFake(t)
	var r = f.run("/ids/rule", "print", "search=emotet", "classtype=trojan-activity", "disabled=no", "action=drop",
		"metadata=signature_severity:Major", "limit=1", "page=2")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "SID", "900509159", "trojan-activity", "Feodo Tracker")
	wantNotContains(t, "stdout", r.stdout, "#")
	wantContains(t, "stderr", r.stderr, "rules 2-2 of 250, page=3")
	var search = f.calls()[0].json(t)
	for key, want := range map[string]any{"searchPhrase": "emotet", "classtype": "trojan-activity", "status": "enabled", "action": "drop",
		"signature_severity": "Major", "rowCount": 1.0, "current": 2.0} {
		if search[key] != want {
			t.Errorf("search %s = %v, want %v (%v)", key, search[key], want, search)
		}
	}

	var shown = f.run("/ids/rule", "show", "900509159")
	wantExit(t, shown, 0)
	wantContains(t, "stdout", shown.stdout, "sid:", "900509159", "action:", "alert", "signature_severity:", "Major")
	wantFailure(t, f.run("/ids/rule", "show", "1"), "not found")
	idsWantNoChanges(t, f)

	t.Run("changes", func(t *testing.T) {
		t.Parallel()
		var f = idsRuleFake(t)
		f.on("POST", "/api/ids/settings/set_rule/900509159", 200, answerSaved)
		f.on("POST", "/api/ids/settings/toggle_rule/900509159/0", 200, answerSaved)
		wantExit(t, f.run("/ids/rule", "set", "900509159", "action=drop", "disabled=no"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", "/api/ids/settings/set_rule/900509159"), map[string]any{"action": "drop", "enabled": "1"})

		var g = idsRuleFake(t)
		g.on("POST", "/api/ids/settings/toggle_rule/900509159/0", 200, answerSaved)
		wantExit(t, g.run("/ids/rule", "disable", "900509159"), 0)
		wantOneMutation(t, g, "POST", "/api/ids/settings/toggle_rule/900509159/0")
		var h = idsRuleFake(t)
		h.on("POST", "/api/ids/settings/toggle_rule/900509159/0", 200, answerSaved)
		wantExit(t, h.run("/ids/rule", "set", "900509159", "disabled"), 0)
		wantOneMutation(t, h, "POST", "/api/ids/settings/toggle_rule/900509159/0")
	})

	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		var f = idsRuleFake(t)
		wantFailure(t, f.run("/ids/rule", "set", "900509159"), "nothing to change")
		wantFailure(t, f.run("/ids/rule", "set", "900509159", "action=pass"), "must be one of")
		wantFailure(t, f.run("/ids/rule", "enable", "12a"), "must be a sid")
		wantFailure(t, f.run("/ids/rule", "print", "limit=0"), "1 to 10000")
		wantFailure(t, f.run("/ids/rule", "print", `search=a"b`), "quotes")
		wantFailure(t, f.run("/ids/rule", "print", "metadata=nocolon"), "name:value")
		wantFailure(t, f.run("/ids/rule", "enable", "900509159,1"), "not found")
		idsWantNoChanges(t, f)
	})

	t.Run("reset and adjustments", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.search("/api/ids/settings/search_policy_rule", map[string]any{"uuid": "u1", "sid": "900509159", "enabled": "0", "action": "drop",
			"msg": "Feodo", "source": "abuse.ch.feodotracker.rules"})
		f.on("POST", "/api/ids/settings/del_policy_rule/u1", 200, answerDeleted)
		var printed = f.run("/ids/policy/adjustment", "print")
		wantExit(t, printed, 0)
		wantContains(t, "stdout", printed.stdout, "0  900509159  yes       drop")
		wantFailure(t, f.run("/ids/rule", "reset", "42"), "not found")
		wantNoMutations(t, f)
		wantExit(t, f.run("/ids/rule", "reset", "900509159"), 0)
		wantOneMutation(t, f, "POST", "/api/ids/settings/del_policy_rule/u1")
	})
}

func idsPolicyFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(idsPolicySearchPath, map[string]any{"uuid": idsTestPolicyUuid, "enabled": "1", "prio": "5", "action": "alert",
		"rulesets": "e8a2", "%rulesets": "abuse.ch.feodotracker.rules", "content": "classtype.trojan-activity", "new_action": "drop",
		"description": "drop trojans"})
	f.on("GET", "/api/ids/settings/get_policy", 200, `{"policy":{"rulesets":{"e8a2":{"value":"abuse.ch.feodotracker.rules","selected":0}},`+
		`"content":{"classtype.trojan-activity":{"value":"trojan-activity","selected":0}}}}`)
	f.on("POST", "/api/ids/settings/add_policy", 200, answerAdded("p-new"))
	f.on("POST", "/api/ids/settings/set_policy/"+idsTestPolicyUuid, 200, answerSaved)
	f.on("POST", "/api/ids/settings/del_policy/"+idsTestPolicyUuid, 200, answerDeleted)
	return f
}

func TestIdsPolicy(t *testing.T) {
	t.Parallel()
	var f = idsPolicyFake(t)
	var r = f.run("/ids/policy", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "drop trojans", "abuse.ch.feodotracker.rules", "classtype:trojan-activity")

	var added = f.run("/ids/policy", "add", "description=new one", "rulesets=abuse.ch.feodotracker.rules",
		"metadata=classtype:trojan-activity", "match-action=alert,drop", "disabled")
	wantExit(t, added, 0)
	if added.stdout != "p-new\n" {
		t.Errorf("add must print the uuid: %q", added.stdout)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/ids/settings/add_policy"), map[string]any{"policy": map[string]any{
		"description": "new one", "enabled": "0", "prio": "0", "rulesets": "e8a2", "content": "classtype.trojan-activity",
		"action": "alert,drop", "new_action": "alert"}})

	t.Run("set, disable, remove", func(t *testing.T) {
		t.Parallel()
		var f = idsPolicyFake(t)
		wantExit(t, f.run("/ids/policy", "set", "drop trojans", "priority=9", "rulesets="), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", "/api/ids/settings/set_policy/"+idsTestPolicyUuid),
			map[string]any{"policy": map[string]any{"prio": "9", "rulesets": ""}})
		var g = idsPolicyFake(t)
		var enable = g.run("/ids/policy", "enable", "0")
		wantExit(t, enable, 0)
		wantContains(t, "stderr", enable.stderr, "already enabled")
		wantNoMutations(t, g)
		wantExit(t, g.run("/ids/policy", "disable", "0"), 0)
		wantJSON(t, wantOneMutation(t, g, "POST", "/api/ids/settings/set_policy/"+idsTestPolicyUuid),
			map[string]any{"policy": map[string]any{"enabled": "0"}})
		var h = idsPolicyFake(t)
		wantExit(t, h.run("/ids/policy", "remove", "drop trojans"), 0)
		wantOneMutation(t, h, "POST", "/api/ids/settings/del_policy/"+idsTestPolicyUuid)
	})

	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		var f = idsPolicyFake(t)
		wantFailure(t, f.run("/ids/policy", "add", "description=drop trojans"), "exists already")
		wantFailure(t, f.run("/ids/policy", "add", "description=x", "rulesets=nope.rules"), "unknown enabled rule set", "abuse.ch.feodotracker.rules")
		wantFailure(t, f.run("/ids/policy", "add", "description=x", "metadata=classtype:nope"), "unknown metadata value")
		wantFailure(t, f.run("/ids/policy", "add", "description=x", "new-action=pass"), "must be one of")
		wantFailure(t, f.run("/ids/policy", "set", "drop trojans"), "nothing to change")
		wantFailure(t, f.run("/ids/policy", "set", "nope", "priority=1"), "not found")
		wantNoMutations(t, f)
	})
}

func TestIdsUserRule(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search("/api/ids/settings/search_user_rule")
	f.on("POST", "/api/ids/settings/add_user_rule", 200, answerAdded("u-new"))
	wantExit(t, f.run("/ids/user-rule", "add", "description=block test", "source=192.0.2.0/24", "action=drop", "disabled"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/ids/settings/add_user_rule"), map[string]any{"rule": map[string]any{
		"description": "block test", "enabled": "0", "source": "192.0.2.0/24", "destination": "", "fingerprint": "",
		"action": "drop", "bypass": "0"}})

	var refused = newFakeOPN(t)
	wantFailure(t, refused.run("/ids/user-rule", "add", "source=192.0.2.0/24"), "description=<string> is required")
	wantFailure(t, refused.run("/ids/user-rule", "add", "description=x", "source=nonsense"), "IP address or a network")
	wantFailure(t, refused.run("/ids/user-rule", "add", "description=x", "fingerprint=zz"), "59 characters")
	wantNoCalls(t, refused)
}

const idsTestAlert = `{"timestamp":"2026-10-25T15:38:01.1+0000","in_iface":"vtnet1","src_ip":"192.0.2.1","src_port":5555,` +
	`"dest_ip":"2001:db8::1","dest_port":80,"proto":"TCP","alert":"ET SCAN probe","alert_sid":2010935,"alert_action":"allowed",` +
	`"filepos":%d,"fileid":""}`

func idsAlertRows(positions ...int) string {
	var rows []string
	for _, position := range positions {
		rows = append(rows, strings.Replace(idsTestAlert, "%d", strconv.Itoa(position), 1))
	}
	return `{"rows":[` + strings.Join(rows, ",") + `],"total":` + strconv.Itoa(len(positions)) + `,"origin":"eve.json"}`
}

func TestIdsAlert(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", idsAlertQueryPath, 200, idsAlertRows(2500, 1250))
	f.on("GET", "/api/ids/service/get_alert_info/1250", 200, strings.Replace(idsTestAlert, "%d", "1250", 1))
	var r = f.runScript("/ids/alert print\n/ids/alert show 1\n")
	wantExit(t, r, 0)
	wantContains(t, r.stdout, r.stdout, "TIME", "allowed", "2010935", "192.0.2.1:5555", "[2001:db8::1]:80", "vtnet1", "ET SCAN probe",
		"alert_sid:", "filepos:", "1250")

	var shown = f.run("/ids/alert", "show", "position=1250", "json")
	wantExit(t, shown, 0)
	wantContains(t, "stdout", shown.stdout, `"filepos":1250`)
	wantFailure(t, f.run("/ids/alert", "show"), "either")
	wantFailure(t, f.run("/ids/alert", "print", "follow", "log=1"), "current log")
	idsWantNoChanges(t, f)

	var logs = newFakeOPN(t)
	logs.on("GET", "/api/ids/service/get_alert_logs", 200, `[{"size":10,"modified":"2026/10/25 15:38","filename":"eve.json","sequence":null},`+
		`{"size":5,"modified":"2026/10/18 1:00","filename":"eve.json.1","sequence":1}]`)
	logs.on("POST", "/api/ids/service/drop_alert_log", 200, `{"status":"ok"}`)
	var printed = logs.run("/ids/alert/log", "print")
	wantExit(t, printed, 0)
	wantContains(t, "stdout", printed.stdout, "eve.json.1", "2026/10/18 1:00")
	wantFailure(t, logs.run("/ids/alert/log", "remove", "eve.json.1"), "confirm=yes")
	wantNoMutations(t, logs)
	wantExit(t, logs.run("/ids/alert/log", "remove", "eve.json.1", "confirm=yes"), 0)
	wantJSON(t, wantOneMutation(t, logs, "POST", "/api/ids/service/drop_alert_log"), map[string]any{"filename": "eve.json.1"})
}

func TestIdsAlertFollow(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var answers = []string{idsAlertRows(1250), idsAlertRows(3750, 2500, 1250)}
	var polls = 0
	f.onFunc("POST", idsAlertQueryPath, func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		var answer = answers[min(polls, len(answers)-1)]
		polls++
		f.mu.Unlock()
		_, _ = io.WriteString(w, answer)
	})
	var p = f.start("/ids/alert", "print", "follow", "interval=0.1")
	p.waitFor("2026-10-25T15:38:01.1+0000 allowed 2010935 TCP 192.0.2.1:5555 -> [2001:db8::1]:80 vtnet1 ET SCAN probe")
	p.waitFor("\n", "ET SCAN probe\n2026")
	var r = p.interrupt()
	wantExit(t, r, 0)
	if got := strings.Count(r.stdout, "ET SCAN probe"); got != 3 {
		t.Errorf("want each alert once (3), got %d:\n%s", got, r.stdout)
	}
}
