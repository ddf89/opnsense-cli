package firewall

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

type filterTestRequest struct {
	Method string
	Path   string
	Body   map[string]any
}

// filterTestAnswer is what the fake answers: Status 0 means 200, a string Body is sent as it is
type filterTestAnswer struct {
	Status int
	Body   any
}

func newFilterTestApi(t *testing.T, handler func(r filterTestRequest) filterTestAnswer) (*FirewallApi, *[]filterTestRequest) {
	t.Helper()
	var requests []filterTestRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var recorded = filterTestRequest{Method: r.Method, Path: r.URL.Path}
		var raw, _ = io.ReadAll(r.Body)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &recorded.Body); err != nil {
				t.Errorf("invalid request body %q: %v", raw, err)
			}
		}
		requests = append(requests, recorded)
		var answer = handler(recorded)
		if answer.Status != 0 {
			w.WriteHeader(answer.Status)
		}
		if text, isText := answer.Body.(string); isText {
			_, _ = io.WriteString(w, text)
			return
		}
		_ = json.NewEncoder(w).Encode(answer.Body)
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &FirewallApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, &requests
}

func filterOk(body any) filterTestAnswer {
	return filterTestAnswer{Body: body}
}

const (
	filterTestUuid  = "d621e174-154f-4ebb-9465-6e2fac4b2bcb"
	filterTestUuid2 = "10adf92d-0e07-4c4d-bd0e-76e0938214f2"
	filterTestAuto  = "02f4bab031b57d1e30553ce08e0ec131"
	// filterTestUnknown is a well-formed uuid no fake knows
	filterTestUnknown = "6c0e4b1c-9b1e-4f43-a0a5-5d3a0c2f7e11"
	filterBase        = "/api/firewall/filter/"
)

// filterTestAutoRow is an automatic rule as search_rule returns it in 26.7
const filterTestAutoRow = `{"log":true,"disablereplyto":1,"ipprotocol":"inet46","quick":false,"#priority":1,"enabled":"1",` +
	`"action":"block","replyto":"","description":"Default deny / state violation rule","source_net":"","source_port":"",` +
	`"destination_net":"","destination_port":"","ref":"","uuid":"02f4bab031b57d1e30553ce08e0ec131","direction":"in",` +
	`"%direction":"In","%action":"Block","%ipprotocol":"","protocol":"","%protocol":"","sort_order":"000001.1000001",` +
	`"legacy":true,"is_automatic":true,"category_colors":[]}`

// filterTestMvcRow is a user rule as search_rule returns it in 26.7 (trimmed)
const filterTestMvcRow = `{"uuid":"d621e174-154f-4ebb-9465-6e2fac4b2bcb","enabled":"1","statetype":"keep","sequence":"1",` +
	`"sort_order":"400000.0000001","prio_group":"400000","action":"pass","%action":"Pass","quick":"1","interfacenot":"0",` +
	`"interface":"lan","%interface":"LAN","direction":"in","ipprotocol":"inet","protocol":"any","source_net":"lan",` +
	`"source_not":"0","source_port":"","destination_net":"any","destination_not":"0","destination_port":"","log":"0",` +
	`"categories":"","description":"Default allow LAN to any rule","category_colors":[],` +
	`"alias_meta_source_net":[{"value":"lan","%value":"LAN network","isAlias":false,"description":""}]}`

func filterTestRows(rows ...string) any {
	return json.RawMessage(`{"total":` + "1" + `,"rowCount":1,"current":1,"rows":[` + strings.Join(rows, ",") + `]}`)
}

func TestFilterRuleSearchDecodes(t *testing.T) {
	var api, requests = newFilterTestApi(t, func(r filterTestRequest) filterTestAnswer {
		return filterOk(filterTestRows(filterTestAutoRow, filterTestMvcRow))
	})
	var rules, err = api.FilterRuleSearch(FilterRuleQuery{SearchPhrase: "default", Interfaces: []string{"lan", "wan"},
		Categories: []string{"c1"}, Statistics: true})
	if err != nil || len(rules) != 2 {
		t.Fatalf("want 2 rules, got %v / %v", rules, err)
	}
	var request = (*requests)[0]
	if request.Method != "POST" || request.Path != filterBase+"search_rule" || request.Body["searchPhrase"] != "default" ||
		request.Body["interface"] != "lan,wan" || request.Body["show_all"] != "1" || request.Body["rowCount"] != float64(-1) {
		t.Errorf("unexpected request %+v", request)
	}

	var auto, mvc = rules[0], rules[1]
	if !auto.IsAutomatic() || auto.Get("log") != "1" || auto.Quick() || auto.Get("disablereplyto") != "1" || auto.Uuid != filterTestAuto {
		t.Errorf("automatic rule not decoded right: %+v", auto)
	}
	if mvc.IsAutomatic() || !mvc.Enabled() || !mvc.Quick() || mvc.Get("interface") != "lan" || mvc.Get("%interface") != "LAN" {
		t.Errorf("mvc rule not decoded right: %+v", mvc)
	}
	if _, hasMeta := mvc.Fields["alias_meta_source_net"]; hasMeta {
		t.Errorf("formatting hints must be dropped")
	}
	if string(mvc.Raw) != filterTestMvcRow {
		t.Errorf("Raw must be the row: %s", mvc.Raw)
	}

	if _, err = api.FilterRuleSearch(FilterRuleQuery{Floating: true}); err != nil {
		t.Fatal(err)
	}
	if body := (*requests)[1].Body; body["interface"] != "" || body["show_all"] != nil || body["category"] != nil {
		t.Errorf("floating must send an empty interface: %v", body)
	}
	if _, err = api.FilterRuleList(); err != nil {
		t.Fatal(err)
	}
	if _, given := (*requests)[2].Body["interface"]; given {
		t.Errorf("all rules must not send an interface: %v", (*requests)[2].Body)
	}
}

func TestFilterRuleGet(t *testing.T) {
	var api, _ = newFilterTestApi(t, func(r filterTestRequest) filterTestAnswer {
		return filterOk(filterTestRows(filterTestAutoRow, filterTestMvcRow))
	})
	if rule, err := api.FilterRuleGet(strings.ToUpper(filterTestUuid)); err != nil || rule.Uuid != filterTestUuid {
		t.Errorf("want the rule, got %+v / %v", rule, err)
	}
	if _, err := api.FilterRuleGet(filterTestUuid2); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
}

func TestFilterRuleCreateAndValidation(t *testing.T) {
	var api, requests = newFilterTestApi(t, func(r filterTestRequest) filterTestAnswer {
		return filterOk(map[string]string{"result": "saved", "uuid": filterTestUuid2})
	})
	var fields = FilterRuleFields{"enabled": "0", "action": "block", "interface": "lan", "destination_net": "198.51.100.0/24",
		"protocol": "TCP", "destination_port": "443", "description": "d"}
	var uuid, err = api.FilterRuleCreate(fields)
	if err != nil || uuid != filterTestUuid2 {
		t.Fatalf("want %s, got %s / %v", filterTestUuid2, uuid, err)
	}
	var sent = (*requests)[0]
	if sent.Path != filterBase+"add_rule" || len(sent.Body["rule"].(map[string]any)) != len(fields) {
		t.Errorf("unexpected request %+v", sent)
	}

	for _, invalid := range []FilterRuleFields{
		{"action": "drop"},
		{"direction": "both"},
		{"ipprotocol": "ipv4"},
		{"enabled": "yes"},
		{"sequence": "0"},
		{"sequence": ""},
		{"max": "-1"},
		{"destination_net": "any,10.0.0.0/8"},
		{"destination_net": ""},
		{"source_net": "10.0.0.0/8 x"},
		{"destination_port": "443"},                         // protocol any
		{"protocol": "TCP", "destination_port": "70000"},    // out of range
		{"protocol": "TCP", "source_port": "80;rm"},         // garbage
		{"destination_net": "2001:db8::/32"},                // IPv6 network on an IPv4 rule
		{"ipprotocol": "inet6", "source_net": "10.0.0.0/8"}, // IPv4 network on an IPv6 rule
		{"source_net": "10.0.0.0/8,lan", "source_not": "1"}, // inverted list
		{"interfacenot": "1", "interface": "lan,wan"},       // inverted list
		{"interfacenot": "1"},                               // no interface
		{"icmptype": "echoreq"},                             // protocol any
		{"tcpflags1": "syn,foo"},
		{"tag": "a b"},
		{"description": "a\nb"},
		{"unknown": "1"},
	} {
		if _, err := api.FilterRuleCreate(invalid); err == nil {
			t.Errorf("%v: want a validation error", invalid)
		}
	}
	if len(*requests) != 1 {
		t.Errorf("invalid input must not be sent, got %d requests", len(*requests))
	}

	for _, valid := range []FilterRuleFields{
		{"ipprotocol": "inet46", "source_net": "10.0.0.0/8", "destination_net": "2001:db8::1"},
		{"protocol": "TCP/UDP", "destination_port": "1024-65535", "source_port": "https"},
		{"protocol": "ICMP", "icmptype": "echoreq,echorep"},
		{"interfacenot": "1", "interface": "wan", "source_net": "(self)", "source_not": "1"},
		{"source_net": "lan,lanip,my_alias", "tcpflags1": "syn,ack", "sequence": "999999", "adaptivestart": "0"},
	} {
		if err := FilterValidateFields(valid, nil); err != nil {
			t.Errorf("%v: unexpected error %v", valid, err)
		}
	}
}

func TestFilterRuleUpdate(t *testing.T) {
	var setAnswer = filterOk(map[string]string{"result": "saved"})
	var api, requests = newFilterTestApi(t, func(r filterTestRequest) filterTestAnswer {
		if strings.HasSuffix(r.Path, "/search_rule") {
			return filterOk(filterTestRows(filterTestAutoRow, filterTestMvcRow))
		}
		return setAnswer
	})
	if err := api.FilterRuleUpdate(filterTestUuid, FilterRuleFields{"description": "x", "log": "1"}); err != nil {
		t.Fatal(err)
	}
	var set = (*requests)[1]
	if set.Path != filterBase+"set_rule/"+filterTestUuid || len(set.Body["rule"].(map[string]any)) != 2 {
		t.Errorf("want only the given fields, got %+v", set)
	}
	// the current protocol (any) refuses ports
	if err := api.FilterRuleUpdate(filterTestUuid, FilterRuleFields{"destination_port": "80"}); err == nil || !strings.Contains(err.Error(), "TCP") {
		t.Errorf("want the protocol error, got %v", err)
	}
	if err := api.FilterRuleUpdate(filterTestUuid2, FilterRuleFields{"log": "1"}); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if err := api.FilterRuleUpdate(filterTestAuto, FilterRuleFields{"log": "1"}); err == nil || !strings.Contains(err.Error(), "automatic") {
		t.Errorf("want the automatic refusal, got %v", err)
	}
	var writes = 0
	for _, request := range *requests {
		if !strings.HasSuffix(request.Path, "/search_rule") {
			writes++
		}
	}
	if writes != 1 {
		t.Errorf("refused updates must not be sent: %+v", *requests)
	}

	setAnswer = filterOk(map[string]any{"result": "failed", "validations": map[string]any{"rule.interface": "Option [bogus] not in list."}})
	if err := api.FilterRuleUpdate(filterTestUuid, FilterRuleFields{"interface": "bogus"}); err == nil ||
		!strings.Contains(err.Error(), "rule.interface: Option [bogus] not in list.") {
		t.Errorf("want the validation message, got %v", err)
	}
	setAnswer = filterOk(map[string]string{"result": "failed"})
	if err := api.FilterRuleUpdate(filterTestUuid, FilterRuleFields{"log": "1"}); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError for a bare failure, got %v", err)
	}
}

func TestFilterRuleRemoveToggleLogMove(t *testing.T) {
	var api, requests = newFilterTestApi(t, func(r filterTestRequest) filterTestAnswer {
		switch r.Path {
		case filterBase + "del_rule/" + filterTestUuid:
			return filterOk(map[string]string{"result": "deleted"})
		case filterBase + "del_rule/" + filterTestUuid2:
			return filterOk(map[string]string{"result": "not found"})
		case filterBase + "toggle_rule/" + filterTestUuid + "/0":
			return filterOk(map[string]any{"result": "Disabled", "changed": true})
		case filterBase + "toggle_rule/" + filterTestUuid2 + "/1":
			return filterOk(map[string]any{"result": "failed"})
		case filterBase + "toggle_rule_log/" + filterTestUuid + "/1", filterBase + "move_rule_before/" + filterTestUuid + "/" + filterTestUuid2:
			return filterOk(map[string]string{"status": "ok"})
		case filterBase + "toggle_rule_log/" + filterTestUuid2 + "/0":
			return filterTestAnswer{Status: 500, Body: map[string]string{"errorMessage": "Rule not found", "errorTitle": ""}}
		case filterBase + "search_rule":
			return filterOk(filterTestRows(filterTestAutoRow, filterTestMvcRow))
		case filterBase + "move_rule_before/" + filterTestUuid + "/" + filterTestUnknown:
			return filterTestAnswer{Status: 500, Body: map[string]string{"errorMessage": "Unexpected error, check log for details"}}
		case filterBase + "move_rule_before/" + filterTestUuid2 + "/" + filterTestUuid:
			return filterTestAnswer{Status: 500, Body: map[string]string{"errorMessage": "Cannot move 'Interface Rule' before 'Floating Rule'.", "errorTitle": "Filter"}}
		}
		return filterTestAnswer{Status: 500, Body: map[string]string{"errorMessage": "Either source or destination is not a rule managed with this component"}}
	})

	if err := api.FilterRuleRemove(filterTestUuid); err != nil {
		t.Errorf("remove: %v", err)
	}
	if err := api.FilterRuleRemove(filterTestUuid2); !coreapi.IsNotFound(err) {
		t.Errorf("remove unknown: want NotFoundError, got %v", err)
	}
	if changed, err := api.FilterRuleSetEnabled(filterTestUuid, false); err != nil || !changed {
		t.Errorf("disable: %v / %v", changed, err)
	}
	if _, err := api.FilterRuleSetEnabled(filterTestUuid2, true); !coreapi.IsNotFound(err) {
		t.Errorf("enable unknown: want NotFoundError, got %v", err)
	}
	if err := api.FilterRuleSetLog(filterTestUuid, true); err != nil {
		t.Errorf("log: %v", err)
	}
	if err := api.FilterRuleSetLog(filterTestUuid2, false); !coreapi.IsNotFound(err) {
		t.Errorf("log unknown: want NotFoundError, got %v", err)
	}
	if err := api.FilterRuleMoveBefore(filterTestUuid, filterTestUuid2); err != nil {
		t.Errorf("move: %v", err)
	}
	if err := api.FilterRuleMoveBefore(filterTestUuid2, filterTestUuid); err == nil || err.Error() != "Cannot move 'Interface Rule' before 'Floating Rule'." {
		t.Errorf("move of different kinds: want the message, got %v", err)
	}
	if err := api.FilterRuleMoveBefore(filterTestUuid, "00000000-0000-4000-8000-000000000000"); !coreapi.IsNotFound(err) {
		t.Errorf("move before unknown: want NotFoundError, got %v", err)
	}
	if err := api.FilterRuleMoveBefore(filterTestUuid, filterTestUnknown); !coreapi.IsNotFound(err) || !strings.Contains(err.Error(), filterTestUnknown) {
		t.Errorf("move before unknown (26.7.7 answer): want NotFoundError for the target, got %v", err)
	}
	var sent = len(*requests)
	for _, refused := range []error{
		api.FilterRuleRemove(filterTestAuto),
		func() error { _, err := api.FilterRuleSetEnabled(filterTestAuto, true); return err }(),
		api.FilterRuleSetLog(filterTestAuto, true),
		api.FilterRuleMoveBefore(filterTestUuid, filterTestAuto),
		api.FilterRuleMoveBefore(filterTestUuid, filterTestUuid),
	} {
		if refused == nil {
			t.Errorf("want a refusal")
		}
	}
	if len(*requests) != sent {
		t.Errorf("refusals must not be sent")
	}
	for _, request := range *requests {
		if request.Method != "POST" {
			t.Errorf("mutations must be POST: %+v", request)
		}
	}
}

func TestFilterApplyAndRollback(t *testing.T) {
	var answers = map[string]filterTestAnswer{}
	var api, requests = newFilterTestApi(t, func(r filterTestRequest) filterTestAnswer {
		if answer, known := answers[r.Path]; known {
			return answer
		}
		return filterTestAnswer{Status: 404, Body: map[string]string{"errorMessage": "Endpoint not found"}}
	})

	answers[filterBase+"apply"] = filterOk(map[string]string{"status": "OK\n\n"})
	if err := api.FilterApply(); err != nil {
		t.Errorf("apply: %v", err)
	}
	answers[filterBase+"apply"] = filterOk(map[string]string{"status": "error"})
	if err := api.FilterApply(); err == nil {
		t.Errorf("apply: want an error for status error")
	}

	// 26.7: no savepoint / rollback endpoints
	for _, err := range []error{
		func() error { _, err := api.FilterSavepoint(); return err }(),
		api.FilterCancelRollback("1729876543.1234"),
		api.FilterRevert("1729876543.1234"),
	} {
		if !errors.Is(err, ErrFilterRollbackUnsupported) {
			t.Errorf("want ErrFilterRollbackUnsupported, got %v", err)
		}
	}
	answers[filterBase+"savepoint"] = filterTestAnswer{Body: ""} // unknown methods of some controllers: empty 200
	if _, err := api.FilterSavepoint(); !errors.Is(err, ErrFilterRollbackUnsupported) {
		t.Errorf("empty answer: want ErrFilterRollbackUnsupported, got %v", err)
	}

	// up to 26.1
	answers[filterBase+"savepoint"] = filterOk(map[string]string{"status": "ok", "retention": "60", "revision": "1729876543.1234"})
	answers[filterBase+"apply/1729876543.1234"] = filterOk(map[string]string{"status": "OK\n\n"})
	answers[filterBase+"cancel_rollback/1729876543.1234"] = filterOk(map[string]string{"status": ""})
	answers[filterBase+"revert/1729876543.1234"] = filterOk(map[string]string{"status": "ok"})
	var revision, err = api.FilterSavepoint()
	if err != nil || revision != "1729876543.1234" {
		t.Fatalf("savepoint: %q / %v", revision, err)
	}
	if err := api.FilterApplyWithRollback(revision); err != nil {
		t.Errorf("apply with rollback: %v", err)
	}
	if err := api.FilterCancelRollback(revision); err != nil {
		t.Errorf("cancel rollback: %v", err)
	}
	if err := api.FilterRevert(revision); err != nil {
		t.Errorf("revert: %v", err)
	}
	answers[filterBase+"cancel_rollback/1729876543.1234"] = filterOk(map[string]string{"status": "Execute error"})
	if err := api.FilterCancelRollback(revision); err == nil || !strings.Contains(err.Error(), "no rollback") {
		t.Errorf("cancel of an expired rollback: want an error, got %v", err)
	}
	answers[filterBase+"revert/1729876543.1234"] = filterOk(map[string]string{"status": "unknown (or removed) savepoint"})
	if err := api.FilterRevert(revision); err == nil || !strings.Contains(err.Error(), "unknown (or removed) savepoint") {
		t.Errorf("revert to an unknown savepoint: want the message, got %v", err)
	}

	var sent = len(*requests)
	for _, bad := range []string{"", "1;reboot", "../x"} {
		if api.FilterApplyWithRollback(bad) == nil || api.FilterCancelRollback(bad) == nil || api.FilterRevert(bad) == nil {
			t.Errorf("%q: want a revision error", bad)
		}
	}
	if len(*requests) != sent {
		t.Errorf("invalid revisions must not be sent")
	}
}

func TestFilterHelperEndpoints(t *testing.T) {
	var api, requests = newFilterTestApi(t, func(r filterTestRequest) filterTestAnswer {
		switch r.Path {
		case filterBase + "get_interface_list":
			return filterOk(json.RawMessage(`{"floating":{"label":"Floating","items":[{"value":"__floating","label":"Floating","type":"floating"}]},` +
				`"groups":{"label":"Groups","items":[{"value":"vpns","label":"VPNs","type":"group"}]},` +
				`"interfaces":{"label":"Interfaces","items":[{"value":"lan","label":"LAN","type":"interface"},{"value":"wan","label":"WAN","type":"interface"}]},` +
				`"any":{"label":"Any","items":[{"value":"__any","label":"All rules","type":"any"}]}}`))
		case filterBase + "list_categories":
			return filterOk(json.RawMessage(`{"rows":[{"uuid":"c1","name":"web","color":"ff0000","used":2}]}`))
		case filterBase + "list_network_select_options":
			return filterOk(json.RawMessage(`{"single":{"label":"Single host or Network"},"aliases":{"label":"Aliases","items":{"bogons":"bogons"}},` +
				`"networks":{"label":"Networks","items":{"any":"any","(self)":"This Firewall","lan":"LAN network"}}}`))
		case filterBase + "list_port_select_options":
			return filterOk(json.RawMessage(`{"single":{"label":"Single port or range"},"aliases":{"label":"Aliases","items":[]},` +
				`"ports":{"label":"Ports","items":{"":"any","https":"HTTPS (443)"}}}`))
		case "/api/firewall/filter_util/rule_stats":
			return filterOk(json.RawMessage(`{"status":"ok","stats":{"` + filterTestUuid + `":{"pf_rules":2,"evaluations":7,"packets":3,"bytes":120,"states":1}}}`))
		case filterBase + "get_rule":
			return filterOk(json.RawMessage(`{"rule":{"enabled":"1","sequence":"111","categories":[],` +
				`"action":{"pass":{"value":"Pass","selected":1},"block":{"value":"Block","selected":0}},` +
				`"interface":{"lan":{"value":"LAN","selected":1},"wan":{"value":"WAN","selected":1}},` +
				`"gateway":{"":{"value":"default","selected":1},"WAN_DHCP":{"value":"WAN_DHCP","selected":0}}}}`))
		}
		return filterTestAnswer{Status: 404, Body: map[string]string{"errorMessage": "Endpoint not found"}}
	})

	var interfaces, err = api.FilterInterfaces()
	if err != nil || len(interfaces) != 3 || interfaces[0] != (FilterInterface{"lan", "LAN", false}) || interfaces[2] != (FilterInterface{"vpns", "VPNs", true}) {
		t.Errorf("interfaces: %+v / %v", interfaces, err)
	}
	var categories, catErr = api.FilterCategories()
	if catErr != nil || len(categories) != 1 || categories[0] != (FilterCategory{"c1", "web", "ff0000", 2}) {
		t.Errorf("categories: %+v / %v", categories, catErr)
	}
	var networks, netErr = api.FilterNetworkOptions()
	if netErr != nil || len(networks) != 4 || networks["(self)"] != "This Firewall" || networks["bogons"] != "bogons" {
		t.Errorf("networks: %v / %v", networks, netErr)
	}
	var ports, portErr = api.FilterPortOptions()
	if portErr != nil || len(ports) != 1 || ports["https"] != "HTTPS (443)" {
		t.Errorf("ports: %v / %v", ports, portErr)
	}
	var stats, statsErr = api.FilterRuleStatistics()
	if statsErr != nil || stats[filterTestUuid] != (FilterRuleStats{2, 7, 3, 120, 1}) {
		t.Errorf("stats: %v / %v", stats, statsErr)
	}
	var record, recordErr = api.FilterRuleRecord("")
	if recordErr != nil || record["sequence"] != "111" || record["action"] != "pass" || record["interface"] != "lan,wan" ||
		record["gateway"] != "" || record["categories"] != "" {
		t.Errorf("record: %v / %v", record, recordErr)
	}
	var gateways, optErr = api.FilterRuleOptions("gateway")
	if optErr != nil || len(gateways) != 1 || gateways["WAN_DHCP"] != "WAN_DHCP" {
		t.Errorf("gateway options: %v / %v", gateways, optErr)
	}
	for _, request := range *requests {
		if request.Method != "GET" {
			t.Errorf("helpers must only read: %+v", request)
		}
	}
}
