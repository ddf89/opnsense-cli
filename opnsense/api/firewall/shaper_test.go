package firewall

import (
	"encoding/json"
	"errors"
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

type shaperTestRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   string
}

// shaperTestAnswer is a status and a body (a string sent as is, anything else JSON encoded)
type shaperTestAnswer struct {
	status int
	body   any
}

// newShaperTestApi starts a fake OPNsense answering with handler, all requests are recorded
func newShaperTestApi(t *testing.T, handler func(r shaperTestRequest) shaperTestAnswer) (*FirewallApi, func() []shaperTestRequest) {
	t.Helper()
	var mu sync.Mutex
	var requests []shaperTestRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw, _ = io.ReadAll(r.Body)
		var recorded = shaperTestRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Body: string(raw)}
		mu.Lock()
		requests = append(requests, recorded)
		mu.Unlock()
		var answer = handler(recorded)
		if answer.status != 0 {
			w.WriteHeader(answer.status)
		}
		switch body := answer.body.(type) {
		case string:
			_, _ = io.WriteString(w, body)
		default:
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &FirewallApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, func() []shaperTestRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]shaperTestRequest(nil), requests...)
	}
}

func shaperTestOk(body any) shaperTestAnswer { return shaperTestAnswer{body: body} }

func shaperTestRows(rows ...any) shaperTestAnswer {
	return shaperTestOk(map[string]any{"rows": rows, "rowCount": len(rows), "total": len(rows), "current": 1})
}

func shaperTestBody(t *testing.T, r shaperTestRequest, key string) map[string]string {
	t.Helper()
	var body map[string]map[string]string
	if err := json.Unmarshal([]byte(r.Body), &body); err != nil {
		t.Fatalf("invalid body %q: %v", r.Body, err)
	}
	return body[key]
}

var shaperTestPipes = []any{
	ShaperPipe{Uuid: "p-wan", Number: "10000", Enabled: "1", Bandwidth: "100", BandwidthMetric: "Mbit", Description: "WAN down"},
	ShaperPipe{Uuid: "p-wan-up", Number: "10001", Enabled: "1", Bandwidth: "20", BandwidthMetric: "Mbit", Description: "WAN down up"},
	ShaperPipe{Uuid: "p-dup1", Number: "10002", Description: "dup"},
	ShaperPipe{Uuid: "p-dup2", Number: "10003", Description: "DUP"},
}

func TestShaperPipeFindByDescription(t *testing.T) {
	var api, requests = newShaperTestApi(t, func(r shaperTestRequest) shaperTestAnswer { return shaperTestRows(shaperTestPipes...) })
	var pipes, err = api.ShaperPipeFindByDescription(" wan DOWN ")
	if err != nil || len(pipes) != 1 || pipes[0].Uuid != "p-wan" {
		t.Errorf("got %+v / %v", pipes, err)
	}
	if got := requests()[0]; got.Method != "GET" || got.Path != "/api/trafficshaper/settings/search_pipes" || got.Query.Get("searchPhrase") != "wan DOWN" {
		t.Errorf("unexpected request %+v", got)
	}
	if _, err = api.ShaperPipeFindByDescription(""); err == nil {
		t.Errorf("an empty description must fail")
	}
}

func TestShaperPipeCreateSendsAllFields(t *testing.T) {
	var api, requests = newShaperTestApi(t, func(r shaperTestRequest) shaperTestAnswer {
		return shaperTestOk(map[string]string{"result": "saved", "uuid": "p-new"})
	})
	var uuid, err = api.ShaperPipeCreate(ShaperPipe{Bandwidth: "10", Description: "x", Number: "123", Origin: "evil"})
	if err != nil || uuid != "p-new" {
		t.Fatalf("got %q / %v", uuid, err)
	}
	var request = requests()[0]
	var body = shaperTestBody(t, request, "pipe")
	if request.Path != "/api/trafficshaper/settings/add_pipe" || len(body) != len(ShaperPipeFieldNames) {
		t.Errorf("want all writable fields to add_pipe, got %s %v", request.Path, body)
	}
	for field, want := range map[string]string{"enabled": "1", "bandwidth": "10", "bandwidthMetric": "Kbit", "mask": "none",
		"codel_enable": "0", "pie_enable": "0", "codel_ecn_enable": "0", "scheduler": "", "description": "x"} {
		if body[field] != want {
			t.Errorf("%s: got %q, want %q", field, body[field], want)
		}
	}
	if _, sent := body["number"]; sent {
		t.Errorf("number is assigned by OPNsense and must not be sent")
	}
}

func TestShaperUpdateChecksExistence(t *testing.T) {
	var api, requests = newShaperTestApi(t, func(r shaperTestRequest) shaperTestAnswer {
		if strings.Contains(r.Path, "/search_") {
			return shaperTestRows(shaperTestPipes...)
		}
		return shaperTestOk(map[string]string{"result": "saved"})
	})
	// set_pipe/<unknown uuid> creates a pipe when the body is complete, so nothing must be sent
	if err := api.ShaperPipeUpdate("0f0f0f0f-1111-4222-8333-444455556666", ShaperFields{"description": "x"}); !coreapi.IsNotFound(err) {
		t.Fatalf("want NotFoundError, got %v", err)
	}
	if len(requests()) != 1 {
		t.Errorf("want only the search, got %+v", requests())
	}
	if err := api.ShaperPipeUpdate("P-WAN", ShaperFields{"bandwidth": "200"}); err != nil {
		t.Fatal(err)
	}
	var set = requests()[2]
	if set.Path != "/api/trafficshaper/settings/set_pipe/p-wan" || !reflect.DeepEqual(shaperTestBody(t, set, "pipe"), map[string]string{"bandwidth": "200"}) {
		t.Errorf("unexpected set %+v", set)
	}
	if err := api.ShaperPipeUpdate("p-wan", ShaperFields{"number": "1"}); err == nil || !strings.Contains(err.Error(), "number") {
		t.Errorf("number is not writable, got %v", err)
	}
	if err := api.ShaperQueueUpdate("p-wan", ShaperFields{"bandwidth": "1"}); err == nil || !strings.Contains(err.Error(), "bandwidth") {
		t.Errorf("bandwidth is no queue field, got %v", err)
	}
}

func TestShaperCreateOrUpdate(t *testing.T) {
	var api, requests = newShaperTestApi(t, func(r shaperTestRequest) shaperTestAnswer {
		switch {
		case strings.Contains(r.Path, "/search_"):
			return shaperTestRows(shaperTestPipes...)
		case strings.Contains(r.Path, "/add_"):
			return shaperTestOk(map[string]string{"result": "saved", "uuid": "p-new"})
		default:
			return shaperTestOk(map[string]string{"result": "saved"})
		}
	})
	var uuid, replaced, err = api.ShaperPipeCreateOrUpdate(ShaperPipe{Bandwidth: "5", BandwidthMetric: "Gbit", Description: "wan down"})
	if err != nil || uuid != "p-wan" || !replaced {
		t.Fatalf("got %q %v %v", uuid, replaced, err)
	}
	var last = requests()[len(requests())-1]
	if last.Path != "/api/trafficshaper/settings/set_pipe/p-wan" || shaperTestBody(t, last, "pipe")["bandwidthMetric"] != "Gbit" ||
		len(shaperTestBody(t, last, "pipe")) != len(ShaperPipeFieldNames) {
		t.Errorf("want a complete set_pipe of p-wan, got %+v", last)
	}
	if uuid, replaced, err = api.ShaperPipeCreateOrUpdate(ShaperPipe{Bandwidth: "5", Description: "new"}); err != nil || uuid != "p-new" || replaced {
		t.Errorf("new description must add: %q %v %v", uuid, replaced, err)
	}
	_, _, err = api.ShaperPipeCreateOrUpdate(ShaperPipe{Bandwidth: "5", Description: "dup"})
	var tooMany *coreapi.TooManyFoundError
	if !errors.As(err, &tooMany) || !strings.Contains(err.Error(), "p-dup1, p-dup2") {
		t.Errorf("want TooManyFoundError, got %v", err)
	}
	if _, _, err = api.ShaperRuleCreateOrUpdate(ShaperRule{Target: "p-wan"}); err == nil || !strings.Contains(err.Error(), "description") {
		t.Errorf("a rule without description can not be replaced, got %v", err)
	}
}

func TestShaperRuleAndQueueFields(t *testing.T) {
	var rule = ShaperRule{Target: "q-1", Description: "voip"}.Fields()
	for field, want := range map[string]string{"enabled": "1", "sequence": "1", "interface": "wan", "proto": "ip", "source": "any",
		"src_port": "any", "destination": "any", "dst_port": "any", "source_not": "0", "destination_not": "0", "direction": "",
		"target": "q-1", "interface2": "", "dscp": ""} {
		if rule[field] != want {
			t.Errorf("rule %s: got %q, want %q", field, rule[field], want)
		}
	}
	if len(rule) != len(ShaperRuleFieldNames) {
		t.Errorf("rule fields %v", rule)
	}
	var queue = ShaperQueue{Pipe: "p-1", Description: "bulk"}.Fields()
	if queue["weight"] != "100" || queue["mask"] != "none" || queue["pipe"] != "p-1" || len(queue) != len(ShaperQueueFieldNames) {
		t.Errorf("queue fields %v", queue)
	}
}

func TestShaperRemove(t *testing.T) {
	var api, requests = newShaperTestApi(t, func(r shaperTestRequest) shaperTestAnswer {
		switch {
		case strings.HasSuffix(r.Path, "/gone"):
			return shaperTestOk(map[string]string{"result": "not found"})
		case strings.HasSuffix(r.Path, "/used"):
			return shaperTestAnswer{status: 500, body: `{"errorMessage":"TrafficShaper - bulk {TrafficShaper.queues.queue.q-1}\nTrafficShaper - voip {TrafficShaper.rules.rule.r-1}\n","errorTitle":"Item pipes.pipe {WAN down} in use by:"}`}
		default:
			return shaperTestOk(map[string]string{"result": "deleted"})
		}
	})
	if err := api.ShaperQueueRemove("q-1"); err != nil {
		t.Fatal(err)
	}
	if got := requests()[0]; got.Method != "POST" || got.Path != "/api/trafficshaper/settings/del_queue/q-1" {
		t.Errorf("unexpected request %+v", got)
	}
	if err := api.ShaperRuleRemove("gone"); !coreapi.IsNotFound(err) || !strings.Contains(err.Error(), "shaper rule gone") {
		t.Errorf("want NotFoundError, got %v", err)
	}
	var err = api.ShaperPipeRemove("used")
	if err == nil || !strings.Contains(err.Error(), "shaper pipe used is in use by: bulk {TrafficShaper.queues.queue.q-1}; voip {TrafficShaper.rules.rule.r-1}") {
		t.Errorf("want an in use error naming the users, got %v", err)
	}
}

func TestShaperSetEnabled(t *testing.T) {
	var api, requests = newShaperTestApi(t, func(r shaperTestRequest) shaperTestAnswer {
		switch {
		case strings.Contains(r.Path, "/gone/"):
			return shaperTestOk(map[string]string{"result": "failed"})
		case strings.HasSuffix(r.Path, "/1"):
			return shaperTestOk(map[string]any{"result": "Enabled", "changed": true})
		default:
			return shaperTestOk(map[string]any{"result": "Disabled", "changed": false})
		}
	})
	if changed, err := api.ShaperRuleSetEnabled("r-1", true); err != nil || !changed {
		t.Errorf("enable: %v %v", changed, err)
	}
	if changed, err := api.ShaperQueueSetEnabled("q-1", false); err != nil || changed {
		t.Errorf("disable: %v %v", changed, err)
	}
	if got := requests()[1]; got.Method != "POST" || got.Path != "/api/trafficshaper/settings/toggle_queue/q-1/0" || got.Body == "" {
		t.Errorf("unexpected request %+v", got)
	}
	if _, err := api.ShaperPipeSetEnabled("gone", true); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
}

func TestShaperRuleOptions(t *testing.T) {
	var api, _ = newShaperTestApi(t, func(r shaperTestRequest) shaperTestAnswer {
		return shaperTestOk(`{"rule":{"enabled":"1","sequence":"6","interface":{"lan":{"value":"LAN","selected":0},` +
			`"wan":{"value":"WAN","selected":1},"opt1":{"value":"DMZ","selected":0}},"target":{"p-1":{"value":"WAN down","selected":0},` +
			`"q-1":{"value":"bulk","selected":0}}}}`)
	})
	var options, err = api.ShaperRuleOptions()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(options.Interfaces, []ShaperOption{{"opt1", "DMZ"}, {"lan", "LAN"}, {"wan", "WAN"}}) ||
		!reflect.DeepEqual(options.Targets, []ShaperOption{{"q-1", "bulk"}, {"p-1", "WAN down"}}) || options.NextSequence != "6" {
		t.Errorf("unexpected options %+v", options)
	}

	api, _ = newShaperTestApi(t, func(r shaperTestRequest) shaperTestAnswer {
		return shaperTestOk(`{"rule":{"sequence":"1","interface":{"wan":{"value":"WAN","selected":1}},"target":[]}}`)
	})
	if options, err = api.ShaperRuleOptions(); err != nil || len(options.Targets) != 0 || len(options.Interfaces) != 1 {
		t.Errorf("no targets: %+v / %v", options, err)
	}
}

func TestShaperService(t *testing.T) {
	for _, tc := range []struct {
		call   func(api *FirewallApi) error
		path   string
		answer string
		err    string
	}{
		{func(api *FirewallApi) error { return api.ShaperReconfigure() }, "/api/trafficshaper/service/reconfigure", `{"status":"ok"}`, ""},
		{func(api *FirewallApi) error { return api.ShaperReconfigure() }, "/api/trafficshaper/service/reconfigure",
			`{"status":"error reloading shaper (Execute error)"}`, "error reloading shaper"},
		{func(api *FirewallApi) error { return api.ShaperReconfigure() }, "/api/trafficshaper/service/reconfigure", `{}`, "no status"},
		{func(api *FirewallApi) error { return api.ShaperFlushReload() }, "/api/trafficshaper/service/flushreload", `{"status":"OK"}`, ""},
		{func(api *FirewallApi) error { return api.ShaperFlushReload() }, "/api/trafficshaper/service/flushreload", `{"status":"Execute error"}`, "Execute error"},
	} {
		var api, requests = newShaperTestApi(t, func(r shaperTestRequest) shaperTestAnswer { return shaperTestOk(tc.answer) })
		var err = tc.call(api)
		if (tc.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%s %s: got %v, want %q", tc.path, tc.answer, err, tc.err)
		}
		if got := requests()[0]; got.Method != "POST" || got.Path != tc.path || got.Body != "" {
			t.Errorf("unexpected request %+v (a POST without body)", got)
		}
	}
}

// shaperTestStatistics is shaped like service/statistics of 26.7 for one pipe with its automatic queue and a queue
const shaperTestStatistics = `{"status":"ok","items":[` +
	`{"pipe":"10000","bw":"100.000 Mbit/s","delay":"0","burst":"0","flows":[],"flowset":{"flow_set_nr":"1","flows":"0"},` +
	`"scheduler":{"sched_nr":"10000","sched_type":"FQ_CODEL","sched_flags":"0x0","sched_buckets":"1","sched_active":"0"},` +
	`"description":"WAN down","uuid":"p-1","type":"pipe","id":10000,"rules":[]},` +
	`{"flow_set_nr":"1","queue_size":"50 sl.","buckets":"64","sched_nr":"10000","weight":"0","lmax":"0","pri":"0",` +
	`"queue_params":"droptail","type":"queue","template":true,"pipe":10000,"id":"10000.1","flows":[` +
	`{"BKT":"0","Prot":"tcp","Source":"192.0.2.10/51000","Destination":"198.51.100.1/443","pkt":10,"bytes":1500,"drop_pkt":1,"drop_bytes":100}],` +
	`"rules":[{"rule":"60001","pkts":10,"bytes":1500,"accessed":"2026-10-25T14:00:00","accessed_epoch":1761400800,` +
	`"attached_to":"10000","rule_uuid":"r-1","description":"all"}]},` +
	`{"flow_set_nr":"10000","queue_size":"50 sl.","buckets":"64","sched_nr":"10000","weight":"10","lmax":"0","pri":"0",` +
	`"queue_params":"","flows":[{"BKT":"1","Prot":"udp","flowid":"5","Source":"2001:db8::1/5060","Destination":"2001:db8::2/5060",` +
	`"pkt":"5","bytes":"500","drop_pkt":"0","drop_bytes":"0"}],"description":"voip","uuid":"q-1","type":"queue","id":"10000.10000","rules":[]}]}`

func TestShaperStatistics(t *testing.T) {
	var api, requests = newShaperTestApi(t, func(r shaperTestRequest) shaperTestAnswer { return shaperTestOk(shaperTestStatistics) })
	var stats, err = api.ShaperStatisticsGet()
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Items) != 3 {
		t.Fatalf("want 3 items, got %+v", stats.Items)
	}
	var pipe, template, queue = stats.Items[0], stats.Items[1], stats.Items[2]
	if pipe.Type != "pipe" || pipe.Id != "10000" || pipe.Bandwidth != "100.000 Mbit/s" || pipe.SchedulerType != "FQ_CODEL" || pipe.Uuid != "p-1" {
		t.Errorf("pipe %+v", pipe)
	}
	if packets, bytes, drops := template.Packets(); !template.Template || packets != 10 || bytes != 1500 || drops != 1 ||
		len(template.Rules) != 1 || template.Rules[0].RuleUuid != "r-1" || template.Rules[0].AccessedEpoch != 1761400800 {
		t.Errorf("automatic queue %+v", template)
	}
	if packets, _, _ := queue.Packets(); queue.Weight != "10" || queue.Description != "voip" || packets != 5 || queue.Flows[0].Source != "2001:db8::1/5060" {
		t.Errorf("queue %+v", queue)
	}
	if !json.Valid(queue.Raw) {
		t.Errorf("raw item not kept")
	}
	if got := requests()[0]; got.Method != "GET" || got.Path != "/api/trafficshaper/service/statistics" {
		t.Errorf("unexpected request %+v", got)
	}

	api, _ = newShaperTestApi(t, func(r shaperTestRequest) shaperTestAnswer { return shaperTestOk(`{"status":"failed"}`) })
	if _, err = api.ShaperStatisticsGet(); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Errorf("want an error for status failed, got %v", err)
	}
}
