package diagnostics

import (
	"encoding/json"
	"errors"
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

type toolsTestCall struct {
	Method string
	Path   string
	Query  string
	Body   string
	Type   string // Content-Type
}

// toolsTestApi answers "METHOD /path" with the routes (a string is a JSON body, a handler is called), 404 for
// others, and records the requests
func toolsTestApi(t *testing.T, routes map[string]any) (*DiagnosticsApi, func() []toolsTestCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []toolsTestCall
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, toolsTestCall{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Body: string(body), Type: r.Header.Get("Content-Type")})
		mu.Unlock()
		switch answer := routes[r.Method+" "+r.URL.Path].(type) {
		case string:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, answer)
		case func(http.ResponseWriter, *http.Request):
			answer(w, r)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errorMessage":"Endpoint not found"}`)
		}
	}))
	t.Cleanup(server.Close)
	var serverUrl, _ = url.Parse(server.URL)
	return &DiagnosticsApi{OPNsense: &coreapi.OPNsense{BaseUrl: *serverUrl}}, func() []toolsTestCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]toolsTestCall(nil), calls...)
	}
}

func toolsTestBody(t *testing.T, call toolsTestCall) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal([]byte(call.Body), &body); err != nil {
		t.Fatalf("body of %s %s is not JSON: %q", call.Method, call.Path, call.Body)
	}
	return body
}

// toolsTestSettings returns body[model]["settings"]
func toolsTestSettings(t *testing.T, call toolsTestCall, model string) map[string]any {
	t.Helper()
	var body = toolsTestBody(t, call)
	var wrapper, _ = body[model].(map[string]any)
	var settings, _ = wrapper["settings"].(map[string]any)
	if settings == nil {
		t.Fatalf("body of %s has no %s.settings: %q", call.Path, model, call.Body)
	}
	return settings
}

const toolsTestJobId = "438d6fbc-7404-4615-a0e4-0e57abbed0e9"

func TestToolsText(t *testing.T) {
	var decoded struct {
		A, B, C, D, E, F ToolsText
		G                ToolsCount
		H                ToolsCount
		I                ToolsCount
	}
	var err = json.Unmarshal([]byte(`{"A":"x","B":12,"C":null,"D":["lighttpd","lighttpd","x"],"E":true,"F":{"a":1},"G":"7","H":3.9,"I":""}`), &decoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.A != "x" || decoded.B != "12" || decoded.C != "" || decoded.D != "lighttpd,x" || decoded.E != "true" ||
		decoded.F != `{"a":1}` || decoded.G != 7 || decoded.H != 3 || decoded.I != 0 {
		t.Errorf("decoded %+v", decoded)
	}
	var count ToolsCount
	if err := json.Unmarshal([]byte(`"x"`), &count); err == nil {
		t.Error("want an error for a non numeric counter")
	}
}

func TestPingJobLifecycle(t *testing.T) {
	var api, calls = toolsTestApi(t, map[string]any{
		"POST /api/diagnostics/ping/set":                      `{"result":"ok","uuid":"` + toolsTestJobId + `"}`,
		"POST /api/diagnostics/ping/start/" + toolsTestJobId:  `{"status":"ok"}`,
		"POST /api/diagnostics/ping/stop/" + toolsTestJobId:   `{"status":"ok","stopped_processes":1}`,
		"POST /api/diagnostics/ping/remove/" + toolsTestJobId: `{"status":"ok","stopped_processes":0}`,
		"GET /api/diagnostics/ping/search_jobs": `{"total":2,"rowCount":2,"current":1,"rows":[` +
			`{"hostname":"10.0.0.1","fam":"ip","source_address":"","packetsize":"","disable_frag":"0","interval":"","description":"other","id":"aaaa","status":"stopped","loss":null,"send":null,"received":null,"min":null,"max":null,"avg":null,"std-dev":null,"last_error":"sendto: Host is down"},` +
			`{"hostname":"127.0.0.1","fam":"ip","source_address":"","packetsize":"1400","disable_frag":"1","interval":"2","description":"probe","id":"` + toolsTestJobId + `","status":"running","loss":"0.0%","send":3,"received":2,"min":0.021,"max":0.041,"avg":0.028,"std-dev":0.009,"last_error":null}]}`,
	})
	var id, err = api.PingCreate(PingSettings{Hostname: "127.0.0.1", PacketSize: 1400, DisableFragmentation: true, Interval: 2, Description: "probe"})
	if err != nil || id != toolsTestJobId {
		t.Fatalf("create: %q, %v", id, err)
	}
	var settings = toolsTestSettings(t, calls()[0], "ping")
	var want = map[string]any{"hostname": "127.0.0.1", "fam": "ip", "source_address": "", "packetsize": "1400", "disable_frag": "1",
		"interval": "2", "description": "probe"}
	if !reflect.DeepEqual(settings, want) {
		t.Errorf("settings %v, want %v", settings, want)
	}
	if err := api.PingStart(id); err != nil {
		t.Fatal(err)
	}
	if call := calls()[1]; call.Method != "POST" || call.Body != "{}\n" || call.Type != "application/json" {
		t.Errorf("start must POST {}: %+v", call)
	}

	job, err := api.PingJob(id)
	if err != nil {
		t.Fatal(err)
	}
	if !job.Running() || *job.Sent != 3 || *job.Received != 2 || *job.Min != 0.021 || *job.Avg != 0.028 || *job.Max != 0.041 ||
		*job.Loss != "0.0%" || job.LastError != nil || job.PacketSize != "1400" || !strings.Contains(string(job.Raw), `"std-dev":0.009`) {
		t.Errorf("job %+v", job)
	}
	jobs, err := api.PingJobs()
	if err != nil || len(jobs) != 2 || jobs[0].Sent != nil || jobs[0].Running() || *jobs[0].LastError != "sendto: Host is down" {
		t.Errorf("jobs %+v, %v", jobs, err)
	}
	if _, err := api.PingJob("bbbb"); !coreapi.IsNotFound(err) {
		t.Errorf("unknown job: want not found, got %v", err)
	}
	if err := api.PingStop(id); err != nil {
		t.Error(err)
	}
	if err := api.PingRemove(id); err != nil {
		t.Error(err)
	}
}

func TestPingErrors(t *testing.T) {
	var api, calls = toolsTestApi(t, map[string]any{
		"POST /api/diagnostics/ping/set":         `{"result":"failed","validations":{"ping.settings.hostname":"Provide a valid hostname or address to ping.","ping.settings.interval":["Invalid integer value."]}}`,
		"POST /api/diagnostics/ping/start/aaaa":  `{"status":"failed","status_msg":"already active (pids: 54217)"}`,
		"POST /api/diagnostics/ping/remove/bbbb": `{"status":"failed"}`,
		"POST /api/diagnostics/ping/stop/cccc":   `{"status":"weird"}`,
	})
	var _, err = api.PingCreate(PingSettings{Hostname: "bad host"})
	var validation *coreapi.ValidationError
	if !errors.As(err, &validation) || validation.Validations["ping.settings.interval"] != "Invalid integer value." {
		t.Errorf("want a validation error, got %v", err)
	}
	if err := api.PingStart("aaaa"); err == nil || !strings.Contains(err.Error(), "already active") {
		t.Errorf("start: %v", err)
	}
	if err := api.PingRemove("bbbb"); !coreapi.IsNotFound(err) {
		t.Errorf("remove of an unknown job: want not found, got %v", err)
	}
	if err := api.PingStop("cccc"); err == nil || !strings.Contains(err.Error(), "weird") {
		t.Errorf("stop: %v", err)
	}
	var before = len(calls())
	for _, id := range []string{"", "../../core/firmware/poweroff", "a/b", "x y"} {
		if err := api.PingRemove(id); err == nil {
			t.Errorf("invalid id %q accepted", id)
		}
	}
	if len(calls()) != before {
		t.Errorf("invalid ids must not be sent: %+v", calls()[before:])
	}

	// set answering "saved" or an invalid uuid is not trusted
	var odd, _ = toolsTestApi(t, map[string]any{"POST /api/diagnostics/ping/set": `{"result":"saved"}`})
	if _, err := odd.PingCreate(PingSettings{Hostname: "x"}); err == nil {
		t.Error("want an error for an unexpected result")
	}
	var noId, _ = toolsTestApi(t, map[string]any{"POST /api/diagnostics/ping/set": `{"result":"ok","uuid":"../x"}`})
	if _, err := noId.PingCreate(PingSettings{Hostname: "x"}); err == nil {
		t.Error("want an error for an invalid job id")
	}
}

func TestTraceroute(t *testing.T) {
	var api, calls = toolsTestApi(t, map[string]any{
		"POST /api/diagnostics/traceroute/set": `{"result":"ok","response":{"rows":[{"address":"10.0.2.2","ttl":"1","AS":"AS0","host":"10.0.2.2","probes":"0.153 ms"},` +
			`{"address":"192.0.2.1","ttl":"2","AS":"AS64500","host":"router.example","probes":"1.2 ms"}],"notice":"traceroute to 192.0.2.1 (192.0.2.1), 64 hops max, 48 byte packets","error":"timeout reached"}}`,
	})
	var result, err = api.Traceroute(TracerouteOptions{Hostname: "192.0.2.1", Protocol: "icmp", SourceAddress: "10.0.2.15"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Hops) != 2 || result.Hops[1] != (TracerouteHop{TTL: "2", AS: "AS64500", Host: "router.example", Address: "192.0.2.1", Probes: "1.2 ms"}) ||
		!strings.HasPrefix(result.Notice, "traceroute to") || result.Error != "timeout reached" || !strings.HasPrefix(string(result.Raw), `{"rows"`) {
		t.Errorf("result %+v", result)
	}
	var settings = toolsTestSettings(t, calls()[0], "traceroute")
	if !reflect.DeepEqual(settings, map[string]any{"hostname": "192.0.2.1", "ipproto": "inet", "protocol": "icmp", "source_address": "10.0.2.15"}) {
		t.Errorf("settings %v", settings)
	}

	var failing, _ = toolsTestApi(t, map[string]any{
		"POST /api/diagnostics/traceroute/set": `{"result":"failed","validations":{"traceroute.settings.hostname":"Provide a valid hostname or address."}}`,
	})
	if _, err := failing.Traceroute(TracerouteOptions{Hostname: "x"}); err == nil || !strings.Contains(err.Error(), "Provide a valid hostname") {
		t.Errorf("want the validation, got %v", err)
	}
	var empty, _ = toolsTestApi(t, map[string]any{"POST /api/diagnostics/traceroute/set": `{"result":"ok","response":null}`})
	if _, err := empty.Traceroute(TracerouteOptions{Hostname: "x"}); err == nil || !strings.Contains(err.Error(), "no result") {
		t.Errorf("want an error for a null response, got %v", err)
	}
}

func TestPortProbe(t *testing.T) {
	var answers = []string{
		`{"result":"ok","response":{"message":"Connection to 127.0.0.1 443 port [tcp\/https] succeeded!","payload":""}}`,
		`{"result":"ok","response":{"message":"nc: connect to 127.0.0.1 port 9 (tcp) failed: Connection refused","payload":""}}`,
	}
	var n = 0
	var api, calls = toolsTestApi(t, map[string]any{
		"POST /api/diagnostics/portprobe/set": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, answers[n])
			n++
		},
	})
	var result, err = api.PortProbe(PortProbeOptions{Hostname: "127.0.0.1", Port: 443, Family: "inet6", SourcePort: 40000, ShowText: true})
	if err != nil || !result.Succeeded() || result.Payload != "" {
		t.Errorf("open port: %+v, %v", result, err)
	}
	var settings = toolsTestSettings(t, calls()[0], "portprobe")
	if !reflect.DeepEqual(settings, map[string]any{"hostname": "127.0.0.1", "port": "443", "ipproto": "inet6", "source_address": "",
		"source_port": "40000", "showtext": "1"}) {
		t.Errorf("settings %v", settings)
	}
	result, err = api.PortProbe(PortProbeOptions{Hostname: "127.0.0.1", Port: 9})
	if err != nil || result.Succeeded() || !strings.Contains(result.Message, "refused") {
		t.Errorf("closed port: %+v, %v", result, err)
	}
	if settings := toolsTestSettings(t, calls()[1], "portprobe"); settings["ipproto"] != "inet" || settings["source_port"] != "" || settings["showtext"] != "0" {
		t.Errorf("defaults %v", settings)
	}
}

func TestDnsLookup(t *testing.T) {
	var api, calls = toolsTestApi(t, map[string]any{
		"POST /api/diagnostics/dns_diagnostics/set": `{"result":"ok","response":{"A":{"answers":["localhost.\t10800\tIN\tA\t127.0.0.1"],"query_time":"0 msec","server":"127.0.0.1"},` +
			`"TXT":{"answers":["example.com.\t300\tIN\tTXT\t\"v=spf1 -all\" \"x y\""],"query_time":"1 msec","server":"127.0.0.1"},` +
			`"MX":{"answers":["example.com.\t300\tIN\tMX\t10 mail.example.com."],"query_time":null,"server":null},` +
			`"AAAA":{"answers":["localhost.\t10800\tIN\tAAAA\t::1"],"query_time":"0 msec","server":"127.0.0.1"}}}`,
	})
	var result, err = api.DnsLookup("localhost", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if settings := toolsTestSettings(t, calls()[0], "dns"); !reflect.DeepEqual(settings, map[string]any{"hostname": "localhost", "server": "127.0.0.1"}) {
		t.Errorf("settings %v", settings)
	}
	if !reflect.DeepEqual(result.Types(), []string{"A", "AAAA", "MX", "TXT"}) || result.Error != "" {
		t.Errorf("types %v", result.Types())
	}
	var answers = result.Answers()
	var want = []DnsLookupAnswer{
		{Type: "A", Name: "localhost.", TTL: "10800", Class: "IN", Data: "127.0.0.1"},
		{Type: "AAAA", Name: "localhost.", TTL: "10800", Class: "IN", Data: "::1"},
		{Type: "MX", Name: "example.com.", TTL: "300", Class: "IN", Data: "10 mail.example.com."},
		{Type: "TXT", Name: "example.com.", TTL: "300", Class: "IN", Data: `"v=spf1 -all" "x y"`},
	}
	if !reflect.DeepEqual(answers, want) {
		t.Errorf("answers:\n got  %+v\n want %+v", answers, want)
	}
	if result.Records["MX"].Server != "" || result.Records["A"].QueryTime != "0 msec" {
		t.Errorf("records %+v", result.Records)
	}
	if odd := DnsLookupParseAnswer("PTR", ";; odd line"); odd != (DnsLookupAnswer{Type: "PTR", Data: ";; odd line"}) {
		t.Errorf("odd line %+v", odd)
	}

	for answer, check := range map[string]func(DnsLookupResult, error) bool{
		`{"result":"ok","response":{"error_message":"Error: error sending query: Error creating socket"}}`: func(r DnsLookupResult, err error) bool {
			return err == nil && r.Error == "Error: error sending query: Error creating socket" && len(r.Records) == 0
		},
		`{"result":"ok","response":{}}`: func(r DnsLookupResult, err error) bool { return err == nil && len(r.Answers()) == 0 },
		`{"result":"ok","response":[]}`: func(r DnsLookupResult, err error) bool { return err == nil && len(r.Answers()) == 0 },
		`{"result":"ok","response":{"PTR":{"answers":["1.0.0.127.in-addr.arpa.\t10800\tIN\tPTR\tlocalhost."],"query_time":"0 ms","server":"127.0.0.1"}}}`: func(r DnsLookupResult, err error) bool {
			return err == nil && len(r.Answers()) == 1 && r.Answers()[0].Data == "localhost."
		},
		`{"result":"ok","response":{"A":"x"}}`: func(_ DnsLookupResult, err error) bool { return err != nil },
		`{"result":"failed","validations":{"dns.settings.server":"Provide a valid server address."}}`: func(_ DnsLookupResult, err error) bool {
			return err != nil && strings.Contains(err.Error(), "valid server")
		},
	} {
		var other, _ = toolsTestApi(t, map[string]any{"POST /api/diagnostics/dns_diagnostics/set": answer})
		if r, err := other.DnsLookup("x", ""); !check(r, err) {
			t.Errorf("answer %s: %+v, %v", answer, r, err)
		}
	}
}
