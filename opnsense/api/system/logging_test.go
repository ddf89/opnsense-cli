package system

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"strings"
	"testing"
)

const loggingTestDestinationRows = `{"rows":[
	{"uuid":"d1","enabled":"0","transport":"udp4","%transport":"UDP(4)","program":"","level":"","facility":"","hostname":"192.0.2.10","certificate":"","port":"514","rfc5424":"0","description":"remote"},
	{"uuid":"d2","enabled":"1","transport":"tcp4","%transport":"TCP(4)","program":"filterlog","level":"info,err","facility":"","hostname":"192.0.2.11","certificate":"","port":"1514","rfc5424":"1","description":"dup"},
	{"uuid":"d3","enabled":"1","transport":"udp4","%transport":"UDP(4)","program":"","level":"","facility":"","hostname":"192.0.2.12","certificate":"","port":"514","rfc5424":"0","description":"dup"},
	{"uuid":"d4","enabled":"1","transport":"udp4","%transport":"UDP(4)","program":"","level":"","facility":"","hostname":"192.0.2.13","certificate":"","port":"514","rfc5424":"0","description":"remote-2"}
],"rowCount":4,"total":4,"current":1}`

// loggingTestRequest is a request the fake OPNsense received
type loggingTestRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   string
}

// loggingTestServer answers search_destinations with the test rows, every other endpoint with responses[path]
// (unknown endpoints get an empty 200 like OPNsense). Received requests are appended to requests
func loggingTestServer(t *testing.T, responses map[string]string, requests *[]loggingTestRequest) *SystemApi {
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		*requests = append(*requests, loggingTestRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Body: string(body)})

		if r.URL.Path == "/api/syslog/settings/search_destinations" {
			_, _ = w.Write([]byte(loggingTestDestinationRows))
			return
		}
		if response, found := responses[r.URL.Path]; found {
			_, _ = w.Write([]byte(response))
		}
	}))
	t.Cleanup(server.Close)

	var baseUrl, _ = url.Parse(server.URL)
	return &SystemApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}
}

// loggingTestBody decodes a JSON request body
func loggingTestBody(t *testing.T, body string) map[string]any {
	var decoded map[string]any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("invalid request body %q: %v", body, err)
	}
	return decoded
}

func TestLoggingGeneralGet(t *testing.T) {
	var requests []loggingTestRequest
	var api = loggingTestServer(t, map[string]string{
		"/api/syslog/settings/get": `{"syslog":{"general":{"enabled":"1","loglocal":"1","maxpreserve":"31","maxfilesize":""},"destinations":{"destination":[]}}}`,
	}, &requests)

	var general, err = api.LoggingGeneralGet()
	if err != nil {
		t.Fatal(err)
	}
	if general != (LoggingGeneral{Enabled: "1", LogLocal: "1", MaxPreserve: "31", MaxFileSize: ""}) {
		t.Errorf("unexpected %+v", general)
	}
}

func TestLoggingGeneralSetSendsOnlyGivenFields(t *testing.T) {
	var requests []loggingTestRequest
	var api = loggingTestServer(t, map[string]string{
		"/api/syslog/settings/set": `{"result":"saved"}`,
	}, &requests)

	var maxPreserve, maxFileSize = "30", ""
	if err := api.LoggingGeneralSet(LoggingGeneralFields{MaxPreserve: &maxPreserve, MaxFileSize: &maxFileSize}); err != nil {
		t.Fatal(err)
	}

	var body = loggingTestBody(t, requests[0].Body)
	var general = body["syslog"].(map[string]any)["general"].(map[string]any)
	if requests[0].Method != "POST" || len(general) != 2 || general["maxpreserve"] != "30" || general["maxfilesize"] != "" {
		t.Errorf("expected POST with only maxpreserve and maxfilesize, got %s %s", requests[0].Method, requests[0].Body)
	}
}

func TestLoggingGeneralSetValidationError(t *testing.T) {
	var requests []loggingTestRequest
	var api = loggingTestServer(t, map[string]string{
		"/api/syslog/settings/set": `{"result":"failed","validations":{"syslog.general.maxpreserve":["Invalid integer value."]}}`,
	}, &requests)

	var maxPreserve = "abc"
	var err = api.LoggingGeneralSet(LoggingGeneralFields{MaxPreserve: &maxPreserve})
	var validationErr *coreapi.ValidationError
	if !errors.As(err, &validationErr) || validationErr.Validations["syslog.general.maxpreserve"] != "Invalid integer value." {
		t.Fatalf("expected ValidationError for maxpreserve, got %v", err)
	}
}

func TestLoggingDestinationFind(t *testing.T) {
	var requests []loggingTestRequest
	var api = loggingTestServer(t, nil, &requests)

	// "remote" must not match "remote-2"
	var destination, err = api.LoggingDestinationFind("remote")
	if err != nil || destination.Uuid != "d1" || destination.Hostname != "192.0.2.10" {
		t.Fatalf("expected d1, got %+v, %v", destination, err)
	}
	if requests[0].Query.Get("searchPhrase") != "remote" {
		t.Errorf("expected searchPhrase remote, got %q", requests[0].Query.Get("searchPhrase"))
	}

	_, err = api.LoggingDestinationFind("REMOTE")
	if !coreapi.IsNotFound(err) {
		t.Fatalf("expected NotFoundError (exact match), got %v", err)
	}

	_, err = api.LoggingDestinationFind("dup")
	var tooMany *coreapi.TooManyFoundError
	if !errors.As(err, &tooMany) || !strings.Contains(tooMany.Name, "d2") || !strings.Contains(tooMany.Name, "d3") {
		t.Fatalf("expected TooManyFoundError listing d2 and d3, got %v", err)
	}
}

func TestLoggingDestinationGet(t *testing.T) {
	var requests []loggingTestRequest
	var api = loggingTestServer(t, map[string]string{
		"/api/syslog/settings/get_destination/d2": `{"destination":{"enabled":"1",
			"transport":{"udp4":{"value":"UDP(4)","selected":0},"tcp4":{"value":"TCP(4)","selected":1}},
			"program":{"filterlog":{"value":"filter (filterlog)","selected":1},"audit":{"value":"audit","selected":0},"unbound":{"value":"resolver (unbound)","selected":1}},
			"level":{"info":{"value":"info","selected":1},"warn":{"value":"warn","selected":0},"err":{"value":"error","selected":1}},
			"facility":{"kern":{"value":"kernel messages","selected":0}},
			"hostname":"192.0.2.11","certificate":{"":{"value":"None","selected":1},"abc":{"value":"cert","selected":0}},
			"port":"1514","rfc5424":"1","description":"dup"}}`,
		"/api/syslog/settings/get_destination/nope": `[]`,
	}, &requests)

	var destination, err = api.LoggingDestinationGet("d2")
	if err != nil {
		t.Fatal(err)
	}
	var expected = LoggingDestination{
		Uuid: "d2", Enabled: "1", Transport: "tcp4", Program: "filterlog,unbound", Level: "info,err", Facility: "",
		Hostname: "192.0.2.11", Certificate: "", Port: "1514", Rfc5424: "1", Description: "dup",
	}
	if destination != expected {
		t.Errorf("expected %+v, got %+v", expected, destination)
	}

	if _, err = api.LoggingDestinationGet("nope"); !coreapi.IsNotFound(err) {
		t.Fatalf("expected NotFoundError, got %v", err)
	}
}

func TestLoggingDestinationCreate(t *testing.T) {
	var requests []loggingTestRequest
	var api = loggingTestServer(t, map[string]string{
		"/api/syslog/settings/add_destination": `{"result":"saved","uuid":"new"}`,
	}, &requests)

	var uuid, err = api.LoggingDestinationCreate(LoggingDestination{Uuid: "ignored", Enabled: "0", Transport: "udp4", Hostname: "192.0.2.10"})
	if err != nil || uuid != "new" {
		t.Fatalf("expected uuid new, got %q, %v", uuid, err)
	}

	var destination = loggingTestBody(t, requests[0].Body)["destination"].(map[string]any)
	if _, found := destination["uuid"]; found {
		t.Errorf("uuid must not be sent: %s", requests[0].Body)
	}
	if _, found := destination["port"]; found {
		t.Errorf("empty port must be omitted to use the OPNsense default: %s", requests[0].Body)
	}
	if destination["enabled"] != "0" || destination["hostname"] != "192.0.2.10" {
		t.Errorf("unexpected body %s", requests[0].Body)
	}
}

func TestLoggingDestinationUpdate(t *testing.T) {
	var requests []loggingTestRequest
	var unknown = "0b3c6a1e-2f4d-4e5a-9b7c-8d9e0f1a2b3c"
	var api = loggingTestServer(t, map[string]string{
		"/api/syslog/settings/get_destination/d1":         `{"destination":{"description":"d1"}}`,
		"/api/syslog/settings/get_destination/gone":       `{"destination":{"description":"gone"}}`,
		"/api/syslog/settings/get_destination/bad":        `{"destination":{"description":"bad"}}`,
		"/api/syslog/settings/get_destination/" + unknown: `[]`,
		"/api/syslog/settings/set_destination/d1":         `{"result":"saved"}`,
		"/api/syslog/settings/set_destination/gone":       `{"result":"failed"}`,
		"/api/syslog/settings/set_destination/bad":        `{"result":"failed","validations":{"destination.port":"Please specify a valid port number (1-65535)."}}`,
		// OPNsense 26.7 creates the destination when set_destination is called with a well-formed unknown uuid
		"/api/syslog/settings/set_destination/" + unknown: `{"result":"saved"}`,
	}, &requests)

	var port, level = "1514", ""
	if err := api.LoggingDestinationUpdate("d1", LoggingDestinationFields{Port: &port, Level: &level}); err != nil {
		t.Fatal(err)
	}
	// the existence check comes first
	if len(requests) != 2 || requests[0].Method != "GET" || requests[0].Path != "/api/syslog/settings/get_destination/d1" {
		t.Fatalf("expected GET get_destination/d1 before the update, got %v", requests)
	}
	var destination = loggingTestBody(t, requests[1].Body)["destination"].(map[string]any)
	if len(destination) != 2 || destination["port"] != "1514" || destination["level"] != "" {
		t.Errorf("expected only port and level, got %s", requests[1].Body)
	}

	requests = nil
	if err := api.LoggingDestinationUpdate(unknown, LoggingDestinationFields{Port: &port}); !coreapi.IsNotFound(err) {
		t.Errorf("expected NotFoundError, got %v", err)
	}
	for _, request := range requests {
		if request.Method != "GET" {
			t.Errorf("an unknown uuid must not be written: %s %s", request.Method, request.Path)
		}
	}

	// deleted between the existence check and the write: bare failure
	if err := api.LoggingDestinationUpdate("gone", LoggingDestinationFields{Port: &port}); !coreapi.IsNotFound(err) {
		t.Errorf("expected NotFoundError, got %v", err)
	}

	var validationErr *coreapi.ValidationError
	if err := api.LoggingDestinationUpdate("bad", LoggingDestinationFields{Port: &port}); !errors.As(err, &validationErr) {
		t.Errorf("expected ValidationError, got %v", err)
	}
}

func TestLoggingDestinationSetEnabled(t *testing.T) {
	var requests []loggingTestRequest
	var api = loggingTestServer(t, map[string]string{
		"/api/syslog/settings/toggle_destination/d1/1":   `{"result":"Enabled","changed":true}`,
		"/api/syslog/settings/toggle_destination/d2/1":   `{"result":"Enabled","changed":false}`,
		"/api/syslog/settings/toggle_destination/nope/0": `{"result":"failed"}`,
	}, &requests)

	if changed, err := api.LoggingDestinationSetEnabled("d1", true); err != nil || !changed {
		t.Errorf("expected changed, got %v, %v", changed, err)
	}
	if changed, err := api.LoggingDestinationSetEnabled("d2", true); err != nil || changed {
		t.Errorf("expected unchanged, got %v, %v", changed, err)
	}
	if _, err := api.LoggingDestinationSetEnabled("nope", false); !coreapi.IsNotFound(err) {
		t.Errorf("expected NotFoundError, got %v", err)
	}
	if requests[0].Method != "POST" || requests[0].Body == "" {
		t.Errorf("toggle must be POSTed with a JSON body, got %s %q", requests[0].Method, requests[0].Body)
	}
}

func TestLoggingDestinationRemove(t *testing.T) {
	var requests []loggingTestRequest
	var api = loggingTestServer(t, map[string]string{
		"/api/syslog/settings/del_destination/d1":   `{"result":"deleted"}`,
		"/api/syslog/settings/del_destination/nope": `{"result":"not found"}`,
	}, &requests)

	if err := api.LoggingDestinationRemove("d1"); err != nil {
		t.Fatal(err)
	}
	if err := api.LoggingDestinationRemove("nope"); !coreapi.IsNotFound(err) {
		t.Errorf("expected NotFoundError, got %v", err)
	}
}

func TestLoggingService(t *testing.T) {
	var requests []loggingTestRequest
	var api = loggingTestServer(t, map[string]string{
		"/api/syslog/service/status":      `{"status":"running","widget":{}}`,
		"/api/syslog/service/restart":     `{"response":"OK"}`,
		"/api/syslog/service/reconfigure": `{"status":"failed","status_msg":"boom"}`,
	}, &requests)

	if status, err := api.LoggingServiceStatus(); err != nil || status != "running" {
		t.Errorf("expected running, got %q, %v", status, err)
	}
	if err := api.LoggingServiceRestart(); err != nil {
		t.Errorf("expected restart ok, got %v", err)
	}
	if err := api.LoggingServiceReconfigure(); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("expected reconfigure error with status_msg, got %v", err)
	}
	for _, request := range requests[1:] {
		if request.Method != "POST" {
			t.Errorf("%s must be POSTed, got %s", request.Path, request.Method)
		}
	}
}

func TestLoggingStatsFiltersClientSide(t *testing.T) {
	var requests []loggingTestRequest
	var api = loggingTestServer(t, map[string]string{
		"/api/syslog/service/stats": `{"total":2,"rowCount":9999,"current":1,"rows":[
			{"#":"a","Description":"","SourceName":"destination","SourceId":"d_local_dnsmasq","SourceInstance":"","State":"a","Type":"processed","Number":"316"},
			{"#":"b","Description":"","SourceName":"global","SourceId":"internal_source","SourceInstance":"","State":"a","Type":"dropped","Number":"0"}]}`,
	}, &requests)

	var stats, err = api.LoggingStats("DNSMASQ")
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 1 || stats[0].SourceId != "d_local_dnsmasq" || stats[0].Number != "316" {
		t.Errorf("expected only the dnsmasq counter, got %+v", stats)
	}

	stats, err = api.LoggingStats("")
	if err != nil || len(stats) != 2 {
		t.Errorf("expected all counters, got %+v, %v", stats, err)
	}
}
