package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"strings"
	"sync"
	"testing"
	"time"
)

const logTestMenu = `[
	{"VisibleName":"System","Url":"","Children":[
		{"VisibleName":"Log Files","Url":"","Children":[
			{"VisibleName":"General","Url":"/ui/diagnostics/log/core/system","Children":[]},
			{"VisibleName":"Backend","Url":"/ui/diagnostics/log/core/configd","Children":[]}
		]},
		{"VisibleName":"Firmware","Url":"","Children":[
			{"VisibleName":"Log File","Url":"/ui/diagnostics/log/core/pkg#tab","Children":[]}
		]}
	]},
	{"VisibleName":"Services","Url":"","Children":[
		{"VisibleName":"HAProxy","Url":"","Children":[
			{"VisibleName":"Log File","Url":"/ui/diagnostics/log/haproxy/haproxy","Children":[]},
			{"VisibleName":"Other Log","Url":"/ui/diagnostics/log/haproxy/system","Children":[]}
		]},
		{"VisibleName":"Foo","Url":"","Children":[
			{"VisibleName":"Log","Url":"/ui/diagnostics/log/foo/shared","Children":[]},
			{"VisibleName":"Same log again","Url":"/ui/diagnostics/log/foo/shared?x=1","Children":[]}
		]},
		{"VisibleName":"Bar","Url":"","Children":[
			{"VisibleName":"Log","Url":"/ui/diagnostics/log/bar/shared","Children":[]}
		]},
		{"VisibleName":"Not a log","Url":"/ui/diagnostics/firewall/log","Children":[]}
	]}
]`

// logTestRequest is a request the fake OPNsense received
type logTestRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   string
}

// logTestServer serves the menu and answers other endpoints with handler (nil: empty 200).
// Received requests are recorded and returned by the requests function
func logTestServer(t *testing.T, handler http.HandlerFunc) (*DiagnosticsApi, func() []logTestRequest) {
	var mutex sync.Mutex
	var requests []logTestRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		mutex.Lock()
		requests = append(requests, logTestRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Body: string(body)})
		mutex.Unlock()

		if r.URL.Path == "/api/core/menu/tree" {
			_, _ = w.Write([]byte(logTestMenu))
			return
		}
		if handler != nil {
			handler(w, r)
		}
	}))
	t.Cleanup(server.Close)

	var baseUrl, _ = url.Parse(server.URL)
	return &DiagnosticsApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, func() []logTestRequest {
		mutex.Lock()
		defer mutex.Unlock()
		return append([]logTestRequest{}, requests...)
	}
}

// logTestEvent renders a live log SSE event, backlog lines are "message" events, new lines "log" events
func logTestEvent(line string, backlog bool) string {
	var event = "log"
	if backlog {
		event = "message"
	}
	var record, _ = json.Marshal(map[string]any{
		"timestamp": "2026-10-25T00:00:00", "parser": "SysLogFormatRFC5424", "facility": 1, "severity": "Notice",
		"process_name": "configd.py", "pid": "428", "rnum": 0, "line": " " + line + "\n",
	})
	return fmt.Sprintf("event: %s\ndata:%s\n\n", event, record)
}

// logTestWriteEvents starts an event stream response and writes events, flushing after each
func logTestWriteEvents(w http.ResponseWriter, events ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	for _, event := range events {
		_, _ = io.WriteString(w, event)
		w.(http.Flusher).Flush()
	}
}

func TestLogList(t *testing.T) {
	var api, _ = logTestServer(t, nil)

	var logFiles, err = api.LogList()
	if err != nil {
		t.Fatal(err)
	}
	var expected = []LogFile{
		{Name: "core/system", Module: "core", Scope: "system", MenuPath: "System > Log Files > General"},
		{Name: "configd", Module: "core", Scope: "configd", MenuPath: "System > Log Files > Backend"},
		{Name: "pkg", Module: "core", Scope: "pkg", MenuPath: "System > Firmware > Log File"},
		{Name: "haproxy", Module: "haproxy", Scope: "haproxy", MenuPath: "Services > HAProxy > Log File"},
		{Name: "haproxy/system", Module: "haproxy", Scope: "system", MenuPath: "Services > HAProxy > Other Log"},
		{Name: "foo/shared", Module: "foo", Scope: "shared", MenuPath: "Services > Foo > Log"},
		{Name: "bar/shared", Module: "bar", Scope: "shared", MenuPath: "Services > Bar > Log"},
	}
	if len(logFiles) != len(expected) {
		t.Fatalf("expected %d logs, got %+v", len(expected), logFiles)
	}
	for i := range expected {
		if logFiles[i] != expected[i] {
			t.Errorf("log %d: expected %+v, got %+v", i, expected[i], logFiles[i])
		}
	}
}

func TestLogResolve(t *testing.T) {
	var api, requests = logTestServer(t, nil)

	var cases = []struct {
		name, module, scope string
	}{
		{"core/system", "core", "system"},
		{"haproxy/haproxy", "haproxy", "haproxy"},
		{"system", "core", "system"},      // core wins over haproxy/system
		{"haproxy", "haproxy", "haproxy"}, // unique plugin scope
	}
	for _, c := range cases {
		var module, scope, err = api.LogResolve(c.name)
		if err != nil || module != c.module || scope != c.scope {
			t.Errorf("%s: expected %s/%s, got %s/%s, %v", c.name, c.module, c.scope, module, scope, err)
		}
	}
	if _, _, err := api.LogResolve("dnsmasq"); !coreapi.IsNotFound(err) || !strings.Contains(err.Error(), "opn diag log list") {
		t.Errorf("expected NotFoundError pointing at the log list for a name not in the menu, got %v", err)
	}
	if len(requests()) != 3 {
		t.Errorf("module/scope names must not fetch the menu, got %d requests", len(requests()))
	}

	var tooMany *coreapi.TooManyFoundError
	if _, _, err := api.LogResolve("shared"); !errors.As(err, &tooMany) || !strings.Contains(err.Error(), "foo/shared") {
		t.Errorf("expected TooManyFoundError listing foo/shared, got %v", err)
	}
	for _, invalid := range []string{"", "a/b/c", "/system", "core/"} {
		if _, _, err := api.LogResolve(invalid); err == nil {
			t.Errorf("expected an error for %q", invalid)
		}
	}
}

func TestLogTail(t *testing.T) {
	var api, requests = logTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"filters":"","rows":[
			{"timestamp":"2026-10-25T00:03:13","parser":"SysLogFormatRFC5424","facility":3,"severity":"Notice","process_name":"dhcp6c","pid":"31413","rnum":1,"line":" newest"},
			{"timestamp":"2026-10-24T23:24:27","parser":"ServiceLogFormat","facility":null,"severity":null,"process_name":"","pid":null,"rnum":2,"line":"oldest\n"}
		],"total_rows":2,"origin":"system","rowCount":2,"total":2,"current":1}`))
	})

	var records, err = api.LogTail("core", "system", 2, LogFilter{SearchPhrase: "sending vtnet1", Severities: []string{"Error", "Warning"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Line != "oldest" || records[1].Line != "newest" {
		t.Fatalf("expected oldest first with trimmed lines, got %+v", records)
	}
	if records[0].Facility != nil || records[0].Severity != "" || *records[1].Facility != 3 || records[1].Pid != "31413" {
		t.Errorf("unexpected fields %+v %+v", records[0], records[1])
	}

	var request = requests()[0]
	var body map[string]any
	_ = json.Unmarshal([]byte(request.Body), &body)
	if request.Method != "POST" || request.Path != "/api/diagnostics/log/core/system" ||
		body["rowCount"] != float64(2) || body["current"] != float64(1) || body["searchPhrase"] != "sending vtnet1" || body["severity"] != "Error,Warning" {
		t.Errorf("unexpected request %s %s %s", request.Method, request.Path, request.Body)
	}

	if records, err = api.LogTail("core", "system", 0, LogFilter{}); err != nil || len(records) != 0 || len(requests()) != 1 {
		t.Errorf("0 lines must not query OPNsense, got %+v, %v", records, err)
	}
}

func TestLogNormalizeSeverity(t *testing.T) {
	for input, expected := range map[string]string{"error": "Error", "ERR": "Error", " warn ": "Warning", "Informational": "Informational", "info": "Informational", "emerg": "Emergency"} {
		if actual, err := LogNormalizeSeverity(input); err != nil || actual != expected {
			t.Errorf("%q: expected %s, got %s, %v", input, expected, actual, err)
		}
	}
	if _, err := LogNormalizeSeverity("loud"); err == nil {
		t.Error("expected an error for an unknown severity")
	}
}

func TestLogClear(t *testing.T) {
	var api, requests = logTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	if err := api.LogClear("core", "system"); err != nil {
		t.Fatal(err)
	}
	if request := requests()[0]; request.Method != "POST" || request.Path != "/api/diagnostics/log/core/system/clear" {
		t.Errorf("unexpected request %s %s", request.Method, request.Path)
	}
}

func TestLogLive(t *testing.T) {
	var api, requests = logTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		logTestWriteEvents(w, logTestEvent("old", true), "event: keepalive\ndata:\n\n", logTestEvent("new", false))
	})

	type received struct {
		line    string
		backlog bool
	}
	var events []received
	var err = api.LogLive(context.Background(), "core", "configd", 5, LogFilter{SearchPhrase: "list ssl", Severities: []string{"Notice", "Error"}},
		func(record LogRecord, backlog bool) error {
			events = append(events, received{record.Line, backlog})
			return nil
		})
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF when the server closes the stream, got %v", err)
	}
	if len(events) != 2 || events[0] != (received{"old", true}) || events[1] != (received{"new", false}) {
		t.Errorf("unexpected events %+v", events)
	}

	var request = requests()[0]
	if request.Path != "/api/diagnostics/log/core/configd/live" || request.Query.Get("offset") != "5" ||
		request.Query.Get("searchPhrase") != "list ssl" || request.Query.Get("severity") != "Notice,Error" {
		t.Errorf("unexpected request %s %v", request.Path, request.Query)
	}
}

// logTestFollow runs LogFollow against connections (one handler per connection, the last one is reused)
// until the handler received want lines, and returns the lines and the requests
func logTestFollow(t *testing.T, lines int, want int, connections ...func(w http.ResponseWriter, r *http.Request)) ([]string, []logTestRequest) {
	var mutex sync.Mutex
	var connection = 0
	var api, requests = logTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		var handler = connections[min(connection, len(connections)-1)]
		connection++
		mutex.Unlock()
		handler(w, r)
	})

	var ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var received []string
	var reconnects = 0
	var err = api.LogFollow(ctx, "core", "configd", LogFollowOptions{
		Lines:       lines,
		MinDelay:    time.Millisecond,
		MaxDelay:    5 * time.Millisecond,
		OnReconnect: func(error, time.Duration) { reconnects++ },
	}, func(record LogRecord) error {
		received = append(received, record.Line)
		if len(received) == want {
			cancel()
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil after cancel, got %v", err)
	}
	if reconnects == 0 && len(connections) > 1 {
		t.Errorf("expected OnReconnect to be called")
	}
	return received, requests()
}

// logTestBlock keeps the stream open until the client goes away
func logTestBlock(r *http.Request) {
	<-r.Context().Done()
}

func TestLogFollowReconnectWithoutDuplicates(t *testing.T) {
	var received, requests = logTestFollow(t, 2, 5,
		func(w http.ResponseWriter, r *http.Request) {
			// tail A B, new C, then the stream drops
			logTestWriteEvents(w, logTestEvent("A", true), logTestEvent("B", true), logTestEvent("C", false))
		},
		func(w http.ResponseWriter, r *http.Request) {
			// D was logged while disconnected: the backlog of 3 is B C D, then new E
			logTestWriteEvents(w, logTestEvent("B", true), logTestEvent("C", true), logTestEvent("D", true), logTestEvent("E", false))
			logTestBlock(r)
		},
	)

	if strings.Join(received, " ") != "A B C D E" {
		t.Errorf("expected A B C D E, got %v", received)
	}
	if requests[0].Query.Get("offset") != "2" || requests[1].Query.Get("offset") != "3" {
		t.Errorf("expected offset 2 then 3, got %s, %s", requests[0].Query.Get("offset"), requests[1].Query.Get("offset"))
	}
}

func TestLogFollowReconnectRepeatedLines(t *testing.T) {
	// identical lines must not be swallowed: the backlog X X Y overlaps the remembered X X, only Y is new
	var received, _ = logTestFollow(t, 2, 4,
		func(w http.ResponseWriter, r *http.Request) {
			logTestWriteEvents(w, logTestEvent("X", true), logTestEvent("X", true))
		},
		func(w http.ResponseWriter, r *http.Request) {
			logTestWriteEvents(w, logTestEvent("X", true), logTestEvent("Y", true), logTestEvent("X", false))
			logTestBlock(r)
		},
	)
	if strings.Join(received, " ") != "X X Y X" {
		t.Errorf("expected X X Y X, got %v", received)
	}
}

func TestLogFollowShortBacklogFlushedByLiveLine(t *testing.T) {
	// the log was cleared while disconnected: fewer backlog lines than requested arrive, the first live line flushes them
	var received, _ = logTestFollow(t, 2, 4,
		func(w http.ResponseWriter, r *http.Request) {
			logTestWriteEvents(w, logTestEvent("A", true), logTestEvent("B", true))
		},
		func(w http.ResponseWriter, r *http.Request) {
			logTestWriteEvents(w, logTestEvent("N1", true), logTestEvent("N2", false))
			logTestBlock(r)
		},
	)
	if strings.Join(received, " ") != "A B N1 N2" {
		t.Errorf("expected A B N1 N2, got %v", received)
	}
}

func TestLogFollowNoTail(t *testing.T) {
	// with 0 lines nothing remembered yet: reconnect without backlog
	var received, requests = logTestFollow(t, 0, 1,
		func(w http.ResponseWriter, r *http.Request) {
			logTestWriteEvents(w)
		},
		func(w http.ResponseWriter, r *http.Request) {
			logTestWriteEvents(w, logTestEvent("new", false))
			logTestBlock(r)
		},
	)
	if strings.Join(received, " ") != "new" || requests[1].Query.Get("offset") != "0" {
		t.Errorf("unexpected %v, offset %s", received, requests[1].Query.Get("offset"))
	}
}

func TestLogFollowStopsOnClientErrors(t *testing.T) {
	var api, requests = logTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"status":401,"message":"Authentication Failed"}`))
	})

	var err = api.LogFollow(context.Background(), "core", "configd", LogFollowOptions{MinDelay: time.Millisecond}, func(LogRecord) error { return nil })
	var httpErr *coreapi.HttpError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != 401 || len(requests()) != 1 {
		t.Errorf("expected a single request failing with HTTP 401, got %v after %d requests", err, len(requests()))
	}

	// a first connection that is not an event stream (unsupported endpoint) is not retried either
	api, requests = logTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	err = api.LogFollow(context.Background(), "core", "configd", LogFollowOptions{MinDelay: time.Millisecond}, func(LogRecord) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "event stream") || len(requests()) != 1 {
		t.Errorf("expected a single request failing with no event stream, got %v after %d requests", err, len(requests()))
	}
}

func TestLogFollowReturnsHandleError(t *testing.T) {
	var api, _ = logTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		logTestWriteEvents(w, logTestEvent("A", true))
		logTestBlock(r)
	})

	var stop = errors.New("stop")
	var err = api.LogFollow(context.Background(), "core", "configd", LogFollowOptions{Lines: 1}, func(LogRecord) error { return stop })
	if !errors.Is(err, stop) {
		t.Errorf("expected the handle error, got %v", err)
	}
}
