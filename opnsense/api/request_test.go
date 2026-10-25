package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// recordedRequest is what the test server saw of the last request
type recordedRequest struct {
	Method      string
	Path        string
	RawQuery    string
	Query       url.Values
	Body        string
	ContentType string
	Accept      string
	User        string
	Password    string
	HasAuth     bool
}

// newTestOPNsense starts a test server answering every request with status and body
func newTestOPNsense(t *testing.T, status int, body string) (*OPNsense, *recordedRequest) {
	t.Helper()
	var recorded = new(recordedRequest)
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody, _ = io.ReadAll(r.Body)
		recorded.Method = r.Method
		recorded.Path = r.URL.Path
		recorded.RawQuery = r.URL.RawQuery
		recorded.Query = r.URL.Query()
		recorded.Body = string(reqBody)
		recorded.ContentType = r.Header.Get("Content-Type")
		recorded.Accept = r.Header.Get("Accept")
		recorded.User, recorded.Password, recorded.HasAuth = r.BasicAuth()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	var baseUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &OPNsense{BaseUrl: *baseUrl, ApiKey: "the-key", ApiSecret: "the-secret"}, recorded
}

func TestDoJSONSuccess(t *testing.T) {
	var opn, recorded = newTestOPNsense(t, 200, `{"status":"running"}`)

	var out struct {
		Status string `json:"status"`
	}
	var endpoint = opn.EndpointForPluginControllerMethod("dnsmasq", "service", "status")
	if err := opn.DoJSON("GET", endpoint, nil, &out); err != nil {
		t.Fatal(err)
	}
	if out.Status != "running" {
		t.Errorf("status = %q, want running", out.Status)
	}
	if recorded.Method != "GET" || recorded.Path != "/api/dnsmasq/service/status" {
		t.Errorf("request = %s %s", recorded.Method, recorded.Path)
	}
	if recorded.Accept != "application/json" {
		t.Errorf("Accept = %q", recorded.Accept)
	}
	if recorded.ContentType != "" || recorded.Body != "" {
		t.Errorf("request without body sent Content-Type %q / body %q", recorded.ContentType, recorded.Body)
	}
}

func TestDoJSONSendsBodyAndBasicAuth(t *testing.T) {
	var opn, recorded = newTestOPNsense(t, 200, `{}`)

	var body = map[string]any{"host": map[string]string{"host": "a b&c"}}
	if err := opn.DoJSON("POST", opn.EndpointForModule("x"), body, nil); err != nil {
		t.Fatal(err)
	}
	if !recorded.HasAuth || recorded.User != "the-key" || recorded.Password != "the-secret" {
		t.Errorf("basic auth = %v %q:%q", recorded.HasAuth, recorded.User, recorded.Password)
	}
	if recorded.ContentType != "application/json" {
		t.Errorf("Content-Type = %q", recorded.ContentType)
	}
	var decoded map[string]map[string]string
	if err := json.Unmarshal([]byte(recorded.Body), &decoded); err != nil || decoded["host"]["host"] != "a b&c" {
		t.Errorf("body = %q (%v)", recorded.Body, err)
	}
}

func TestDoJSONNilOutIgnoresBody(t *testing.T) {
	var opn, _ = newTestOPNsense(t, 200, ``)
	if err := opn.DoJSON("POST", opn.EndpointForModule("x"), nil, nil); err != nil {
		t.Errorf("unexpected error %v", err)
	}
}

func TestDoJSONHttpErrors(t *testing.T) {
	var cases = []struct {
		name    string
		status  int
		body    string
		message string
	}{
		{"json message", 401, `{"status":401,"message":"Authentication Failed"}`, "Authentication Failed"},
		{"json errorMessage", 404, `{"errorMessage":"Endpoint not found"}`, "Endpoint not found"},
		{"plain body", 500, "  Internal Server Error\n", "Internal Server Error"},
		{"json without message", 403, `{"status":403}`, `{"status":403}`},
		{"empty body", 502, ``, ``},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var opn, _ = newTestOPNsense(t, c.status, c.body)
			var out map[string]any
			var err = opn.DoJSON("GET", opn.EndpointForModule("x"), nil, &out)

			var httpErr *HttpError
			if !errors.As(err, &httpErr) {
				t.Fatalf("err = %v (%T), want *HttpError", err, err)
			}
			if httpErr.StatusCode != c.status || httpErr.Message != c.message {
				t.Errorf("HttpError = %d %q, want %d %q", httpErr.StatusCode, httpErr.Message, c.status, c.message)
			}
		})
	}
}

func TestHttpErrorString(t *testing.T) {
	var err = &HttpError{StatusCode: 401, Message: "Authentication Failed"}
	if err.Error() != "HTTP 401: Authentication Failed" {
		t.Errorf("Error() = %q", err.Error())
	}
}

func TestDoJSONEmpty200(t *testing.T) {
	for _, body := range []string{"", " \n"} {
		var opn, _ = newTestOPNsense(t, 200, body)
		var out map[string]any
		var err = opn.DoJSON("GET", opn.EndpointForModule("unknown"), nil, &out)
		if err == nil || !strings.Contains(err.Error(), "empty response from GET") {
			t.Errorf("body %q: err = %v, want empty response error", body, err)
		}
	}
}

func TestDoJSONInvalidJSON(t *testing.T) {
	var opn, _ = newTestOPNsense(t, 200, `<html>`)
	var out map[string]any
	var err = opn.DoJSON("GET", opn.EndpointForModule("x"), nil, &out)
	if err == nil || !strings.Contains(err.Error(), "could not decode response") {
		t.Errorf("err = %v, want decode error", err)
	}
}

func TestDoJSONUnencodableBody(t *testing.T) {
	var opn, _ = newTestOPNsense(t, 200, `{}`)
	if err := opn.DoJSON("POST", opn.EndpointForModule("x"), make(chan int), nil); err == nil {
		t.Errorf("expected an encoding error")
	}
}

func TestMutate(t *testing.T) {
	var cases = []struct {
		name     string
		body     string
		wantUuid string
		check    func(t *testing.T, err error)
	}{
		{"saved with uuid", `{"result":"saved","uuid":"1234-abcd"}`, "1234-abcd", nil},
		{"saved without uuid", `{"result":"saved"}`, "", nil},
		{"deleted", `{"result":"deleted"}`, "", nil},
		{"not found", `{"result":"not found"}`, "", func(t *testing.T, err error) {
			if !IsNotFound(err) {
				t.Errorf("err = %v, want NotFoundError", err)
			}
		}},
		{"failed", `{"result":"failed","validations":{"host.ip":"invalid ip","host.domain":"required"}}`, "", func(t *testing.T, err error) {
			var validationErr *ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("err = %v (%T), want *ValidationError", err, err)
			}
			if len(validationErr.Validations) != 2 || validationErr.Validations["host.ip"] != "invalid ip" {
				t.Errorf("validations = %v", validationErr.Validations)
			}
			if IsNotFound(err) {
				t.Errorf("validation error reported as not found")
			}
		}},
		{"failed with message lists", `{"result":"failed","validations":{"host.ttl":["Invalid integer value."],"host.ip":["a","b"],"host.mx":"plain"}}`, "", func(t *testing.T, err error) {
			var validationErr *ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("err = %v (%T), want *ValidationError", err, err)
			}
			var want = map[string]string{"host.ttl": "Invalid integer value.", "host.ip": "a; b", "host.mx": "plain"}
			for field, message := range want {
				if validationErr.Validations[field] != message {
					t.Errorf("validations[%s] = %q, want %q", field, validationErr.Validations[field], message)
				}
			}
		}},
		{"unexpected", `{"result":"weird"}`, "", func(t *testing.T, err error) {
			if err == nil || !strings.Contains(err.Error(), `unexpected result`) || !strings.Contains(err.Error(), `"weird"`) {
				t.Errorf("err = %v", err)
			}
		}},
		{"no result", `{}`, "", func(t *testing.T, err error) {
			if err == nil || !strings.Contains(err.Error(), `unexpected result`) {
				t.Errorf("err = %v", err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var opn, recorded = newTestOPNsense(t, 200, c.body)
			var uuid, err = opn.Mutate(opn.EndpointForPluginControllerMethod("dnsmasq", "settings", "add_host"), map[string]string{"a": "b"})
			if recorded.Method != "POST" || recorded.Path != "/api/dnsmasq/settings/add_host" {
				t.Errorf("request = %s %s", recorded.Method, recorded.Path)
			}
			if uuid != c.wantUuid {
				t.Errorf("uuid = %q, want %q", uuid, c.wantUuid)
			}
			if c.check == nil {
				if err != nil {
					t.Errorf("unexpected error %v", err)
				}
				return
			}
			c.check(t, err)
		})
	}
}

func TestMutateHttpError(t *testing.T) {
	var opn, _ = newTestOPNsense(t, 401, `{"status":401,"message":"Authentication Failed"}`)
	var _, err = opn.Mutate(opn.EndpointForModule("x"), nil)
	var httpErr *HttpError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != 401 {
		t.Errorf("err = %v, want *HttpError 401", err)
	}
}

func TestValidationErrorString(t *testing.T) {
	var err = &ValidationError{Validations: map[string]string{
		"host.ip":     "invalid ip",
		"host.domain": "required",
		"host.alias":  "too long",
	}}
	var want = "validation failed: host.alias: too long; host.domain: required; host.ip: invalid ip"
	// map iteration is random, repeat to make an unsorted implementation fail reliably
	for i := 0; i < 20; i++ {
		if err.Error() != want {
			t.Fatalf("Error() = %q, want %q", err.Error(), want)
		}
	}

	var empty = &ValidationError{}
	if empty.Error() != "validation failed" {
		t.Errorf("empty Error() = %q", empty.Error())
	}
}

func TestNotFoundError(t *testing.T) {
	var err error = &NotFoundError{Name: "foo"}
	if err.Error() != "not found: foo" {
		t.Errorf("Error() = %q", err.Error())
	}
	if !IsNotFound(err) {
		t.Errorf("IsNotFound(NotFoundError) = false")
	}
	if !IsNotFound(errors.Join(errors.New("context"), err)) {
		t.Errorf("IsNotFound(wrapped NotFoundError) = false")
	}
	if IsNotFound(errors.New("other")) || IsNotFound(nil) {
		t.Errorf("IsNotFound(other) = true")
	}
}

type searchTestRow struct {
	Uuid string `json:"uuid"`
	Host string `json:"host"`
}

func TestSearchWithoutPhrase(t *testing.T) {
	var opn, recorded = newTestOPNsense(t, 200, `{"total":2,"rowCount":2,"current":1,"rows":[{"uuid":"u1","host":"a"},{"uuid":"u2","host":"b"}]}`)

	var rows, err = Search[searchTestRow](opn, opn.EndpointForPluginControllerMethod("dnsmasq", "settings", "search_host"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0] != (searchTestRow{"u1", "a"}) || rows[1] != (searchTestRow{"u2", "b"}) {
		t.Errorf("rows = %+v", rows)
	}
	if recorded.Method != "GET" || recorded.Path != "/api/dnsmasq/settings/search_host" || recorded.RawQuery != "" {
		t.Errorf("request = %s %s?%s", recorded.Method, recorded.Path, recorded.RawQuery)
	}
}

func TestSearchWithPhrase(t *testing.T) {
	var opn, recorded = newTestOPNsense(t, 200, `{"rows":[]}`)

	var rows, err = Search[searchTestRow](opn, opn.EndpointForModule("x"), "a b&c")
	if err != nil {
		t.Fatal(err)
	}
	if rows == nil || len(rows) != 0 {
		t.Errorf("rows = %#v, want empty slice", rows)
	}
	if recorded.RawQuery != "searchPhrase=a+b%26c" {
		t.Errorf("raw query = %q, want escaped phrase", recorded.RawQuery)
	}
	if got := recorded.Query.Get("searchPhrase"); got != "a b&c" {
		t.Errorf("searchPhrase = %q", got)
	}
	if len(recorded.Query) != 1 {
		t.Errorf("phrase leaked into other parameters: %v", recorded.Query)
	}
}

func TestSearchErrors(t *testing.T) {
	var opn, _ = newTestOPNsense(t, 200, ``)
	if _, err := Search[searchTestRow](opn, opn.EndpointForModule("x"), ""); err == nil {
		t.Errorf("expected error for empty answer")
	}

	opn, _ = newTestOPNsense(t, 401, `{"status":401,"message":"Authentication Failed"}`)
	var _, err = Search[searchTestRow](opn, opn.EndpointForModule("x"), "")
	var httpErr *HttpError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != 401 {
		t.Errorf("err = %v, want *HttpError 401", err)
	}
}

func TestFilter(t *testing.T) {
	var even = Filter([]int{1, 2, 3, 4}, func(i int) bool { return i%2 == 0 })
	if len(even) != 2 || even[0] != 2 || even[1] != 4 {
		t.Errorf("Filter = %v", even)
	}
	var none = Filter([]int{1}, func(int) bool { return false })
	if none == nil || len(none) != 0 {
		t.Errorf("Filter without match = %#v, want empty slice", none)
	}
}

func TestVerboseLogsRequests(t *testing.T) {
	var opn, _ = newTestOPNsense(t, 200, `{"status":"ok"}`)
	var output bytes.Buffer
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	if err := opn.DoJSON("GET", opn.EndpointForModule("quiet"), nil, nil); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Errorf("not verbose must log nothing, got %q", output.String())
	}

	opn.Verbose = true
	if err := opn.DoJSON("POST", opn.EndpointForModule("loud"), nil, nil); err != nil {
		t.Fatal(err)
	}
	var logged = output.String()
	for _, want := range []string{"POST ", "/api/loud", "200 OK"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log %q lacks %q", logged, want)
		}
	}
	if strings.Contains(logged, "the-secret") || strings.Contains(logged, "the-key") {
		t.Errorf("credentials must never be logged: %q", logged)
	}
}
