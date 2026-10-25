package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

type testRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   map[string]any
}

// newTestApi starts a fake OPNsense answering every request with the status and raw JSON of handler, all requests
// are recorded
func newTestApi(t *testing.T, handler func(r testRequest) (int, string)) (*AuthApi, *[]testRequest) {
	t.Helper()
	var requests []testRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var recorded = testRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query()}
		var raw, _ = io.ReadAll(r.Body)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &recorded.Body); err != nil {
				t.Errorf("invalid request body %q: %v", raw, err)
			}
		}
		requests = append(requests, recorded)
		var status, body = handler(recorded)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)

	var baseUrl, _ = url.Parse(server.URL)
	return &AuthApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, &requests
}

// posts returns the POST requests
func posts(requests []testRequest) []testRequest {
	var result []testRequest
	for _, request := range requests {
		if request.Method == "POST" {
			result = append(result, request)
		}
	}
	return result
}

func wantBody(t *testing.T, request testRequest, want map[string]any) {
	t.Helper()
	if !reflect.DeepEqual(request.Body, want) {
		var got, _ = json.Marshal(request.Body)
		var wanted, _ = json.Marshal(want)
		t.Errorf("body of %s %s:\n got  %s\n want %s", request.Method, request.Path, got, wanted)
	}
}

func TestDecodeOptions(t *testing.T) {
	var options, err = decodeOptions(json.RawMessage(`{"b":{"value":"B","selected":1},"a":{"value":"A","selected":0}}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := []Option{{Key: "b", Value: "B", Selected: true}, {Key: "a", Value: "A"}}; !reflect.DeepEqual(options, want) {
		t.Errorf("got %+v", options)
	}
	// PHP sends a map with the keys 0..n-1 as a list
	options, err = decodeOptions(json.RawMessage(`[{"value":"root","selected":"1"},{"value":"alice","selected":0}]`))
	if err != nil {
		t.Fatal(err)
	}
	if want := []Option{{Key: "0", Value: "root", Selected: true}, {Key: "1", Value: "alice"}}; !reflect.DeepEqual(options, want) {
		t.Errorf("got %+v", options)
	}
	if _, err := decodeOptions(json.RawMessage(`"x"`)); err == nil {
		t.Error("want an error for a string")
	}
}
