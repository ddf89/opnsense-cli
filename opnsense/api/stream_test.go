package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseEventStream(t *testing.T) {
	var input = "event: keepalive\ndata:\n\n" +
		"event: message\ndata: {\"a\":1}\n\n" +
		": a comment\n" +
		"data: first\ndata: second\nid: 7\n\n" +
		"data: no trailing blank line is not dispatched\n"

	var events []StreamEvent
	var err = ParseEventStream(strings.NewReader(input), func(event StreamEvent) error {
		events = append(events, event)
		return nil
	})
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
	var want = []StreamEvent{
		{Event: "keepalive", Data: ""},
		{Event: "message", Data: `{"a":1}`},
		{Event: "message", Data: "first\nsecond", Id: "7"},
	}
	if !reflect.DeepEqual(events, want) {
		t.Errorf("events = %#v\nwant %#v", events, want)
	}
}

func TestParseEventStreamHandlerError(t *testing.T) {
	var stop = errors.New("stop")
	var count int
	var err = ParseEventStream(strings.NewReader("data: 1\n\ndata: 2\n\n"), func(StreamEvent) error {
		count++
		return stop
	})
	if !errors.Is(err, stop) || count != 1 {
		t.Errorf("err = %v, count = %d", err, count)
	}
}

func newStreamTestOPNsense(t *testing.T, handler http.HandlerFunc) *OPNsense {
	var server = httptest.NewServer(handler)
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &OPNsense{BaseUrl: *baseUrl, ApiKey: "key", ApiSecret: "secret"}
}

func TestStreamSkipsKeepalivesAndEndsWithEOF(t *testing.T) {
	var opn = newStreamTestOPNsense(t, func(w http.ResponseWriter, r *http.Request) {
		if user, pass, ok := r.BasicAuth(); !ok || user != "key" || pass != "secret" {
			t.Errorf("basic auth not sent")
		}
		w.Header().Set("Content-Type", "text/event-stream;charset=UTF-8")
		_, _ = fmt.Fprint(w, "event: keepalive\ndata:\n\nevent: message\ndata: hello\n\n")
	})

	var events []StreamEvent
	var err = opn.Stream(context.Background(), opn.EndpointForModule("x"), func(event StreamEvent) error {
		events = append(events, event)
		return nil
	})
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
	if len(events) != 1 || events[0].Data != "hello" {
		t.Errorf("events = %#v", events)
	}
}

func TestStreamCancelReturnsNil(t *testing.T) {
	var opn = newStreamTestOPNsense(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for {
			if _, err := fmt.Fprint(w, "event: message\ndata: tick\n\n"); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	})

	var ctx, cancel = context.WithCancel(context.Background())
	var count int
	var err = opn.Stream(ctx, opn.EndpointForModule("x"), func(StreamEvent) error {
		count++
		if count == 3 {
			cancel()
		}
		return nil
	})
	if err != nil || count < 3 {
		t.Errorf("err = %v, count = %d", err, count)
	}
}

func TestStreamErrors(t *testing.T) {
	var cases = []struct {
		name        string
		status      int
		contentType string
		body        string
		want        string
	}{
		{"http error", 404, "application/json", `{"errorMessage":"Endpoint not found"}`, "HTTP 404"},
		{"not an event stream", 200, "application/json", `[]`, "did not answer with an event stream"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var opn = newStreamTestOPNsense(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", c.contentType)
				w.WriteHeader(c.status)
				_, _ = fmt.Fprint(w, c.body)
			})
			var err = opn.Stream(context.Background(), opn.EndpointForModule("x"), func(StreamEvent) error { return nil })
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
		})
	}
}
