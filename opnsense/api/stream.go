package api

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// StreamEvent is one server-sent event of a text/event-stream response
type StreamEvent struct {
	Event string // "message" when the server did not name the event
	Data  string // multiple data: lines are joined by "\n"
	Id    string
}

// StreamKeepalive is the event OPNsense sends about every second on idle streams, Stream does not pass it on
const StreamKeepalive = "keepalive"

// Stream GETs a text/event-stream endpoint (e.g. api/diagnostics/log/core/system/live) and calls handle for every event,
// skipping keepalives. It returns when ctx is cancelled (nil), the server closes the stream (io.EOF) or handle returns an error
func (opn *OPNsense) Stream(ctx context.Context, endpoint string, handle func(StreamEvent) error) error {
	request, reqCreationErr := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if reqCreationErr != nil {
		return reqCreationErr
	}
	request.Header.Set("Accept", "text/event-stream")

	response, reqErr := opn.SendStream(request)
	if reqErr != nil {
		if ctx.Err() != nil {
			return nil
		}
		return reqErr
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		var body, _ = io.ReadAll(io.LimitReader(response.Body, 4096))
		return &HttpError{StatusCode: response.StatusCode, Message: strings.TrimSpace(string(body))}
	}
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/event-stream") {
		return fmt.Errorf("%s did not answer with an event stream but %q (unsupported endpoint or OPNsense version?)", endpoint, contentType)
	}

	var err = ParseEventStream(response.Body, func(event StreamEvent) error {
		if event.Event == StreamKeepalive {
			return nil
		}
		return handle(event)
	})
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// ParseEventStream reads server-sent events from reader until EOF (returned as io.EOF) or handle returns an error
func ParseEventStream(reader io.Reader, handle func(StreamEvent) error) error {
	var scanner = bufio.NewScanner(reader)
	// single events like firewall log entries can be long
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var event StreamEvent
	var data []string
	var hasData bool
	for scanner.Scan() {
		var line = scanner.Text()
		if line == "" { // a blank line dispatches the event
			if hasData || event.Event != "" {
				if event.Event == "" {
					event.Event = "message"
				}
				event.Data = strings.Join(data, "\n")
				if err := handle(event); err != nil {
					return err
				}
			}
			event, data, hasData = StreamEvent{}, nil, false
			continue
		}
		if strings.HasPrefix(line, ":") { // comment
			continue
		}

		var field, value, _ = strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			event.Event = value
		case "data":
			data = append(data, value)
			hasData = true
		case "id":
			event.Id = value
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return io.EOF
}
