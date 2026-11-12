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
		var body, _ = io.ReadAll(io.LimitReader(response.Body, 4096))
		return &StreamRefusedError{Endpoint: endpoint, ContentType: contentType, Answer: streamShorten(body)}
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

// StreamRefusedError is returned by Stream when OPNsense answers 200 but not with an event stream. Answer is the
// (shortened) body. Since 26.7.9 OPNsense serves at most 15 streams at once (all users and sessions together, e.g.
// live views open in the GUI) and answers further ones with the plain text "Unable to open stream, max slots (15)
// used", translated to the language of the API user; Busy tells whether the answer is that text
type StreamRefusedError struct {
	Endpoint    string
	ContentType string
	Answer      string
}

func (e *StreamRefusedError) Error() string {
	if e.Busy() {
		return fmt.Sprintf("OPNsense has no free stream slot, other live views (GUI or API) use them all: %q", e.Answer)
	}
	if e.Answer == "" {
		return fmt.Sprintf("%s did not answer with an event stream but an empty %q (unsupported endpoint or OPNsense version?)",
			e.Endpoint, e.ContentType)
	}
	return fmt.Sprintf("%s did not answer with an event stream but %q: %s", e.Endpoint, e.ContentType, e.Answer)
}

// Busy tells whether OPNsense refused the stream because all its stream slots are in use (26.7.9 and later), a
// retry can succeed once other streams end. As the text may be translated, any short plain text answer counts:
// the API answers JSON otherwise, a web page (like a login page of a proxy) is HTML
func (e *StreamRefusedError) Busy() bool {
	if strings.Contains(e.Answer, "max slots") {
		return true
	}
	return e.Answer != "" && len(e.Answer) <= 200 && !strings.ContainsAny(e.Answer[:1], "{[<\"")
}

// IsStreamBusy tells whether err is (or wraps) a StreamRefusedError of a busy OPNsense, see StreamRefusedError.Busy
func IsStreamBusy(err error) bool {
	var refused *StreamRefusedError
	return errors.As(err, &refused) && refused.Busy()
}

// streamShorten makes a non stream answer printable: whitespace collapsed, at most 200 characters
func streamShorten(body []byte) string {
	var text = strings.Join(strings.Fields(string(body)), " ")
	if runes := []rune(text); len(runes) > 200 {
		text = string(runes[:200]) + "..."
	}
	return text
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
