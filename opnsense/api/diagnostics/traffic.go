package diagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	coreapi "opnsense-cli/opnsense/api"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Reporting > Traffic (api/diagnostics/traffic, OPNsense\Diagnostics\Api\TrafficController):
//   - interface: per-interface totals since boot (configd "interface show traffic", ifconfig counters as strings)
//   - stream/<seconds>: text/event-stream, one event every <seconds> (at least 1) with the counter DELTAS since the
//     previous event (scripts/interfaces/traffic_stats.php). The first event is a baseline taken right after the
//     initial snapshot, so it is (nearly) all zero
//   - top/<interfaces>: top talkers per interface, measured by iftop over ~2 seconds per request (not a stream)
// Only enabled, non-virtual interfaces are reported, keyed by their OPNsense name (lan, wan, opt1, ...)

// TrafficCount is a counter, OPNsense sends it as JSON number or numeric string
type TrafficCount int64

func (c *TrafficCount) UnmarshalJSON(data []byte) error {
	var text = strings.Trim(string(data), `"`)
	if text == "" || text == "null" {
		*c = 0
		return nil
	}
	if value, err := strconv.ParseInt(text, 10, 64); err == nil {
		*c = TrafficCount(value)
		return nil
	}
	var value, err = strconv.ParseFloat(text, 64)
	if err != nil {
		return fmt.Errorf("invalid counter %s", data)
	}
	*c = TrafficCount(value)
	return nil
}

// TrafficCounters are the counter deltas of one interface for one interval of TrafficStream
type TrafficCounters struct {
	Name       string       `json:"name"` // description, e.g. "LAN"
	InBytes    TrafficCount `json:"inbytes"`
	OutBytes   TrafficCount `json:"outbytes"`
	InPkts     TrafficCount `json:"inpkts"`
	OutPkts    TrafficCount `json:"outpkts"`
	InErrs     TrafficCount `json:"inerrs"`
	OutErrs    TrafficCount `json:"outerrs"`
	Collisions TrafficCount `json:"collisions"`
}

// TrafficSample is one event of TrafficStream
type TrafficSample struct {
	Interfaces map[string]TrafficCounters // keyed by interface (lan, wan, opt1, ...)
	Time       float64                    // unix time with fraction
	Raw        json.RawMessage            // the event data as sent by OPNsense
}

// Timestamp returns Time as time.Time
func (s TrafficSample) Timestamp() time.Time {
	var seconds = int64(s.Time)
	return time.Unix(seconds, int64((s.Time-float64(seconds))*1e9))
}

// TrafficRate is the throughput of one interface over one interval
type TrafficRate struct {
	Interface           string  `json:"interface"`
	Name                string  `json:"name"`
	Seconds             float64 `json:"seconds"` // length of the interval
	InBitsPerSecond     float64 `json:"in_bps"`
	OutBitsPerSecond    float64 `json:"out_bps"`
	InPacketsPerSecond  float64 `json:"in_pps"`
	OutPacketsPerSecond float64 `json:"out_pps"`
	Errors              int64   `json:"errors"` // input + output errors + collisions within the interval
}

// TrafficRates converts the deltas of current into rates over the time passed since previous, sorted by interface.
// Returns nil when no time passed
func TrafficRates(previous TrafficSample, current TrafficSample) []TrafficRate {
	var seconds = current.Time - previous.Time
	if seconds <= 0 {
		return nil
	}
	var keys = make([]string, 0, len(current.Interfaces))
	for key := range current.Interfaces {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var rates = make([]TrafficRate, 0, len(keys))
	for _, key := range keys {
		var c = current.Interfaces[key]
		rates = append(rates, TrafficRate{
			Interface:           key,
			Name:                c.Name,
			Seconds:             seconds,
			InBitsPerSecond:     float64(c.InBytes) * 8 / seconds,
			OutBitsPerSecond:    float64(c.OutBytes) * 8 / seconds,
			InPacketsPerSecond:  float64(c.InPkts) / seconds,
			OutPacketsPerSecond: float64(c.OutPkts) / seconds,
			Errors:              int64(c.InErrs + c.OutErrs + c.Collisions),
		})
	}
	return rates
}

// TrafficStream streams api/diagnostics/traffic/stream/<intervalSeconds> and calls handle for every sample
// (including the initial baseline). Returns like (*OPNsense).Stream: nil on ctx cancel, io.EOF when OPNsense closes
// the stream, otherwise the error of the request or handle
func (opn *DiagnosticsApi) TrafficStream(ctx context.Context, intervalSeconds int, handle func(TrafficSample) error) error {
	if intervalSeconds < 1 {
		return fmt.Errorf("traffic interval must be at least 1 second, got %d", intervalSeconds)
	}
	var endpoint = opn.endpoint("traffic", fmt.Sprintf("stream/%d", intervalSeconds))
	return opn.Stream(ctx, endpoint, func(event coreapi.StreamEvent) error {
		var sample, err = trafficParseSample(event.Data)
		if err != nil {
			return err
		}
		return handle(sample)
	})
}

func trafficParseSample(data string) (TrafficSample, error) {
	// {"interfaces":{"lan":{"inbytes":66,...,"name":"LAN"}},"time":1792886639.86}, PHP sends "interfaces":[] when empty
	var container struct {
		Interfaces json.RawMessage `json:"interfaces"`
		Time       *float64        `json:"time"`
	}
	if err := json.Unmarshal([]byte(data), &container); err != nil {
		return TrafficSample{}, fmt.Errorf("unexpected traffic event %q: %w", data, err)
	}
	if container.Time == nil {
		return TrafficSample{}, fmt.Errorf("unexpected traffic event without time: %q", data)
	}
	var sample = TrafficSample{Interfaces: map[string]TrafficCounters{}, Time: *container.Time, Raw: json.RawMessage(data)}
	if err := trafficDecodeObject(container.Interfaces, &sample.Interfaces); err != nil {
		return TrafficSample{}, fmt.Errorf("unexpected traffic event %q: %w", data, err)
	}
	return sample, nil
}

// TrafficFollowOptions configures the reconnects of TrafficWatch and CpuWatch, zero values use the defaults
type TrafficFollowOptions struct {
	// OnReconnect is called (when not nil) before waiting delay to reconnect after the stream failed or ended
	OnReconnect func(err error, delay time.Duration)
	// MinDelay / MaxDelay bound the exponential reconnect backoff (defaults 1s / 30s)
	MinDelay time.Duration
	MaxDelay time.Duration
	// Sleep waits d or until ctx is cancelled (false), for tests. Default: a timer
	Sleep func(ctx context.Context, d time.Duration) bool
}

// trafficCallbackError marks errors raised while handling an event (invalid event data or the caller's handle),
// they end a follow instead of reconnecting
type trafficCallbackError struct {
	err error
}

func (e *trafficCallbackError) Error() string {
	return e.err.Error()
}

func (e *trafficCallbackError) Unwrap() error {
	return e.err
}

// trafficFollow runs connect (one stream connection) until ctx is cancelled (nil) or a permanent error occurs.
// connect reports whether the connection passed anything on to the caller. Permanent are: errors of the event
// handling (trafficCallbackError, returned unwrapped), HTTP 4xx answers, and a first connection that fails without
// delivering anything (e.g. not an event stream, unreachable). Everything else (stream closed, network errors,
// 5xx later on) is retried with exponential backoff, a connection that delivered something resets the backoff
func trafficFollow(ctx context.Context, options TrafficFollowOptions, connect func() (bool, error)) error {
	var minDelay, maxDelay = options.MinDelay, options.MaxDelay
	if minDelay <= 0 {
		minDelay = time.Second
	}
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second
	}
	var sleep = options.Sleep
	if sleep == nil {
		sleep = trafficSleep
	}

	var delay = minDelay
	var first = true
	for {
		var delivered, err = connect()
		if ctx.Err() != nil {
			return nil
		}
		var callbackErr *trafficCallbackError
		if errors.As(err, &callbackErr) {
			return callbackErr.err
		}
		var httpErr *coreapi.HttpError
		if errors.As(err, &httpErr) && httpErr.StatusCode < 500 {
			return err
		}
		if first && !delivered && err != nil && err != io.EOF {
			return err
		}
		first = false
		if err == nil {
			err = io.EOF
		}
		if delivered {
			delay = minDelay
		}
		if options.OnReconnect != nil {
			options.OnReconnect(err, delay)
		}
		if !sleep(ctx, delay) {
			return nil
		}
		delay = min(delay*2, maxDelay)
	}
}

func trafficSleep(ctx context.Context, d time.Duration) bool {
	var timer = time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// TrafficWatch streams traffic like TrafficStream until ctx is cancelled (nil) or handle returns an error, skipping
// the baseline event of every connection and handing every following sample to handle together with its rates.
// Dropped streams are reconnected with backoff (see TrafficFollowOptions), each reconnect starts with a new baseline.
// 4xx answers, answers that are no event stream, invalid events and a first connection that fails are returned
func (opn *DiagnosticsApi) TrafficWatch(ctx context.Context, intervalSeconds int, options TrafficFollowOptions, handle func(TrafficSample, []TrafficRate) error) error {
	if intervalSeconds < 1 {
		return fmt.Errorf("traffic interval must be at least 1 second, got %d", intervalSeconds)
	}
	var endpoint = opn.endpoint("traffic", fmt.Sprintf("stream/%d", intervalSeconds))
	return trafficFollow(ctx, options, func() (bool, error) {
		var previous *TrafficSample
		var delivered = false
		var err = opn.Stream(ctx, endpoint, func(event coreapi.StreamEvent) error {
			var sample, err = trafficParseSample(event.Data)
			if err != nil {
				return &trafficCallbackError{err}
			}
			if previous != nil {
				delivered = true
				if err := handle(sample, TrafficRates(*previous, sample)); err != nil {
					return &trafficCallbackError{err}
				}
			}
			previous = &sample
			return nil
		})
		return delivered, err
	})
}

// TrafficInterface are the totals of one interface since boot as reported by ifconfig, all values are strings
// (e.g. "bytes received", "packets transmitted", "mtu", "line rate", "device", "name")
type TrafficInterface map[string]string

// TrafficInterfaces returns the totals of all enabled, non-virtual interfaces keyed by interface (lan, wan, ...)
func (opn *DiagnosticsApi) TrafficInterfaces() (map[string]TrafficInterface, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("traffic", "interface"), nil, &raw); err != nil {
		return nil, err
	}
	var container struct {
		Interfaces json.RawMessage `json:"interfaces"`
	}
	if err := json.Unmarshal(raw, &container); err != nil {
		return nil, fmt.Errorf("unexpected answer from traffic interface: %w", err)
	}
	if container.Interfaces == nil {
		return nil, fmt.Errorf("unexpected answer from traffic interface: no interfaces")
	}

	var decoded map[string]map[string]any
	if err := trafficDecodeObject(container.Interfaces, &decoded); err != nil {
		return nil, fmt.Errorf("unexpected answer from traffic interface: %w", err)
	}
	var result = make(map[string]TrafficInterface, len(decoded))
	for key, fields := range decoded {
		var values = make(TrafficInterface, len(fields))
		for field, value := range fields {
			switch v := value.(type) {
			case string:
				values[field] = v
			case nil:
				values[field] = ""
			default:
				var encoded, _ = json.Marshal(v)
				values[field] = string(encoded)
			}
		}
		result[key] = values
	}
	return result, nil
}

// TrafficTopDetail is one remote end a host talked to
type TrafficTopDetail struct {
	Address         string   `json:"address"`
	Rate            string   `json:"rate"` // iftop format, e.g. "1.2Kb"
	RateBits        int64    `json:"rate_bits"`
	Cumulative      string   `json:"cumulative"`
	CumulativeBytes int64    `json:"cumulative_bytes"`
	Tags            []string `json:"tags"`
}

// TrafficTopHost is one host of the top talkers, rates are in bits/s (averaged over ~2 seconds),
// cumulative values in bytes. Tags may contain "local" (an address of the firewall) and "private"
type TrafficTopHost struct {
	Address            string             `json:"address"`
	ReverseName        string             `json:"rname"`
	RateBitsIn         int64              `json:"rate_bits_in"`
	RateBitsOut        int64              `json:"rate_bits_out"`
	RateBits           int64              `json:"rate_bits"`
	CumulativeBytesIn  int64              `json:"cumulative_bytes_in"`
	CumulativeBytesOut int64              `json:"cumulative_bytes_out"`
	CumulativeBytes    int64              `json:"cumulative_bytes"`
	RateIn             string             `json:"rate_in"`
	RateOut            string             `json:"rate_out"`
	Rate               string             `json:"rate"`
	CumulativeIn       string             `json:"cumulative_in"`
	CumulativeOut      string             `json:"cumulative_out"`
	Cumulative         string             `json:"cumulative"`
	Tags               []string           `json:"tags"`
	Details            []TrafficTopDetail `json:"details"`
}

// TrafficTopInterface is the top talkers result of one interface, sorted by rate (highest first, at most 200).
// Status is "ok" or "timeout" (iftop did not finish within 10 seconds)
type TrafficTopInterface struct {
	Status  string           `json:"status"`
	Records []TrafficTopHost `json:"records"`
}

// TrafficTop measures the top talkers of the given interfaces (OPNsense names like lan, wan, opt1) for ~2 seconds.
// Unknown and disabled interfaces are silently left out of the answer by OPNsense. The raw answer is returned too
func (opn *DiagnosticsApi) TrafficTop(interfaces []string) (map[string]TrafficTopInterface, json.RawMessage, error) {
	if len(interfaces) == 0 {
		return nil, nil, fmt.Errorf("no interface given")
	}
	for _, name := range interfaces {
		if name == "" || strings.ContainsAny(name, ",/?#% ") {
			return nil, nil, fmt.Errorf("invalid interface name %q", name)
		}
	}
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("traffic", "top/"+strings.Join(interfaces, ",")), nil, &raw); err != nil {
		return nil, nil, err
	}
	var result = map[string]TrafficTopInterface{}
	if err := trafficDecodeObject(raw, &result); err != nil {
		return nil, nil, fmt.Errorf("unexpected answer from traffic top: %w", err)
	}
	return result, raw, nil
}

// trafficDecodeObject decodes a JSON object into out, accepting the empty array PHP sends for an empty object
func trafficDecodeObject(raw json.RawMessage, out any) error {
	var trimmed = bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("[]")) || bytes.Equal(trimmed, []byte("null")) || len(trimmed) == 0 {
		return nil
	}
	return json.Unmarshal(trimmed, out)
}
