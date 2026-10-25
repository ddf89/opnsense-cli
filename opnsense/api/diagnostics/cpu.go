package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
)

// CPU usage of the dashboard widget (api/diagnostics/cpu_usage, OPNsense\Diagnostics\Api\CpuUsageController):
//   - getCPUType: ["Intel(R) ... (4 cores, 8 threads)"]
//   - stream: text/event-stream of "iostat -w 1 cpu" (scripts/system/cpu.py), one event per second:
//     {"total":5,"user":4,"nice":0,"sys":1,"intr":0,"idle":95} in percent, total = 100 - idle.
//     Like iostat, the FIRST event is the average since boot, not the last second

// CpuUsage is one event of CpuStream, all values in percent
type CpuUsage struct {
	Total int             `json:"total"`
	User  int             `json:"user"`
	Nice  int             `json:"nice"`
	Sys   int             `json:"sys"`
	Intr  int             `json:"intr"`
	Idle  int             `json:"idle"`
	Raw   json.RawMessage `json:"-"` // the event data as sent by OPNsense
}

// CpuStream streams api/diagnostics/cpu_usage/stream and calls handle once per second. The first event is the
// average since boot (see CpuWatch). Returns like (*OPNsense).Stream: nil on ctx cancel, io.EOF when OPNsense
// closes the stream, otherwise the error of the request or handle
func (opn *DiagnosticsApi) CpuStream(ctx context.Context, handle func(CpuUsage) error) error {
	return opn.Stream(ctx, opn.endpoint("cpu_usage", "stream"), func(event coreapi.StreamEvent) error {
		var usage, err = cpuParseUsage(event.Data)
		if err != nil {
			return err
		}
		return handle(usage)
	})
}

// CpuWatch streams the CPU usage until ctx is cancelled (nil) or handle returns an error, skipping the first event
// of every connection (the average since boot). Dropped streams are reconnected with backoff like TrafficWatch,
// 4xx answers, answers that are no event stream, invalid events and a first connection that fails are returned
func (opn *DiagnosticsApi) CpuWatch(ctx context.Context, options TrafficFollowOptions, handle func(CpuUsage) error) error {
	var endpoint = opn.endpoint("cpu_usage", "stream")
	return trafficFollow(ctx, options, func() (bool, error) {
		var first = true
		var delivered = false
		var err = opn.Stream(ctx, endpoint, func(event coreapi.StreamEvent) error {
			var usage, err = cpuParseUsage(event.Data)
			if err != nil {
				return &trafficCallbackError{err}
			}
			if first {
				first = false
				return nil
			}
			delivered = true
			if err := handle(usage); err != nil {
				return &trafficCallbackError{err}
			}
			return nil
		})
		return delivered, err
	})
}

func cpuParseUsage(data string) (CpuUsage, error) {
	var container struct {
		Total *int `json:"total"`
		User  *int `json:"user"`
		Nice  *int `json:"nice"`
		Sys   *int `json:"sys"`
		Intr  *int `json:"intr"`
		Idle  *int `json:"idle"`
	}
	if err := json.Unmarshal([]byte(data), &container); err != nil {
		return CpuUsage{}, fmt.Errorf("unexpected cpu usage event %q: %w", data, err)
	}
	if container.Total == nil || container.Idle == nil {
		return CpuUsage{}, fmt.Errorf("unexpected cpu usage event %q: no total/idle", data)
	}
	var value = func(p *int) int {
		if p == nil {
			return 0
		}
		return *p
	}
	return CpuUsage{
		Total: *container.Total, User: value(container.User), Nice: value(container.Nice), Sys: value(container.Sys),
		Intr: value(container.Intr), Idle: *container.Idle, Raw: json.RawMessage(data),
	}, nil
}

// CpuType returns the CPU model with its core and thread count, e.g. "Intel(R) ... (4 cores, 8 threads)"
func (opn *DiagnosticsApi) CpuType() (string, error) {
	var answer []string
	if err := opn.DoJSON("GET", opn.endpoint("cpu_usage", "getCPUType"), nil, &answer); err != nil {
		return "", err
	}
	if len(answer) == 0 || answer[0] == "" {
		return "", fmt.Errorf("unexpected answer from cpu type: %v", answer)
	}
	return answer[0], nil
}
