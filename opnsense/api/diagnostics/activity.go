package diagnostics

import (
	"encoding/json"
	"fmt"
)

// Diagnostics > Activity (api/diagnostics/activity/get_activity, OPNsense\Diagnostics\Api\ActivityController) runs
// "top -aHSTn -d2" through configd (scripts/system/activity.py) and answers
// {"headers":["last pid: ...  load averages: ...","143 threads: ...","CPU: ...","Mem: ..."],"details":[{...}]}.
// There is no stream, follow by polling. The call takes about 2 seconds (top samples twice)

// ActivityThread is one row of top: a thread (top runs with -H), sorted by CPU usage (highest first).
// All values are strings as top prints them
type ActivityThread struct {
	Pid      string `json:"PID"`
	Thread   string `json:"THR"`
	User     string `json:"USERNAME"`
	Priority string `json:"PRI"`
	Nice     string `json:"NICE"`
	Size     string `json:"SIZE"`
	Resident string `json:"RES"`
	State    string `json:"STATE"`
	Cpu      string `json:"C"`
	Time     string `json:"TIME"`
	CpuUsage string `json:"WCPU"` // e.g. "14.55%"
	Command  string `json:"COMMAND"`
}

// Activity is the system activity as shown by top
type Activity struct {
	Headers []string         `json:"headers"` // top's summary lines (load, threads, CPU, Mem, ...)
	Threads []ActivityThread `json:"details"`
	Raw     json.RawMessage  `json:"-"` // the answer as sent by OPNsense
}

// ActivityGet returns the current system activity (top)
func (opn *DiagnosticsApi) ActivityGet() (*Activity, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("activity", "get_activity"), nil, &raw); err != nil {
		return nil, err
	}
	var activity Activity
	if err := json.Unmarshal(raw, &activity); err != nil {
		return nil, fmt.Errorf("unexpected answer from activity: %w", err)
	}
	if activity.Headers == nil && activity.Threads == nil {
		return nil, fmt.Errorf("unexpected answer from activity: no headers and no details")
	}
	activity.Raw = raw
	return &activity, nil
}
