package system

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Power > Reboot and Power > Power Off of the web UI (/ui/core/reboot, /ui/core/halt) are backed by
// api/core/system/reboot and api/core/system/halt (OPNsense\Core\Api\SystemController). Both only act on a POST:
// they start the configd action detached and answer {"status":"ok"}, any other method answers {"status":"failed"}
// without doing anything.

const (
	// PowerDefaultWaitTimeout is the overall time PowerWaitUntilUp waits when no timeout is given
	PowerDefaultWaitTimeout = 10 * time.Minute
	// PowerDefaultPollInterval is the time between two probes of PowerWaitUntilUp when no interval is given
	PowerDefaultPollInterval = 5 * time.Second
	// PowerDefaultProbeTimeout limits a single probe, a powered off box often does not refuse but drops connections
	PowerDefaultProbeTimeout = 5 * time.Second
)

func (opn *SystemApi) powerEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("core", "system", method)
}

// PowerReboot reboots the system (Power > Reboot). The call returns as soon as OPNsense accepted the reboot,
// use PowerWaitUntilUp to wait for the system to come back
func (opn *SystemApi) PowerReboot() error {
	return opn.powerAction("reboot")
}

// PowerOff halts and powers off the system (Power > Power Off). It does not come back without physical or
// console access
func (opn *SystemApi) PowerOff() error {
	return opn.powerAction("halt")
}

func (opn *SystemApi) powerAction(action string) error {
	var container struct {
		Status string `json:"status"`
	}
	// must be POSTed, OPNsense answers anything else with {"status":"failed"} and does nothing
	if err := opn.DoJSON("POST", opn.powerEndpoint(action), nil, &container); err != nil {
		return err
	}
	if container.Status != "ok" {
		return fmt.Errorf("system %s was not accepted: status %q", action, container.Status)
	}
	return nil
}

// PowerWaitState is reported to PowerWaitOptions.Progress when the state of the system changes
type PowerWaitState string

const (
	// PowerStateDown the API stopped answering (the reboot is in progress)
	PowerStateDown PowerWaitState = "down"
	// PowerStateUp the API answers again after it was down
	PowerStateUp PowerWaitState = "up"
)

// PowerWaitEvent is one state change seen by PowerWaitUntilUp
type PowerWaitEvent struct {
	State PowerWaitState
	// Elapsed since PowerWaitUntilUp was called
	Elapsed time.Duration
	// Err is why the system was considered down (only set for PowerStateDown)
	Err error
}

// PowerWaitOptions configures PowerWaitUntilUp, zero values use the defaults
type PowerWaitOptions struct {
	// Timeout for the whole wait (going down and coming back), default PowerDefaultWaitTimeout
	Timeout time.Duration
	// PollInterval between two probes, default PowerDefaultPollInterval
	PollInterval time.Duration
	// ProbeTimeout limits a single probe request, default PowerDefaultProbeTimeout
	ProbeTimeout time.Duration
	// Progress is called on every state change, optional
	Progress func(PowerWaitEvent)
	// Now and Sleep replace the clock (for tests), default time.Now and time.Sleep
	Now   func() time.Time
	Sleep func(time.Duration)
}

func (o PowerWaitOptions) withDefaults() PowerWaitOptions {
	if o.Timeout <= 0 {
		o.Timeout = PowerDefaultWaitTimeout
	}
	if o.PollInterval <= 0 {
		o.PollInterval = PowerDefaultPollInterval
	}
	if o.ProbeTimeout <= 0 {
		o.ProbeTimeout = PowerDefaultProbeTimeout
	}
	if o.Progress == nil {
		o.Progress = func(PowerWaitEvent) {}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = time.Sleep
	}
	return o
}

// PowerWaitUntilUp waits after PowerReboot until the system first stops answering and then answers again.
// It polls the read-only api/core/system/status, the system counts as up when that answers 200 with its JSON
// status document; connection errors, timeouts, non 200 answers and other bodies count as down.
// Returns an error when the timeout expires, either because the system never went down (the reboot did
// not start or was too quick to be noticed) or because it did not come back
func (opn *SystemApi) PowerWaitUntilUp(options PowerWaitOptions) error {
	options = options.withDefaults()
	var start = options.Now()
	var deadline = start.Add(options.Timeout)
	var wentDown = false
	var lastErr error

	for {
		var err = opn.powerProbe(options.ProbeTimeout)
		var elapsed = options.Now().Sub(start)
		if !wentDown {
			if err != nil {
				wentDown = true
				lastErr = err
				options.Progress(PowerWaitEvent{State: PowerStateDown, Elapsed: elapsed, Err: err})
			}
		} else if err == nil {
			options.Progress(PowerWaitEvent{State: PowerStateUp, Elapsed: elapsed})
			return nil
		} else {
			lastErr = err
		}

		var remaining = deadline.Sub(options.Now())
		if remaining <= 0 {
			if !wentDown {
				return fmt.Errorf("timed out after %s: the system kept answering and never went down, the reboot did not start (or was missed)", options.Timeout)
			}
			return fmt.Errorf("timed out after %s waiting for the system to come back up (last error: %v)", options.Timeout, lastErr)
		}
		options.Sleep(min(options.PollInterval, remaining))
	}
}

// powerProbe returns nil when api/core/system/status answers like a running OPNsense
func (opn *SystemApi) powerProbe(timeout time.Duration) error {
	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var endpoint = opn.powerEndpoint("status")
	var request, err = http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")

	response, err := opn.Send(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", response.StatusCode, endpoint)
	}
	// e.g. {"metadata":{"system":{"status":2,"message":"No pending messages","title":"System"},...},"subsystems":[]}
	var container struct {
		Metadata json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(body, &container); err != nil || !bytes.HasPrefix(bytes.TrimSpace(container.Metadata), []byte("{")) {
		return fmt.Errorf("unexpected answer from %s", endpoint)
	}
	return nil
}
