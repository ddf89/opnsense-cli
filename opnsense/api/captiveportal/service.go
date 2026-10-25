package captiveportal

import (
	"fmt"
	"strings"
)

// ServiceStatus returns the state of the captive portal service: running, stopped, disabled (no enabled zone) or
// unknown
func (opn *CaptivePortalApi) ServiceStatus() (string, error) {
	var answer struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("service", "status"), nil, &answer); err != nil {
		return "", err
	}
	if answer.Status == "" {
		return "", fmt.Errorf("unexpected answer from captive portal service status: no status given")
	}
	return answer.Status, nil
}

// ServiceReconfigure applies the saved zones and templates: regenerates and reloads the ipfw rules (also those of
// the traffic shaper), the portal web servers and restarts the captive portal service, or stops it when no zone is
// enabled. It answers {"status":"ok"}, or a status naming the ipfw error
func (opn *CaptivePortalApi) ServiceReconfigure() error {
	var answer struct {
		Status string `json:"status"`
	}
	// actions must be POSTed, a GET answers {"status":"failed"}
	if err := opn.DoJSON("POST", opn.endpoint("service", "reconfigure"), nil, &answer); err != nil {
		return err
	}
	if answer.Status != "ok" {
		return fmt.Errorf("captive portal reconfigure failed: %s", answer.Status)
	}
	return nil
}

// ServiceStart starts the captive portal service
func (opn *CaptivePortalApi) ServiceStart() error {
	return opn.serviceAction("start")
}

// ServiceStop stops the captive portal service
func (opn *CaptivePortalApi) ServiceStop() error {
	return opn.serviceAction("stop")
}

// ServiceRestart restarts the captive portal service
func (opn *CaptivePortalApi) ServiceRestart() error {
	return opn.serviceAction("restart")
}

// serviceAction POSTs start / stop / restart, OPNsense passes the configd answer through as {"response":"OK"}
func (opn *CaptivePortalApi) serviceAction(action string) error {
	var answer struct {
		Response any `json:"response"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("service", action), nil, &answer); err != nil {
		return err
	}
	if response, isString := answer.Response.(string); !isString || !strings.EqualFold(strings.TrimSpace(response), "OK") {
		return fmt.Errorf("captive portal service %s failed: unexpected response %v", action, answer.Response)
	}
	return nil
}
