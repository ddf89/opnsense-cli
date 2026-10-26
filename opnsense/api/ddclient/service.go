package ddclient

import "fmt"

// ServiceStatus returns the state of the ddclient service: running, stopped or disabled (general.enabled off)
func (opn *DdclientApi) ServiceStatus() (string, error) {
	var answer struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("service", "status"), nil, &answer); err != nil {
		return "", err
	}
	if answer.Status == "" {
		return "", fmt.Errorf("unexpected answer of dyndns/service/status: no status")
	}
	return answer.Status, nil
}

// ServiceStart starts the service
func (opn *DdclientApi) ServiceStart() error { return opn.serviceAction("start") }

// ServiceStop stops the service
func (opn *DdclientApi) ServiceStop() error { return opn.serviceAction("stop") }

// ServiceRestart restarts the service
func (opn *DdclientApi) ServiceRestart() error { return opn.serviceAction("restart") }

// ServiceReconfigure applies the saved configuration: writes it and restarts the service, stops it when disabled.
// OPNsense answers {"status":"ok"}
func (opn *DdclientApi) ServiceReconfigure() error {
	var answer struct {
		Status    string `json:"status"`
		StatusMsg string `json:"status_msg"`
	}
	// actions must be POSTed, a GET is silently ignored ({"status":"failed"})
	if err := opn.DoJSON("POST", opn.endpoint("service", "reconfigure"), nil, &answer); err != nil {
		return err
	}
	if answer.Status != "ok" {
		if answer.StatusMsg != "" {
			return fmt.Errorf("ddclient reconfigure failed: %s", answer.StatusMsg)
		}
		return fmt.Errorf("ddclient reconfigure failed: status %q", answer.Status)
	}
	return nil
}

// serviceAction POSTs start/stop/restart, OPNsense answers {"response":"OK"}
func (opn *DdclientApi) serviceAction(action string) error {
	var answer struct {
		Response any `json:"response"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("service", action), nil, &answer); err != nil {
		return err
	}
	if response, isString := answer.Response.(string); !isString || response != "OK" {
		return fmt.Errorf("ddclient service %s failed: unexpected response %v", action, answer.Response)
	}
	return nil
}
