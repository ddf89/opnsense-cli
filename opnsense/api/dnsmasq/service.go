package dnsmasq

import (
	"fmt"
)

func (opn *DnsmasqApi) serviceEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("dnsmasq", "service", method)
}

// ServiceStatus returns the state of the dnsmasq service: running, stopped, disabled or unknown
func (opn *DnsmasqApi) ServiceStatus() (string, error) {
	var container struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.serviceEndpoint("status"), nil, &container); err != nil {
		return "", err
	}
	if container.Status == "" {
		return "", fmt.Errorf("unexpected answer from dnsmasq service status: no status given")
	}
	return container.Status, nil
}

// ServiceReconfigure applies the saved configuration (regenerates the config and reloads/restarts dnsmasq).
// OPNsense answers {"status":"ok"} or {"status":"failed","status_msg":"..."}
func (opn *DnsmasqApi) ServiceReconfigure() error {
	var container struct {
		Status    string `json:"status"`
		StatusMsg string `json:"status_msg"`
	}
	// actions must be POSTed, a GET is silently ignored by OPNsense
	if err := opn.DoJSON("POST", opn.serviceEndpoint("reconfigure"), nil, &container); err != nil {
		return err
	}
	if container.Status != "ok" {
		if container.StatusMsg != "" {
			return fmt.Errorf("dnsmasq reconfigure failed: %s", container.StatusMsg)
		}
		return fmt.Errorf("dnsmasq reconfigure failed: status %q", container.Status)
	}
	return nil
}

// ServiceRestart restarts the dnsmasq service
func (opn *DnsmasqApi) ServiceRestart() error {
	return opn.serviceAction("restart")
}

// ServiceStart starts the dnsmasq service
func (opn *DnsmasqApi) ServiceStart() error {
	return opn.serviceAction("start")
}

// ServiceStop stops the dnsmasq service
func (opn *DnsmasqApi) ServiceStop() error {
	return opn.serviceAction("stop")
}

// serviceAction POSTs start/stop/restart. OPNsense passes the configd result through as {"response":"OK"},
// configd answers e.g. "Execute error" when the action failed
func (opn *DnsmasqApi) serviceAction(action string) error {
	var container struct {
		Response any `json:"response"`
	}
	// actions must be POSTed, a GET is silently ignored by OPNsense and answers {"response":[]}
	if err := opn.DoJSON("POST", opn.serviceEndpoint(action), nil, &container); err != nil {
		return err
	}
	if response, isString := container.Response.(string); !isString || response != "OK" {
		return fmt.Errorf("dnsmasq service %s failed: unexpected response %v", action, container.Response)
	}
	return nil
}
