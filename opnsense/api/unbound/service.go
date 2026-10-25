package unbound

import (
	"fmt"
	"strings"
)

func (opn *UnboundApi) serviceEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("unbound", "service", method)
}

// ServiceRestart restarts Unbound, OPNsense answers {"response":"OK"} on success
func (opn *UnboundApi) ServiceRestart() error {
	var container struct {
		Response string `json:"response"`
	}
	if err := opn.DoJSON("POST", opn.serviceEndpoint("restart"), nil, &container); err != nil {
		return err
	}
	if strings.TrimSpace(container.Response) != "OK" {
		return fmt.Errorf("restarting unbound failed: %q", container.Response)
	}
	return nil
}

// ServiceReconfigure applies the configuration (e.g. host overrides), OPNsense answers {"status":"ok"} on success
func (opn *UnboundApi) ServiceReconfigure() error {
	var container struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.serviceEndpoint("reconfigure"), nil, &container); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(container.Status), "ok") {
		return fmt.Errorf("reconfiguring unbound failed: %q", container.Status)
	}
	return nil
}

// ServiceStatus returns the service status like running, stopped or disabled
func (opn *UnboundApi) ServiceStatus() (string, error) {
	var container struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.serviceEndpoint("status"), nil, &container); err != nil {
		return "", err
	}
	return container.Status, nil
}
