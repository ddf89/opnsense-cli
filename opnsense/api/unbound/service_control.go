package unbound

import (
	"fmt"
	"strings"
)

// ServiceStart starts Unbound, OPNsense answers {"response":"OK"} on success
func (opn *UnboundApi) ServiceStart() error {
	return opn.serviceResponse("start")
}

// ServiceStop stops Unbound (the DNS resolver of the firewall and usually its clients)
func (opn *UnboundApi) ServiceStop() error {
	return opn.serviceResponse("stop")
}

func (opn *UnboundApi) serviceResponse(action string) error {
	var container struct {
		Response any `json:"response"`
	}
	// actions must be POSTed, a GET is a silent no-op
	if err := opn.DoJSON("POST", opn.serviceEndpoint(action), nil, &container); err != nil {
		return err
	}
	if response, isString := container.Response.(string); !isString || strings.TrimSpace(response) != "OK" {
		return fmt.Errorf("unbound %s failed: unexpected response %v", action, container.Response)
	}
	return nil
}

// ServiceReconfigureGeneral is ServiceReconfigure as the General page does it: it also reloads the system DNS
// configuration and restarts the DHCP servers (needed after changing enabled, DHCP registration, ...)
func (opn *UnboundApi) ServiceReconfigureGeneral() error {
	return opn.serviceStatus("reconfigure_general", "reconfiguring unbound")
}

// ServiceDnsbl downloads the blocklists of the enabled DNSBL policies and loads them into Unbound
func (opn *UnboundApi) ServiceDnsbl() error {
	return opn.serviceStatus("dnsbl", "updating the unbound blocklists")
}

// serviceStatus POSTs an action answering {"status":"ok"} (configd output like "OK")
func (opn *UnboundApi) serviceStatus(action string, what string) error {
	var container struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.serviceEndpoint(action), nil, &container); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(container.Status), "ok") {
		return fmt.Errorf("%s failed: %q", what, strings.TrimSpace(container.Status))
	}
	return nil
}
