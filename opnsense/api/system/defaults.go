package system

import (
	"fmt"
)

// Defaults describes what System > Configuration > Defaults resets the firewall to
type Defaults struct {
	// LAN address of the factory default configuration, e.g. 192.168.1.1
	DefaultIp string `json:"default_ip"`
}

func (opn *SystemApi) defaultsEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("core", "defaults", method)
}

// DefaultsGet returns what a factory reset will reset the firewall to
func (opn *SystemApi) DefaultsGet() (Defaults, error) {
	var defaults Defaults
	if err := opn.DoJSON("GET", opn.defaultsEndpoint("get"), nil, &defaults); err != nil {
		return Defaults{}, err
	}
	if defaults.DefaultIp == "" {
		return Defaults{}, fmt.Errorf("unexpected answer from core defaults: no default_ip given")
	}
	return defaults, nil
}

// DefaultsFactoryReset resets the WHOLE configuration to factory defaults and reboots the firewall.
// All settings, including users and API keys, are lost. OPNsense schedules the reset and answers
// {"status":"ok"} before it starts, so a nil error only means the reset was accepted.
func (opn *SystemApi) DefaultsFactoryReset() error {
	var container struct {
		Status string `json:"status"`
	}
	// the endpoint only acts on POST, any other method is answered with {"status":"failed"}
	if err := opn.DoJSON("POST", opn.defaultsEndpoint("factory_defaults"), map[string]any{}, &container); err != nil {
		return err
	}
	if container.Status != "ok" {
		return fmt.Errorf("factory reset was not accepted, status: %q", container.Status)
	}
	return nil
}
