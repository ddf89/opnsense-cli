package ipsec

import (
	"fmt"
)

// The IPsec service (api/ipsec/service), the global IPsec on/off switch (connections/is_enabled, toggle) and the
// legacy subsystem (pending changes of key pairs and legacy tunnels, legacy_subsystem/status, apply_config)

func (opn *IPsecApi) serviceEndpoint(method string) string {
	return opn.endpoint("service", method)
}

// ServiceStatus returns the state of the strongSwan service: running, stopped, disabled (IPsec is off) or unknown
func (opn *IPsecApi) ServiceStatus() (string, error) {
	var container struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.serviceEndpoint("status"), nil, &container); err != nil {
		return "", err
	}
	if container.Status == "" {
		return "", fmt.Errorf("unexpected answer from ipsec service status: no status given")
	}
	return container.Status, nil
}

// ServiceReconfigure applies the saved configuration: it registers the VTI interfaces, reloads the firewall
// rules, regenerates the strongSwan configuration and (re)loads strongSwan, or stops it when IPsec is disabled.
// OPNsense answers {"status":"ok"} or {"status":"failed","status_msg":"..."}
func (opn *IPsecApi) ServiceReconfigure() error {
	var container struct {
		Status    string `json:"status"`
		StatusMsg string `json:"status_msg"`
	}
	// actions must be POSTed, a GET is answered with {"status":"failed"}
	if err := opn.DoJSON("POST", opn.serviceEndpoint("reconfigure"), nil, &container); err != nil {
		return err
	}
	if container.Status != "ok" {
		return fmt.Errorf("ipsec reconfigure failed: %s", coreapiMessage(container.StatusMsg, container.Status))
	}
	return nil
}

// ServiceStart starts strongSwan (configd "ipsec start": the full IPsec configure, it does nothing while IPsec is
// disabled)
func (opn *IPsecApi) ServiceStart() error {
	return opn.serviceAction("start")
}

// ServiceStop stops strongSwan, all tunnels go down
func (opn *IPsecApi) ServiceStop() error {
	return opn.serviceAction("stop")
}

// ServiceRestart stops and starts strongSwan, all tunnels are re-established
func (opn *IPsecApi) ServiceRestart() error {
	return opn.serviceAction("restart")
}

// serviceAction POSTs start/stop/restart. OPNsense passes the configd result through as {"response":"OK"}
func (opn *IPsecApi) serviceAction(action string) error {
	var container struct {
		Response any `json:"response"`
	}
	// a GET is silently ignored by OPNsense and answers {"response":[]}
	if err := opn.DoJSON("POST", opn.serviceEndpoint(action), nil, &container); err != nil {
		return err
	}
	if response, isString := container.Response.(string); !isString || response != "OK" {
		return fmt.Errorf("ipsec service %s failed: unexpected response %v", action, container.Response)
	}
	return nil
}

// IsEnabled tells whether IPsec is enabled (the "Enable IPsec" switch of VPN > IPsec > Connections)
func (opn *IPsecApi) IsEnabled() (bool, error) {
	var answer struct {
		Enabled *bool `json:"enabled"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("connections", "is_enabled"), nil, &answer); err != nil {
		return false, err
	}
	if answer.Enabled == nil {
		return false, fmt.Errorf("unexpected answer from ipsec/connections/is_enabled")
	}
	return *answer.Enabled, nil
}

// SetEnabled switches IPsec on or off (connections/toggle/<1|0>). Like in the GUI this only saves the switch,
// ServiceReconfigure applies it (starting or stopping strongSwan)
func (opn *IPsecApi) SetEnabled(enabled bool) error {
	var answer struct {
		Status string `json:"status"`
	}
	var endpoint = opn.endpoint("connections", "toggle") + "/" + map[bool]string{true: "1", false: "0"}[enabled]
	if err := opn.DoJSON("POST", endpoint, nil, &answer); err != nil {
		return err
	}
	if answer.Status != "ok" {
		return fmt.Errorf("switching ipsec %s failed: status %q", map[bool]string{true: "on", false: "off"}[enabled], answer.Status)
	}
	return nil
}

// LegacyStatus is the state of the legacy subsystem
type LegacyStatus struct {
	// Enabled tells whether IPsec is enabled
	Enabled bool `json:"enabled"`
	// Pending (isDirty) is set by changes of key pairs (and legacy tunnels) until ApplyLegacy
	Pending bool `json:"isDirty"`
}

// LegacyStatus returns whether IPsec is enabled and whether key pair changes wait to be applied
func (opn *IPsecApi) LegacyStatus() (LegacyStatus, error) {
	var status LegacyStatus
	if err := opn.DoJSON("GET", opn.endpoint("legacy_subsystem", "status"), nil, &status); err != nil {
		return LegacyStatus{}, err
	}
	return status, nil
}

// ApplyLegacy applies the pending changes like the Apply button of the key pairs page (configd "ipsec reload",
// the full IPsec configure) and clears the pending flag
func (opn *IPsecApi) ApplyLegacy() error {
	var answer struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("legacy_subsystem", "apply_config"), nil, &answer); err != nil {
		return err
	}
	if answer.Status != "ok" {
		return fmt.Errorf("applying the ipsec configuration failed: status %q", answer.Status)
	}
	return nil
}
