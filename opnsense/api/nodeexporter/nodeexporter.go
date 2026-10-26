// Package nodeexporter wraps the API of the OPNsense plugin os-node_exporter (Services > Node Exporter,
// api/nodeexporter/general and api/nodeexporter/service), the Prometheus exporter for machine metrics: its general
// settings and its service.
//
// Behaviour of the API this package relies on (verified on 26.7.7 with os-node_exporter 1.2):
//   - without the plugin every endpoint answers HTTP 404 {"errorMessage":"Endpoint not found"} (*api.HttpError)
//   - general/set is a partial merge, unsent fields are kept; changes only take effect with ServiceReconfigure,
//     which stops node_exporter, regenerates its rc.conf.d file and starts it again when enabled
//   - service/start and service/restart answer {"response":"OK"} although nothing was started while node_exporter's
//     rc.conf.d says NO (rc.d refuses and exits 0): when disabled (service/status says "disabled") and when
//     enabled but not reconfigured yet (service/status says "stopped")
//   - the listen address accepts "any" and other non-addresses that end up verbatim in node_exporter's
//     --web.listen-address, the CLI accepts only IP addresses
//   - the plugin's rc.conf.d template ignores the interrupts collector flag (1.2): node_exporter never gets
//     --collector.interrupts
//   - the metrics themselves are only served by node_exporter on its own port, there is no OPNsense API for them
package nodeexporter

import (
	"errors"
	"fmt"
	"slices"

	coreapi "opnsense-cli/opnsense/api"
)

// NodeExporterApi wraps api/nodeexporter
//
//goland:noinspection GoNameStartsWithPackageName
type NodeExporterApi struct {
	*coreapi.OPNsense
}

// Plugin is the name of the OPNsense plugin package that provides this API
const Plugin = "os-node_exporter"

func (opn *NodeExporterApi) endpoint(controller string, method string) string {
	return opn.EndpointForPluginControllerMethod("nodeexporter", controller, method)
}

// CollectorNames are the collectors the plugin switches on and off, in the order of the settings page.
// Collectors not listed here keep node_exporter's own default
var CollectorNames = []string{"cpu", "exec", "filesystem", "loadavg", "meminfo", "netdev", "time", "devstat", "interrupts", "ntp", "zfs"}

// Settings are the general settings (api/nodeexporter/general/get). Flags are "1"/"0"
type Settings struct {
	Enabled       string `json:"enabled"`
	ListenAddress string `json:"listenaddress"`
	ListenPort    string `json:"listenport"`
	Cpu           string `json:"cpu"`
	Exec          string `json:"exec"`
	Filesystem    string `json:"filesystem"`
	Loadavg       string `json:"loadavg"`
	Meminfo       string `json:"meminfo"`
	Netdev        string `json:"netdev"`
	Time          string `json:"time"`
	Devstat       string `json:"devstat"`
	Interrupts    string `json:"interrupts"`
	Ntp           string `json:"ntp"`
	Zfs           string `json:"zfs"`
}

// collector returns the flag of a collector of CollectorNames
func (s *Settings) collector(name string) *string {
	switch name {
	case "cpu":
		return &s.Cpu
	case "exec":
		return &s.Exec
	case "filesystem":
		return &s.Filesystem
	case "loadavg":
		return &s.Loadavg
	case "meminfo":
		return &s.Meminfo
	case "netdev":
		return &s.Netdev
	case "time":
		return &s.Time
	case "devstat":
		return &s.Devstat
	case "interrupts":
		return &s.Interrupts
	case "ntp":
		return &s.Ntp
	case "zfs":
		return &s.Zfs
	}
	return nil
}

// Collectors returns the enabled collectors in the order of CollectorNames
func (s Settings) Collectors() []string {
	var enabled = []string{}
	for _, name := range CollectorNames {
		if *s.collector(name) == "1" {
			enabled = append(enabled, name)
		}
	}
	return enabled
}

// SettingsUpdate are the settings to change, nil fields are kept
type SettingsUpdate struct {
	Enabled       *bool
	ListenAddress *string
	ListenPort    *int
	// Collectors are exactly the collectors to enable (names of CollectorNames), the others are disabled; nil keeps
	// them, an empty non-nil list disables all
	Collectors []string
}

// SettingsGet returns the general settings
func (opn *NodeExporterApi) SettingsGet() (Settings, error) {
	var answer struct {
		General *Settings `json:"general"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("general", "get"), nil, &answer); err != nil {
		return Settings{}, err
	}
	if answer.General == nil {
		return Settings{}, errors.New("unexpected answer of nodeexporter/general/get: no settings")
	}
	return *answer.General, nil
}

// SettingsSet changes the given settings, the others are kept. They are only saved, ServiceReconfigure applies them
func (opn *NodeExporterApi) SettingsSet(update SettingsUpdate) error {
	var fields = map[string]string{}
	if update.Enabled != nil {
		fields["enabled"] = flag(*update.Enabled)
	}
	if update.ListenAddress != nil {
		fields["listenaddress"] = *update.ListenAddress
	}
	if update.ListenPort != nil {
		fields["listenport"] = fmt.Sprint(*update.ListenPort)
	}
	if update.Collectors != nil {
		for _, name := range update.Collectors {
			if !slices.Contains(CollectorNames, name) {
				return fmt.Errorf("unknown collector %q", name)
			}
		}
		for _, name := range CollectorNames {
			fields[name] = flag(slices.Contains(update.Collectors, name))
		}
	}
	if len(fields) == 0 {
		return errors.New("nothing to change")
	}
	_, err := opn.Mutate(opn.endpoint("general", "set"), map[string]any{"general": fields})
	return err
}

func flag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// Service states of ServiceStatus
const (
	StatusRunning  = "running"
	StatusStopped  = "stopped"
	StatusDisabled = "disabled"
	StatusUnknown  = "unknown"
)

// ServiceStatus returns the state of node_exporter: running, stopped, disabled (not enabled in the settings) or
// unknown (rc.d answered neither running nor not running)
func (opn *NodeExporterApi) ServiceStatus() (string, error) {
	var answer struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("service", "status"), nil, &answer); err != nil {
		return "", err
	}
	if answer.Status == "" {
		return "", errors.New("unexpected answer of nodeexporter/service/status: no status")
	}
	return answer.Status, nil
}

// ServiceStart starts node_exporter. OPNsense answers OK without starting anything while it is disabled
func (opn *NodeExporterApi) ServiceStart() error {
	return opn.serviceAction("start")
}

// ServiceStop stops node_exporter (until the next reconfigure or boot)
func (opn *NodeExporterApi) ServiceStop() error {
	return opn.serviceAction("stop")
}

// ServiceRestart restarts node_exporter
func (opn *NodeExporterApi) ServiceRestart() error {
	return opn.serviceAction("restart")
}

// serviceAction POSTs start/stop/restart (a GET is silently ignored), OPNsense passes configd's answer through as
// {"response":"OK"}
func (opn *NodeExporterApi) serviceAction(action string) error {
	var answer struct {
		Response any `json:"response"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("service", action), nil, &answer); err != nil {
		return err
	}
	if response, isString := answer.Response.(string); !isString || response != "OK" {
		return fmt.Errorf("node_exporter %s failed: unexpected response %v", action, answer.Response)
	}
	return nil
}

// ServiceReconfigure applies the saved settings: stops node_exporter, regenerates its configuration and starts it
// when enabled. OPNsense answers {"status":"ok"} or {"status":"failed","status_msg":"..."}
func (opn *NodeExporterApi) ServiceReconfigure() error {
	var answer struct {
		Status    string `json:"status"`
		StatusMsg string `json:"status_msg"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("service", "reconfigure"), nil, &answer); err != nil {
		return err
	}
	if answer.Status != "ok" {
		if answer.StatusMsg != "" {
			return fmt.Errorf("node_exporter reconfigure failed: %s", answer.StatusMsg)
		}
		return fmt.Errorf("node_exporter reconfigure failed: status %q", answer.Status)
	}
	return nil
}
