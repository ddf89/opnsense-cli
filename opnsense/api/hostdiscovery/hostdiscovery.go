// Package hostdiscovery wraps Interfaces > Neighbors > Automatic Discovery (api/hostdiscovery): the settings of the
// hostwatch daemon, which passively watches ARP / NDP traffic on the selected interfaces, the service and the
// discovered hosts
package hostdiscovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// HostDiscoveryApi wraps api/hostdiscovery/settings and api/hostdiscovery/service
//
//goland:noinspection GoNameStartsWithPackageName
type HostDiscoveryApi struct {
	*coreapi.OPNsense
}

func (opn *HostDiscoveryApi) endpoint(controller string, method string) string {
	return opn.EndpointForPluginControllerMethod("hostdiscovery", controller, method)
}

// Settings are the host discovery settings. Booleans are "0" / "1", lists comma separated
type Settings struct {
	Enabled string
	// Promisc puts the watched interfaces in promiscuous mode
	Promisc string
	// Verbose logs every discovery
	Verbose string
	// SkipNets are networks whose addresses are not recorded
	SkipNets string
	// Expire4Interval and Expire6Interval are the seconds after which an unseen IPv4 / IPv6 address is forgotten
	// (at least 3600, "" for the default)
	Expire4Interval string
	Expire6Interval string
	// Interfaces are the watched interfaces (keys like lan, opt1), "" for all
	Interfaces string
	// InterfaceOptions are the interfaces that can be selected, Key is the interface key, Value its description
	InterfaceOptions []InterfaceOption
}

// InterfaceOption is an interface that can be watched
type InterfaceOption struct {
	Key      string
	Value    string
	Selected bool
}

// SettingsFields are the settings to change, nil fields are not sent and kept
type SettingsFields struct {
	Enabled         *string `json:"enabled,omitempty"`
	Promisc         *string `json:"promisc,omitempty"`
	Verbose         *string `json:"verbose,omitempty"`
	SkipNets        *string `json:"skip_nets,omitempty"`
	Expire4Interval *string `json:"expire4_interval,omitempty"`
	Expire6Interval *string `json:"expire6_interval,omitempty"`
	Interfaces      *string `json:"interface,omitempty"`
}

// Host is a discovered host: an IP address seen with a MAC address on an interface
type Host struct {
	// Source is where the data comes from: hostwatch, or arp-ndp (the ARP and NDP tables) when hostwatch does not run
	Source string `json:"source"`
	// Interface is the description of the interface (LAN, WAN, ...)
	Interface    string `json:"interface_name"`
	MAC          string `json:"ether_address"`
	IP           string `json:"ip_address"`
	Organization string `json:"organization_name"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
}

// SettingsGet returns the settings with the interfaces that can be watched
func (opn *HostDiscoveryApi) SettingsGet() (Settings, error) {
	var answer struct {
		Hostdiscovery struct {
			General map[string]json.RawMessage `json:"general"`
		} `json:"hostdiscovery"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("settings", "get"), nil, &answer); err != nil {
		return Settings{}, err
	}
	var general = answer.Hostdiscovery.General
	if general == nil {
		return Settings{}, fmt.Errorf("unexpected answer from hostdiscovery settings: no general section")
	}
	var plain = func(name string) string {
		var value string
		_ = json.Unmarshal(general[name], &value)
		return value
	}
	var settings = Settings{
		Enabled: plain("enabled"), Promisc: plain("promisc"), Verbose: plain("verbose"),
		Expire4Interval: plain("expire4_interval"), Expire6Interval: plain("expire6_interval"),
	}
	var skipNets, err = optionMap(general["skip_nets"])
	if err != nil {
		return Settings{}, fmt.Errorf("unexpected skip_nets from hostdiscovery settings: %w", err)
	}
	settings.SkipNets = selectedKeys(skipNets)
	var interfaces, ifErr = optionMap(general["interface"])
	if ifErr != nil {
		return Settings{}, fmt.Errorf("unexpected interface from hostdiscovery settings: %w", ifErr)
	}
	settings.Interfaces = selectedKeys(interfaces)
	settings.InterfaceOptions = interfaces
	return settings, nil
}

// SettingsSet changes the non nil settings (a partial merge), they take effect with ServiceReconfigure
func (opn *HostDiscoveryApi) SettingsSet(fields SettingsFields) error {
	var _, err = opn.Mutate(opn.endpoint("settings", "set"), map[string]any{"hostdiscovery": map[string]any{"general": fields}})
	return err
}

// HostList returns the discovered hosts (search ignores ?searchPhrase=, filter the result)
func (opn *HostDiscoveryApi) HostList() ([]Host, error) {
	return coreapi.Search[Host](opn.OPNsense, opn.endpoint("service", "search"), "")
}

// ServiceStatus returns the state of the hostwatch service: running, stopped, disabled or unknown
func (opn *HostDiscoveryApi) ServiceStatus() (string, error) {
	var answer struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("service", "status"), nil, &answer); err != nil {
		return "", err
	}
	if answer.Status == "" {
		return "", fmt.Errorf("unexpected answer from hostdiscovery service status: no status given")
	}
	return answer.Status, nil
}

// ServiceReconfigure applies the saved settings: writes the configuration and (re)starts hostwatch, or stops it
// when disabled
func (opn *HostDiscoveryApi) ServiceReconfigure() error {
	var answer struct {
		Status    string `json:"status"`
		StatusMsg string `json:"status_msg"`
	}
	// actions must be POSTed, a GET is silently ignored
	if err := opn.DoJSON("POST", opn.endpoint("service", "reconfigure"), nil, &answer); err != nil {
		return err
	}
	if answer.Status != "ok" {
		if answer.StatusMsg != "" {
			return fmt.Errorf("hostdiscovery reconfigure failed: %s", answer.StatusMsg)
		}
		return fmt.Errorf("hostdiscovery reconfigure failed: status %q", answer.Status)
	}
	return nil
}

// ServiceStart, ServiceStop and ServiceRestart control the hostwatch service
func (opn *HostDiscoveryApi) ServiceStart() error {
	return opn.serviceAction("start")
}

func (opn *HostDiscoveryApi) ServiceStop() error {
	return opn.serviceAction("stop")
}

func (opn *HostDiscoveryApi) ServiceRestart() error {
	return opn.serviceAction("restart")
}

// serviceAction POSTs start/stop/restart, OPNsense passes the configd answer through as {"response":"OK"}
func (opn *HostDiscoveryApi) serviceAction(action string) error {
	var answer struct {
		Response any `json:"response"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("service", action), nil, &answer); err != nil {
		return err
	}
	if response, isString := answer.Response.(string); !isString || response != "OK" {
		return fmt.Errorf("hostdiscovery service %s failed: unexpected response %v", action, answer.Response)
	}
	return nil
}

// optionMap decodes an OPNsense option map {"<key>":{"value":"..","selected":0|1},...} keeping its order
func optionMap(raw json.RawMessage) ([]InterfaceOption, error) {
	var options = make([]InterfaceOption, 0)
	if len(raw) == 0 {
		return options, nil
	}
	var decoder = json.NewDecoder(bytes.NewReader(raw))
	var token, err = decoder.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('{') {
		if token == json.Delim('[') { // an empty map is sent as []
			return options, nil
		}
		return nil, fmt.Errorf("not an option map: %.50s", raw)
	}
	for decoder.More() {
		var keyToken, keyErr = decoder.Token()
		if keyErr != nil {
			return nil, keyErr
		}
		var option struct {
			Value    string `json:"value"`
			Selected any    `json:"selected"`
		}
		if err := decoder.Decode(&option); err != nil {
			return nil, err
		}
		var key, _ = keyToken.(string)
		var selected = fmt.Sprint(option.Selected)
		options = append(options, InterfaceOption{Key: key, Value: option.Value, Selected: selected == "1" || selected == "true"})
	}
	return options, nil
}

// selectedKeys joins the non empty selected keys with commas
func selectedKeys(options []InterfaceOption) string {
	var keys []string
	for _, option := range options {
		if option.Selected && option.Key != "" {
			keys = append(keys, option.Key)
		}
	}
	return strings.Join(keys, ",")
}
