package diagnostics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// NetFlow of Reporting > NetFlow (api/diagnostics/netflow, OPNsense\Diagnostics\Api\NetflowController, model
// OPNsense/Diagnostics/Netflow.xml):
//   - getconfig: {"netflow":{"capture":{"interfaces":{"lan":{"value":"LAN","selected":0},...},"egress_only":{...},
//     "version":{"v5":{...},"v9":{"value":"v9","selected":1}},"targets":{"":{"value":"","selected":1}}},
//     "collect":{"enable":"0"},"activeTimeout":"1800","inactiveTimeout":"15"}} (targets: one key per ip:port,
//     the key "" when there are none)
//   - setconfig (POST {"netflow":{...}}): partial merge, {"result":"saved"} or "failed" with validations keyed
//     "netflow.capture.targets" etc. With collect.enable=1 OPNsense adds the local collector 127.0.0.1:2056 to the
//     targets (and never removes it again)
//   - isEnabled: {"netflow":1,"local":1}, netflow = interfaces and targets are configured, local = collect.enable
//   - status: {"status":"active","collectors":"1"} or {"status":"inactive"}
//   - cacheStats: {"netflow_vtnet0":{"Pkts":12,"if":"vtnet0","SrcIPaddresses":3,"DstIPaddresses":5}}, [] when
//     nothing is captured
//   - reconfigure (POST): restarts the capture and the local collector / aggregator, {"status":"ok"}
//   - reset (POST): deletes all locally collected data (the Insight graphs), {"status":"OK\n"} (script output)

// NetflowSettings are the capture settings
type NetflowSettings struct {
	Interfaces      []string // interface keys (lan, wan, opt1) sending flows
	EgressOnly      []string // interfaces of which only outgoing flows are captured (WAN interfaces in multi-WAN)
	Version         string   // v5 or v9
	Targets         []string // collectors as ip:port
	LocalCollection bool     // collect.enable: collect and aggregate on the firewall (Insight)
	ActiveTimeout   string   // seconds
	InactiveTimeout string   // seconds
	// InterfaceOptions maps the selectable interface keys to their descriptions
	InterfaceOptions map[string]string
	Versions         []string
	Raw              json.RawMessage
}

// NetflowSettingsFields are the settings to change, nil fields are kept
type NetflowSettingsFields struct {
	Interfaces      *[]string
	EgressOnly      *[]string
	Version         *string
	Targets         *[]string
	LocalCollection *bool
	ActiveTimeout   *string
	InactiveTimeout *string
}

// NetflowStatus is the state of the capture
type NetflowStatus struct {
	Active     bool
	Collectors string // number of configured collectors while active
	Raw        json.RawMessage
}

// NetflowCacheNode is the flow cache of one captured interface
type NetflowCacheNode struct {
	Node         string // netgraph node, e.g. netflow_vtnet0
	Interface    string // device, e.g. vtnet0
	Packets      int64
	Sources      int64 // distinct source addresses
	Destinations int64 // distinct destination addresses
	Raw          json.RawMessage
}

// netflowOption is one choice of an option list of getconfig
type netflowOption struct {
	Value    string          `json:"value"`
	Selected json.RawMessage `json:"selected"`
}

func (o netflowOption) isSelected() bool {
	switch strings.Trim(string(bytes.TrimSpace(o.Selected)), `"`) {
	case "1", "true":
		return true
	}
	return false
}

// netflowSelected returns the sorted selected keys of an option list (without the empty key) and all choices
func netflowSelected(raw json.RawMessage) ([]string, map[string]string, error) {
	var options = map[string]netflowOption{}
	if err := healthDecodeObject(raw, &options); err != nil {
		return nil, nil, err
	}
	var selected = []string{}
	var choices = map[string]string{}
	for key, option := range options {
		if key == "" {
			continue
		}
		choices[key] = option.Value
		if option.isSelected() {
			selected = append(selected, key)
		}
	}
	sort.Strings(selected)
	return selected, choices, nil
}

// NetflowSettings returns the capture settings
func (opn *DiagnosticsApi) NetflowSettings() (*NetflowSettings, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("netflow", "getconfig"), nil, &raw); err != nil {
		return nil, err
	}
	var answer struct {
		Netflow *struct {
			Capture struct {
				Interfaces json.RawMessage `json:"interfaces"`
				EgressOnly json.RawMessage `json:"egress_only"`
				Version    json.RawMessage `json:"version"`
				Targets    json.RawMessage `json:"targets"`
			} `json:"capture"`
			Collect struct {
				Enable string `json:"enable"`
			} `json:"collect"`
			ActiveTimeout   string `json:"activeTimeout"`
			InactiveTimeout string `json:"inactiveTimeout"`
		} `json:"netflow"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil || answer.Netflow == nil {
		return nil, fmt.Errorf("unexpected answer from netflow getconfig: %s", healthShorten(raw))
	}
	var settings = &NetflowSettings{
		LocalCollection: answer.Netflow.Collect.Enable == "1",
		ActiveTimeout:   answer.Netflow.ActiveTimeout,
		InactiveTimeout: answer.Netflow.InactiveTimeout,
		Raw:             raw,
	}
	var err error
	var versions map[string]string
	var versionSelected []string
	if settings.Interfaces, settings.InterfaceOptions, err = netflowSelected(answer.Netflow.Capture.Interfaces); err == nil {
		if settings.EgressOnly, _, err = netflowSelected(answer.Netflow.Capture.EgressOnly); err == nil {
			if versionSelected, versions, err = netflowSelected(answer.Netflow.Capture.Version); err == nil {
				settings.Targets, _, err = netflowSelected(answer.Netflow.Capture.Targets)
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("unexpected answer from netflow getconfig: %w", err)
	}
	if len(versionSelected) > 0 {
		settings.Version = versionSelected[0]
	}
	for version := range versions {
		settings.Versions = append(settings.Versions, version)
	}
	sort.Strings(settings.Versions)
	return settings, nil
}

// NetflowSetSettings saves the given settings (the others are kept), NetflowReconfigure applies them.
// Validation errors are a *ValidationError
func (opn *DiagnosticsApi) NetflowSetSettings(fields NetflowSettingsFields) error {
	var capture = map[string]string{}
	var netflow = map[string]any{}
	if fields.Interfaces != nil {
		capture["interfaces"] = strings.Join(*fields.Interfaces, ",")
	}
	if fields.EgressOnly != nil {
		capture["egress_only"] = strings.Join(*fields.EgressOnly, ",")
	}
	if fields.Version != nil {
		capture["version"] = *fields.Version
	}
	if fields.Targets != nil {
		capture["targets"] = strings.Join(*fields.Targets, ",")
	}
	if len(capture) > 0 {
		netflow["capture"] = capture
	}
	if fields.LocalCollection != nil {
		var flag = "0"
		if *fields.LocalCollection {
			flag = "1"
		}
		netflow["collect"] = map[string]string{"enable": flag}
	}
	if fields.ActiveTimeout != nil {
		netflow["activeTimeout"] = *fields.ActiveTimeout
	}
	if fields.InactiveTimeout != nil {
		netflow["inactiveTimeout"] = *fields.InactiveTimeout
	}
	if len(netflow) == 0 {
		return fmt.Errorf("no netflow settings to change")
	}
	var _, err = opn.Mutate(opn.endpoint("netflow", "setconfig"), map[string]any{"netflow": netflow})
	return err
}

// NetflowEnabled returns whether flows are exported (interfaces and targets configured) and collected locally
func (opn *DiagnosticsApi) NetflowEnabled() (capture bool, local bool, err error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("netflow", "isEnabled"), nil, &raw); err != nil {
		return false, false, err
	}
	var answer struct {
		Netflow *json.Number `json:"netflow"`
		Local   *json.Number `json:"local"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil || answer.Netflow == nil {
		return false, false, fmt.Errorf("unexpected answer from netflow isEnabled: %s", healthShorten(raw))
	}
	return answer.Netflow.String() == "1", answer.Local != nil && answer.Local.String() == "1", nil
}

// NetflowStatus returns whether the capture is running
func (opn *DiagnosticsApi) NetflowStatus() (*NetflowStatus, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("netflow", "status"), nil, &raw); err != nil {
		return nil, err
	}
	var answer struct {
		Status     string `json:"status"`
		Collectors string `json:"collectors"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil || (answer.Status != "active" && answer.Status != "inactive") {
		return nil, fmt.Errorf("unexpected answer from netflow status: %s", healthShorten(raw))
	}
	return &NetflowStatus{Active: answer.Status == "active", Collectors: answer.Collectors, Raw: raw}, nil
}

// NetflowCache returns the flow cache statistics per captured interface, sorted by node
func (opn *DiagnosticsApi) NetflowCache() ([]NetflowCacheNode, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("netflow", "cacheStats"), nil, &raw); err != nil {
		return nil, err
	}
	var nodes = map[string]json.RawMessage{}
	if err := healthDecodeObject(raw, &nodes); err != nil {
		return nil, fmt.Errorf("unexpected answer from netflow cacheStats: %s", healthShorten(raw))
	}
	var result = make([]NetflowCacheNode, 0, len(nodes))
	for node, item := range nodes {
		var decoded struct {
			Packets      json.Number `json:"Pkts"`
			Interface    string      `json:"if"`
			Sources      json.Number `json:"SrcIPaddresses"`
			Destinations json.Number `json:"DstIPaddresses"`
		}
		if err := json.Unmarshal(item, &decoded); err != nil {
			return nil, fmt.Errorf("unexpected netflow cache statistics of %s: %s", node, healthShorten(item))
		}
		var number = func(n json.Number) int64 {
			var value, _ = strconv.ParseInt(n.String(), 10, 64)
			return value
		}
		result = append(result, NetflowCacheNode{Node: node, Interface: decoded.Interface, Packets: number(decoded.Packets),
			Sources: number(decoded.Sources), Destinations: number(decoded.Destinations), Raw: item})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Node < result[j].Node })
	return result, nil
}

// NetflowReconfigure applies the settings: restarts the capture and starts or stops the local collector
func (opn *DiagnosticsApi) NetflowReconfigure() error {
	return healthPostStatus(opn.OPNsense, opn.endpoint("netflow", "reconfigure"), "netflow reconfigure")
}

// NetflowReset deletes all locally collected NetFlow data (the Insight data)
func (opn *DiagnosticsApi) NetflowReset() error {
	return healthPostStatus(opn.OPNsense, opn.endpoint("netflow", "reset"), "resetting the netflow data")
}
