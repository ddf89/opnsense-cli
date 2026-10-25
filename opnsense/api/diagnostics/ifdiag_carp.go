package diagnostics

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Interfaces > Virtual IPs > Status (api/diagnostics/interface/get_vip_status, carp_status/<action>,
// get_pfsync_nodes). get_vip_status lists the virtual IPs with a vhid (CARP and IP aliases bound to a vhid) with
// their CARP state and adds the global CARP state of this node

// VipStatusEntry is the state of one virtual IP with a vhid
type VipStatusEntry struct {
	Interface string    `json:"interface"` // description, e.g. LAN
	Vhid      ToolsText `json:"vhid"`
	AdvBase   ToolsText `json:"advbase"`
	AdvSkew   ToolsText `json:"advskew"`
	Subnet    string    `json:"subnet"`
	Mode      string    `json:"mode"`   // carp or ipalias
	Status    string    `json:"status"` // MASTER, BACKUP, INIT or DISABLED
	// Raw is the row as sent by OPNsense
	Raw json.RawMessage `json:"-"`
}

// CarpStatus is the global CARP state of this node
type CarpStatus struct {
	// Demotion is net.inet.carp.demotion, 0 normally, 240 in maintenance mode, other values when CARP demoted the
	// node because of a problem
	Demotion ToolsText `json:"demotion"`
	// Allow is net.inet.carp.allow, "1" when CARP is enabled
	Allow ToolsText `json:"allow"`
	// MaintenanceMode is the persistent maintenance mode of the configuration
	MaintenanceMode bool `json:"maintenancemode"`
	// Message explains a problem ("CARP has detected a problem ...", "Could not locate any defined CARP
	// interfaces."), HTML line breaks are replaced by blanks
	Message string `json:"status_msg"`
}

// Enabled tells whether CARP is allowed on this node
func (s CarpStatus) Enabled() bool {
	return s.Allow == "1"
}

// VipStatusGet returns the virtual IPs with a vhid and the global CARP state. raw is the answer
func (opn *DiagnosticsApi) VipStatusGet() ([]VipStatusEntry, CarpStatus, json.RawMessage, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("interface", "get_vip_status"), nil, &raw); err != nil {
		return nil, CarpStatus{}, nil, err
	}
	var container struct {
		Rows []json.RawMessage `json:"rows"`
		Carp json.RawMessage   `json:"carp"`
	}
	if err := json.Unmarshal(raw, &container); err != nil {
		return nil, CarpStatus{}, nil, fmt.Errorf("unexpected answer from get_vip_status: %w", err)
	}
	if container.Rows == nil {
		return nil, CarpStatus{}, nil, fmt.Errorf("unexpected answer from get_vip_status: no rows")
	}
	var entries, err = toolsDecodeRows("virtual IP", container.Rows, func(entry *VipStatusEntry, row json.RawMessage) { entry.Raw = row })
	if err != nil {
		return nil, CarpStatus{}, nil, err
	}
	var status CarpStatus
	if err := trafficDecodeObject(container.Carp, &status); err != nil {
		return nil, CarpStatus{}, nil, fmt.Errorf("unexpected CARP status %s: %w", container.Carp, err)
	}
	status.Message = strings.TrimSpace(strings.NewReplacer("<br />", " ", "<br>", " ", "<br/>", " ").Replace(status.Message))
	return entries, status, raw, nil
}

// CarpActions are the actions of CarpSetStatus
var CarpActions = []string{"maintenance", "enable", "disable"}

// CarpSetStatus changes the CARP state of this node:
//   - maintenance TOGGLES the persistent maintenance mode: entering sets the demotion to 240 (the peer becomes
//     MASTER), leaving restores it; both write the configuration
//   - disable sets net.inet.carp.allow=0 and takes all VIPs with a vhid down (the peer takes over), not persistent
//   - enable reconfigures pfsync, sets net.inet.carp.allow=1 and configures the VIPs again
//
// It returns the action OPNsense reports (enter_maintenance, leave_maintenance, enable, disable)
func (opn *DiagnosticsApi) CarpSetStatus(action string) (string, error) {
	if !slices.Contains(CarpActions, action) {
		return "", fmt.Errorf("invalid CARP action %q, want one of %s", action, strings.Join(CarpActions, ", "))
	}
	var answer struct {
		Status  string `json:"status"`
		Action  string `json:"action"`
		Message string `json:"message"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("interface", "carp_status/"+action), map[string]any{}, &answer); err != nil {
		return "", err
	}
	if answer.Status != "ok" {
		var reason = answer.Status
		if answer.Message != "" {
			reason = answer.Message
		}
		return "", fmt.Errorf("CARP %s failed: %s", action, reason)
	}
	return answer.Action, nil
}

// PfsyncNode is a pfsync peer by its pf host id, This marks the node itself
type PfsyncNode struct {
	CreatorId string    `json:"creatorid"`
	This      ToolsText `json:"this"`
}

// IsThis tells whether the node is this firewall
func (n PfsyncNode) IsThis() bool {
	return n.This == "1" || n.This == "true"
}

// PfsyncNodes lists the pfsync nodes the states come from (pfctl -s creatorids)
func (opn *DiagnosticsApi) PfsyncNodes() ([]PfsyncNode, error) {
	var rows, err = opn.toolsSearchRaw("interface", "get_pfsync_nodes")
	if err != nil {
		return nil, err
	}
	return toolsDecodeRows("pfsync node", rows, func(*PfsyncNode, json.RawMessage) {})
}
