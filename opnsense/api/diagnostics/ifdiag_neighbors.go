package diagnostics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Interfaces > Diagnostics > ARP Table and NDP Table (api/diagnostics/interface/get_arp, flush_arp, get_ndp).
// Incomplete entries are left out by OPNsense. ARP host names come from DHCP leases or, with resolve, reverse DNS

// ArpEntry is one entry of the ARP table
type ArpEntry struct {
	Ip                   string `json:"ip"`
	Mac                  string `json:"mac"`
	Interface            string `json:"intf"`             // device, e.g. vtnet0
	InterfaceDescription string `json:"intf_description"` // e.g. LAN
	Hostname             string `json:"hostname"`
	Manufacturer         string `json:"manufacturer"`
	Type                 string `json:"type"` // e.g. ethernet
	Permanent            bool   `json:"permanent"`
	Expired              bool   `json:"expired"`
	// Expires is the number of seconds until the entry expires, -1 for permanent entries
	Expires int64 `json:"expires"`
	// Raw is the entry as sent by OPNsense
	Raw json.RawMessage `json:"-"`
}

// NdpEntry is one entry of the IPv6 neighbor table
type NdpEntry struct {
	Ip                   string          `json:"ip"` // link local addresses with %device
	Mac                  string          `json:"mac"`
	Interface            string          `json:"intf"`
	InterfaceDescription string          `json:"intf_description"`
	Manufacturer         string          `json:"manufacturer"`
	Raw                  json.RawMessage `json:"-"`
}

// ArpList returns the ARP table, with resolve the host names are looked up by reverse DNS (slower)
func (opn *DiagnosticsApi) ArpList(resolve bool) ([]ArpEntry, error) {
	var endpoint = opn.endpoint("interface", "get_arp")
	if resolve {
		endpoint += "?resolve=yes"
	}
	var rows []json.RawMessage
	if err := ifdiagGetList(opn, endpoint, &rows); err != nil {
		return nil, fmt.Errorf("ARP table: %w", err)
	}
	return toolsDecodeRows("ARP", rows, func(entry *ArpEntry, raw json.RawMessage) { entry.Raw = raw })
}

// NdpList returns the IPv6 neighbor table
func (opn *DiagnosticsApi) NdpList() ([]NdpEntry, error) {
	var rows []json.RawMessage
	if err := ifdiagGetList(opn, opn.endpoint("interface", "get_ndp"), &rows); err != nil {
		return nil, fmt.Errorf("NDP table: %w", err)
	}
	return toolsDecodeRows("NDP", rows, func(entry *NdpEntry, raw json.RawMessage) { entry.Raw = raw })
}

// ifdiagGetList GETs a JSON list, null (the configd script failed) is an error
func ifdiagGetList(opn *DiagnosticsApi, endpoint string, out *[]json.RawMessage) error {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", endpoint, nil, &raw); err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("OPNsense returned no table")
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("unexpected answer: %w", err)
	}
	return nil
}

// ArpFlush deletes all entries of the ARP table (arp -da) and returns the lines arp printed, one per deleted entry
// (e.g. "192.168.1.2 (192.168.1.2) deleted")
func (opn *DiagnosticsApi) ArpFlush() ([]string, error) {
	var _, content, err = opn.toolsDoRaw("POST", opn.endpoint("interface", "flush_arp"), "{}")
	if err != nil {
		return nil, err
	}
	// the arp output is sent as plain text; a refused request is {"message":"error"}
	var refusal struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(content, &refusal) == nil && refusal.Message != "" {
		return nil, fmt.Errorf("OPNsense refused to flush the ARP table: %s", refusal.Message)
	}
	var text string
	if json.Unmarshal(content, &text) != nil {
		text = string(content)
	}
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}
