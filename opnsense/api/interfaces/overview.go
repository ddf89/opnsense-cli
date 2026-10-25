package interfaces

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// text is a JSON scalar (string, number, bool) or null read as a string, OPNsense mixes them (vlan_tag, vhid)
type text string

func (t *text) UnmarshalJSON(data []byte) error {
	*t = text(valueText(data))
	return nil
}

// OverviewInterface is one network device of Interfaces > Overview (api/interfaces/overview/interfaces_info):
// the ifconfig state combined with the assignment. Unassigned devices have no Identifier
type OverviewInterface struct {
	Device string `json:"device"`
	// Identifier is the assignment like lan, wan, opt1, lo0; "" for unassigned devices
	Identifier string `json:"identifier"`
	// Description is the interface description, "Unassigned Interface" for unassigned devices
	Description string `json:"description"`
	// Status is up, down or what ifconfig reports otherwise (e.g. no carrier)
	Status string `json:"status"`
	// Enabled tells whether the assigned interface is enabled
	Enabled bool `json:"enabled"`
	// LinkType and LinkTypeV6 are the configuration types: static, dhcp, dhcp6, track6, none, ...
	LinkType   string `json:"link_type"`
	LinkTypeV6 string `json:"link_typev6"`
	// Addr4 and Addr6 are the primary addresses (address/bits)
	Addr4    string            `json:"addr4"`
	Addr6    string            `json:"addr6"`
	IPv4     []OverviewAddress `json:"ipv4"`
	IPv6     []OverviewAddress `json:"ipv6"`
	Gateways []string          `json:"gateways"`
	Routes   []string          `json:"routes"`
	// VlanTag is the VLAN tag; OPNsense only sets vlan_tag for assigned devices, it is taken from Vlan otherwise
	VlanTag text `json:"vlan_tag"`
	// Vlan are the VLAN details of a VLAN device (parent, tag, pcp, proto)
	Vlan       map[string]text `json:"vlan"`
	MacAddr    string          `json:"macaddr"`
	Mtu        text            `json:"mtu"`
	Media      string          `json:"media"`
	IsPhysical bool            `json:"is_physical"`
	Flags      []string        `json:"flags"`
	Groups     []string        `json:"groups"`
	// Raw is the row as OPNsense sent it
	Raw json.RawMessage `json:"-"`
}

// OverviewAddress is an address of an interface, with the CARP state for CARP addresses
type OverviewAddress struct {
	// Address is address/bits
	Address string `json:"ipaddr"`
	Vhid    text   `json:"vhid"`
	// Status is the CARP state (MASTER, BACKUP, INIT)
	Status  text `json:"status"`
	Advbase text `json:"advbase"`
	Advskew text `json:"advskew"`
}

func (i *OverviewInterface) UnmarshalJSON(data []byte) error {
	type plain OverviewInterface
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*i = OverviewInterface(decoded)
	if i.VlanTag == "" {
		i.VlanTag = i.Vlan["tag"]
	}
	i.Raw = append(json.RawMessage(nil), data...)
	return nil
}

// Overview returns all network devices with their state (Interfaces > Overview) where the device, description,
// status, link type, addresses, gateways, VLAN tag or routes contain searchPhrase ("" for all). interfaces_info
// ignores searchPhrase on GET, a search is POSTed like the GUI grid does
func (opn *InterfacesApi) Overview(searchPhrase string) ([]OverviewInterface, error) {
	var endpoint = opn.endpoint("overview", "interfaces_info")
	if searchPhrase == "" {
		return coreapi.Search[OverviewInterface](opn.OPNsense, endpoint, "")
	}
	var container struct {
		Rows []OverviewInterface `json:"rows"`
	}
	var body = map[string]any{"current": 1, "rowCount": -1, "searchPhrase": searchPhrase}
	if err := opn.DoJSON("POST", endpoint, body, &container); err != nil {
		return nil, err
	}
	return container.Rows, nil
}

// OverviewEntry is one property of OverviewDetail
type OverviewEntry struct {
	// Key is the API name like "mtu", "packets received"
	Key string
	// Label is the display name OPNsense gives it (the key when it has none)
	Label string
	// Value is the raw JSON value (string, number, list, object)
	Value json.RawMessage
}

// OverviewDetail are all properties of one device in API order: ifconfig state, assignment, statistics
type OverviewDetail struct {
	Entries []OverviewEntry
}

// Get returns the value of a property as text (see Item for the rendering), "" when it is missing
func (d OverviewDetail) Get(key string) string {
	for _, entry := range d.Entries {
		if entry.Key == key {
			return valueText(entry.Value)
		}
	}
	return ""
}

// OverviewGet returns all properties of one device (vtnet0, vlan01, lo0, ...) including the statistics, or a
// *NotFoundError for an unknown device
func (opn *InterfacesApi) OverviewGet(device string) (OverviewDetail, error) {
	if device == "" || strings.ContainsAny(device, "/ ") {
		return OverviewDetail{}, fmt.Errorf("invalid device name %q", device)
	}
	var container struct {
		Message json.RawMessage `json:"message"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("overview", "get_interface")+"/"+url.PathEscape(device), nil, &container); err != nil {
		return OverviewDetail{}, err
	}
	var failed string
	if json.Unmarshal(container.Message, &failed) == nil {
		return OverviewDetail{}, &coreapi.NotFoundError{Name: "device " + device}
	}
	var decoder = json.NewDecoder(bytes.NewReader(container.Message))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return OverviewDetail{}, fmt.Errorf("unexpected answer for device %s: %.80s", device, container.Message)
	}
	var detail OverviewDetail
	for decoder.More() {
		var keyToken, keyErr = decoder.Token()
		if keyErr != nil {
			return OverviewDetail{}, keyErr
		}
		var property struct {
			Value       json.RawMessage `json:"value"`
			Translation string          `json:"translation"`
		}
		if err := decoder.Decode(&property); err != nil {
			return OverviewDetail{}, err
		}
		var key, _ = keyToken.(string)
		var label = property.Translation
		if label == "" {
			label = key
		}
		if property.Value == nil {
			property.Value = json.RawMessage("null")
		}
		detail.Entries = append(detail.Entries, OverviewEntry{Key: key, Label: label, Value: property.Value})
	}
	return detail, nil
}

// OverviewReload reconfigures an assigned interface by its identifier (lan, wan, opt1) like the Reload button of
// Interfaces > Overview (rc.configure_interface): addresses are applied again and DHCP / PPP clients restarted,
// which interrupts the traffic of the interface and can cut off the access through it. Returns the configd output
func (opn *InterfacesApi) OverviewReload(identifier string) (string, error) {
	if identifier == "" || strings.ContainsAny(identifier, "/ ") {
		return "", fmt.Errorf("invalid interface identifier %q", identifier)
	}
	var container struct {
		Message string `json:"message"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("overview", "reload_interface")+"/"+url.PathEscape(identifier),
		map[string]any{}, &container); err != nil {
		return "", err
	}
	if container.Message == "failed" {
		return "", errors.New("reload failed")
	}
	return strings.TrimSpace(container.Message), nil
}

// Assignment is one assigned interface of Interfaces > Assignments (api/interfaces/assignment, read only here:
// changing assignments remotely can cut off the access)
type Assignment struct {
	// Identifier is the interface key like lan, wan, opt1
	Identifier string
	// Description is the description, OPNsense shows the upper case identifier when it is empty
	Description string
	// Device is the network device like vtnet0, vlan01
	Device string
	// DeviceText is the device with its MAC address or VLAN details as OPNsense shows it
	DeviceText string
	// Locked interfaces can not be removed
	Locked bool
	// Group is how OPNsense groups the device (hardware, vlan, ...)
	Group string
	// Raw is the row as OPNsense sent it
	Raw json.RawMessage
}

// Assignments returns the assigned interfaces in API order
func (opn *InterfacesApi) Assignments() ([]Assignment, error) {
	var rows, err = coreapi.Search[Item](opn.OPNsense, opn.endpoint("assignment", "search_item"), "")
	if err != nil {
		return nil, err
	}
	var assignments = make([]Assignment, 0, len(rows))
	for _, row := range rows {
		var identifier = row.Get("identifier")
		if identifier == "" {
			identifier = row.Uuid
		}
		var description = row.Get("descr")
		if description == "" {
			description = row.Display["descr"]
		}
		assignments = append(assignments, Assignment{
			Identifier: identifier, Description: description, Device: row.Get("if"), DeviceText: row.Display["if"],
			Locked: row.Get("lock") == "1", Group: row.Get("optgroup"), Raw: row.Raw,
		})
	}
	return assignments, nil
}
