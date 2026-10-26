package interfaces

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// The address configuration of assigned interfaces (Interfaces > [LAN], [optN] in the GUI). OPNsense 26.7 keeps it
// in the same record as the assignment (api/interfaces/assignment, model NetworkInterface): the address types
// (type4, type6), static addresses (ipaddr, ipaddrv6 as address/bits), gateways, MTU, MSS, MAC spoofing, the
// private/bogon block rules and the DHCP client settings. Like the device and the enabled state, every change of
// these is staged (search_item shows pending_action "update") until AssignmentApply; only descr and lock are saved
// at once.
//
// The apply writes the whole record to config.xml and drops every interface setting the model does not know
// (e.g. the advanced DHCP client settings of the legacy GUI) of the changed interface

// IPv4 address types (Address.Type4, AddressChange.Type4), the type4 values of OPNsense
const (
	AddressType4None   = ""
	AddressType4Static = "staticv4"
	AddressType4DHCP   = "dhcp"
)

// IPv6 address types (Address.Type6, AddressChange.Type6), the type6 values of OPNsense
const (
	AddressType6None     = ""
	AddressType6Static   = "staticv6"
	AddressType6DHCP     = "dhcp6"
	AddressType6Track    = "track6"
	AddressType6IDAssoc  = "idassoc6"
	AddressType6SLAAC    = "slaac"
	AddressType6LinkOnly = "linklocal"
)

// Address is the address configuration of one assigned interface. Assignment holds the identifier, description,
// device, enabled state, staged action and the static addresses (IPv4, IPv6 as address/bits; set only for the
// static types)
type Address struct {
	Assignment
	// Type4 and Type6 are the address types as OPNsense keys them (AddressType4Static, "dhcp", "", ...)
	Type4 string
	Type6 string
	// Gateway4 and Gateway6 are the names of the upstream gateways of a static interface ("" none)
	Gateway4 string
	Gateway6 string
	// Track6Interface is the parent interface of the track6 and idassoc6 types, Track6PrefixID the prefix ID (hex,
	// 0x1)
	Track6Interface string
	Track6PrefixID  string
	// MTU and MSS are the configured values, "" for the default
	MTU string
	MSS string
	// SpoofMAC is the MAC address that replaces the device's own one, "" none
	SpoofMAC string
	// BlockPrivate and BlockBogons add the block rules for private and bogon source networks
	BlockPrivate bool
	BlockBogons  bool
	// DHCPHostname is the hostname the DHCP client sends, DHCPRejectFrom the DHCP servers it ignores
	DHCPHostname   string
	DHCPRejectFrom []string
}

// AddressChange are the fields of an address change, nil fields are kept
type AddressChange struct {
	Type4 *string
	// IPv4 is address/bits, only for AddressType4Static
	IPv4 *string
	// Gateway4 is a gateway name of this interface (AddressChoices), only for AddressType4Static
	Gateway4 *string
	Type6    *string
	// IPv6 is address/bits, only for AddressType6Static
	IPv6 *string
	// Gateway6 is a gateway name of this interface (AddressChoices), only for AddressType6Static
	Gateway6 *string
	// Track6Interface and Track6PrefixID (hex like 0x1) are for AddressType6Track and AddressType6IDAssoc
	Track6Interface *string
	Track6PrefixID  *string
	MTU             *string
	MSS             *string
	SpoofMAC        *string
	BlockPrivate    *bool
	BlockBogons     *bool
	DHCPHostname    *string
	DHCPRejectFrom  *[]string
}

// addressFields maps the change to the API fields, in the order they are compared after the update
func (change AddressChange) fields() [][2]string {
	var fields [][2]string
	var add = func(name string, value *string) {
		if value != nil {
			fields = append(fields, [2]string{name, *value})
		}
	}
	var addBool = func(name string, value *bool) {
		if value != nil {
			fields = append(fields, [2]string{name, boolText(*value)})
		}
	}
	add("type4", change.Type4)
	add("ipaddr", change.IPv4)
	add("gateway", change.Gateway4)
	// a type other than static drops the static address and gateway, OPNsense would keep them in the record
	if change.Type4 != nil && *change.Type4 != AddressType4Static {
		if change.IPv4 == nil {
			fields = append(fields, [2]string{"ipaddr", ""})
		}
		if change.Gateway4 == nil {
			fields = append(fields, [2]string{"gateway", ""})
		}
	}
	add("type6", change.Type6)
	add("ipaddrv6", change.IPv6)
	add("gatewayv6", change.Gateway6)
	if change.Type6 != nil && *change.Type6 != AddressType6Static {
		if change.IPv6 == nil {
			fields = append(fields, [2]string{"ipaddrv6", ""})
		}
		if change.Gateway6 == nil {
			fields = append(fields, [2]string{"gatewayv6", ""})
		}
	}
	add("track6-interface", change.Track6Interface)
	add("track6-prefix-id", change.Track6PrefixID)
	add("mtu", change.MTU)
	add("mss", change.MSS)
	add("spoofmac", change.SpoofMAC)
	addBool("blockpriv", change.BlockPrivate)
	addBool("blockbogons", change.BlockBogons)
	add("dhcphostname", change.DHCPHostname)
	if change.DHCPRejectFrom != nil {
		fields = append(fields, [2]string{"dhcprejectfrom", strings.Join(*change.DHCPRejectFrom, ",")})
	}
	return fields
}

func addressFromItem(row Item) Address {
	var address = Address{
		Assignment: assignmentFromItem(row),
		Type4:      row.Get("type4"), Type6: row.Get("type6"),
		Gateway4: row.Get("gateway"), Gateway6: row.Get("gatewayv6"),
		Track6Interface: row.Get("track6-interface"), Track6PrefixID: row.Get("track6-prefix-id"),
		MTU: row.Get("mtu"), MSS: row.Get("mss"), SpoofMAC: row.Get("spoofmac"),
		BlockPrivate: row.Get("blockpriv") == "1", BlockBogons: row.Get("blockbogons") == "1",
		DHCPHostname: row.Get("dhcphostname"),
	}
	for _, server := range strings.Split(row.Get("dhcprejectfrom"), ",") {
		if server = strings.TrimSpace(server); server != "" {
			address.DHCPRejectFrom = append(address.DHCPRejectFrom, server)
		}
	}
	return address
}

// AddressSearch returns the address configuration of the assigned interfaces where any field contains
// searchPhrase ("" for all), in API order. The values are the staged ones when a change is staged
func (opn *InterfacesApi) AddressSearch(searchPhrase string) ([]Address, error) {
	var rows, err = coreapi.Search[Item](opn.OPNsense, opn.endpoint("assignment", "search_item"), searchPhrase)
	if err != nil {
		return nil, err
	}
	var addresses = make([]Address, 0, len(rows))
	for _, row := range rows {
		addresses = append(addresses, addressFromItem(row))
	}
	return addresses, nil
}

// Addresses returns the address configuration of every assigned interface in API order
func (opn *InterfacesApi) Addresses() ([]Address, error) {
	return opn.AddressSearch("")
}

// AddressGet returns the address configuration of the interface with this identifier or a *NotFoundError
func (opn *InterfacesApi) AddressGet(identifier string) (Address, error) {
	if err := checkAssignmentIdentifier(identifier); err != nil {
		return Address{}, err
	}
	var addresses, err = opn.Addresses()
	if err != nil {
		return Address{}, err
	}
	for _, address := range addresses {
		if address.Identifier == identifier {
			return address, nil
		}
	}
	return Address{}, &coreapi.NotFoundError{Name: "interface " + identifier}
}

// AddressChoices are the values OPNsense offers for the option fields of an interface's address configuration
// (get_item of the interface), "" (none) included
type AddressChoices struct {
	Type4           []Option
	Type6           []Option
	Gateway4        []Option
	Gateway6        []Option
	Track6Interface []Option
}

// AddressChoices returns the choices of the interface: the address types, the gateways (only configured ones,
// OPNsense does not offer dynamic gateways like WAN_DHCP) and the parent interfaces for track6 (enabled
// interfaces with DHCPv6, 6rd or 6to4). An empty identifier returns the choices of a new interface
func (opn *InterfacesApi) AddressChoices(identifier string) (AddressChoices, error) {
	var endpoint = opn.endpoint("assignment", "get_item")
	if identifier != "" {
		if err := checkAssignmentIdentifier(identifier); err != nil {
			return AddressChoices{}, err
		}
		endpoint += "/" + url.PathEscape(identifier)
	}
	var answer json.RawMessage
	if err := opn.DoJSON("GET", endpoint, nil, &answer); err != nil {
		return AddressChoices{}, err
	}
	var container map[string]map[string]json.RawMessage
	if err := json.Unmarshal(answer, &container); err != nil || container["interface"] == nil {
		// get_item answers an unknown identifier with []
		return AddressChoices{}, &coreapi.NotFoundError{Name: "interface " + identifier}
	}
	var record = container["interface"]
	var choices AddressChoices
	for field, target := range map[string]*[]Option{"type4": &choices.Type4, "type6": &choices.Type6, "gateway": &choices.Gateway4,
		"gatewayv6": &choices.Gateway6, "track6-interface": &choices.Track6Interface} {
		var raw, has = record[field]
		if !has {
			return AddressChoices{}, fmt.Errorf("unexpected answer from assignment get_item: no %s choices", field)
		}
		var options, err = parseOptions(raw)
		if err != nil {
			return AddressChoices{}, fmt.Errorf("unexpected %s choices of assignment get_item: %w", field, err)
		}
		*target = options
	}
	return choices, nil
}

// AddressUpdate changes the given address fields of an assigned interface, the others are kept. Every change is
// staged for AssignmentApply. A type other than static clears the static address and gateway of that family.
//
// Like for AssignmentUpdate, OPNsense ignores a change back to the applied value while another change of the
// interface is staged; the record is read back and such an ignored change is an error
func (opn *InterfacesApi) AddressUpdate(identifier string, change AddressChange) error {
	if _, err := opn.AddressGet(identifier); err != nil {
		return err
	}
	var fields = change.fields()
	if len(fields) == 0 {
		return errors.New("nothing to change")
	}
	var body = map[string]string{}
	for _, field := range fields {
		body[field[0]] = field[1]
	}
	if _, err := opn.Mutate(opn.endpoint("assignment", "set_item")+"/"+url.PathEscape(identifier), map[string]any{"interface": body}); err != nil {
		return err
	}
	var rows, err = coreapi.Search[Item](opn.OPNsense, opn.endpoint("assignment", "search_item"), "")
	if err != nil {
		return err
	}
	for _, row := range rows {
		if assignmentFromItem(row).Identifier != identifier {
			continue
		}
		var ignored []string
		for name, value := range body {
			if !addressSameValue(name, row.Get(name), value) {
				ignored = append(ignored, name)
			}
		}
		if len(ignored) > 0 {
			return fmt.Errorf("OPNsense kept the staged %s of %s: a change back to the applied value is ignored while a change of the interface is staged, apply the staged change first",
				strings.Join(addressSortedFields(fields, ignored), ", "), identifier)
		}
		return nil
	}
	return &coreapi.NotFoundError{Name: "interface " + identifier}
}

// addressSameValue compares a read back value with the sent one: case-insensitive (MAC addresses), hex prefix
// IDs by number, lists without spaces
func addressSameValue(field string, got string, sent string) bool {
	if strings.EqualFold(strings.ReplaceAll(got, " ", ""), strings.ReplaceAll(sent, " ", "")) {
		return true
	}
	if field == "track6-prefix-id" {
		var gotNumber, gotErr = strconv.ParseUint(strings.TrimPrefix(strings.ToLower(got), "0x"), 16, 64)
		var sentNumber, sentErr = strconv.ParseUint(strings.TrimPrefix(strings.ToLower(sent), "0x"), 16, 64)
		return gotErr == nil && sentErr == nil && gotNumber == sentNumber
	}
	return false
}

// addressSortedFields returns the names of ignored in the order of fields
func addressSortedFields(fields [][2]string, ignored []string) []string {
	var sorted []string
	for _, field := range fields {
		for _, name := range ignored {
			if field[0] == name {
				sorted = append(sorted, name)
			}
		}
	}
	return sorted
}
