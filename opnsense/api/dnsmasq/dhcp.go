package dnsmasq

import (
	"encoding/json"
	"fmt"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/internal/dnsmodel"
)

// DHCP tags, ranges, options and boot entries of Services > Dnsmasq DNS & DHCP (api/dnsmasq/settings/*_tag,
// *_range, *_option, *_boot). None of them has an enabled flag. Changes are only saved, ServiceReconfigure applies
// them. Fields holding tags (SetTag, Tag) store tag uuids, comma separated where several are allowed; interfaces
// are interface keys (lan, opt1), empty for any

// Patch maps API field names (the JSON names of the record types) to new values; fields not in it are kept
type Patch = dnsmodel.Patch

// SettingsOption is one choice of an option field: Key is stored and sent, Value is the display name
type SettingsOption = dnsmodel.Option

var (
	tagKind    = dnsmodel.Kind{Module: "dnsmasq", Controller: "settings", Method: "tag", Container: "tag", Name: "DHCP tag"}
	rangeKind  = dnsmodel.Kind{Module: "dnsmasq", Controller: "settings", Method: "range", Container: "range", Name: "DHCP range"}
	optionKind = dnsmodel.Kind{Module: "dnsmasq", Controller: "settings", Method: "option", Container: "option", Name: "DHCP option"}
	bootKind   = dnsmodel.Kind{Module: "dnsmasq", Controller: "settings", Method: "boot", Container: "boot", Name: "DHCP boot entry"}
)

// Tag is a DHCP tag (dnsmasq set:/tag:), referenced by ranges, options, boot entries and hosts by its uuid
type Tag struct {
	Uuid string `json:"uuid,omitempty"`
	// Tag is the unique name
	Tag string `json:"tag"`
}

// Range is a DHCP (or IPv6 / router advertisement) range
type Range struct {
	Uuid string `json:"uuid,omitempty"`
	// Interface key, empty for any interface with a matching subnet
	Interface string `json:"interface,omitempty"`
	// SetTag is the uuid of the tag given to clients of this range
	SetTag    string `json:"set_tag,omitempty"`
	StartAddr string `json:"start_addr,omitempty"`
	// EndAddr may only be empty for static IPv4 ranges (Mode static)
	EndAddr    string `json:"end_addr,omitempty"`
	SubnetMask string `json:"subnet_mask,omitempty"`
	// Constructor is the interface key whose IPv6 prefix completes the partial addresses (::1000)
	Constructor string `json:"constructor,omitempty"`
	// Mode is "static" or empty
	Mode      string `json:"mode,omitempty"`
	PrefixLen string `json:"prefix_len,omitempty"`
	LeaseTime string `json:"lease_time,omitempty"`
	// DomainType is "range" (default) or "interface"
	DomainType string `json:"domain_type,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Nosync     string `json:"nosync,omitempty"`
	// RaMode is a comma separated list of ra-only, slaac, ra-names, ra-stateless, ra-advrouter, off-link
	RaMode string `json:"ra_mode,omitempty"`
	// RaPriority is high, low or empty for normal
	RaPriority       string `json:"ra_priority,omitempty"`
	RaMtu            string `json:"ra_mtu,omitempty"`
	RaInterval       string `json:"ra_interval,omitempty"`
	RaRouterLifetime string `json:"ra_router_lifetime,omitempty"`
	Description      string `json:"description,omitempty"`
}

// Option is a DHCP option sent to clients (Type set), or a match on an option a client sends that sets a tag
// (Type match)
type Option struct {
	Uuid string `json:"uuid,omitempty"`
	// Type is "set" (default) or "match"
	Type string `json:"type,omitempty"`
	// Option is the DHCPv4 option code, Option6 the DHCPv6 one; exactly one of them is set
	Option  string `json:"option,omitempty"`
	Option6 string `json:"option6,omitempty"`
	// Interface key (only for Type set), empty for any
	Interface string `json:"interface,omitempty"`
	// Tag is the comma separated list of tag uuids a client needs (only for Type set)
	Tag string `json:"tag,omitempty"`
	// SetTag is the tag uuid a matching client gets (required for Type match)
	SetTag string `json:"set_tag,omitempty"`
	Value  string `json:"value,omitempty"`
	// Force sends the option even when the client did not ask for it (only for Type set)
	Force       string `json:"force,omitempty"`
	Description string `json:"description,omitempty"`
}

// Boot is a DHCP boot (PXE) entry
type Boot struct {
	Uuid      string `json:"uuid,omitempty"`
	Interface string `json:"interface,omitempty"`
	// Tag is the comma separated list of tag uuids a client needs
	Tag string `json:"tag,omitempty"`
	// Filename of the boot image (required), Servername / Address of the TFTP server
	Filename    string `json:"filename,omitempty"`
	Servername  string `json:"servername,omitempty"`
	Address     string `json:"address,omitempty"`
	Description string `json:"description,omitempty"`
}

// --- tags

// TagList returns the tags where any column contains searchPhrase ("" for all)
func (opn *DnsmasqApi) TagList(searchPhrase string) ([]Tag, error) {
	return dnsmodel.Search[Tag](opn.OPNsense, tagKind, searchPhrase)
}

// TagGet returns the tag with the given uuid or a *coreapi.NotFoundError
func (opn *DnsmasqApi) TagGet(uuid string) (Tag, error) {
	return dnsmodel.Get[Tag](opn.OPNsense, tagKind, uuid)
}

// TagGetByName returns the tag with exactly this name (case-insensitive) or a *coreapi.NotFoundError
func (opn *DnsmasqApi) TagGetByName(name string) (Tag, error) {
	var tags, err = opn.TagList("")
	if err != nil {
		return Tag{}, err
	}
	for _, tag := range tags {
		if strings.EqualFold(tag.Tag, name) {
			return tag, nil
		}
	}
	return Tag{}, &coreapi.NotFoundError{Name: fmt.Sprintf("DHCP tag %q", name)}
}

// TagCreate adds a tag and returns its uuid. Tag names are unique
func (opn *DnsmasqApi) TagCreate(tag Tag) (string, error) {
	return dnsmodel.Create(opn.OPNsense, tagKind, tag)
}

// TagUpdate changes the fields of patch (only "tag"), *coreapi.NotFoundError for an unknown uuid
func (opn *DnsmasqApi) TagUpdate(uuid string, patch Patch) error {
	return dnsmodel.Update(opn.OPNsense, tagKind, uuid, patch)
}

// TagRemove deletes a tag. A tag used by a range, option, boot entry or host can not be removed
func (opn *DnsmasqApi) TagRemove(uuid string) error {
	return dnsmodel.Remove(opn.OPNsense, tagKind, uuid)
}

// --- ranges

// RangeList returns the DHCP ranges where any column contains searchPhrase ("" for all)
func (opn *DnsmasqApi) RangeList(searchPhrase string) ([]Range, error) {
	return dnsmodel.Search[Range](opn.OPNsense, rangeKind, searchPhrase)
}

// RangeGet returns the range with the given uuid or a *coreapi.NotFoundError
func (opn *DnsmasqApi) RangeGet(uuid string) (Range, error) {
	return dnsmodel.Get[Range](opn.OPNsense, rangeKind, uuid)
}

// RangeCreate adds a range and returns its uuid, empty fields get the OPNsense defaults
func (opn *DnsmasqApi) RangeCreate(dhcpRange Range) (string, error) {
	return dnsmodel.Create(opn.OPNsense, rangeKind, dhcpRange)
}

// RangeUpdate changes the fields of patch, *coreapi.NotFoundError for an unknown uuid
func (opn *DnsmasqApi) RangeUpdate(uuid string, patch Patch) error {
	return dnsmodel.Update(opn.OPNsense, rangeKind, uuid, patch)
}

// RangeRemove deletes a range
func (opn *DnsmasqApi) RangeRemove(uuid string) error {
	return dnsmodel.Remove(opn.OPNsense, rangeKind, uuid)
}

// --- options

// OptionList returns the DHCP options where any column contains searchPhrase ("" for all)
func (opn *DnsmasqApi) OptionList(searchPhrase string) ([]Option, error) {
	return dnsmodel.Search[Option](opn.OPNsense, optionKind, searchPhrase)
}

// OptionGet returns the option with the given uuid or a *coreapi.NotFoundError
func (opn *DnsmasqApi) OptionGet(uuid string) (Option, error) {
	return dnsmodel.Get[Option](opn.OPNsense, optionKind, uuid)
}

// OptionCreate adds an option and returns its uuid. OPNsense clears SetTag for Type set and Interface, Tag and
// Force for Type match
func (opn *DnsmasqApi) OptionCreate(option Option) (string, error) {
	return dnsmodel.Create(opn.OPNsense, optionKind, option)
}

// OptionUpdate changes the fields of patch, *coreapi.NotFoundError for an unknown uuid. Include "type": OPNsense
// clears the fields that do not belong to the type sent (set: set_tag, match: interface, tag and force)
func (opn *DnsmasqApi) OptionUpdate(uuid string, patch Patch) error {
	return dnsmodel.Update(opn.OPNsense, optionKind, uuid, patch)
}

// OptionRemove deletes an option
func (opn *DnsmasqApi) OptionRemove(uuid string) error {
	return dnsmodel.Remove(opn.OPNsense, optionKind, uuid)
}

// OptionCodes returns the known DHCPv4 (or with v6 the DHCPv6) option codes: Key is the code, Value the name
// with the code like "dns-server [6]", Group is Common, Assigned or Unassigned
func (opn *DnsmasqApi) OptionCodes(v6 bool) ([]SettingsOption, error) {
	var answer struct {
		Option map[string]json.RawMessage `json:"option"`
	}
	if err := opn.DoJSON("GET", opn.settingsEndpoint("get_option"), nil, &answer); err != nil {
		return nil, err
	}
	var field = "option"
	if v6 {
		field = "option6"
	}
	var raw, found = answer.Option[field]
	if !found {
		return nil, fmt.Errorf("unexpected answer from get_option: no %s field", field)
	}
	var codes []SettingsOption
	for _, option := range dnsmodel.ParseOptionList(raw) {
		if option.Key != "" {
			codes = append(codes, option)
		}
	}
	return codes, nil
}

// --- boot entries

// BootList returns the boot entries where any column contains searchPhrase ("" for all)
func (opn *DnsmasqApi) BootList(searchPhrase string) ([]Boot, error) {
	return dnsmodel.Search[Boot](opn.OPNsense, bootKind, searchPhrase)
}

// BootGet returns the boot entry with the given uuid or a *coreapi.NotFoundError
func (opn *DnsmasqApi) BootGet(uuid string) (Boot, error) {
	return dnsmodel.Get[Boot](opn.OPNsense, bootKind, uuid)
}

// BootCreate adds a boot entry and returns its uuid
func (opn *DnsmasqApi) BootCreate(boot Boot) (string, error) {
	return dnsmodel.Create(opn.OPNsense, bootKind, boot)
}

// BootUpdate changes the fields of patch, *coreapi.NotFoundError for an unknown uuid
func (opn *DnsmasqApi) BootUpdate(uuid string, patch Patch) error {
	return dnsmodel.Update(opn.OPNsense, bootKind, uuid, patch)
}

// BootRemove deletes a boot entry
func (opn *DnsmasqApi) BootRemove(uuid string) error {
	return dnsmodel.Remove(opn.OPNsense, bootKind, uuid)
}

// --- interfaces

// Interface is an interface choice of the DHCP fields: Key like lan or opt1, Name the description
type Interface struct {
	Key  string
	Name string
}

// DhcpInterfaces returns the interfaces the DHCP fields accept (get_tag_list, without interface groups)
func (opn *DnsmasqApi) DhcpInterfaces() ([]Interface, error) {
	var answer struct {
		Interfaces struct {
			Items []struct {
				Value string `json:"value"`
				Label string `json:"label"`
			} `json:"items"`
		} `json:"interfaces"`
	}
	if err := opn.DoJSON("GET", opn.settingsEndpoint("get_tag_list"), nil, &answer); err != nil {
		return nil, err
	}
	var interfaces = make([]Interface, 0, len(answer.Interfaces.Items))
	for _, item := range answer.Interfaces.Items {
		interfaces = append(interfaces, Interface{Key: item.Value, Name: item.Label})
	}
	return interfaces, nil
}
