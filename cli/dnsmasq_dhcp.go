package cli

import (
	"encoding/json"
	"fmt"
	"opnsense-cli/opnsense/api/dnsmasq"
	"strconv"
	"strings"
)

// /dnsmasq/tag, /dnsmasq/range, /dnsmasq/option, /dnsmasq/boot: the DHCP tags, ranges, options and boot (PXE)
// entries of Dnsmasq. None of them can be disabled. Tags are referenced by name (the API stores their uuids),
// interfaces by key (lan, opt1), empty means any interface

// dnsmasqTagRef resolves tag names to uuids
var dnsmasqTagRef = &dnsRef{What: "DHCP tag", Load: func(c *Context) ([]dnsRefItem, error) {
	var api, err = dnsmasqApi(c)
	if err != nil {
		return nil, err
	}
	var tags, listErr = api.TagList("")
	if listErr != nil {
		return nil, listErr
	}
	var items = make([]dnsRefItem, len(tags))
	for i, tag := range tags {
		items[i] = dnsRefItem{Uuid: tag.Uuid, Names: []string{tag.Tag}}
	}
	return items, nil
}}

// dnsmasqInterfaceComplete completes the interface keys the DHCP fields accept
func dnsmasqInterfaceComplete(c *Context) []string {
	var api, err = dnsmasqApi(c)
	if err != nil {
		return nil
	}
	var interfaces, listErr = api.DhcpInterfaces()
	if listErr != nil {
		return nil
	}
	var keys = make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		keys = append(keys, iface.Key)
	}
	return keys
}

func dnsmasqInterfaceField() dnsField {
	return dnsField{Arg: Arg{Name: "interface", Help: "interface key like lan or opt1, empty for any", Complete: dnsmasqInterfaceComplete}, Api: "interface"}
}

func dnsmasqDescriptionField() dnsField {
	return dnsField{Arg: Arg{Name: "description", Help: "any text"}, Api: "description"}
}

// dnsmasqRecord builds the search / create / update / remove functions of a dnsmasq record type
func dnsmasqRecord[T any](m *dnsRecordMenu, method string,
	create func(api *dnsmasq.DnsmasqApi, record T) (string, error),
	update func(api *dnsmasq.DnsmasqApi, uuid string, patch dnsmasq.Patch) error,
	remove func(api *dnsmasq.DnsmasqApi, uuid string) error) *dnsRecordMenu {
	m.ApplyHint = dnsmasqApplyHint
	m.Search = func(c *Context, searchPhrase string) ([]json.RawMessage, error) {
		return dnsSearchRaw(c, "dnsmasq", "settings", "search_"+method, searchPhrase)
	}
	m.Create = func(c *Context, patch map[string]string) (string, error) {
		var api, err = dnsmasqApi(c)
		if err != nil {
			return "", err
		}
		var record T
		if err := dnsDecodeStrict(patch, &record); err != nil {
			return "", err
		}
		return create(api, record)
	}
	m.Update = func(c *Context, row dnsRow, patch map[string]string) error {
		var api, err = dnsmasqApi(c)
		if err != nil {
			return err
		}
		return update(api, row.uuid(), patch)
	}
	m.Remove = func(c *Context, uuid string) error {
		var api, err = dnsmasqApi(c)
		if err != nil {
			return err
		}
		return remove(api, uuid)
	}
	return m
}

func init() {
	dnsmasqRecord(&dnsRecordMenu{
		Path:     "dnsmasq/tag",
		Help:     "DHCP tags: labels set by ranges, hosts and option matches and required by options and boot entries",
		What:     "tag",
		ItemHelp: "the #, uuid or name of the tag",
		RemoveLong: `A tag used by a range, option, boot entry or host can not be removed.`,
		Fields: []dnsField{
			{Arg: Arg{Name: "name", Help: "the tag name (unique)", Required: true, Validate: dnsNotEmpty}, Api: "tag"},
		},
		Columns: []string{"name"},
		Names:   func(row dnsRow) []string { return []string{row["tag"]} },
		Key:     func(row dnsRow) string { return row["tag"] },
		KeyHelp: "the same name",
	}, "tag", (*dnsmasq.DnsmasqApi).TagCreate, (*dnsmasq.DnsmasqApi).TagUpdate, (*dnsmasq.DnsmasqApi).TagRemove).register()

	dnsmasqRecord(&dnsRecordMenu{
		Path: "dnsmasq/range",
		Help: "DHCP ranges: the address pools (and IPv6 router advertisements) Dnsmasq serves",
		What: "range",
		ItemHelp: "the #, uuid, start address, start-end (like 192.168.1.100-192.168.1.199) or description of " +
			"the range",
		AddLong: `A range is served on the interface whose subnet contains it (interface= limits it to one interface).
end= may only be left out for static IPv4 ranges (mode=static), IPv6 ranges can use partial addresses
(start=::1000 end=::2000) together with constructor=<interface>.

  add interface=lan start=192.168.1.100 end=192.168.1.199 lease-time=86400
  add interface=lan start=::1000 end=::2000 constructor=lan ra-mode=slaac`,
		Fields: []dnsField{
			dnsmasqInterfaceField(),
			{Arg: Arg{Name: "start", Help: "first address (IPv6 may be partial like ::1000)", Required: true, Validate: dnsmasqValidateRangeAddress}, Api: "start_addr"},
			{Arg: Arg{Name: "end", Help: "last address, empty for static IPv4 ranges", Validate: dnsmasqValidateRangeAddress}, Api: "end_addr"},
			{Arg: Arg{Name: "subnet-mask", Help: "IPv4 subnet mask like 255.255.255.0, empty for the interface's", Validate: ValidateIP}, Api: "subnet_mask"},
			{Arg: Arg{Name: "constructor", Help: "interface whose IPv6 prefix completes partial addresses", Complete: dnsmasqInterfaceComplete}, Api: "constructor"},
			{Arg: Arg{Name: "mode", Help: `static: only static mappings are served from this range, "" for dynamic`, Values: []string{"static"}}, Api: "mode"},
			{Arg: Arg{Name: "prefix-len", Type: Int, Help: "IPv6 prefix length, 1-64", Validate: ValidateRange(1, 64)}, Api: "prefix_len"},
			{Arg: Arg{Name: "lease-time", Type: Int, Help: "lease time in seconds, empty for the default", Validate: dnsmasqValidateSeconds}, Api: "lease_time"},
			{Arg: Arg{Name: "set-tag", Help: "tag the clients of this range get"}, Api: "set_tag", Ref: dnsmasqTagRef},
			{Arg: Arg{Name: "domain-type", Help: "what the domain applies to: range (default) or interface", Values: []string{"range", "interface"}},
				Api: "domain_type", Reset: "range"},
			{Arg: Arg{Name: "domain", Help: "domain of the clients, empty for the default"}, Api: "domain"},
			{Arg: Arg{Name: "ra-mode", Type: List, Help: "router advertisement modes", Values: []string{"ra-only", "slaac", "ra-names", "ra-stateless", "ra-advrouter", "off-link"}},
				Api: "ra_mode", Kind: dnsList},
			{Arg: Arg{Name: "ra-priority", Help: `router advertisement priority: high, low, "" for normal`, Values: []string{"high", "low"}}, Api: "ra_priority"},
			{Arg: Arg{Name: "ra-mtu", Type: Int, Help: "MTU announced in router advertisements", Validate: ValidateRange(0, 65535)}, Api: "ra_mtu"},
			{Arg: Arg{Name: "ra-interval", Type: Int, Help: "seconds between router advertisements", Validate: dnsmasqValidateSeconds}, Api: "ra_interval"},
			{Arg: Arg{Name: "ra-router-lifetime", Type: Int, Help: "router lifetime in seconds", Validate: dnsmasqValidateSeconds}, Api: "ra_router_lifetime"},
			{Arg: Arg{Name: "no-sync", Type: Bool, Help: "don't sync this range to the HA peer"}, Api: "nosync", Kind: dnsBool, Reset: "0"},
			dnsmasqDescriptionField(),
		},
		Columns: []string{"interface", "start", "end", "mode", "set-tag", "domain", "lease-time", "description"},
		Names: func(row dnsRow) []string {
			return []string{row["start_addr"], row["start_addr"] + "-" + row["end_addr"], row["description"]}
		},
		Key:     func(row dnsRow) string { return row["interface"] + " " + dnsmasqCanonicalIP(row["start_addr"]) },
		KeyHelp: "the same interface and start address",
	}, "range", (*dnsmasq.DnsmasqApi).RangeCreate, (*dnsmasq.DnsmasqApi).RangeUpdate, (*dnsmasq.DnsmasqApi).RangeRemove).register()

	dnsmasqRecord(&dnsRecordMenu{
		Path:     "dnsmasq/option",
		Help:     "DHCP options sent to clients, and matches on options clients send",
		What:     "option",
		ItemHelp: "the #, uuid or description of the option",
		AddLong: `type=set (default) sends option (DHCPv4) or option6 (DHCPv6) with value to the clients on interface= that
have all tags of tag=; force sends it even when the client did not ask for it. type=match gives the clients that
send option (with value, if given) the tag set-tag=. Options are given by code or name, see "codes".

  add option=dns-server value=192.168.1.53,192.168.1.54 interface=lan
  add option6=dns-server value=[fd00::53] tag=lab
  add type=match option=user-class value=pxe set-tag=pxe`,
		SetLong: `Changing type to set clears set-tag, changing it to match clears interface, tag and force.`,
		Fields: []dnsField{
			{Arg: Arg{Name: "type", Help: "set (send the option) or match (tag clients sending it)", Values: []string{"set", "match"}, Default: "set"},
				Api: "type", Reset: "set"},
			{Arg: Arg{Name: "option", Help: "DHCPv4 option code or name like 6 or dns-server, see codes", Complete: dnsmasqOptionComplete(false)},
				Api: "option", ToApi: dnsmasqOptionCode(false), Describe: true},
			{Arg: Arg{Name: "option6", Help: "DHCPv6 option code or name like 23 or dns-server, see codes v6", Complete: dnsmasqOptionComplete(true)},
				Api: "option6", ToApi: dnsmasqOptionCode(true), Describe: true},
			dnsmasqInterfaceField(),
			{Arg: Arg{Name: "tag", Type: List, Help: "only for clients with all these tags (type set)"}, Api: "tag", Kind: dnsList, Ref: dnsmasqTagRef},
			{Arg: Arg{Name: "set-tag", Help: "tag the matching clients get (required for type match)"}, Api: "set_tag", Ref: dnsmasqTagRef},
			{Arg: Arg{Name: "value", Help: "the option value, lists comma separated, IPv6 addresses in [brackets]"}, Api: "value"},
			{Arg: Arg{Name: "force", Type: Bool, Help: "send the option even when the client did not ask for it (type set)"}, Api: "force", Kind: dnsBool, Reset: "0"},
			dnsmasqDescriptionField(),
		},
		Columns: []string{"type", "option", "option6", "interface", "tag", "set-tag", "value", "force", "description"},
		Names:   func(row dnsRow) []string { return []string{row["description"]} },
		Prepare: dnsmasqOptionPrepare,
	}, "option", (*dnsmasq.DnsmasqApi).OptionCreate, (*dnsmasq.DnsmasqApi).OptionUpdate, (*dnsmasq.DnsmasqApi).OptionRemove).register(
		&Command{Name: "codes", Help: "list the DHCP option codes and names option= (option6= with v6) accepts", Args: []Arg{
			{Name: "v6", Type: Bool, Help: "the DHCPv6 options"},
			{Name: "search", Help: "only options whose name or code contains this text"},
			{Name: "json", Type: Bool, Help: "one JSON object per line"},
		}, Run: dnsmasqOptionCodes},
	)

	dnsmasqRecord(&dnsRecordMenu{
		Path:     "dnsmasq/boot",
		Help:     "DHCP boot entries: the network boot (PXE) image and TFTP server sent to clients",
		What:     "boot entry",
		ItemHelp: "the #, uuid, description or filename of the boot entry",
		AddLong: `The clients on interface= with all tags of tag= get filename from the TFTP server servername / address
(empty: this firewall).

  add filename=pxelinux.0 address=192.168.1.10 tag=pxe`,
		Fields: []dnsField{
			dnsmasqInterfaceField(),
			{Arg: Arg{Name: "tag", Type: List, Help: "only for clients with all these tags"}, Api: "tag", Kind: dnsList, Ref: dnsmasqTagRef},
			{Arg: Arg{Name: "filename", Help: "the boot image", Required: true, Validate: dnsNotEmpty}, Api: "filename"},
			{Arg: Arg{Name: "servername", Help: "host name of the TFTP server"}, Api: "servername"},
			{Arg: Arg{Name: "address", Help: "address of the TFTP server", Validate: ValidateIP}, Api: "address"},
			dnsmasqDescriptionField(),
		},
		Columns: []string{"interface", "tag", "filename", "servername", "address", "description"},
		Names:   func(row dnsRow) []string { return []string{row["description"], row["filename"]} },
	}, "boot", (*dnsmasq.DnsmasqApi).BootCreate, (*dnsmasq.DnsmasqApi).BootUpdate, (*dnsmasq.DnsmasqApi).BootRemove).register()
}

// dnsmasqValidateRangeAddress accepts an IP address or a partial IPv6 address like ::1000
func dnsmasqValidateRangeAddress(value string) error {
	return ValidateIP(value)
}

// dnsmasqCanonicalIP returns an address in canonical form, other values as they are
func dnsmasqCanonicalIP(value string) string {
	return dnsmasqNormalizeIPs([]string{value})
}

// dnsmasqOptionPrepare completes the type and checks option / option6. Changing an option to the other family
// clears the old one
func dnsmasqOptionPrepare(_ *Context, row dnsRow, patch map[string]string) error {
	if _, given := patch["type"]; !given {
		// OPNsense decides which fields to clear by the type sent, so always send it
		patch["type"] = "set"
		if row != nil && row["type"] != "" {
			patch["type"] = row["type"]
		}
	}
	if row != nil {
		for _, pair := range [][2]string{{"option", "option6"}, {"option6", "option"}} {
			var _, otherGiven = patch[pair[1]]
			if patch[pair[0]] != "" && !otherGiven {
				patch[pair[1]] = ""
			}
		}
	}
	var merged = dnsMerged(row, patch)
	switch {
	case merged["option"] == "" && merged["option6"] == "":
		return fmt.Errorf("give option= (DHCPv4) or option6= (DHCPv6)")
	case merged["option"] != "" && merged["option6"] != "":
		return fmt.Errorf("give either option= (DHCPv4) or option6= (DHCPv6), not both")
	case patch["type"] == "match" && merged["set_tag"] == "":
		return fmt.Errorf("type match needs set-tag=")
	}
	return nil
}

// dnsmasqOptionName is the name of an option code entry: "dns-server [6]" -> dns-server
func dnsmasqOptionName(option dnsmasq.SettingsOption) string {
	var name, _, _ = strings.Cut(option.Value, " [")
	return strings.TrimSpace(name)
}

// dnsmasqOptionCode converts an option name to its code, codes are passed on
func dnsmasqOptionCode(v6 bool) func(c *Context, value string) (string, error) {
	return func(c *Context, value string) (string, error) {
		if _, err := strconv.Atoi(value); err == nil {
			return value, nil
		}
		var api, err = dnsmasqApi(c)
		if err != nil {
			return "", err
		}
		codes, err := api.OptionCodes(v6)
		if err != nil {
			return "", err
		}
		var matches []string
		for _, option := range codes {
			if strings.EqualFold(dnsmasqOptionName(option), value) {
				matches = append(matches, option.Key)
			}
		}
		var list = "codes"
		if v6 {
			list = "codes v6"
		}
		switch len(matches) {
		case 0:
			return "", fmt.Errorf("unknown option %q, see %q for the names", value, list)
		case 1:
			return matches[0], nil
		}
		return "", fmt.Errorf("option name %q is ambiguous (codes %s), give the code", value, strings.Join(matches, ", "))
	}
}

func dnsmasqOptionComplete(v6 bool) func(c *Context) []string {
	return func(c *Context) []string {
		var api, err = dnsmasqApi(c)
		if err != nil {
			return nil
		}
		var codes, listErr = api.OptionCodes(v6)
		if listErr != nil {
			return nil
		}
		var names []string
		for _, option := range codes {
			if name := dnsmasqOptionName(option); name != "" && !strings.Contains(name, " ") {
				names = append(names, name)
			}
		}
		return names
	}
}

func dnsmasqOptionCodes(c *Context, args *Args) error {
	var api, err = dnsmasqApi(c)
	if err != nil {
		return err
	}
	codes, err := api.OptionCodes(args.Bool("v6"))
	if err != nil {
		return err
	}
	var search = strings.ToLower(args.String("search"))
	var rows [][]string
	for _, option := range codes {
		var name = dnsmasqOptionName(option)
		if search != "" && !strings.Contains(strings.ToLower(name), search) && !strings.Contains(option.Key, search) {
			continue
		}
		if args.Bool("json") {
			if err := c.JSON(map[string]string{"code": option.Key, "name": name, "group": option.Group}); err != nil {
				return err
			}
			continue
		}
		rows = append(rows, []string{option.Key, name, option.Group})
	}
	if !args.Bool("json") {
		c.Table([]string{"CODE", "NAME", "GROUP"}, rows)
	}
	return nil
}
