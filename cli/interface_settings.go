package cli

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"opnsense-cli/opnsense/api/interfaces"
)

// /interface/settings: the global interface settings of Interfaces > Settings (api/interfaces/settings):
// hardware offloading, VLAN hardware filtering and the IPv6 / DHCPv6 client options

const interfaceSettingsApplyHint = `Changes are only saved, run "/interface/settings apply" to apply them to all interfaces.`

// interfaceSettingsField maps a settings argument to its API field
type interfaceSettingsField struct {
	Arg
	value  func(s interfaces.Settings) string
	target func(f *interfaces.SettingsFields) **string
	flag   bool
}

var interfaceSettingsVlanFilter = [][2]string{{"enable", "0"}, {"disable", "1"}, {"default", "2"}}

var interfaceSettingsFields = []interfaceSettingsField{
	{Arg{Name: "disable-checksum-offload", Type: Bool, Help: "disable hardware checksum offloading (OPNsense default yes)"},
		func(s interfaces.Settings) string { return s.DisableChecksumOffloading },
		func(f *interfaces.SettingsFields) **string { return &f.DisableChecksumOffloading }, true},
	{Arg{Name: "disable-segmentation-offload", Type: Bool, Help: "disable hardware TCP segmentation offloading, TSO (OPNsense default yes)"},
		func(s interfaces.Settings) string { return s.DisableSegmentationOffloading },
		func(f *interfaces.SettingsFields) **string { return &f.DisableSegmentationOffloading }, true},
	{Arg{Name: "disable-large-receive-offload", Type: Bool, Help: "disable hardware large receive offloading, LRO (OPNsense default yes)"},
		func(s interfaces.Settings) string { return s.DisableLargeReceiveOffloading },
		func(f *interfaces.SettingsFields) **string { return &f.DisableLargeReceiveOffloading }, true},
	{Arg{Name: "vlan-hw-filter", Help: "VLAN hardware filtering: enable, disable or default (leave the driver default)",
		Values: []string{"enable", "disable", "default"}},
		func(s interfaces.Settings) string { return interfaceSettingsVlanFilterText(s.DisableVlanHwFilter) },
		func(f *interfaces.SettingsFields) **string { return &f.DisableVlanHwFilter }, false},
	{Arg{Name: "disable-ipv6", Type: Bool, Help: "ignore the IPv6 configuration of all interfaces and block forwarded IPv6 traffic"},
		func(s interfaces.Settings) string { return s.DisableIpv6 },
		func(f *interfaces.SettingsFields) **string { return &f.DisableIpv6 }, true},
	{Arg{Name: "dhcp6-no-release", Type: Bool, Help: "the DHCPv6 client does not release its address or prefix on exit"},
		func(s interfaces.Settings) string { return s.Dhcp6NoRelease },
		func(f *interfaces.SettingsFields) **string { return &f.Dhcp6NoRelease }, true},
	{Arg{Name: "dhcp6-debug", Type: Bool, Help: "debug logging of the IPv6 clients"},
		func(s interfaces.Settings) string { return s.Dhcp6Debug },
		func(f *interfaces.SettingsFields) **string { return &f.Dhcp6Debug }, true},
	{Arg{Name: "dhcp6-duid", Help: `the DHCP unique identifier of the firewall like 00:01:00:01:..., "" for the generated one (see print detail)`,
		Validate: interfaces.SettingsValidateDuid},
		func(s interfaces.Settings) string { return s.Dhcp6Duid },
		func(f *interfaces.SettingsFields) **string { return &f.Dhcp6Duid }, false},
	{Arg{Name: "dhcp6-ra-timeout", Type: Int, Help: "seconds to wait for router advertisements before reloading without them, 0 never (OPNsense default 10)",
		Validate: ValidateRange(0, 1<<31-1)},
		func(s interfaces.Settings) string { return s.Dhcp6RaTimeout },
		func(f *interfaces.SettingsFields) **string { return &f.Dhcp6RaTimeout }, false},
}

func interfaceSettingsVlanFilterText(value string) string {
	for _, pair := range interfaceSettingsVlanFilter {
		if pair[1] == value {
			return pair[0]
		}
	}
	return value
}

func init() {
	var menu = Root.Menu("interface/settings")
	menu.Help = "global interface settings: offloading, VLAN filtering, IPv6 (Interfaces > Settings)"
	var setArgs = make([]Arg, len(interfaceSettingsFields))
	for i, field := range interfaceSettingsFields {
		setArgs[i] = field.Arg
	}
	menu.Add(
		&Command{Name: "print", Help: "show the interface settings",
			Long: `detail adds the DUIDs OPNsense offers for dhcp6-duid (llt, ll, uuid, en; current is the DUID in use).
json prints the settings as one object with the API field names.`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "also show the DUIDs OPNsense offers"},
				{Name: "json", Type: Bool, Help: "print the settings as one JSON object"},
			},
			Run: interfaceSettingsPrint},
		&Command{Name: "set", Help: "change interface settings, the others are kept",
			Long: `Changes the given settings, the others are kept.

  set disable-checksum-offload=no vlan-hw-filter=default
  set dhcp6-ra-timeout=30

` + interfaceSettingsApplyHint,
			Args: setArgs, Check: interfaceSettingsCheckSet, Run: interfaceSettingsSet},
		&Command{Name: "apply", Aliases: []string{"reconfigure"}, Help: "apply the interface settings to all interfaces",
			Long: `Reloads the network configuration of all interfaces with the saved settings: offloading and VLAN filtering
changes reset the hardware settings of every interface, which may interrupt the traffic on all of them.`,
			Confirm: "This reapplies the global interface settings to every interface, traffic on all interfaces may be interrupted.",
			Run:     interfaceSettingsApply},
	)
}

func interfaceSettingsPrint(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var settings, getErr = api.SettingsGet()
	if getErr != nil {
		return getErr
	}
	if args.Bool("json") {
		return c.JSON(settings)
	}
	var fields = make([][2]string, 0, len(interfaceSettingsFields))
	for _, field := range interfaceSettingsFields {
		var value = field.value(settings)
		if field.flag {
			value = YesNo(value)
		}
		fields = append(fields, [2]string{field.Name, value})
	}
	if args.Bool("detail") {
		var kinds = make([]string, 0, len(settings.Duids))
		for kind := range settings.Duids {
			kinds = append(kinds, kind)
		}
		sort.Strings(kinds)
		for _, kind := range kinds {
			fields = append(fields, [2]string{"duid-" + kind, settings.Duids[kind]})
		}
	}
	c.Fields(fields)
	return nil
}

func interfaceSettingsCheckSet(args *Args) error {
	for _, field := range interfaceSettingsFields {
		if args.Has(field.Name) {
			return nil
		}
	}
	return errors.New("set: nothing to change, give at least one setting (type \"set ?\" for help)")
}

func interfaceSettingsSet(c *Context, args *Args) error {
	var fields interfaces.SettingsFields
	for _, field := range interfaceSettingsFields {
		if !args.Has(field.Name) {
			continue
		}
		var value = args.String(field.Name)
		switch {
		case field.flag:
			value = Flag(args.Bool(field.Name))
		case field.Name == "vlan-hw-filter":
			for _, pair := range interfaceSettingsVlanFilter {
				if strings.EqualFold(pair[0], value) {
					value = pair[1]
				}
			}
		}
		*field.target(&fields) = &value
	}
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	if err := api.SettingsSet(fields); err != nil {
		return fmt.Errorf("interface settings: %w", err)
	}
	return nil
}

func interfaceSettingsApply(c *Context, _ *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	return api.SettingsReconfigure()
}
