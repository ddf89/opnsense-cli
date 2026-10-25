package cli

import (
	"opnsense-cli/opnsense/api/interfaces"
)

// /interface/lagg: Interfaces > Devices > LAGG (api/interfaces/lagg_settings), link aggregation of unassigned
// physical devices. Items are selected by the # of print, the uuid, the device name (lagg0) or the description

func init() {
	var kind = interfaces.Laggs
	var spec = &interfaceSpec{
		path:     "interface/lagg",
		help:     "link aggregation devices (Interfaces > Devices > LAGG)",
		kind:     kind,
		itemHelp: "the #, uuid, device name (like lagg0) or description of the LAGG",
		fields: []interfaceField{
			{Arg: Arg{Name: "members", Type: List, Required: true,
				Help:     "the member devices, comma separated: physical devices that are not assigned (see the completion)",
				Validate: interfaceValidateNames, Complete: interfaceCompleteOptions(kind, "members")}, api: "members"},
			{Arg: Arg{Name: "primary", Help: `the member added first, the primary interface ("" for none)`,
				Validate: interfaceValidateName, Complete: interfaceCompleteOptions(kind, "members")}, api: "primary_member"},
			{Arg: Arg{Name: "protocol", Help: "the aggregation protocol (OPNsense default lacp)"}, api: "proto", kind: interfaceMapped,
				mapping: interfaceChoices("none", "lacp", "failover", "fec", "loadbalance", "roundrobin")},
			{Arg: Arg{Name: "lacp-fast-timeout", Type: Bool, Help: "LACP fast timeout"}, api: "lacp_fast_timeout", kind: interfaceFlag},
			{Arg: Arg{Name: "use-flowid", Help: "use the RSS hash of the network card, default: the net.link.lagg.default_use_flowid tunable"},
				api: "use_flowid", kind: interfaceMapped, mapping: [][2]string{{"default", ""}, {"yes", "1"}, {"no", "0"}}},
			{Arg: Arg{Name: "hash", Type: List, Help: `the packet layers hashed by the load balancing protocols: l2, l3, l4, "" for the default`,
				Values: []string{"l2", "l3", "l4"}}, api: "lagghash"},
			{Arg: Arg{Name: "lacp-strict", Help: "LACP strict compliance, default: the net.link.lagg.lacp.default_strict_mode tunable"},
				api: "lacp_strict", kind: interfaceMapped, mapping: [][2]string{{"default", ""}, {"yes", "1"}, {"no", "0"}}},
			{Arg: Arg{Name: "mtu", Type: Int, Help: `the MTU, 576-65535, "" for the smallest MTU of the members`,
				Validate: ValidateRange(576, 65535)}, api: "mtu"},
			interfaceDescription("descr"),
		},
		names:     func(item interfaces.Item) []string { return []string{item.Get("descr")} },
		printLong: `DEVICE is the LAGG device, assigned by OPNsense (lagg0, lagg1, ...) and fixed.`,
		addLong: `members is required, a device can be a member of one LAGG only. The device name (lagg0, lagg1, ...) is
chosen by OPNsense.

  add members=igb2,igb3 protocol=lacp lacp-fast-timeout description=uplink`,
		setLong: `The device name can not be changed.`,
		apply: interfaceApplySpec{
			help: "apply the LAGG changes: (re)configure the changed LAGG devices, remove deleted ones",
			long: `Removes deleted LAGG devices (which frees their members) and configures the added or changed ones: their
members are attached again, traffic over the LAGG is interrupted.`,
			confirm: "This reconfigures the changed LAGG devices and reattaches their members, traffic over them is interrupted.",
		},
	}
	spec.columns = []interfaceColumn{
		interfaceFieldColumn("MEMBERS", spec, "members"),
		interfaceFieldColumn("PROTOCOL", spec, "protocol"),
		interfaceFieldColumn("MTU", spec, "mtu"),
		interfaceFieldColumn("DESCRIPTION", spec, "description"),
	}
	interfaceRegister(spec)
}
