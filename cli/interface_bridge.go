package cli

import (
	"opnsense-cli/opnsense/api/interfaces"
)

// /interface/bridge: Interfaces > Devices > Bridge (api/interfaces/bridge_settings). Members are assigned
// interfaces (lan, opt1), not devices. Items are selected by the # of print, the uuid, the device name (bridge0)
// or the description

func init() {
	var kind = interfaces.Bridges
	var members = func(name string, api string, help string) interfaceField {
		return interfaceField{Arg: Arg{Name: name, Type: List, Help: help + `, comma separated members ("" for none)`,
			Validate: interfaceValidateNames, Complete: interfaceCompleteOptions(kind, "members")}, api: api}
	}
	var spec = &interfaceSpec{
		path:     "interface/bridge",
		help:     "bridge devices (Interfaces > Devices > Bridge)",
		kind:     kind,
		itemHelp: "the #, uuid, device name (like bridge0) or description of the bridge",
		fields: []interfaceField{
			{Arg: Arg{Name: "members", Type: List, Required: true, Help: "the member interfaces, comma separated assigned interfaces like opt1,opt2",
				Validate: interfaceValidateNames, Complete: interfaceCompleteOptions(kind, "members")}, api: "members"},
			{Arg: Arg{Name: "link-local", Type: Bool, Help: "enable the IPv6 link-local address of the bridge (removes the IPv6 addresses of the members)"},
				api: "linklocal", kind: interfaceFlag},
			{Arg: Arg{Name: "stp", Type: Bool, Help: "enable the spanning tree protocol"}, api: "enablestp", kind: interfaceFlag},
			{Arg: Arg{Name: "protocol", Help: "the spanning tree protocol (OPNsense default rstp)"}, api: "proto",
				kind: interfaceMapped, mapping: interfaceChoices("rstp", "stp")},
			members("stp-members", "stp", "the members spanning tree is enabled on"),
			{Arg: Arg{Name: "max-age", Type: Int, Help: `seconds a spanning tree configuration is valid, 6-40, "" for the default 20`,
				Validate: ValidateRange(6, 40)}, api: "maxage"},
			{Arg: Arg{Name: "forward-delay", Type: Int, Help: `seconds before a member forwards with spanning tree, 4-30, "" for the default 15`,
				Validate: ValidateRange(4, 30)}, api: "fwdelay"},
			{Arg: Arg{Name: "hold-count", Type: Int, Help: `spanning tree transmit hold count, 1-10, "" for the default 6`,
				Validate: ValidateRange(1, 10)}, api: "holdcnt"},
			{Arg: Arg{Name: "cache-size", Type: Int, Help: `size of the address cache, "" for the default 2000`,
				Validate: ValidateRange(1, 1<<31-1)}, api: "maxaddr"},
			{Arg: Arg{Name: "cache-timeout", Type: Int, Help: `seconds until address cache entries expire, 0 never, "" for the default 1200`,
				Validate: ValidateRange(0, 1<<31-1)}, api: "timeout"},
			{Arg: Arg{Name: "span", Help: `the span port: an interface (not a member) getting a copy of every frame, "" for none`,
				Validate: interfaceValidateName, Complete: interfaceCompleteOptions(kind, "span")}, api: "span"},
			members("edge", "edge", "the edge ports (connected to end stations)"),
			members("auto-edge", "autoedge", "the ports detecting their edge status automatically"),
			members("ptp", "ptp", "the point-to-point ports"),
			members("auto-ptp", "autoptp", "the ports detecting their point-to-point status automatically"),
			members("sticky", "static", "the sticky ports (learned addresses are never aged out)"),
			members("private", "private", "the private ports (no forwarding between private ports)"),
			interfaceDescription("descr"),
		},
		names:     func(item interfaces.Item) []string { return []string{item.Get("descr")} },
		printLong: `DEVICE is the bridge device, assigned by OPNsense (bridge0, bridge1, ...) and fixed.`,
		addLong: `members is required: assigned interfaces like opt1,opt2. The device name (bridge0, ...) is chosen by
OPNsense. The port lists (stp-members, edge, ...) may only contain members.

  add members=opt1,opt2 description="lab bridge"`,
		setLong: `The device name can not be changed.`,
		apply: interfaceApplySpec{
			help: "apply the bridge changes: remove deleted bridges, reconfigure all bridges and their members",
			long: `Removes the bridge devices that are no longer configured and configures every configured bridge with its
members, bridged traffic is interrupted.`,
			confirm: "This reconfigures every bridge and its member interfaces, bridged traffic is interrupted.",
		},
	}
	spec.columns = []interfaceColumn{
		interfaceFieldColumn("MEMBERS", spec, "members"),
		interfaceFieldColumn("STP", spec, "stp"),
		interfaceFieldColumn("DESCRIPTION", spec, "description"),
	}
	interfaceRegister(spec)
}
