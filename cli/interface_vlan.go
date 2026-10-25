package cli

import (
	"fmt"
	"regexp"

	"opnsense-cli/opnsense/api/interfaces"
)

// /interface/vlan: Interfaces > Devices > VLAN (api/interfaces/vlan_settings). Items are selected by the # of
// print, the uuid, the device name (vlan01) or the description. A VLAN on a VLAN parent is a QinQ device (qinq0N)

var interfaceVlanNamePattern = regexp.MustCompile(`^(vlan|qinq)0[0-9.]{1,10}$`)

func interfaceVlanValidateName(value string) error {
	if value != "" && !interfaceVlanNamePattern.MatchString(value) {
		return fmt.Errorf(`must be "vlan0" (or "qinq0" on a VLAN parent) followed by up to 10 digits and dots like vlan0.10, got %q`, value)
	}
	return nil
}

func init() {
	var kind = interfaces.Vlans
	var spec = &interfaceSpec{
		path:     "interface/vlan",
		help:     "VLAN devices (Interfaces > Devices > VLAN)",
		kind:     kind,
		itemHelp: "the #, uuid, device name (like vlan01) or description of the VLAN",
		fields: []interfaceField{
			{Arg: Arg{Name: "parent", Required: true, Help: "the parent device like vtnet0, igb1 or a VLAN for QinQ",
				Validate: interfaceValidateName, Complete: interfaceCompleteOptions(kind, "if")}, api: "if"},
			{Arg: Arg{Name: "tag", Type: Int, Required: true, Help: "the 802.1Q VLAN tag, 1-4094 (unique per parent)",
				Validate: ValidateRange(1, 4094)}, api: "tag"},
			{Arg: Arg{Name: "pcp", Type: Int, Help: "the 802.1Q priority code point, 0-7 (OPNsense default 0, best effort)",
				Validate: ValidateRange(0, 7)}, api: "pcp"},
			{Arg: Arg{Name: "proto", Help: "the VLAN protocol, auto: 802.1q, but 802.1ad on a VLAN parent (QinQ)"},
				api: "proto", kind: interfaceMapped, mapping: [][2]string{{"auto", ""}, {"802.1q", "802.1q"}, {"802.1ad", "802.1ad"}}},
			{Arg: Arg{Name: "name", Help: `the device name: "vlan0" (or "qinq0" on a VLAN parent) followed by digits and dots like vlan0.10, chosen by OPNsense (vlan0N) when not given or ""`,
				Validate: interfaceVlanValidateName}, api: "vlanif", device: true},
			interfaceDescription("descr"),
		},
		names:   func(item interfaces.Item) []string { return []string{item.Get("descr")} },
		keyArgs: []string{"parent", "tag"},
		keyMatch: func(item interfaces.Item, fields map[string]string) bool {
			return item.Get("if") == fields["if"] && item.Get("tag") == fields["tag"]
		},
		printLong: `DEVICE is the VLAN device, PARENT the device it is tagged on.`,
		addLong: `parent and tag are required. If a VLAN with this parent and tag exists, add fails unless replace is
given, then that VLAN is replaced completely (fields not given get their defaults, the device name stays unless
name= is given).

  add parent=vtnet0 tag=10 description=guests
  add parent=vtnet0 tag=20 pcp=5 name=vlan0.20`,
		setLong: `The tag and the device name of an assigned VLAN can not be changed. name="" lets OPNsense choose a new
device name, e.g. after moving a VLAN to a VLAN parent (QinQ devices are named qinq0N).`,
		apply: interfaceApplySpec{
			help: "apply the VLAN changes: create new VLAN devices, remove deleted ones",
			long: `Creates the new VLAN devices (and brings their parents up), removes deleted or renamed ones and updates
the priority and protocol of existing ones. A changed parent or tag of an existing device is not applied (OPNsense
does not allow it for assigned VLANs), remove and add the VLAN instead.`,
		},
	}
	spec.columns = []interfaceColumn{
		interfaceFieldColumn("PARENT", spec, "parent"),
		interfaceFieldColumn("TAG", spec, "tag"),
		interfaceFieldColumn("PCP", spec, "pcp"),
		interfaceFieldColumn("PROTO", spec, "proto"),
		interfaceFieldColumn("DESCRIPTION", spec, "description"),
	}
	interfaceRegister(spec)
}
