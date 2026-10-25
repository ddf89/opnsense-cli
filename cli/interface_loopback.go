package cli

import (
	"opnsense-cli/opnsense/api/interfaces"
)

// /interface/loopback: Interfaces > Devices > Loopback (api/interfaces/loopback_settings), additional loopback
// devices lo1, lo2, ... Items are selected by the # of print, the uuid, the device name or the description

func init() {
	var loopback = &interfaceSpec{
		path:     "interface/loopback",
		help:     "loopback devices (Interfaces > Devices > Loopback)",
		kind:     interfaces.Loopbacks,
		itemHelp: "the #, uuid, device name (like lo1) or description of the loopback",
		fields: []interfaceField{
			{Arg: Arg{Name: "description", Required: true, Help: "any text (required)", Validate: interfaceValidateText}, api: "description"},
		},
		names:     func(item interfaces.Item) []string { return []string{item.Get("description")} },
		printLong: `DEVICE is lo followed by the number OPNsense gave the loopback.`,
		addLong: `The device number is chosen by OPNsense.

  add description="router id"`,
		apply: interfaceApplySpec{
			help: "apply the loopback changes: create the configured loopback devices, remove the others (lo0 stays)",
		},
	}
	loopback.columns = []interfaceColumn{interfaceFieldColumn("DESCRIPTION", loopback, "description")}
	interfaceRegister(loopback)
}
