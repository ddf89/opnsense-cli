package cli

import (
	"opnsense-cli/opnsense/api/interfaces"
)

// /interface/tap: Interfaces > Devices > TAP (api/interfaces/tap_settings, OPNsense 26.7.9 and later), TAP devices
// tap01, tap02, ... Items are selected by the # of print, the uuid, the device name or the description

func init() {
	var tap = &interfaceSpec{
		path:     "interface/tap",
		help:     "TAP devices (Interfaces > Devices > TAP, OPNsense 26.7.9 and later)",
		kind:     interfaces.Taps,
		itemHelp: "the #, uuid, device name (like tap01) or description of the TAP device",
		fields: []interfaceField{
			{Arg: Arg{Name: "description", Required: true, Help: "any text (required)", Validate: interfaceValidateText}, api: "description"},
		},
		names:     func(item interfaces.Item) []string { return []string{item.Get("description")} },
		printLong: `DEVICE is tap0 followed by the number OPNsense gave the TAP device (tap01, tap02, ...).`,
		addLong: `The device number is chosen by OPNsense. A TAP device can be assigned as an interface (/interface/assignment).

  add description="vm bridge"`,
		apply: interfaceApplySpec{
			help: "apply the TAP changes: create the configured TAP devices, remove the others",
		},
	}
	tap.columns = []interfaceColumn{interfaceFieldColumn("DESCRIPTION", tap, "description")}
	interfaceRegister(tap)
}
