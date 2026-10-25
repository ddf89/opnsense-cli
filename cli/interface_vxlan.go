package cli

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"opnsense-cli/opnsense/api/interfaces"
)

// /interface/vxlan: Interfaces > Devices > VXLAN (api/interfaces/vxlan_settings). Items are selected by the # of
// print, the uuid or the device name (vxlan1), VXLANs have no description

func init() {
	var kind = interfaces.Vxlans
	var vxlan = &interfaceSpec{
		path:     "interface/vxlan",
		help:     "VXLAN devices (Interfaces > Devices > VXLAN)",
		kind:     kind,
		itemHelp: "the #, uuid or device name (like vxlan1) of the VXLAN",
		fields: []interfaceField{
			{Arg: Arg{Name: "vni", Type: Int, Required: true, Help: "the VXLAN network identifier, 0-16777215",
				Validate: ValidateRange(0, 16777215)}, api: "vxlanid"},
			{Arg: Arg{Name: "local-address", Required: true, Help: "the source address, an address of the firewall", Validate: ValidateIP},
				api: "vxlanlocal"},
			{Arg: Arg{Name: "local-port", Type: Int, Help: `the source port, "" for 4789`, Validate: ValidatePort}, api: "vxlanlocalport"},
			{Arg: Arg{Name: "remote-address", Help: "the unicast address of the peer (or use group)", Validate: ValidateIP}, api: "vxlanremote"},
			{Arg: Arg{Name: "remote-port", Type: Int, Help: `the destination port, "" for 4789`, Validate: ValidatePort}, api: "vxlanremoteport"},
			{Arg: Arg{Name: "group", Help: "the multicast group (instead of remote-address), needs interface", Validate: interfaceVxlanValidateGroup},
				api: "vxlangroup"},
			{Arg: Arg{Name: "interface", Help: `the interface sending the multicast packets (only with group), "" for none`,
				Validate: interfaceValidateName, Complete: interfaceCompleteOptions(kind, "vxlandev")}, api: "vxlandev"},
		},
		printLong: `DEVICE is vxlan followed by the number OPNsense gave the VXLAN. REMOTE is the remote address or the
multicast group. A VXLAN is only created by apply when its local address exists on the firewall.`,
		addLong: `vni, local-address and either remote-address or group (with interface) are required. The device number is
chosen by OPNsense.

  add vni=100 local-address=203.0.113.1 remote-address=198.51.100.7
  add vni=200 local-address=192.168.1.1 group=239.1.1.200 interface=lan`,
		check: interfaceVxlanCheck,
		apply: interfaceApplySpec{
			help: "apply the VXLAN changes: create or update the VXLAN devices, remove the others",
			long: `Creates or updates the configured VXLAN devices whose local address exists on the firewall (changed ones are
brought down and up again, the interfaces assigned to them are reconfigured) and removes the VXLAN devices that are
no longer configured.`,
		},
	}
	vxlan.columns = []interfaceColumn{
		interfaceFieldColumn("VNI", vxlan, "vni"),
		interfaceFieldColumn("LOCAL", vxlan, "local-address"),
		{header: "REMOTE", value: func(item interfaces.Item) string {
			if group := item.Get("vxlangroup"); group != "" {
				return group
			}
			return item.Get("vxlanremote")
		}},
		interfaceFieldColumn("INTERFACE", vxlan, "interface"),
	}
	interfaceRegister(vxlan)
}

func interfaceVxlanValidateGroup(value string) error {
	if value == "" {
		return nil
	}
	if addr, err := netip.ParseAddr(value); err != nil || !addr.IsMulticast() {
		return fmt.Errorf("must be a multicast address like 239.1.1.1 or ff05::1, got %q", value)
	}
	return nil
}

// interfaceVxlanCheck: a VXLAN has a remote address or a multicast group (with an interface), not both
func interfaceVxlanCheck(args *Args, add bool) error {
	var remote, group = strings.TrimSpace(args.String("remote-address")), strings.TrimSpace(args.String("group"))
	switch {
	case remote != "" && group != "":
		return errors.New("give remote-address or group, not both")
	case add && remote == "" && group == "":
		return errors.New("give remote-address or group (with interface)")
	case add && group != "" && args.String("interface") == "":
		return errors.New("group needs interface, the interface sending the multicast packets")
	case add && remote != "" && args.String("interface") != "":
		return errors.New("interface is only used with group, not with remote-address")
	}
	return nil
}
