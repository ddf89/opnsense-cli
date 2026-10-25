package cli

import (
	"opnsense-cli/opnsense/api/interfaces"
)

// /interface/gif and /interface/gre: Interfaces > Devices > GIF and GRE (api/interfaces/gif_settings,
// gre_settings), IP-in-IP and GRE tunnels. Items are selected by the # of print, the uuid, the device name (gif0,
// gre0) or the description

// interfaceTunnelSpec builds the spec of a tunnel menu, gif adds its flags
func interfaceTunnelSpec(kind interfaces.Kind, name string, help string, flags []interfaceField) *interfaceSpec {
	var fields = []interfaceField{
		{Arg: Arg{Name: "local-address", Required: true,
			Help:     "the outer local address: an interface (wan, opt1), a CARP virtual IP (wan_vip1), an IP alias or an address",
			Validate: interfaceValidateIPOrName, Complete: interfaceCompleteIdentifiers}, api: "local-addr"},
		{Arg: Arg{Name: "remote-address", Required: true, Help: "the outer address of the peer the encapsulated packets are sent to",
			Validate: ValidateIP}, api: "remote-addr"},
		{Arg: Arg{Name: "tunnel-local-address", Help: "the local address inside the tunnel", Validate: ValidateIP}, api: "tunnel-local-addr"},
		{Arg: Arg{Name: "tunnel-remote-address", Help: "the remote address inside the tunnel", Validate: ValidateIP}, api: "tunnel-remote-addr"},
		{Arg: Arg{Name: "tunnel-prefix", Type: Int, Help: "the netmask bits (IPv4) or prefix length (IPv6) of the tunnel, 1-128 (OPNsense default 32)",
			Validate: ValidateRange(1, 128)}, api: "tunnel-remote-net"},
	}
	fields = append(append(fields, flags...), interfaceDescription("descr"))
	var spec = &interfaceSpec{
		path:      "interface/" + name,
		help:      help,
		kind:      kind,
		itemHelp:  "the #, uuid, device name (like " + name + "0) or description of the tunnel",
		fields:    fields,
		names:     func(item interfaces.Item) []string { return []string{item.Get("descr")} },
		printLong: `DEVICE is the tunnel device, assigned by OPNsense (` + name + `0, ` + name + `1, ...) and fixed. LOCAL and REMOTE are the outer addresses.`,
		addLong: `local-address and remote-address are required. The device name (` + name + `0, ...) is chosen by OPNsense.

  add local-address=wan remote-address=198.51.100.7 tunnel-local-address=10.255.0.1 tunnel-remote-address=10.255.0.2 tunnel-prefix=30`,
		setLong: `The device name can not be changed.`,
		apply: interfaceApplySpec{
			help: "apply the " + kind.Name + " changes: configure the changed tunnels, remove deleted ones",
			long: `Removes deleted ` + kind.Name + ` devices and (re)configures the added or changed ones: their addresses are set again,
traffic through them is interrupted briefly.`,
		},
	}
	spec.columns = []interfaceColumn{
		interfaceFieldColumn("LOCAL", spec, "local-address"),
		interfaceFieldColumn("REMOTE", spec, "remote-address"),
		{header: "TUNNEL", value: interfaceTunnelText},
		interfaceFieldColumn("DESCRIPTION", spec, "description"),
	}
	return spec
}

// interfaceTunnelText renders the inner addresses like "10.255.0.1 -> 10.255.0.2/30"
func interfaceTunnelText(item interfaces.Item) string {
	var local, remote = item.Get("tunnel-local-addr"), item.Get("tunnel-remote-addr")
	if local == "" && remote == "" {
		return ""
	}
	return local + " -> " + remote + "/" + item.Get("tunnel-remote-net")
}

func init() {
	interfaceRegister(interfaceTunnelSpec(interfaces.Gifs, "gif", "IP-in-IP tunnel devices (Interfaces > Devices > GIF)", []interfaceField{
		{Arg: Arg{Name: "ecn", Type: Bool, Help: "ECN friendly behavior (violates RFC 2893, agree on it with the peer)"},
			api: "link1", kind: interfaceFlag},
		{Arg: Arg{Name: "no-ingress-filter", Type: Bool, Help: "disable the ingress filtering of the outer source (for asymmetric routing)"},
			api: "link2", kind: interfaceFlag},
		{Arg: Arg{Name: "no-clamp", Type: Bool, Help: "don't clamp the MTU to 1280 bytes when the outer protocol is IPv6 (newer OPNsense releases)"},
			api: "noclamp", kind: interfaceFlag, optional: true},
	}))
	interfaceRegister(interfaceTunnelSpec(interfaces.Gres, "gre", "GRE tunnel devices (Interfaces > Devices > GRE)", nil))
}
