package cli

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"opnsense-cli/opnsense/api/interfaces"
)

// /interface/vip: Interfaces > Virtual IPs (api/interfaces/vip_settings): IP aliases, CARP addresses and proxy
// ARP networks. Items are selected by the # of print, the uuid, the address (with or without /bits) or the
// description. The CARP password is never shown

// interfaceVipNetwork returns address/bits, a bare address gets /32 (IPv4) or /128 (IPv6)
func interfaceVipNetwork(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "/") {
		return value
	}
	if addr, err := netip.ParseAddr(value); err == nil && addr.Is6() {
		return value + "/128"
	}
	return value + "/32"
}

func interfaceVipValidateAddress(value string) error {
	if _, err := netip.ParsePrefix(interfaceVipNetwork(value)); err != nil {
		return fmt.Errorf("must be an address with or without /bits like 192.168.1.10/24, got %q", value)
	}
	return nil
}

func interfaceVipValidateFamily(want string) func(string) error {
	return func(value string) error {
		if value == "" {
			return nil
		}
		var addr, err = netip.ParseAddr(value)
		if err != nil || want == "ipv4" && !addr.Is4() || want == "ipv6" && !addr.Is6() {
			return fmt.Errorf("must be an %s address, got %q", want, value)
		}
		return nil
	}
}

// interfaceVipCheck: CARP needs a VHID and a password (OPNsense checks it too, this fails before any call)
func interfaceVipCheck(args *Args, add bool) error {
	if !add || !strings.EqualFold(args.String("mode"), "carp") {
		return nil
	}
	if args.String("vhid") == "" || args.String("password") == "" {
		return errors.New("mode=carp needs vhid= (1-255, the same on all members) and password=")
	}
	return nil
}

func init() {
	var kind = interfaces.Vips
	var spec = &interfaceSpec{
		path:     "interface/vip",
		help:     "virtual IPs: IP aliases, CARP and proxy ARP (Interfaces > Virtual IPs)",
		kind:     kind,
		itemHelp: "the #, uuid, address or description of the virtual IP",
		fields: []interfaceField{
			{Arg: Arg{Name: "interface", Required: true, Help: "the interface like lan, opt1 or lo0",
				Validate: interfaceValidateName, Complete: interfaceCompleteOptions(kind, "interface")}, api: "interface"},
			{Arg: Arg{Name: "mode", Help: "ipalias: an additional address, carp: a shared address of a CARP group, proxyarp: answer ARP for a network (OPNsense default ipalias)"},
				api: "mode", kind: interfaceMapped, mapping: interfaceChoices("ipalias", "carp", "proxyarp")},
			{Arg: Arg{Name: "address", Required: true, Help: "the address with its subnet bits like 192.168.1.10/24, a bare address is a /32 (/128); proxyarp takes a network",
				Validate: interfaceVipValidateAddress}, api: "network", display: interfaces.VipNetwork},
			{Arg: Arg{Name: "gateway", Help: `the gateway some interface types need for an IP alias (ppp, pppoe, tun), "" for none`,
				Validate: ValidateIP}, api: "gateway"},
			{Arg: Arg{Name: "no-expand", Type: Bool, Help: "don't expand the network into its addresses in NAT lists"}, api: "noexpand", kind: interfaceFlag},
			{Arg: Arg{Name: "no-bind", Type: Bool, Help: "services bound to the interface don't bind to this address"}, api: "nobind", kind: interfaceFlag},
			{Arg: Arg{Name: "vhid", Type: Int, Help: "carp: the VHID group, 1-255 and the same on all members; ipalias: the VHID of a CARP address on the interface to follow",
				Validate: ValidateRange(1, 255)}, api: "vhid"},
			{Arg: Arg{Name: "password", Help: "carp: the password shared by the members of the VHID group (never shown)", Validate: interfaceValidateText},
				api: "password", kind: interfaceSecret},
			{Arg: Arg{Name: "adv-base", Type: Int, Help: "carp: the advertisement interval in seconds, 1-254 (OPNsense default 1)",
				Validate: ValidateRange(1, 254)}, api: "advbase"},
			{Arg: Arg{Name: "adv-skew", Type: Int, Help: "carp: the advertisement skew, 0-254, the lowest becomes master (OPNsense default 0)",
				Validate: ValidateRange(0, 254)}, api: "advskew"},
			{Arg: Arg{Name: "peer", Help: `carp: the IPv4 address of the peer for unicast advertisements, "" for multicast`,
				Validate: interfaceVipValidateFamily("ipv4")}, api: "peer"},
			{Arg: Arg{Name: "peer6", Help: `carp: the IPv6 address of the peer for unicast advertisements, "" for multicast`,
				Validate: interfaceVipValidateFamily("ipv6")}, api: "peer6"},
			{Arg: Arg{Name: "no-sync", Type: Bool, Help: "don't synchronize this virtual IP to the HA peer"}, api: "nosync", kind: interfaceFlag},
			interfaceDescription("descr"),
		},
		names: func(item interfaces.Item) []string {
			return []string{item.Get("subnet"), interfaces.VipNetwork(item), item.Get("descr")}
		},
		keyArgs: []string{"address"},
		keyMatch: func(item interfaces.Item, fields map[string]string) bool {
			var address, _, _ = strings.Cut(fields["network"], "/")
			return item.Get("subnet") == address
		},
		convert: func(args *Args, fields map[string]string) {
			if args.Has("address") {
				fields["network"] = interfaceVipNetwork(args.String("address"))
			}
		},
		check:     interfaceVipCheck,
		printLong: `VHID is the CARP group (carp) or the CARP group an IP alias follows.`,
		addLong: `interface and address are required, CARP also needs vhid and password. If a virtual IP with this address
exists, add fails unless replace is given, then that virtual IP is replaced completely (fields not given get their
defaults).

  add interface=lan address=192.168.1.10/24 description=service
  add interface=wan mode=carp address=203.0.113.10/24 vhid=10 password=secret adv-skew=100`,
		setLong: `Addresses used by NAT rules can not be changed.`,
		apply: interfaceApplySpec{
			help: "apply the virtual IP changes: remove deleted addresses, add new and changed ones",
			long: `Removes the addresses of deleted or changed virtual IPs and configures the new and changed ones (IP
aliases and CARP), proxy ARP is restarted when needed.`,
		},
	}
	spec.columns = []interfaceColumn{
		interfaceFieldColumn("INTERFACE", spec, "interface"),
		interfaceFieldColumn("MODE", spec, "mode"),
		interfaceFieldColumn("ADDRESS", spec, "address"),
		interfaceFieldColumn("VHID", spec, "vhid"),
		interfaceFieldColumn("DESCRIPTION", spec, "description"),
	}
	interfaceRegister(spec)
}
