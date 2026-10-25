package cli

import (
	"errors"
	"fmt"
	"net/netip"

	"opnsense-cli/opnsense/api/dhcp"
)

// /radvd: router advertisements (Services > Router Advertisements): /radvd/entry, one per interface, and
// /radvd/service. Changes are only saved until "/radvd/service reconfigure"

const radvdApplyHint = `Changes are only saved, run "/radvd/service reconfigure" to apply them.`

func init() {
	Root.Menu("radvd").Help = "IPv6 router advertisements (Services > Router Advertisements)"
	var autoOnOff = []string{"on", "off"}
	keaRegisterItems(&keaItems{
		path: "radvd/entry", help: "the router advertisements of an interface (Services > Router Advertisements)",
		noun: "entry", itemHelp: "the #, uuid or interface of the entry",
		addLong: `One entry per interface. mode: router (only the router), unmanaged (SLAAC), managed (DHCPv6 for addresses
and other configuration), assist (SLAAC and DHCPv6) or stateless (SLAAC with DHCPv6 for other configuration, the
default). min-interval may be at most 3/4 of max-interval. Advertising on a WAN interface can disturb the upstream
network, add such entries disabled.`,
		hint:    radvdApplyHint,
		records: keaRecordsOf(func(api *dhcp.DhcpApi) keaRecords { return api.RadvdEntries() }),
		fields: func(add bool) []keaField {
			return []keaField{
				{Arg: keaRequired(add, Arg{Name: "interface", Help: "the interface to advertise on (key like lan), one entry per interface"}), api: "interface", options: true},
				{Arg: Arg{Name: "disabled", Type: Bool, Help: "keep the entry, but don't send advertisements"}, api: "enabled", kind: keaDisabled},
				{Arg: Arg{Name: "mode", Values: []string{"router", "unmanaged", "managed", "assist", "stateless"}, Validate: radvdNotEmpty,
					Help: "the advertised configuration mode (default stateless)"}, api: "mode"},
				{Arg: Arg{Name: "base6-interface", Help: "advertise the prefix of this interface instead (constructor), empty for the interface itself"},
					api: "Base6Interface", options: true},
				{Arg: Arg{Name: "dns-servers", Type: List, Help: "DNS servers to advertise (RDNSS)", Validate: keaValidateAddresses(6)}, api: "RDNSS", kind: keaList},
				{Arg: Arg{Name: "dns-search", Type: List, Help: "DNS search domains to advertise (DNSSL)", Validate: keaValidateDomains}, api: "DNSSL", kind: keaList},
				{Arg: Arg{Name: "dns", Type: Bool, Help: "advertise DNS servers (RDNSS/DNSSL) at all (default yes)"}, api: "dns", kind: keaFlag},
				{Arg: Arg{Name: "routes", Type: List, Help: "more specific routes to advertise (CIDR)", Validate: keaValidateNetworks(6)}, api: "routes", kind: keaList},
				{Arg: Arg{Name: "default-preference", Values: []string{"low", "medium", "high"}, Validate: radvdNotEmpty,
					Help: "preference of this router as default router (default medium)"}, api: "AdvDefaultPreference"},
				{Arg: Arg{Name: "min-interval", Type: Int, Help: "minimum seconds between advertisements (default 200, at least 3)", Validate: radvdNumber(3, 1350)}, api: "MinRtrAdvInterval"},
				{Arg: Arg{Name: "max-interval", Type: Int, Help: "maximum seconds between advertisements (default 600, 4-1800)", Validate: radvdNumber(4, 1800)}, api: "MaxRtrAdvInterval"},
				{Arg: Arg{Name: "default-lifetime", Type: Int, Help: "router lifetime in seconds (max-interval to 9000), empty for 3 * max-interval",
					Validate: keaValidateMin(0)}, api: "AdvDefaultLifetime"},
				{Arg: Arg{Name: "valid-lifetime", Type: Int, Help: "prefix valid lifetime in seconds", Validate: keaValidateLifetime}, api: "AdvValidLifetime"},
				{Arg: Arg{Name: "preferred-lifetime", Type: Int, Help: "prefix preferred lifetime in seconds", Validate: keaValidateLifetime}, api: "AdvPreferredLifetime"},
				{Arg: Arg{Name: "route-lifetime", Type: Int, Help: "lifetime of the routes in seconds", Validate: keaValidateLifetime}, api: "AdvRouteLifetime"},
				{Arg: Arg{Name: "rdnss-lifetime", Type: Int, Help: "lifetime of the DNS servers in seconds", Validate: keaValidateLifetime}, api: "AdvRDNSSLifetime"},
				{Arg: Arg{Name: "dnssl-lifetime", Type: Int, Help: "lifetime of the search domains in seconds", Validate: keaValidateLifetime}, api: "AdvDNSSLLifetime"},
				{Arg: Arg{Name: "link-mtu", Type: Int, Help: "MTU to advertise (1280-65535), empty for none", Validate: ValidateRange(1280, 65535)}, api: "AdvLinkMTU"},
				{Arg: Arg{Name: "hop-limit", Type: Int, Help: "hop limit for the clients (default 64, 0 unspecified)", Validate: radvdNumber(0, 255)}, api: "AdvCurHopLimit"},
				{Arg: Arg{Name: "source-address", Help: "link-local CARP virtual IP of the interface to send from, empty for the interface address",
					Validate: radvdValidateLinkLocal}, api: "AdvRASrcAddress"},
				{Arg: Arg{Name: "nat64-prefix", Help: "NAT64 prefix to advertise (PREF64), length 32, 40, 48, 56, 64 or 96", Validate: keaValidateNetwork(6)}, api: "nat64prefix"},
				{Arg: Arg{Name: "deprecate-prefix", Values: autoOnOff, Help: "deprecate the prefixes when radvd stops, empty for automatic"}, api: "DeprecatePrefix"},
				{Arg: Arg{Name: "remove-adv-on-exit", Values: autoOnOff, Help: "send a final advertisement with lifetime 0 when radvd stops, empty for automatic"}, api: "RemoveAdvOnExit"},
				{Arg: Arg{Name: "remove-route", Values: autoOnOff, Help: "withdraw the routes when radvd stops, empty for automatic"}, api: "RemoveRoute"},
			}
		},
		columns: []keaColumn{keaColumnOf("INTERFACE", "interface"), keaColumnOf("MODE", "mode"),
			keaColumnOf("DNS-SERVERS", "RDNSS"), keaColumnOf("DNS-SEARCH", "DNSSL"), keaColumnOf("ROUTES", "routes")},
		names: func(row dhcp.Row) []string { return []string{row["interface"]} },
		key:   "interface",
		same:  func(row dhcp.Row, fields dhcp.Fields) bool { return row["interface"] == fields["interface"] },
		check: func(_ bool, args *Args) error {
			if args.Has("min-interval") && args.Has("max-interval") && args.Int("max-interval") > 0 &&
				args.Int("min-interval") > args.Int("max-interval")*3/4 {
				return fmt.Errorf("min-interval may be at most 3/4 of max-interval (%d)", args.Int("max-interval")*3/4)
			}
			return nil
		},
	})

	keaRegisterService("radvd/service", "the radvd service", dhcp.RadvdService,
		"apply the saved entries: regenerate the configuration and restart radvd",
		"This stops radvd, IPv6 clients stop getting router advertisements and lose their default route when it expires.",
		"This restarts radvd.")
}

func radvdNotEmpty(value string) error {
	if value == "" {
		return errors.New("must not be empty, leave it out to keep the current value")
	}
	return nil
}

// radvdNumber is a required number (the field has a default and can not be cleared) from min to max
func radvdNumber(min int, max int) func(string) error {
	return func(value string) error {
		if err := radvdNotEmpty(value); err != nil {
			return err
		}
		return ValidateRange(min, max)(value)
	}
}

// radvdValidateLinkLocal accepts an IPv6 link-local address without zone or prefix length
func radvdValidateLinkLocal(value string) error {
	if value == "" {
		return nil
	}
	if address, err := netip.ParseAddr(value); err != nil || !address.Is6() || address.Zone() != "" || !address.IsLinkLocalUnicast() {
		return fmt.Errorf("must be an IPv6 link-local address like fe80::1, got %q", value)
	}
	return nil
}
