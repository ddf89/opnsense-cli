package cli

import (
	"errors"
	"opnsense-cli/opnsense/api/firewall"
	"strings"
)

// /firewall/nat/destination: Destination NAT (port forward) rules. The API is shaped like the legacy port
// forwards: descr, a disabled flag and nested source / destination

var firewallNatDestination = &firewallNatKind{
	path: "firewall/nat/destination",
	help: "destination NAT (port forward) rules (Firewall > NAT > Destination NAT)",
	long: "With filter-rule=manual (the default) the redirected traffic needs a filter rule of its own.\n",
	rules: func(api *firewall.FirewallApi) *firewall.NatRules {
		return api.DestinationNat()
	},
	protocol: func(value string) string {
		if strings.EqualFold(value, "any") {
			return ""
		}
		return strings.ToLower(value)
	},
	plural:     "destination NAT rules",
	exportNote: "\nOPNsense exports the source and destination of a rule as two empty columns, export writes their fields\n(source.network, source.port, source.not, destination.*) instead, which the import understands.",
	columns:    []string{"INTERFACE", "PROTOCOL", "SOURCE", "DESTINATION", "TARGET"},
}

func init() {
	var kind = firewallNatDestination
	kind.fields = []firewallNatField{
		firewallNatInterfaceField(kind, "interface", true, "the interfaces the traffic arrives on, e.g. wan"),
		firewallNatMappedField("ip-protocol", "ipprotocol", "inet (IPv4), inet6 (IPv6), inet46 (both) or any",
			[][2]string{{"any", ""}, {"inet", "inet"}, {"inet6", "inet6"}, {"inet46", "inet46"}}),
		firewallNatProtocolField(kind, ""),
		firewallNatAddressField("source", "source.network", "", "source address, network or alias (default any)"),
		firewallNatFlagField("source-invert", "source.not", "match all sources except source"),
		firewallNatPortField("source-port", "source.port", "source port or range, only for tcp/udp"),
		firewallNatAddressField("destination", "destination.network", "", "destination address, network or alias, e.g. wanip (default any)"),
		firewallNatFlagField("destination-invert", "destination.not", "match all destinations except destination"),
		firewallNatPortField("destination-port", "destination.port", "destination port or range, only for tcp/udp"),
		firewallNatAddressField("target", "target", "", "redirect to this internal address or alias"),
		firewallNatPortField("target-port", "local-port", "redirect to this port (a range starts at it), only for tcp/udp"),
		firewallNatFlagField("no-rdr", "nordr", "don't redirect the matching traffic (an exception for the following rules), without target"),
		firewallNatMappedField("pool-options", "poolopts", "how target addresses of a network or alias are chosen", firewallNatPoolOptions),
		firewallNatMappedField("nat-reflection", "natreflection", "NAT reflection for clients on internal networks",
			[][2]string{{"default", ""}, {"enable", "purenat"}, {"disable", "disable"}}),
		firewallNatMappedField("filter-rule", "pass", "manual: add a filter rule yourself, pass: pass the redirected traffic, register: OPNsense adds a filter rule",
			[][2]string{{"manual", ""}, {"pass", "pass"}, {"register", "rule"}}),
		firewallNatFlagField("log", "log", "log the packets matching this rule"),
	}
	kind.fields = append(kind.fields, firewallNatTagFields()...)
	kind.fields = append(kind.fields,
		firewallNatFlagField("no-sync", "nosync", "don't synchronize this rule to the HA peer"),
		firewallNatSequenceField())
	kind.row = firewallNatDestinationRow
	kind.check = firewallNatDestinationCheck
	firewallNatRegister(kind)
}

func firewallNatDestinationRow(fields firewall.NatRuleFields) []string {
	var target = fields["target"]
	if fields["nordr"] == "1" {
		target = "no rdr"
	}
	if fields["local-port"] != "" {
		target += " port " + fields["local-port"]
	}
	var protocol = strings.ToLower(fields["protocol"])
	if protocol == "" {
		protocol = "any"
	}
	if fields["ipprotocol"] == "inet6" || fields["ipprotocol"] == "inet46" {
		protocol += " (" + fields["ipprotocol"] + ")"
	}
	return []string{fields["interface"], protocol,
		firewallNatEndpoint(fields["source.network"], fields["source.not"], fields["source.port"]),
		firewallNatEndpoint(fields["destination.network"], fields["destination.not"], fields["destination.port"]),
		target}
}

func firewallNatDestinationCheck(fields firewall.NatRuleFields) error {
	if err := firewallNatCheckPorts(fields, fields["protocol"], [][2]string{
		{"source.port", "source-port"}, {"destination.port", "destination-port"}, {"local-port", "target-port"},
	}); err != nil {
		return err
	}
	if fields["nordr"] == "1" && (fields["target"] != "" || fields["local-port"] != "") {
		return errors.New("no-rdr does not redirect, give no target or target-port (target= target-port= clears them)")
	}
	return firewallNatCheckFamily(fields, fields["ipprotocol"], [][2]string{
		{"source.network", "source"}, {"destination.network", "destination"}, {"target", "target"},
	})
}
