package cli

import (
	"fmt"
	"opnsense-cli/opnsense/api/firewall"
)

// /firewall/nat/one-to-one: One-to-One NAT rules (BINAT: an internal address or network maps to an external one)

var firewallNatOneToOne = &firewallNatKind{
	path: "firewall/nat/one-to-one",
	help: "one-to-one NAT rules (Firewall > NAT > One-to-One)",
	rules: func(api *firewall.FirewallApi) *firewall.NatRules {
		return api.OneToOne()
	},
	plural:  "one-to-one NAT rules",
	columns: []string{"INTERFACE", "TYPE", "SOURCE", "DESTINATION", "EXTERNAL"},
}

func init() {
	var kind = firewallNatOneToOne
	kind.fields = []firewallNatField{
		firewallNatInterfaceField(kind, "interface", false, "the interface of the external address, e.g. wan"),
		{arg: Arg{Name: "type", Help: "binat (both directions) or nat (outbound only) (default binat)", Values: []string{"binat", "nat"}},
			api: "type", def: "binat"},
		{arg: Arg{Name: "source", Help: "the internal address, network or alias", Validate: firewallNatValidateAddress},
			api: "source_net", required: true},
		firewallNatFlagField("source-invert", "source_not", "match all sources except source"),
		firewallNatAddressField("destination", "destination_net", "any", "only for traffic to this address, network or alias (default any)"),
		firewallNatFlagField("destination-invert", "destination_not", "match all destinations except destination"),
		{arg: Arg{Name: "external", Help: "the external address or network, of the same size as source", Validate: firewallNatValidateIP},
			api: "external", required: true},
		firewallNatMappedField("nat-reflection", "natreflection", "NAT reflection for clients on internal networks",
			[][2]string{{"default", ""}, {"enable", "enable"}, {"disable", "disable"}}),
		firewallNatFlagField("log", "log", "log the packets matching this rule"),
		firewallNatSequenceField(),
	}
	kind.row = func(fields firewall.NatRuleFields) []string {
		return []string{fields["interface"], fields["type"],
			firewallNatEndpoint(fields["source_net"], fields["source_not"], ""),
			firewallNatEndpoint(fields["destination_net"], fields["destination_not"], ""),
			fields["external"]}
	}
	kind.check = firewallNatOneToOneCheck
	firewallNatRegister(kind)
}

func firewallNatOneToOneCheck(fields firewall.NatRuleFields) error {
	for _, required := range [][2]string{{"source_net", "source"}, {"external", "external"}} {
		if err := firewallNatRequire(fields, required[0], required[1]); err != nil {
			return err
		}
	}
	var source, external = fields["source_net"], fields["external"]
	if sourceFamily, externalFamily := firewallNatFamily(source), firewallNatFamily(external); sourceFamily != "" && sourceFamily != externalFamily {
		return fmt.Errorf("source %s and external %s must both be IPv4 or both IPv6", source, external)
	}
	if sourceBits, externalBits := firewallNatPrefixLength(source), firewallNatPrefixLength(external); fields["type"] == "binat" &&
		sourceBits >= 0 && sourceBits != externalBits {
		return fmt.Errorf("binat maps source %s to external %s one to one, they need the same prefix length", source, external)
	}
	return nil
}
