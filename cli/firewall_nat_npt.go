package cli

import (
	"errors"
	"fmt"
	"opnsense-cli/opnsense/api/firewall"
)

// /firewall/nat/npt: NPTv6 rules (IPv6 network prefix translation, RFC 6296)

var firewallNatNpt = &firewallNatKind{
	path: "firewall/nat/npt",
	help: "NPTv6 rules, IPv6 prefix translation (Firewall > NAT > NPTv6)",
	rules: func(api *firewall.FirewallApi) *firewall.NatRules {
		return api.Npt()
	},
	plural:  "NPTv6 rules",
	columns: []string{"INTERFACE", "INTERNAL", "EXTERNAL"},
}

func init() {
	var kind = firewallNatNpt
	kind.fields = []firewallNatField{
		firewallNatInterfaceField(kind, "interface", false, "the interface the external prefix is used on, e.g. wan"),
		{arg: Arg{Name: "internal-prefix", Help: "the internal IPv6 prefix, e.g. fd00:1::/48", Validate: firewallNatValidateIPv6},
			api: "source_net", required: true},
		{arg: Arg{Name: "external-prefix", Help: "the external IPv6 prefix of the same length; empty with track-interface",
			Validate: firewallNatValidateIPv6}, api: "destination_net"},
		{arg: Arg{Name: "track-interface", Help: "take the external prefix from this interface (dynamic IPv6)",
			Validate: firewallNatValidateInterface, Complete: kind.completeOption("trackif")}, api: "trackif"},
		firewallNatFlagField("log", "log", "log the packets matching this rule"),
		firewallNatSequenceField(),
	}
	kind.row = func(fields firewall.NatRuleFields) []string {
		var external = fields["destination_net"]
		if fields["trackif"] != "" {
			external = fmt.Sprintf("%s (track %s)", external, fields["trackif"])
		}
		return []string{fields["interface"], fields["source_net"], external}
	}
	kind.check = firewallNatNptCheck
	firewallNatRegister(kind)
}

func firewallNatNptCheck(fields firewall.NatRuleFields) error {
	if err := firewallNatRequire(fields, "source_net", "internal-prefix"); err != nil {
		return err
	}
	var internal, external = fields["source_net"], fields["destination_net"]
	if external == "" && fields["trackif"] == "" {
		return errors.New("give external-prefix or track-interface")
	}
	if external != "" && firewallNatPrefixLength(internal) != firewallNatPrefixLength(external) {
		return fmt.Errorf("internal-prefix %s and external-prefix %s need the same prefix length", internal, external)
	}
	return nil
}
