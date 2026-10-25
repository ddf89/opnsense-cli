package cli

import (
	"fmt"
	"opnsense-cli/opnsense/api/firewall"
	"strings"
)

// /firewall/nat/source: Source NAT (outbound NAT) rules, and /firewall/nat/source/mode: the outbound NAT mode

var firewallNatSource = &firewallNatKind{
	path: "firewall/nat/source",
	help: "source NAT (outbound NAT) rules (Firewall > NAT > Source NAT)",
	long: "The outbound NAT mode (see mode) decides whether the manual rules are used.\n",
	rules: func(api *firewall.FirewallApi) *firewall.NatRules {
		return api.SourceNat()
	},
	protocol: func(value string) string {
		if value == "" || strings.EqualFold(value, "any") {
			return "any"
		}
		return strings.ToUpper(value)
	},
	plural:     "source NAT rules",
	exportNote: "\nThe manual rules are exported in every outbound NAT mode.",
	columns:    []string{"INTERFACE", "PROTOCOL", "SOURCE", "DESTINATION", "TARGET"},
}

func init() {
	var kind = firewallNatSource
	kind.fields = []firewallNatField{
		firewallNatInterfaceField(kind, "interface", false, "the interface the traffic leaves on, e.g. wan"),
		{arg: Arg{Name: "ip-protocol", Help: "inet (IPv4) or inet6 (IPv6) (default inet)", Values: []string{"inet", "inet6"}}, api: "ipprotocol", def: "inet"},
		firewallNatProtocolField(kind, "any"),
		firewallNatAddressField("source", "source_net", "any", "source address, network or alias (default any)"),
		firewallNatFlagField("source-invert", "source_not", "match all sources except source"),
		firewallNatPortField("source-port", "source_port", "source port or range, only for tcp/udp"),
		firewallNatAddressField("destination", "destination_net", "any", "destination address, network or alias (default any)"),
		firewallNatFlagField("destination-invert", "destination_not", "match all destinations except destination"),
		firewallNatPortField("destination-port", "destination_port", "destination port or range, only for tcp/udp"),
		firewallNatAddressField("target", "target", "", "translate to this address, network or alias; empty for the address of the interface"),
		firewallNatPortField("target-port", "target_port", "translate to this port or range, only for tcp/udp"),
		firewallNatFlagField("no-nat", "nonat", "don't translate the matching traffic (an exception for the following rules)"),
		firewallNatFlagField("static-port", "staticnatport", "keep the source port"),
		firewallNatMappedField("pool-options", "poolopts", "how target addresses of a network or alias are chosen", firewallNatPoolOptions),
		{arg: Arg{Name: "source-hash-key", Help: "key for pool-options=source-hash: 0x and 32 hex digits, empty for a random key",
			Validate: firewallNatValidateHashKey}, api: "poolopts_sourcehashkey"},
		firewallNatFlagField("log", "log", "log the packets matching this rule"),
	}
	kind.fields = append(kind.fields, firewallNatTagFields()...)
	kind.fields = append(kind.fields,
		firewallNatFlagField("no-sync", "nosync", "don't synchronize this rule to the HA peer"),
		firewallNatSequenceField())
	kind.row = firewallNatSourceRow
	kind.check = firewallNatSourceCheck
	kind.listHint = firewallNatSourceHint
	var menu = firewallNatRegister(kind)

	var modeMenu = menu.Sub("mode", "the outbound NAT mode: automatic, hybrid, manual or disabled")
	modeMenu.Add(
		&Command{Name: "print", Help: "show the outbound NAT mode", Run: firewallNatModePrint},
		&Command{Name: "set", Help: "change the outbound NAT mode",
			Long: `automatic: only the rules OPNsense generates for the local networks; hybrid: the manual rules first, then the
automatic ones; manual: only the manual rules; disabled: no source NAT at all.
` + kind.applyHint(),
			Args: []Arg{{Name: "mode", Help: "automatic, hybrid, manual or disabled", Required: true, Values: firewallNatModeNames()}},
			Run:  firewallNatModeSet},
	)
}

func firewallNatValidateHashKey(value string) error {
	if value == "" {
		return nil
	}
	if len(value) != 34 || !strings.HasPrefix(value, "0x") || strings.Trim(value[2:], "0123456789abcdefABCDEF") != "" {
		return fmt.Errorf("must be 0x followed by 32 hex digits, got %q", value)
	}
	return nil
}

func firewallNatSourceRow(fields firewall.NatRuleFields) []string {
	var target = fields["target"]
	switch {
	case fields["nonat"] == "1":
		target = "no nat"
	case target == "":
		target = "interface address"
	}
	if fields["target_port"] != "" {
		target += " port " + fields["target_port"]
	}
	var protocol = strings.ToLower(fields["protocol"])
	if fields["ipprotocol"] == "inet6" {
		protocol += " (ipv6)"
	}
	return []string{fields["interface"], protocol,
		firewallNatEndpoint(fields["source_net"], fields["source_not"], fields["source_port"]),
		firewallNatEndpoint(fields["destination_net"], fields["destination_not"], fields["destination_port"]),
		target}
}

func firewallNatSourceCheck(fields firewall.NatRuleFields) error {
	if err := firewallNatCheckPorts(fields, fields["protocol"], [][2]string{
		{"source_port", "source-port"}, {"destination_port", "destination-port"}, {"target_port", "target-port"},
	}); err != nil {
		return err
	}
	if strings.EqualFold(fields["target"], "any") {
		return errFirewallNatTargetAny
	}
	return firewallNatCheckFamily(fields, fields["ipprotocol"], [][2]string{
		{"source_net", "source"}, {"destination_net", "destination"}, {"target", "target"},
	})
}

// firewallNatSourceHint tells when the outbound NAT mode ignores the listed manual rules
func firewallNatSourceHint(c *Context, api *firewall.FirewallApi, rules []firewall.NatRule) {
	for _, rule := range rules {
		if rule.Inactive {
			var mode, err = api.SourceNatMode()
			if err != nil {
				mode = "automatic or disabled"
			}
			c.Infof("the outbound NAT mode is %s: the manual rules are not used, see /firewall/nat/source/mode", mode)
			return
		}
	}
}

// --- mode

// firewallNatModeAliases maps the API mode advanced to the argument value manual
var firewallNatModeAliases = map[string]string{firewall.SourceNatModeManual: "manual"}

func firewallNatModeNames() []string {
	var names = make([]string, len(firewall.SourceNatModes))
	for i, mode := range firewall.SourceNatModes {
		names[i] = mode
		if alias, ok := firewallNatModeAliases[mode]; ok {
			names[i] = alias
		}
	}
	return names
}

func firewallNatModePrint(c *Context, _ *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var mode, modeErr = api.SourceNatMode()
	if modeErr != nil {
		return modeErr
	}
	if alias, ok := firewallNatModeAliases[mode]; ok {
		mode = alias
	}
	c.Fields([][2]string{{"mode", mode}})
	return nil
}

func firewallNatModeSet(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var mode = strings.ToLower(args.String("mode"))
	for apiMode, alias := range firewallNatModeAliases {
		if mode == alias {
			mode = apiMode
		}
	}
	return api.SourceNatSetMode(mode)
}
