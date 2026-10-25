package cli

import (
	"errors"
	"fmt"
	"net/netip"
	"opnsense-cli/opnsense/api/firewall"
	"regexp"
	"strings"
)

// Field arguments shared by several /firewall/nat menus

// firewallNatInterfaceNamePattern matches interface identifiers like wan, lan, opt1
var firewallNatInterfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func firewallNatValidateInterface(value string) error {
	for _, element := range splitList(value) {
		if !firewallNatInterfaceNamePattern.MatchString(element) {
			return fmt.Errorf("must be an interface identifier like wan or lan, got %q", element)
		}
	}
	return nil
}

// firewallNatTagPattern is the tag / tagged mask of OPNsense
var firewallNatTagPattern = regexp.MustCompile(`^[0-9a-zA-Z.,_-]{0,512}$`)

func firewallNatValidateTag(value string) error {
	if !firewallNatTagPattern.MatchString(value) {
		return fmt.Errorf("must be letters, digits and . , _ - (at most 512), got %q", value)
	}
	return nil
}

func firewallNatInterfaceField(kind *firewallNatKind, apiField string, list bool, help string) firewallNatField {
	var field = firewallNatField{
		arg: Arg{Name: "interface", Help: help, Validate: firewallNatValidateInterface, Complete: kind.completeOption(apiField)},
		api: apiField, required: true,
	}
	if list {
		field.arg.Type = List
		field.conv = firewallNatList
	}
	return field
}

func firewallNatProtocolField(kind *firewallNatKind, def string) firewallNatField {
	return firewallNatField{
		arg: Arg{Name: "protocol", Help: "IP protocol like tcp, udp, tcp/udp, icmp or any (default any)",
			Validate: firewallNatValidateProtocol, Complete: kind.completeOption("protocol")},
		api: "protocol", conv: firewallNatProtocol, def: def,
	}
}

var firewallNatProtocolPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9/.+-]*$`)

func firewallNatValidateProtocol(value string) error {
	if value != "" && !firewallNatProtocolPattern.MatchString(value) {
		return fmt.Errorf("must be a protocol name like tcp, udp, tcp/udp or any, got %q", value)
	}
	return nil
}

func firewallNatAddressField(name string, apiField string, def string, help string) firewallNatField {
	return firewallNatField{arg: Arg{Name: name, Help: help, Validate: firewallNatValidateAddress}, api: apiField, def: def}
}

func firewallNatPortField(name string, apiField string, help string) firewallNatField {
	return firewallNatField{arg: Arg{Name: name, Help: help, Validate: firewallNatValidatePort}, api: apiField}
}

func firewallNatFlagField(name string, apiField string, help string) firewallNatField {
	return firewallNatField{arg: Arg{Name: name, Help: help, Type: Bool}, api: apiField, conv: firewallNatFlag, def: "0"}
}

// firewallNatMappedField is an option argument whose values are mapped to API values, the first is the default
func firewallNatMappedField(name string, apiField string, help string, values [][2]string) firewallNatField {
	var names = make([]string, len(values))
	for i, pair := range values {
		names[i] = pair[0]
	}
	if len(names) > 6 { // the usage shows <string> then
		help += ": " + strings.Join(names, ", ")
	}
	return firewallNatField{
		arg: Arg{Name: name, Help: help + " (default " + values[0][0] + ")", Values: names},
		api: apiField, conv: firewallNatMapped, values: values, def: values[0][1],
	}
}

func firewallNatSequenceField() firewallNatField {
	return firewallNatField{
		arg: Arg{Name: "sequence", Type: Int, Validate: ValidateRange(1, 999999),
			Help: "position in the evaluation order, lower first (1-999999), new rules go to the end; see move"},
		api: "sequence", keep: true,
	}
}

func firewallNatTagFields() []firewallNatField {
	return []firewallNatField{
		{arg: Arg{Name: "tag", Help: "tag the matching packets with this name (for filter rules with tagged=)", Validate: firewallNatValidateTag}, api: "tag"},
		{arg: Arg{Name: "tagged", Help: "only match packets tagged with this name", Validate: firewallNatValidateTag}, api: "tagged"},
	}
}

var firewallNatPoolOptions = [][2]string{
	{"default", ""}, {"round-robin", "round-robin"}, {"round-robin-sticky", "round-robin sticky-address"}, {"random", "random"},
	{"random-sticky", "random sticky-address"}, {"source-hash", "source-hash"}, {"bitmask", "bitmask"},
}

// firewallNatPrefixLength returns the prefix length of an address (32 / 128) or network, -1 for names
func firewallNatPrefixLength(value string) int {
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.BitLen()
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Bits()
	}
	return -1
}

// firewallNatValidateIPv6 accepts an IPv6 address or prefix
func firewallNatValidateIPv6(value string) error {
	if value == "" {
		return nil
	}
	if addr, err := netip.ParseAddr(value); err == nil && addr.Is6() && !addr.Is4In6() {
		return nil
	}
	if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Is6() {
		return nil
	}
	return fmt.Errorf("must be an IPv6 prefix like 2001:db8:1::/48, got %q", value)
}

// firewallNatRequire fails when an API field is empty
func firewallNatRequire(fields firewall.NatRuleFields, apiField string, argument string) error {
	if strings.TrimSpace(fields[apiField]) == "" {
		return fmt.Errorf("%s is required", argument)
	}
	return nil
}

var errFirewallNatTargetAny = errors.New("target can not be any, give an address, a network or an alias (empty is the interface address)")
