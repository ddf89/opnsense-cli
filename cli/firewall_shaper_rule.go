package cli

import (
	"errors"
	"fmt"
	"strings"

	"opnsense-cli/opnsense/api/firewall"
)

// /firewall/shaper/rule: shaper rules sending matching traffic to a pipe or queue, named by their (optional)
// description

var firewallShaperRules = firewallShaperKind[firewall.ShaperRule]{
	what:        "rule",
	list:        func(api *firewall.FirewallApi) ([]firewall.ShaperRule, error) { return api.ShaperRuleList("") },
	uuid:        func(r firewall.ShaperRule) string { return r.Uuid },
	description: func(r firewall.ShaperRule) string { return r.Description },
	enabled:     func(r firewall.ShaperRule) string { return r.Enabled },
	remove:      (*firewall.FirewallApi).ShaperRuleRemove,
	setEnabled:  (*firewall.FirewallApi).ShaperRuleSetEnabled,
}

func init() {
	var menu = Root.Menu("firewall/shaper/rule")
	menu.Help = "shaper rules: which traffic goes to which pipe or queue"
	menu.Add(firewallShaperRules.commands(
		firewallShaperPrintArgs("rule"), firewallShaperRulePrint, firewallShaperRuleShow,
		`Rules are evaluated by sequence, the first match sends the packet to its target pipe or queue. Without
sequence the rule is added after the last one, without interface it applies to wan. A rule with a description is named
by it: if a rule with the same description exists, add fails unless replace is given, then that rule is replaced
completely (fields not given are reset).

  add interface=wan target="WAN download interactive" protocol=udp destination-port=5060 description=voip`,
		firewallShaperRuleArgs(true), firewallShaperRuleAdd,
		firewallShaperRuleArgs(false), firewallShaperRuleSet,
	)...)
}

func firewallShaperRuleArgs(add bool) []Arg {
	return []Arg{
		{Name: "sequence", Type: Int, Validate: ValidateRange(1, 1000000), Help: "order of evaluation (1-1000000), add: after the last rule"},
		{Name: "interface", Validate: dnsmasqNotEmpty, Complete: firewallShaperInterfaceNames, Help: "interface (wan, lan, opt1 or its description), add: wan"},
		{Name: "interface2", Complete: firewallShaperInterfaceNames, Help: "only traffic between interface and this interface, empty for none"},
		{Name: "protocol", Values: firewall.ShaperProtocols, Help: "protocol, add: ip (all)"},
		{Name: "ip-length", Type: Int, Validate: ValidateRange(2, 65535), Help: "only packets up to this length in bytes, empty for all"},
		{Name: "source", Type: List, Validate: firewallShaperValidateNetworks, Help: "source networks / addresses, any (or empty) for all"},
		{Name: "source-invert", Type: Bool, Help: "invert the source match"},
		{Name: "source-port", Validate: firewallShaperValidatePort, Help: "source port, range (1000-2000) or service name, any (or empty) for all"},
		{Name: "destination", Type: List, Validate: firewallShaperValidateNetworks, Help: "destination networks / addresses, any (or empty) for all"},
		{Name: "destination-invert", Type: Bool, Help: "invert the destination match"},
		{Name: "destination-port", Validate: firewallShaperValidatePort, Help: "destination port, range (1000-2000) or service name, any (or empty) for all"},
		{Name: "dscp", Type: List, Values: firewall.ShaperDscpValues, Help: "only packets with one of these DSCP values, empty for all"},
		{Name: "direction", Values: []string{"in", "out", "both"}, Help: "direction on the interface, add: both"},
		{Name: "target", Required: add, Validate: dnsmasqNotEmpty, Complete: firewallShaperTargetNames, Help: "the pipe or queue (description or uuid)"},
		{Name: "description", Help: "description, names the rule"},
		{Name: "disabled", Type: Bool, Help: "keep the rule, but don't use it"},
	}
}

var firewallShaperRuleFieldMap = []firewallShaperArgField{
	{"sequence", "sequence", "text"}, {"protocol", "proto", "text"}, {"ip-length", "iplen", "text"},
	{"source-invert", "source_not", "flag"}, {"destination-invert", "destination_not", "flag"},
	{"description", "description", "text"}, {"disabled", "enabled", "notFlag"},
}

// firewallShaperInterfaceNames completes interfaces: the keys (wan, lan, opt1)
func firewallShaperInterfaceNames(c *Context) []string {
	var options = firewallShaperRuleOptionsOf(c)
	var names = make([]string, len(options.Interfaces))
	for i, option := range options.Interfaces {
		names[i] = option.Key
	}
	return names
}

// firewallShaperTargetNames completes targets: the descriptions of the pipes and queues
func firewallShaperTargetNames(c *Context) []string {
	var options = firewallShaperRuleOptionsOf(c)
	var names = make([]string, len(options.Targets))
	for i, option := range options.Targets {
		names[i] = option.Label
	}
	return names
}

func firewallShaperRuleOptionsOf(c *Context) firewall.ShaperRuleOptions {
	var api, err = firewallApi(c)
	if err != nil {
		return firewall.ShaperRuleOptions{}
	}
	var options, _ = api.ShaperRuleOptions()
	return options
}

// firewallShaperRuleFields returns the arguments as API fields (all for add, the given ones for set), resolving
// interfaces and the target with the options of get_rule (fetched when needed, also returned for add's sequence)
func firewallShaperRuleFields(api *firewall.FirewallApi, args *Args, onlyGiven bool) (firewall.ShaperFields, *firewall.ShaperRuleOptions, error) {
	var fields = firewallShaperFields(args, firewallShaperRuleFieldMap, onlyGiven)
	var given = func(name string) bool { return !onlyGiven || args.Has(name) }

	if given("protocol") {
		fields["proto"] = strings.ToLower(fields["proto"])
		if fields["proto"] == "" {
			fields["proto"] = "ip"
		}
	}
	if given("source") {
		fields["source"] = firewallShaperNetworks(args.List("source"))
	}
	if given("destination") {
		fields["destination"] = firewallShaperNetworks(args.List("destination"))
	}
	if given("source-port") {
		fields["src_port"] = firewallShaperPort(args.String("source-port"))
	}
	if given("destination-port") {
		fields["dst_port"] = firewallShaperPort(args.String("destination-port"))
	}
	if given("dscp") {
		fields["dscp"] = strings.ToLower(strings.Join(args.List("dscp"), ","))
	}
	if given("direction") {
		fields["direction"] = strings.ToLower(args.String("direction"))
		if fields["direction"] == "both" {
			fields["direction"] = ""
		}
	}

	var options *firewall.ShaperRuleOptions
	if !onlyGiven || args.Has("interface") || args.Has("interface2") || args.Has("target") {
		var fetched, err = api.ShaperRuleOptions()
		if err != nil {
			return nil, nil, err
		}
		options = &fetched
	}
	if given("interface") {
		var value = args.String("interface")
		if !args.Has("interface") {
			value = "wan"
		}
		var key, err = firewallShaperResolveOption("interface", options.Interfaces, value)
		if err != nil {
			return nil, nil, err
		}
		fields["interface"] = key
	}
	if given("interface2") {
		fields["interface2"] = ""
		if value := strings.TrimSpace(args.String("interface2")); value != "" && !strings.EqualFold(value, "none") {
			var key, err = firewallShaperResolveOption("interface", options.Interfaces, value)
			if err != nil {
				return nil, nil, err
			}
			fields["interface2"] = key
		}
	}
	if args.Has("target") {
		var key, err = firewallShaperResolveOption("pipe or queue", options.Targets, args.String("target"))
		if err != nil {
			return nil, nil, err
		}
		fields["target"] = key
	}
	return fields, options, nil
}

// firewallShaperMatch renders an address match of a rule like "!192.0.2.0/24 port 80"
func firewallShaperMatch(addresses string, not string, port string) string {
	var text = strings.ReplaceAll(addresses, ",", ", ")
	if not == "1" {
		text = "!" + text
	}
	if port != "" && port != "any" {
		text += " port " + port
	}
	return text
}

func firewallShaperRuleInterfaces(rule firewall.ShaperRule) string {
	var text = firewallShaperLabel(rule.InterfaceLabel, rule.Interface)
	if rule.Interface2 != "" {
		text += ", " + firewallShaperLabel(rule.Interface2Label, rule.Interface2)
	}
	return text
}

func firewallShaperRuleDirection(rule firewall.ShaperRule) string {
	if rule.Direction == "" {
		return "both"
	}
	return rule.Direction
}

func firewallShaperRuleDetail(rule firewall.ShaperRule) [][2]string {
	return [][2]string{
		{"uuid", rule.Uuid},
		{"sequence", rule.Sequence},
		{"description", rule.Description},
		{"disabled", firewallShaperDisabled(rule.Enabled)},
		{"interface", firewallShaperLabel(rule.InterfaceLabel, rule.Interface)},
		{"interface2", firewallShaperLabel(rule.Interface2Label, rule.Interface2)},
		{"protocol", rule.Proto},
		{"ip-length", rule.Iplen},
		{"source", rule.Source},
		{"source-invert", YesNo(rule.SourceNot)},
		{"source-port", rule.SrcPort},
		{"destination", rule.Destination},
		{"destination-invert", YesNo(rule.DestinationNot)},
		{"destination-port", rule.DstPort},
		{"dscp", rule.Dscp},
		{"direction", firewallShaperRuleDirection(rule)},
		{"target", firewallShaperLabel(rule.TargetLabel, rule.Target)},
	}
}

func firewallShaperRulePrint(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	raws, rules, err := api.ShaperRuleListRaw(args.String("search"))
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return firewallShaperPrintJSON(c, raws)
	}
	var uuids = make([]string, len(rules))
	for i, rule := range rules {
		uuids[i] = rule.Uuid
	}
	if args.Bool("detail") {
		var details = make([][][2]string, len(rules))
		for i, rule := range rules {
			details[i] = firewallShaperRuleDetail(rule)
		}
		c.Details(details, uuids)
		return nil
	}
	var rows = make([][]string, len(rules))
	for i, rule := range rules {
		rows[i] = []string{firewallShaperDisabled(rule.Enabled), rule.Sequence, firewallShaperRuleInterfaces(rule), rule.Proto,
			firewallShaperMatch(rule.Source, rule.SourceNot, rule.SrcPort),
			firewallShaperMatch(rule.Destination, rule.DestinationNot, rule.DstPort), firewallShaperRuleDirection(rule),
			firewallShaperLabel(rule.TargetLabel, rule.Target), rule.Description}
	}
	c.Items([]string{"DISABLED", "SEQUENCE", "INTERFACE", "PROTOCOL", "SOURCE", "DESTINATION", "DIRECTION", "TARGET", "DESCRIPTION"}, rows, uuids)
	return nil
}

func firewallShaperRuleShow(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	rule, _, err := firewallShaperRules.selectItem(c, api, args.String("item"))
	if err != nil {
		return err
	}
	c.Fields(firewallShaperRuleDetail(rule))
	return nil
}

func firewallShaperRuleAdd(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	if args.Bool("replace") && strings.TrimSpace(args.String("description")) == "" {
		return errors.New("replace finds the rule by its description, give description=")
	}
	fields, options, err := firewallShaperRuleFields(api, args, false)
	if err != nil {
		return err
	}
	if !args.Has("sequence") {
		fields["sequence"] = options.NextSequence
	}
	var rule = firewall.ShaperRule{
		Enabled: fields["enabled"], Sequence: fields["sequence"], Interface: fields["interface"], Interface2: fields["interface2"],
		Proto: fields["proto"], Iplen: fields["iplen"], Source: fields["source"], SourceNot: fields["source_not"],
		SrcPort: fields["src_port"], Destination: fields["destination"], DestinationNot: fields["destination_not"],
		DstPort: fields["dst_port"], Dscp: fields["dscp"], Direction: fields["direction"], Target: fields["target"],
		Description: fields["description"],
	}
	return firewallShaperAdd(c, args.Bool("replace"), "rule", rule.Description,
		func() ([]string, error) {
			return firewallShaperRules.uuids(api.ShaperRuleFindByDescription(rule.Description))
		},
		func() (string, error) { return api.ShaperRuleCreate(rule) },
		func() (string, bool, error) { return api.ShaperRuleCreateOrUpdate(rule) })
}

func firewallShaperRuleSet(c *Context, args *Args) error {
	if len(args.Given()) <= 1 {
		return errors.New("set: nothing to change, give at least one field like target= or description= (type \"set ?\" for help)")
	}
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	fields, _, err := firewallShaperRuleFields(api, args, true)
	if err != nil {
		return err
	}
	rule, rules, err := firewallShaperRules.selectItem(c, api, args.String("item"))
	if err != nil {
		return err
	}
	if description := fields["description"]; description != "" {
		for _, other := range rules {
			if other.Uuid != rule.Uuid && strings.EqualFold(strings.TrimSpace(other.Description), description) {
				return fmt.Errorf("another rule described %q exists already (%s)", description, other.Uuid)
			}
		}
	}
	return api.ShaperRuleUpdate(rule.Uuid, fields)
}
