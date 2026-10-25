package cli

import (
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/firewall"
	"sort"
	"strings"
)

// /firewall/rule: Firewall > Rules (api/firewall/filter). Items are selected by the # of print, the uuid or the
// description. Next to the user rules OPNsense lists the automatic rules it generates (anti-lockout, default deny,
// DHCP, bogons, ...), they have md5 keys instead of uuids and can only be shown. export / import are added by
// firewall_rule_transfer.go

const firewallRuleItemHelp = "the #, uuid or description of the rule"

const firewallRuleApplyHint = `Changes are only saved, run "/firewall/rule apply" to load them into the firewall.`

// firewallRuleLastRevision is the savepoint of the last apply with rollback in this session, the default of confirm-apply
var firewallRuleLastRevision string

// firewallRuleKind tells how an argument maps to its API field
type firewallRuleKind int

const (
	firewallRuleKindText       firewallRuleKind = iota
	firewallRuleKindFlag                        // yes/no -> "1"/"0"
	firewallRuleKindDisabled                    // disabled yes/no -> enabled "0"/"1"
	firewallRuleKindIpProtocol                  // ipv4/ipv6/any -> inet/inet6/inet46
	firewallRuleKindProtocol                    // any stays, others upper case like the API (TCP, TCP/UDP, IPV6-ICMP)
	firewallRuleKindInterface                   // keys or names (LAN) -> keys
	firewallRuleKindCategories                  // names or uuids -> uuids
	firewallRuleKindNetwork                     // source / destination: a leading ! inverts
)

type firewallRuleField struct {
	arg   string
	field string
	kind  firewallRuleKind
}

// firewallRuleFieldMap lists the field arguments of add and set
var firewallRuleFieldMap = []firewallRuleField{
	{"action", "action", firewallRuleKindText},
	{"disabled", "enabled", firewallRuleKindDisabled},
	{"quick", "quick", firewallRuleKindFlag},
	{"interface", "interface", firewallRuleKindInterface},
	{"interface-invert", "interfacenot", firewallRuleKindFlag},
	{"direction", "direction", firewallRuleKindText},
	{"ip-protocol", "ipprotocol", firewallRuleKindIpProtocol},
	{"protocol", "protocol", firewallRuleKindProtocol},
	{"source", "source_net", firewallRuleKindNetwork},
	{"source-invert", "source_not", firewallRuleKindFlag},
	{"source-port", "source_port", firewallRuleKindText},
	{"destination", "destination_net", firewallRuleKindNetwork},
	{"destination-invert", "destination_not", firewallRuleKindFlag},
	{"destination-port", "destination_port", firewallRuleKindText},
	{"icmp-types", "icmptype", firewallRuleKindText},
	{"icmp6-types", "icmp6type", firewallRuleKindText},
	{"log", "log", firewallRuleKindFlag},
	{"categories", "categories", firewallRuleKindCategories},
	{"schedule", "sched", firewallRuleKindText},
	{"description", "description", firewallRuleKindText},
	{"sequence", "sequence", firewallRuleKindText},
	{"gateway", "gateway", firewallRuleKindText},
	{"reply-to", "replyto", firewallRuleKindText},
	{"disable-reply-to", "disablereplyto", firewallRuleKindFlag},
	{"state-type", "statetype", firewallRuleKindText},
	{"state-policy", "state-policy", firewallRuleKindText},
	{"state-timeout", "statetimeout", firewallRuleKindText},
	{"allow-options", "allowopts", firewallRuleKindFlag},
	{"no-sync", "nosync", firewallRuleKindFlag},
	{"no-pfsync", "nopfsync", firewallRuleKindFlag},
	{"max-states", "max", firewallRuleKindText},
	{"max-src-nodes", "max-src-nodes", firewallRuleKindText},
	{"max-src-states", "max-src-states", firewallRuleKindText},
	{"max-src-conn", "max-src-conn", firewallRuleKindText},
	{"max-src-conn-rate", "max-src-conn-rate", firewallRuleKindText},
	{"max-src-conn-rate-seconds", "max-src-conn-rates", firewallRuleKindText},
	{"overload", "overload", firewallRuleKindText},
	{"adaptive-start", "adaptivestart", firewallRuleKindText},
	{"adaptive-end", "adaptiveend", firewallRuleKindText},
	{"udp-first", "udp-first", firewallRuleKindText},
	{"udp-multiple", "udp-multiple", firewallRuleKindText},
	{"udp-single", "udp-single", firewallRuleKindText},
	{"tcp-flags", "tcpflags1", firewallRuleKindText},
	{"tcp-flags-of", "tcpflags2", firewallRuleKindText},
	{"tcp-flags-any", "tcpflags_any", firewallRuleKindFlag},
	{"priority", "prio", firewallRuleKindText},
	{"set-priority", "set-prio", firewallRuleKindText},
	{"set-priority-low", "set-prio-low", firewallRuleKindText},
	{"tag", "tag", firewallRuleKindText},
	{"tagged", "tagged", firewallRuleKindText},
	{"tos", "tos", firewallRuleKindText},
	{"divert-to", "divert-to", firewallRuleKindText},
	{"shaper", "shaper1", firewallRuleKindText},
	{"shaper-reverse", "shaper2", firewallRuleKindText},
}

var firewallRuleTcpFlags = []string{"syn", "ack", "fin", "rst", "psh", "urg", "ece", "cwr"}

var firewallRulePriorities = []string{"0", "1", "2", "3", "4", "5", "6", "7"}

// firewallRuleFieldArgs are the field arguments of add (with the OPNsense defaults) and set
func firewallRuleFieldArgs(add bool) []Arg {
	var defaultValue = func(value string) string {
		if add {
			return value
		}
		return ""
	}
	var number = func(name string, help string, min int, max int) Arg {
		return Arg{Name: name, Type: Int, Help: help + `, "" for none`, Validate: ValidateRange(min, max)}
	}
	const maxInt = 2147483647
	return []Arg{
		{Name: "action", Help: "what to do with matching packets", Values: []string{"pass", "block", "reject"}, Default: defaultValue("pass")},
		{Name: "disabled", Type: Bool, Help: "keep the rule, but don't use it", Default: defaultValue("no")},
		{Name: "quick", Type: Bool, Help: "the first matching rule wins (no: the last matching rule wins)", Default: defaultValue("yes")},
		{Name: "interface", Type: List, Help: `interfaces or interface groups like lan,opt1, "" for a floating rule on all interfaces`,
			Validate: firewallRuleValidateWords, Complete: firewallRuleInterfaceKeys},
		{Name: "interface-invert", Type: Bool, Help: "match all interfaces but the (single) given one", Default: defaultValue("no")},
		{Name: "direction", Help: "the direction of the packets", Values: []string{"in", "out", "any"}, Default: defaultValue("in")},
		{Name: "ip-protocol", Help: "the IP version", Values: []string{"ipv4", "ipv6", "any"}, Default: defaultValue("ipv4")},
		{Name: "protocol", Help: "any, TCP, UDP, TCP/UDP, ICMP, IPV6-ICMP, ESP, GRE, ...", Default: defaultValue("any"),
			Validate: firewallRuleValidateProtocol, Complete: firewallRuleOptionKeys("protocol")},
		{Name: "source", Help: `addresses, networks, aliases, any, (self) or interface networks like lan (lanip: its address), comma separated; a leading ! inverts a single one`,
			Default: defaultValue("any"), Validate: firewallRuleValidateNetwork, Complete: firewallRuleNetworkNames},
		{Name: "source-invert", Type: Bool, Help: "match everything but the (single) source"},
		{Name: "source-port", Help: "a port, a range like 1024-65535, a name like https or a port alias (TCP/UDP only)",
			Validate: firewallRuleValidatePort, Complete: firewallRulePortNames},
		{Name: "destination", Help: "like source", Default: defaultValue("any"), Validate: firewallRuleValidateNetwork, Complete: firewallRuleNetworkNames},
		{Name: "destination-invert", Type: Bool, Help: "match everything but the (single) destination"},
		{Name: "destination-port", Help: "like source-port", Validate: firewallRuleValidatePort, Complete: firewallRulePortNames},
		{Name: "icmp-types", Type: List, Help: "ICMP types like echoreq,unreach (protocol ICMP only)", Validate: firewallRuleValidateWords,
			Complete: firewallRuleOptionKeys("icmptype")},
		{Name: "icmp6-types", Type: List, Help: "ICMPv6 types as numbers like 128,129 (protocol IPV6-ICMP only)", Validate: firewallRuleValidateWords,
			Complete: firewallRuleOptionKeys("icmp6type")},
		{Name: "log", Type: Bool, Help: "log the packets matching this rule", Default: defaultValue("no")},
		{Name: "categories", Type: List, Help: "names (or uuids) of firewall categories", Validate: firewallRuleValidateText,
			Complete: firewallRuleCategoryNames},
		{Name: "schedule", Help: "the schedule the rule is active in", Validate: firewallRuleValidateText, Complete: firewallRuleOptionKeys("sched")},
		{Name: "description", Help: "any text, also the name of the rule", Validate: firewallRuleValidateText},
		{Name: "sequence", Type: Int, Help: "the position within its kind (1-999999), new rules go to the end, see also move",
			Validate: ValidateRange(1, 999999)},
		{Name: "gateway", Help: `policy routing: the gateway (group) for matching packets, "" for the routing table`,
			Validate: firewallRuleValidateText, Complete: firewallRuleOptionKeys("gateway")},
		{Name: "reply-to", Help: `the gateway for the replies, "" for the default`, Validate: firewallRuleValidateText,
			Complete: firewallRuleOptionKeys("replyto")},
		{Name: "disable-reply-to", Type: Bool, Help: "no automatic reply-to for this rule", Default: defaultValue("no")},
		{Name: "state-type", Help: "state tracking", Values: []string{"keep", "sloppy", "modulate", "synproxy", "none"}, Default: defaultValue("keep")},
		{Name: "state-policy", Help: `states bound to the interface or floating, "" for the default`, Values: []string{"if-bound", "floating"}},
		number("state-timeout", "state timeout in seconds (TCP only)", 1, maxInt),
		{Name: "allow-options", Type: Bool, Help: "allow packets with IP options", Default: defaultValue("no")},
		{Name: "no-sync", Type: Bool, Help: "don't sync the rule to an HA peer", Default: defaultValue("no")},
		{Name: "no-pfsync", Type: Bool, Help: "don't sync the states of the rule with pfsync", Default: defaultValue("no")},
		number("max-states", "maximum states of the rule", 1, maxInt),
		number("max-src-nodes", "maximum source addresses with states", 1, maxInt),
		number("max-src-states", "maximum states per source address", 1, maxInt),
		number("max-src-conn", "maximum established connections per source (TCP only)", 1, maxInt),
		number("max-src-conn-rate", "maximum new connections per source in max-src-conn-rate-seconds (TCP only)", 1, 4294967),
		number("max-src-conn-rate-seconds", "the period of max-src-conn-rate (TCP only)", 1, maxInt),
		{Name: "overload", Help: "the alias table sources exceeding the limits are added to (TCP only)", Validate: firewallRuleValidateText,
			Complete: firewallRuleOptionKeys("overload")},
		number("adaptive-start", "adaptive timeouts start at this number of states", 0, maxInt),
		number("adaptive-end", "adaptive timeouts end at this number of states", 0, maxInt),
		number("udp-first", "UDP state timeout after the first packet", 1, maxInt),
		number("udp-multiple", "UDP state timeout with packets in both directions", 1, maxInt),
		number("udp-single", "UDP state timeout with packets in one direction", 1, maxInt),
		{Name: "tcp-flags", Type: List, Help: "TCP flags that must be set, like syn", Values: firewallRuleTcpFlags},
		{Name: "tcp-flags-of", Type: List, Help: "TCP flags that are checked (out of), like syn,ack", Values: firewallRuleTcpFlags},
		{Name: "tcp-flags-any", Type: Bool, Help: "any TCP flags", Default: defaultValue("no")},
		{Name: "priority", Help: `match the VLAN priority 0-7, "" for any`, Values: firewallRulePriorities},
		{Name: "set-priority", Help: `set the VLAN priority 0-7, "" to keep it`, Values: firewallRulePriorities},
		{Name: "set-priority-low", Help: `set the VLAN priority 0-7 of low delay / ACK packets, "" to keep it`, Values: firewallRulePriorities},
		{Name: "tag", Help: "tag matching packets (a-z, 0-9, .,_-)", Validate: firewallRuleValidateText},
		{Name: "tagged", Help: "match packets with this tag", Validate: firewallRuleValidateText},
		{Name: "tos", Help: "match the TOS / DSCP value, like lowdelay or af11", Validate: firewallRuleValidateText, Complete: firewallRuleOptionKeys("tos")},
		{Name: "divert-to", Help: "divert matching packets to this port", Validate: firewallRuleValidateText, Complete: firewallRuleOptionKeys("divert-to")},
		{Name: "shaper", Help: "uuid of the traffic shaper pipe or queue", Validate: firewallRuleValidateText, Complete: firewallRuleOptionKeys("shaper1")},
		{Name: "shaper-reverse", Help: "uuid of the traffic shaper pipe or queue for the reverse direction", Validate: firewallRuleValidateText,
			Complete: firewallRuleOptionKeys("shaper2")},
	}
}

func init() {
	var menu = Root.Menu("firewall/rule")
	menu.Help = "firewall rules (Firewall > Rules)"
	var item = Arg{Name: "item", Help: firewallRuleItemHelp, Positional: true, Required: true, Complete: firewallRuleItemNames}
	menu.Add(
		&Command{Name: "print", Help: "list the firewall rules in evaluation order",
			Long: `Lists the user rules and the automatic rules OPNsense generates, in the order the firewall evaluates
them. FLAGS: A = automatic rule (can only be shown), L = logged, N = not quick (the last matching rule wins).
SOURCE / DESTINATION starting with ! are inverted.

interface= shows what the firewall evaluates on these interfaces: their rules, floating rules (no or several
interfaces), rules of interface groups containing them and the automatic rules. stats adds the pf counters.`,
			Args: []Arg{
				{Name: "detail", Help: "show all fields of every rule", Type: Bool},
				{Name: "json", Help: "one JSON object per line, as the API returns them", Type: Bool},
				{Name: "search", Help: "only rules where any field contains all of these words"},
				{Name: "interface", Type: List, Help: "only the rules evaluated on these interfaces", Validate: firewallRuleValidateWords,
					Complete: firewallRuleInterfaceKeys},
				{Name: "floating", Type: Bool, Help: "only floating rules (no or several interfaces)"},
				{Name: "category", Type: List, Help: "only rules with one of these categories (names)", Validate: firewallRuleValidateText,
					Complete: firewallRuleCategoryNames},
				{Name: "automatic", Type: Bool, Default: "yes", Help: "include the automatic rules"},
				{Name: "stats", Type: Bool, Help: "add the counters: evaluations, packets, bytes and states"},
			},
			Check: firewallRulePrintCheck, Run: firewallRulePrint},
		&Command{Name: "show", Help: "show all fields of one rule with its counters", Args: []Arg{item}, Run: firewallRuleShow},
		&Command{Name: "add", Help: "add a rule, prints its uuid",
			Long: `Without arguments a rule passes everything (pass, in, IPv4, any to any) on all interfaces: give at least
interface, action and what to match. New rules go to the end of their kind (floating, group or interface rules)
unless place-before or sequence is given. If a rule with this description exists, add fails unless replace is
given, then that rule is replaced completely (arguments not given are reset to their defaults, the position stays).

  add interface=lan action=block protocol=TCP destination=198.51.100.0/24 destination-port=443 description="no web" log
` + firewallRuleApplyHint,
			Args: append(firewallRuleFieldArgs(true),
				Arg{Name: "place-before", Help: "put the rule right before this rule (#, uuid or description)", Complete: firewallRuleItemNames},
				Arg{Name: "replace", Help: "replace the rule with the same description", Type: Bool}),
			Check: firewallRuleCheck, Run: firewallRuleAdd},
		&Command{Name: "set", Help: "change fields of a rule, the others are kept",
			Long: `Automatic rules can not be changed. Giving source= or destination= also sets whether it is inverted
(leading !). Use move to change the position.
` + firewallRuleApplyHint,
			Args:  append([]Arg{item}, firewallRuleFieldArgs(false)...),
			Check: firewallRuleCheck, Run: firewallRuleSet},
		&Command{Name: "remove", Help: "remove a rule", Long: firewallRuleApplyHint, Args: []Arg{item}, Run: firewallRuleRemove},
		&Command{Name: "enable", Help: "enable a rule", Long: firewallRuleApplyHint, Args: []Arg{item}, Run: firewallRuleEnabler(true)},
		&Command{Name: "disable", Help: "disable a rule", Long: firewallRuleApplyHint, Args: []Arg{item}, Run: firewallRuleEnabler(false)},
		&Command{Name: "move", Help: "move a rule right before another rule",
			Long: `Both rules must be of the same kind: floating, interface group or interface rules (one interface).
` + firewallRuleApplyHint,
			Args: []Arg{item, {Name: "before", Required: true, Help: "the rule to move before (#, uuid or description)", Complete: firewallRuleItemNames}},
			Run:  firewallRuleMove},
		&Command{Name: "apply", Help: "load the saved rules into the firewall",
			Long: `Where OPNsense supports it (up to 26.1) apply first stores a savepoint and applies with a rollback timer
like the GUI did: unless "confirm-apply" follows within 60 seconds, OPNsense restores the previous rules, so a
rule that cuts off access reverts itself. OPNsense 26.7 has no savepoints any more, there apply loads the rules
directly like the GUI does. no-rollback applies directly on all versions.`,
			Confirm: "This loads the saved rules into the firewall, a wrong rule can cut off access to it.",
			Args:    []Arg{{Name: "no-rollback", Type: Bool, Help: "apply without savepoint and rollback timer"}},
			Run:     firewallRuleApply},
		&Command{Name: "confirm-apply", Help: "keep the rules of an apply with rollback (stops the rollback timer)",
			Long: `Must follow "apply" within 60 seconds, otherwise OPNsense restores the rules of the savepoint.
Without revision the savepoint of the last apply in this session is used (OPNsense up to 26.1).`,
			Args: []Arg{{Name: "revision", Positional: true, Help: "the savepoint printed by apply", Validate: firewallRuleValidateRevision}},
			Run:  firewallRuleConfirmApply},
		&Command{Name: "revert", Help: "restore and apply the rules of a savepoint",
			Long:    `Restores the filter rules of the savepoint created by apply and loads them (OPNsense up to 26.1).`,
			Confirm: "This replaces the filter rules with those of the savepoint and loads them into the firewall.",
			Args: []Arg{{Name: "revision", Positional: true, Required: true, Help: "the savepoint printed by apply",
				Validate: firewallRuleValidateRevision}},
			Run: firewallRuleRevert},
	)
}

// --- validation

func firewallRuleValidateText(value string) error {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return fmt.Errorf("must not contain control characters like newlines, got %q", value)
		}
	}
	return nil
}

func firewallRuleValidateWords(value string) error {
	for _, element := range splitList(value) {
		if strings.ContainsAny(element, " \t\r\n/") {
			return fmt.Errorf("invalid element %q", element)
		}
	}
	return firewallRuleValidateText(value)
}

func firewallRuleValidateProtocol(value string) error {
	if value == "" || strings.ContainsAny(value, " \t\r\n,") {
		return fmt.Errorf("must be a protocol like any, TCP, UDP, TCP/UDP or ICMP, got %q", value)
	}
	return nil
}

func firewallRuleValidateNetwork(value string) error {
	var network = strings.TrimPrefix(value, "!")
	if err := firewall.FilterValidateNetwork(network); err != nil {
		return err
	}
	if network != value && len(splitList(network)) > 1 {
		return errors.New("only a single network can be inverted")
	}
	return nil
}

func firewallRuleValidatePort(value string) error {
	return firewall.FilterValidatePort(value)
}

func firewallRuleValidateRevision(value string) error {
	for _, char := range value {
		if (char < '0' || char > '9') && char != '.' {
			return fmt.Errorf("must be a savepoint revision like 1729876543.1234, got %q", value)
		}
	}
	return nil
}

// firewallRuleCheck checks the arguments which belong together
func firewallRuleCheck(args *Args) error {
	for _, side := range []string{"source", "destination"} {
		if args.Has(side) && args.Has(side+"-invert") && strings.HasPrefix(args.String(side), "!") && !args.Bool(side+"-invert") {
			return fmt.Errorf("%s=%s is inverted, but %s-invert=no", side, args.String(side), side)
		}
	}
	if args.Has("interface-invert") && args.Bool("interface-invert") && args.Has("interface") && len(args.List("interface")) != 1 {
		return errors.New("interface-invert needs exactly one interface")
	}
	if args.String("max-src-conn-rate") != "" && args.Has("max-src-conn-rate-seconds") && args.String("max-src-conn-rate-seconds") == "" ||
		args.String("max-src-conn-rate-seconds") != "" && args.Has("max-src-conn-rate") && args.String("max-src-conn-rate") == "" {
		return errors.New("max-src-conn-rate and max-src-conn-rate-seconds must be given together")
	}
	return nil
}

func firewallRulePrintCheck(args *Args) error {
	if args.Bool("floating") && args.Has("interface") {
		return errors.New("floating and interface can not be combined")
	}
	return nil
}

// --- lookups

func firewallRuleUuid(rule firewall.FilterRule) string {
	return rule.Uuid
}

func firewallRuleNames(rule firewall.FilterRule) []string {
	return []string{rule.Get("description")}
}

// firewallRuleSelect loads all rules and finds the one selector refers to
func firewallRuleSelect(c *Context, api *firewall.FirewallApi, selector string) (firewall.FilterRule, error) {
	var rules, err = api.FilterRuleList()
	if err != nil {
		return firewall.FilterRule{}, err
	}
	return Select(c, selector, rules, firewallRuleUuid, firewallRuleNames)
}

// firewallRuleRequireUser refuses automatic rules for changes
func firewallRuleRequireUser(rule firewall.FilterRule) error {
	if !rule.IsAutomatic() {
		return nil
	}
	var where = ""
	if ref := rule.Get("ref"); ref != "" {
		where = fmt.Sprintf(", it comes from the GUI page %s", ref)
	}
	return fmt.Errorf("%q is an automatic rule generated by OPNsense and can not be changed here%s", rule.Get("description"), where)
}

// firewallRuleItemNames completes item names (descriptions of user rules)
func firewallRuleItemNames(c *Context) []string {
	var api, err = firewallApi(c)
	if err != nil {
		return nil
	}
	var rules, listErr = api.FilterRuleList()
	if listErr != nil {
		return nil
	}
	var names []string
	for _, rule := range rules {
		if description := rule.Get("description"); description != "" && !rule.IsAutomatic() {
			names = append(names, description)
		}
	}
	return names
}

func firewallRuleInterfaceKeys(c *Context) []string {
	var api, err = firewallApi(c)
	if err != nil {
		return nil
	}
	var interfaces, listErr = api.FilterInterfaces()
	if listErr != nil {
		return nil
	}
	var keys = make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		keys = append(keys, iface.Key)
	}
	return keys
}

func firewallRuleCategoryNames(c *Context) []string {
	var api, err = firewallApi(c)
	if err != nil {
		return nil
	}
	var categories, listErr = api.FilterCategories()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(categories))
	for _, category := range categories {
		names = append(names, category.Name)
	}
	return names
}

func firewallRuleSortedKeys(options map[string]string) []string {
	var keys = make([]string, 0, len(options))
	for key := range options {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func firewallRuleNetworkNames(c *Context) []string {
	var api, err = firewallApi(c)
	if err != nil {
		return nil
	}
	var options, listErr = api.FilterNetworkOptions()
	if listErr != nil {
		return nil
	}
	return firewallRuleSortedKeys(options)
}

func firewallRulePortNames(c *Context) []string {
	var api, err = firewallApi(c)
	if err != nil {
		return nil
	}
	var options, listErr = api.FilterPortOptions()
	if listErr != nil {
		return nil
	}
	return firewallRuleSortedKeys(options)
}

// firewallRuleOptionKeys completes with the options of a field of the rule editor (get_rule)
func firewallRuleOptionKeys(field string) func(c *Context) []string {
	return func(c *Context) []string {
		var api, err = firewallApi(c)
		if err != nil {
			return nil
		}
		var options, listErr = api.FilterRuleOptions(field)
		if listErr != nil {
			return nil
		}
		return firewallRuleSortedKeys(options)
	}
}

// firewallRuleResolveInterfaces maps interface keys or names (LAN) to the keys
func firewallRuleResolveInterfaces(api *firewall.FirewallApi, values []string) (string, error) {
	if len(values) == 0 {
		return "", nil
	}
	var interfaces, err = api.FilterInterfaces()
	if err != nil {
		return "", err
	}
	var keys []string
	for _, value := range values {
		var key = ""
		for _, iface := range interfaces {
			if strings.EqualFold(iface.Key, value) || key == "" && strings.EqualFold(iface.Name, value) {
				key = iface.Key
			}
		}
		if key == "" {
			var known = make([]string, 0, len(interfaces))
			for _, iface := range interfaces {
				known = append(known, iface.Key)
			}
			return "", fmt.Errorf("unknown interface %q, rules can use: %s", value, strings.Join(known, ", "))
		}
		keys = append(keys, key)
	}
	return strings.Join(keys, ","), nil
}

// firewallRuleResolveCategories maps category names (or uuids) to uuids
func firewallRuleResolveCategories(api *firewall.FirewallApi, values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	var categories, err = api.FilterCategories()
	if err != nil {
		return nil, err
	}
	var uuids []string
	for _, value := range values {
		var uuid = ""
		for _, category := range categories {
			if strings.EqualFold(category.Name, value) || strings.EqualFold(category.Uuid, value) {
				uuid = category.Uuid
			}
		}
		if uuid == "" {
			var names = make([]string, 0, len(categories))
			for _, category := range categories {
				names = append(names, category.Name)
			}
			return nil, fmt.Errorf("unknown category %q, known are: %s", value, strings.Join(names, ", "))
		}
		uuids = append(uuids, uuid)
	}
	return uuids, nil
}

// --- output

func firewallRuleIpName(ipprotocol string) string {
	switch ipprotocol {
	case "inet":
		return "ipv4"
	case "inet6":
		return "ipv6"
	}
	return "any"
}

func firewallRuleIpProtocolValue(name string) string {
	switch strings.ToLower(name) {
	case "ipv6":
		return "inet6"
	case "any":
		return "inet46"
	}
	return "inet"
}

// firewallRuleKindNetwork renders source / destination with a leading ! when inverted
func firewallRuleNetwork(rule firewall.FilterRule, side string) string {
	var network = rule.Get(side + "_net")
	if network == "" {
		network = "any"
	}
	if rule.Flag(side + "_not") {
		network = "!" + network
	}
	return network
}

func firewallRuleInterface(rule firewall.FilterRule) string {
	var iface = rule.Get("interface")
	if iface == "" {
		return "any"
	}
	if rule.Flag("interfacenot") {
		return "!" + iface
	}
	return iface
}

func firewallRuleFlags(rule firewall.FilterRule) string {
	var flags = ""
	if rule.IsAutomatic() {
		flags += "A"
	}
	if rule.Flag("log") {
		flags += "L"
	}
	if !rule.Quick() {
		flags += "N"
	}
	return flags
}

func firewallRuleYesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func firewallRuleTruncate(text string, length int) string {
	var runes = []rune(text)
	if len(runes) <= length {
		return text
	}
	return string(runes[:length-3]) + "..."
}

// firewallRuleCategoryText renders the category uuids of a rule as names
func firewallRuleCategoryText(uuids string, categories []firewall.FilterCategory) string {
	var names []string
	for _, uuid := range splitList(uuids) {
		var name = uuid
		for _, category := range categories {
			if category.Uuid == uuid {
				name = category.Name
			}
		}
		names = append(names, name)
	}
	return strings.Join(names, ",")
}

// firewallRuleFields are the fields of show and print detail, named like the arguments of add and set
func firewallRuleFields(rule firewall.FilterRule, categories []firewall.FilterCategory) [][2]string {
	var fields = [][2]string{
		{"uuid", rule.Uuid},
		{"automatic", firewallRuleYesNo(rule.IsAutomatic())},
	}
	if ref := rule.Get("ref"); ref != "" {
		fields = append(fields, [2]string{"origin", ref})
	}
	fields = append(fields,
		[2]string{"disabled", firewallRuleYesNo(!rule.Enabled())},
		[2]string{"description", rule.Get("description")},
		[2]string{"action", rule.Get("action")},
		[2]string{"quick", firewallRuleYesNo(rule.Quick())},
		[2]string{"interface", firewallRuleInterface(rule)},
		[2]string{"direction", rule.Get("direction")},
		[2]string{"ip-protocol", firewallRuleIpName(rule.Get("ipprotocol"))},
		[2]string{"protocol", rule.Get("protocol")},
		[2]string{"source", firewallRuleNetwork(rule, "source")},
		[2]string{"source-port", rule.Get("source_port")},
		[2]string{"destination", firewallRuleNetwork(rule, "destination")},
		[2]string{"destination-port", rule.Get("destination_port")},
		[2]string{"log", firewallRuleYesNo(rule.Flag("log"))},
		[2]string{"categories", firewallRuleCategoryText(rule.Get("categories"), categories)},
		[2]string{"sequence", rule.Get("sequence")},
		[2]string{"evaluation-order", rule.Get("sort_order")},
	)
	if rule.IsAutomatic() {
		return fields
	}
	// the advanced fields, only shown when set
	for _, mapping := range firewallRuleFieldMap {
		switch mapping.arg {
		case "action", "disabled", "quick", "interface", "interface-invert", "direction", "ip-protocol", "protocol", "source",
			"source-invert", "source-port", "destination", "destination-invert", "destination-port", "log", "categories",
			"description", "sequence":
			continue
		}
		var value = rule.Get(mapping.field)
		if value == "" || mapping.kind == firewallRuleKindFlag && value == "0" || mapping.arg == "state-type" && value == "keep" {
			continue
		}
		if mapping.kind == firewallRuleKindFlag {
			value = "yes"
		}
		fields = append(fields, [2]string{mapping.arg, value})
	}
	return fields
}

func firewallRuleStatsFields(stats firewall.FilterRuleStats) [][2]string {
	return [][2]string{
		{"evaluations", fmt.Sprint(stats.Evaluations)},
		{"packets", fmt.Sprint(stats.Packets)},
		{"bytes", fmt.Sprint(stats.Bytes)},
		{"states", fmt.Sprint(stats.States)},
		{"pf-rules", fmt.Sprint(stats.PfRules)},
	}
}

func firewallRulePrint(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var query = firewall.FilterRuleQuery{SearchPhrase: args.String("search"), Floating: args.Bool("floating"), Statistics: args.Bool("stats")}
	if args.Has("interface") {
		var keys, resolveErr = firewallRuleResolveInterfaces(api, args.List("interface"))
		if resolveErr != nil {
			return resolveErr
		}
		query.Interfaces = splitList(keys)
	}
	var categories, catErr = api.FilterCategories()
	if catErr != nil && (args.Has("category") || args.Bool("detail")) {
		return catErr
	}
	if args.Has("category") {
		if query.Categories, err = firewallRuleResolveCategories(api, args.List("category")); err != nil {
			return err
		}
	}
	var all, searchErr = api.FilterRuleSearch(query)
	if searchErr != nil {
		return searchErr
	}

	var rules []firewall.FilterRule
	var uuids []string
	for _, rule := range all {
		if !args.Bool("automatic") && rule.IsAutomatic() {
			continue
		}
		rules = append(rules, rule)
		uuids = append(uuids, rule.Uuid)
	}

	switch {
	case args.Bool("json"):
		for _, rule := range rules {
			c.Println(string(rule.Raw))
		}
	case args.Bool("detail"):
		var items = make([][][2]string, len(rules))
		for i, rule := range rules {
			items[i] = firewallRuleFields(rule, categories)
			if args.Bool("stats") {
				items[i] = append(items[i], [][2]string{{"evaluations", rule.Get("evaluations")}, {"packets", rule.Get("packets")},
					{"bytes", rule.Get("bytes")}, {"states", rule.Get("states")}}...)
			}
		}
		c.Details(items, uuids)
	default:
		var headers = []string{"DISABLED", "FLAGS", "ACTION", "INTERFACE", "DIR", "IP", "PROTOCOL", "SOURCE", "DESTINATION", "PORT", "DESCRIPTION"}
		if args.Bool("stats") {
			headers = append(headers, "EVALUATIONS", "PACKETS", "BYTES", "STATES")
		}
		var rows = make([][]string, len(rules))
		for i, rule := range rules {
			var source = firewallRuleNetwork(rule, "source")
			if port := rule.Get("source_port"); port != "" {
				source += " port " + port
			}
			rows[i] = []string{firewallRuleYesNo(!rule.Enabled()), firewallRuleFlags(rule), rule.Get("action"), firewallRuleInterface(rule),
				rule.Get("direction"), firewallRuleIpName(rule.Get("ipprotocol")), strings.ToLower(rule.Get("protocol")), source,
				firewallRuleNetwork(rule, "destination"), rule.Get("destination_port"), firewallRuleTruncate(rule.Get("description"), 40)}
			if args.Bool("stats") {
				rows[i] = append(rows[i], rule.Get("evaluations"), rule.Get("packets"), rule.Get("bytes"), rule.Get("states"))
			}
		}
		c.Items(headers, rows, uuids)
	}
	return nil
}

func firewallRuleShow(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var rule, selectErr = firewallRuleSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var categories, _ = api.FilterCategories()
	var fields = firewallRuleFields(rule, categories)
	// the counters are extra information, a failure (e.g. missing privilege) does not fail show
	if stats, statsErr := api.FilterRuleStatistics(); statsErr == nil {
		if ruleStats, found := stats[rule.Uuid]; found {
			fields = append(fields, firewallRuleStatsFields(ruleStats)...)
		}
	}
	c.Fields(fields)
	return nil
}

// --- changes

// firewallRuleChanges returns the given field arguments as API fields, with all also the defaults of the arguments
// not given (but no sequence, OPNsense numbers new rules)
func firewallRuleChanges(api *firewall.FirewallApi, args *Args, all bool) (firewall.FilterRuleFields, error) {
	var fields = firewall.FilterRuleFields{}
	for _, mapping := range firewallRuleFieldMap {
		var given = args.Has(mapping.arg)
		if !given && (!all || mapping.arg == "sequence" || mapping.kind == firewallRuleKindFlag && strings.HasSuffix(mapping.arg, "-invert")) {
			continue
		}
		var value = args.String(mapping.arg)
		switch mapping.kind {
		case firewallRuleKindFlag:
			value = Flag(args.Bool(mapping.arg))
		case firewallRuleKindDisabled:
			value = Flag(!args.Bool(mapping.arg))
		case firewallRuleKindIpProtocol:
			value = firewallRuleIpProtocolValue(value)
		case firewallRuleKindProtocol:
			if !strings.EqualFold(value, "any") {
				value = strings.ToUpper(value)
			} else {
				value = "any"
			}
		case firewallRuleKindInterface:
			var keys, err = firewallRuleResolveInterfaces(api, args.List(mapping.arg))
			if err != nil {
				return nil, err
			}
			value = keys
		case firewallRuleKindCategories:
			var uuids, err = firewallRuleResolveCategories(api, args.List(mapping.arg))
			if err != nil {
				return nil, err
			}
			value = strings.Join(uuids, ",")
		case firewallRuleKindNetwork:
			var side = strings.TrimSuffix(mapping.field, "_net")
			var inverted = strings.HasPrefix(value, "!")
			value = strings.Join(splitList(strings.TrimPrefix(value, "!")), ",")
			if !args.Has(mapping.arg + "-invert") {
				fields[side+"_not"] = Flag(inverted)
			}
		default:
			if args.spec(mapping.arg).Type == List {
				value = strings.Join(args.List(mapping.arg), ",")
			}
		}
		fields[mapping.field] = value
	}
	for _, side := range []string{"source", "destination"} {
		if args.Has(side + "-invert") {
			fields[side+"_not"] = Flag(args.Bool(side + "-invert"))
		}
	}
	if all {
		for _, flag := range []string{"interfacenot", "source_not", "destination_not"} {
			if _, set := fields[flag]; !set {
				fields[flag] = "0"
			}
		}
	}
	return fields, nil
}

func firewallRuleAdd(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var rules, listErr = api.FilterRuleList()
	if listErr != nil {
		return listErr
	}

	var target *firewall.FilterRule
	if args.Has("place-before") {
		var found, selectErr = Select(c, args.String("place-before"), rules, firewallRuleUuid, firewallRuleNames)
		if selectErr != nil {
			return selectErr
		}
		if err := firewallRuleRequireUser(found); err != nil {
			return fmt.Errorf("place-before: %w", err)
		}
		target = &found
	}

	var existing []firewall.FilterRule
	if description := args.String("description"); description != "" {
		for _, rule := range rules {
			if !rule.IsAutomatic() && strings.EqualFold(rule.Get("description"), description) {
				existing = append(existing, rule)
			}
		}
	}
	switch {
	case len(existing) > 1:
		var uuids = make([]string, len(existing))
		for i, rule := range existing {
			uuids[i] = rule.Uuid
		}
		return &coreapi.TooManyFoundError{Name: fmt.Sprintf("%d rules have the description %q (%s), change or remove them with set or remove",
			len(existing), args.String("description"), strings.Join(uuids, ", "))}
	case len(existing) == 1 && !args.Bool("replace"):
		return fmt.Errorf("a rule with the description %q exists already (%s), change it with set or replace it with add ... replace",
			existing[0].Get("description"), existing[0].Uuid)
	}

	var fields, changesErr = firewallRuleChanges(api, args, true)
	if changesErr != nil {
		return changesErr
	}
	var uuid string
	if len(existing) == 1 {
		uuid = existing[0].Uuid
		if err := api.FilterRuleUpdate(uuid, fields); err != nil {
			return err
		}
		c.Infof("replaced the existing rule %q", existing[0].Get("description"))
	} else {
		var createErr error
		if uuid, createErr = api.FilterRuleCreate(fields); createErr != nil {
			return createErr
		}
	}
	c.Println(uuid)

	if target != nil {
		if err := api.FilterRuleMoveBefore(uuid, target.Uuid); err != nil {
			return fmt.Errorf("the rule %s was saved, but could not be placed before %q: %w", uuid, target.Get("description"), err)
		}
	}
	return nil
}

func firewallRuleSet(c *Context, args *Args) error {
	var given = false
	for _, mapping := range firewallRuleFieldMap {
		given = given || args.Has(mapping.arg)
	}
	if !given {
		return errors.New("set: nothing to change, give at least one field like action= or description= (type \"set ?\" for help)")
	}
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var rule, selectErr = firewallRuleSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if err := firewallRuleRequireUser(rule); err != nil {
		return err
	}
	var fields, changesErr = firewallRuleChanges(api, args, false)
	if changesErr != nil {
		return changesErr
	}
	if len(fields) == 1 && args.Has("log") {
		// like the log switch of the GUI
		return api.FilterRuleSetLog(rule.Uuid, args.Bool("log"))
	}
	return api.FilterRuleUpdate(rule.Uuid, fields)
}

func firewallRuleRemove(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var rule, selectErr = firewallRuleSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if err := firewallRuleRequireUser(rule); err != nil {
		return err
	}
	return api.FilterRuleRemove(rule.Uuid)
}

func firewallRuleEnabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = firewallApi(c)
		if err != nil {
			return err
		}
		var rule, selectErr = firewallRuleSelect(c, api, args.String("item"))
		if selectErr != nil {
			return selectErr
		}
		if err := firewallRuleRequireUser(rule); err != nil {
			return err
		}
		var changed, toggleErr = api.FilterRuleSetEnabled(rule.Uuid, enabled)
		if toggleErr != nil {
			return toggleErr
		}
		if !changed {
			c.Infof("rule %q is already %s", rule.Get("description"), EnabledWord(enabled))
		}
		return nil
	}
}

func firewallRuleMove(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var rules, listErr = api.FilterRuleList()
	if listErr != nil {
		return listErr
	}
	var rule, selectErr = Select(c, args.String("item"), rules, firewallRuleUuid, firewallRuleNames)
	if selectErr != nil {
		return selectErr
	}
	var target, targetErr = Select(c, args.String("before"), rules, firewallRuleUuid, firewallRuleNames)
	if targetErr != nil {
		return fmt.Errorf("before: %w", targetErr)
	}
	if err := firewallRuleRequireUser(rule); err != nil {
		return err
	}
	if err := firewallRuleRequireUser(target); err != nil {
		return fmt.Errorf("before: %w", err)
	}
	return api.FilterRuleMoveBefore(rule.Uuid, target.Uuid)
}

func firewallRuleApply(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	if args.Bool("no-rollback") {
		return api.FilterApply()
	}
	var revision, savepointErr = api.FilterSavepoint()
	if errors.Is(savepointErr, firewall.ErrFilterRollbackUnsupported) {
		c.Infof("this OPNsense version has no savepoints (removed in 26.7), the rules are applied without rollback like the GUI does")
		return api.FilterApply()
	}
	if savepointErr != nil {
		return savepointErr
	}
	if err := api.FilterApplyWithRollback(revision); err != nil {
		return err
	}
	firewallRuleLastRevision = revision
	c.Infof("applied with savepoint %s: run \"/firewall/rule confirm-apply %s\" within 60 seconds to keep the rules,\n"+
		"otherwise OPNsense restores the previous rules", revision, revision)
	return nil
}

func firewallRuleConfirmApply(c *Context, args *Args) error {
	var revision = args.String("revision")
	if revision == "" {
		revision = firewallRuleLastRevision
	}
	if revision == "" {
		return errors.New("confirm-apply: give the savepoint revision printed by apply")
	}
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	if err := api.FilterCancelRollback(revision); err != nil {
		return err
	}
	if revision == firewallRuleLastRevision {
		firewallRuleLastRevision = ""
	}
	return nil
}

func firewallRuleRevert(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	return api.FilterRevert(args.String("revision"))
}
