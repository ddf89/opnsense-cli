package cli

import (
	"cmp"
	"fmt"
	"net/netip"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/diagnostics"
	"slices"
	"strconv"
	"strings"
)

// /firewall/state: the pf state table (Firewall > Diagnostics > States, api/diagnostics/firewall): list, drop
// states one by one or by filter, flush the state and source tracking tables, the rule ids of the running ruleset

const (
	firewallStateRemoveConfirm       = "This drops the connection of the state."
	firewallStateKillConfirm         = "This drops every connection matching the filters, including yours when it matches."
	firewallStateFlushConfirm        = "This drops every connection through the firewall, including yours."
	firewallStateFlushSourcesConfirm = "This clears the source tracking table (sticky addresses and per source limits)."
	firewallStateFlushFlag           = "drop-own-connection"
)

// firewallStateSortFields are the values of print sort=
var firewallStateSortFields = []string{"interface", "protocol", "source", "destination", "state", "age", "expires", "packets", "bytes", "rule"}

// firewallStateFilterArgs are the filters shared by print and kill
func firewallStateFilterArgs() []Arg {
	return []Arg{
		{Name: "search", Help: "OPNsense's filter: addresses / networks (optionally with :port) must match an address of the state, other words must occur in any field (case-sensitive)"},
		{Name: "rule", Help: "only states created by this rule id (see rule-ids)", Complete: firewallStateCompleteRule},
		{Name: "interface", Type: List, Help: `only states bound to these interfaces, by device (vtnet0) or name (lan); floating states are bound to "all"`,
			Complete: firewallLogCompleteInterfaces},
		{Name: "protocol", Help: "only states of this protocol (tcp, udp, icmp, ...) or address family (ipv4, ipv6)"},
		{Name: "src", Help: "only states from this address or network (CIDR)", Validate: firewallLogValidatePrefix},
		{Name: "dst", Help: "only states to this address or network (CIDR)", Validate: firewallLogValidatePrefix},
		{Name: "port", Help: "only states with this source or destination port", Validate: ValidatePort},
	}
}

func init() {
	var menu = Root.Menu("firewall/state")
	menu.Help = "the pf state table: list and drop states"
	menu.Add(
		&Command{
			Name: "print",
			Help: "show the states of the firewall",
			Long: `Shows the pf states (connections tracked by the firewall) in pfctl order. The filters are combined with
AND; search= and rule= are evaluated by OPNsense, the others here. sort= orders the rows (reverse for
descending), limit= shows only the first rows. PACKETS and BYTES are the totals of both directions, RULE the
description of the rule that created the state. detail shows every field, json the states as OPNsense
returns them, one per line. follow refreshes the view every interval until Ctrl-C.

  print src=192.168.1.0/24 protocol=tcp
  print sort=bytes reverse limit=10 follow`,
			Args: append(firewallStateFilterArgs(),
				Arg{Name: "sort", Help: "order the rows by this column", Values: firewallStateSortFields},
				Arg{Name: "reverse", Type: Bool, Help: "sort descending"},
				Arg{Name: "limit", Type: Int, Default: "0", Help: "show at most this many states, 0 for all", Validate: ValidateRange(0, 100000000)},
				Arg{Name: "detail", Type: Bool, Help: "show every field of every state"},
				Arg{Name: "json", Type: Bool, Help: "print the states as JSON, one object per line"},
				Arg{Name: "follow", Type: Bool, Help: "refresh until Ctrl-C"},
				Arg{Name: "interval", Type: Duration, Default: "2s", Help: "pause between two refreshes of follow", Validate: systemActivityValidateInterval},
			),
			Check: firewallStateCheckReverse,
			Run:   firewallStatePrint,
		},
		&Command{
			Name: "remove",
			Help: "drop a state",
			Long: `Drops one state, the connection it tracks is cut (a new packet of it has to pass the rules again, TCP
connections usually fail). The item is the # of the last print or the state id as shown by print detail
(<state id>/<creator id>).`,
			Args: []Arg{
				{Name: "item", Positional: true, Required: true, Help: "the # or the state id"},
			},
			Confirm: firewallStateRemoveConfirm,
			Run:     firewallStateRemove,
		},
		&Command{
			Name: "kill",
			Help: "drop every state matching the filters",
			Long: `Drops every state matching the filters, which work like those of print (check with print first). At
least one filter is required, flush drops all states. The states are selected here and dropped one by one,
which is exact (OPNsense's own kill_states mangles networks, ports and IPv6 addresses). The number of dropped
states is reported on stderr.

  kill src=192.168.1.50 confirm=yes
  kill rule=b7cd97a164650b538506fb551a0369e7 confirm=yes`,
			Args:    firewallStateFilterArgs(),
			Confirm: firewallStateKillConfirm,
			Check:   firewallStateCheckKill,
			Run:     firewallStateKill,
		},
		&Command{
			Name: "flush",
			Help: "drop every state (cuts every connection, including yours)",
			Long: `Drops the whole state table (pfctl -F state): every connection through and to the firewall is cut,
including the one of this CLI and of the web GUI. Requires ` + firewallStateFlushFlag + ` besides the confirmation.`,
			Args: []Arg{
				{Name: firewallStateFlushFlag, Type: Bool, Help: "required: acknowledge that your own connection is cut too"},
			},
			Confirm: firewallStateFlushConfirm,
			Check:   firewallStateCheckFlush,
			Run:     firewallStateFlush,
		},
		&Command{
			Name:    "flush-sources",
			Help:    "clear the source tracking table",
			Long:    `Clears the source tracking table (pfctl -F Sources): sticky address assignments and the per source connection limits start over.`,
			Confirm: firewallStateFlushSourcesConfirm,
			Run:     firewallStateFlushSources,
		},
		&Command{
			Name: "rule-ids",
			Help: "show the rule ids of the running ruleset (for rule=)",
			Args: []Arg{
				{Name: "search", Help: "only rule ids where the id or description contains this text (case-insensitive)"},
				{Name: "json", Type: Bool, Help: "print the rule ids as JSON, one object per line"},
			},
			Run: firewallStateRuleIds,
		},
	)
}

func firewallStateCompleteRule(c *Context) []string {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return nil
	}
	var ids, listErr = api.FirewallRuleIds()
	if listErr != nil {
		return nil
	}
	var values = make([]string, 0, len(ids))
	for _, id := range ids {
		values = append(values, id.Id)
	}
	return values
}

// --- filters

type firewallStateFilter struct {
	query      diagnostics.FirewallStateQuery
	interfaces []string
	protocol   string
	src, dst   *netip.Prefix
	port       string
	names      map[string]string // device -> interface name, loaded when interface= is given
}

func firewallStateFilterNames() []string {
	var names []string
	for _, arg := range firewallStateFilterArgs() {
		names = append(names, arg.Name)
	}
	return names
}

// firewallStateHasFilter tells whether any filter argument was given with a value
func firewallStateHasFilter(args *Args) bool {
	for _, name := range firewallStateFilterNames() {
		if strings.TrimSpace(args.String(name)) != "" {
			return true
		}
	}
	return false
}

func firewallStateNewFilter(c *Context, api *diagnostics.DiagnosticsApi, args *Args) (firewallStateFilter, error) {
	var filter = firewallStateFilter{
		query:      diagnostics.FirewallStateQuery{Search: strings.TrimSpace(args.String("search")), RuleId: strings.TrimSpace(args.String("rule"))},
		interfaces: args.List("interface"),
		protocol:   strings.ToLower(strings.TrimSpace(args.String("protocol"))),
		port:       strings.TrimSpace(args.String("port")),
	}
	filter.src, _ = firewallLogParsePrefix(strings.TrimSpace(args.String("src")))
	filter.dst, _ = firewallLogParsePrefix(strings.TrimSpace(args.String("dst")))
	if len(filter.interfaces) > 0 {
		var names, err = systemActivityAwait(c, api.FirewallInterfaceNames)
		if err != nil {
			return filter, err
		}
		filter.names = names
	}
	return filter, nil
}

func (filter firewallStateFilter) match(state diagnostics.FirewallState) bool {
	if filter.query.RuleId != "" && !strings.EqualFold(state.Label, filter.query.RuleId) {
		return false
	}
	if len(filter.interfaces) > 0 {
		var matches = false
		for _, name := range filter.interfaces {
			if strings.EqualFold(state.Iface, name) || strings.EqualFold(state.Interface, name) ||
				strings.EqualFold(filter.names[state.Iface], name) {
				matches = true
			}
		}
		if !matches {
			return false
		}
	}
	if filter.protocol != "" && !strings.EqualFold(state.Proto, filter.protocol) && !strings.EqualFold(state.IpProto, filter.protocol) {
		return false
	}
	if filter.src != nil && !firewallLogMatchAddr(filter.src, state.SrcAddr) {
		return false
	}
	if filter.dst != nil && !firewallLogMatchAddr(filter.dst, state.DstAddr) {
		return false
	}
	if filter.port != "" && state.SrcPort != filter.port && state.DstPort != filter.port {
		return false
	}
	return true
}

func (filter firewallStateFilter) list(c *Context, api *diagnostics.DiagnosticsApi) ([]diagnostics.FirewallState, error) {
	var states, err = systemActivityAwait(c, func() ([]diagnostics.FirewallState, error) {
		return api.FirewallStateList(filter.query)
	})
	if err != nil {
		return nil, err
	}
	return coreapi.Filter(states, filter.match), nil
}

// --- print

var firewallStateHeaders = []string{"INTERFACE", "PROTO", "DIR", "SOURCE", "DESTINATION", "STATE", "AGE", "EXPIRES", "PACKETS", "BYTES", "RULE"}

func firewallStateCheckReverse(args *Args) error {
	if args.Bool("reverse") && args.String("sort") == "" {
		return fmt.Errorf("reverse needs sort=")
	}
	return nil
}

func firewallStatePrint(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var filter, filterErr = firewallStateNewFilter(c, api, args)
	if filterErr != nil {
		return filterErr
	}
	var asJSON = args.Bool("json")
	var refresh = systemActivityNewRefresher(c, args.Bool("follow") && !asJSON)

	return systemActivityPoll(c, args.Bool("follow"), args.Duration("interval"), func() error {
		var states, listErr = filter.list(c, api)
		if listErr != nil {
			return listErr
		}
		firewallStateSort(states, args.String("sort"), args.Bool("reverse"))
		if limit := args.Int("limit"); limit > 0 && len(states) > limit {
			states = states[:limit]
		}

		if asJSON {
			for _, state := range states {
				if err := c.JSON(state.Raw); err != nil {
					return err
				}
			}
			return nil
		}
		refresh()
		var ids = make([]string, 0, len(states))
		for _, state := range states {
			ids = append(ids, state.Id)
		}
		if args.Bool("detail") {
			var items = make([][][2]string, 0, len(states))
			for _, state := range states {
				items = append(items, firewallStateFields(state))
			}
			c.Details(items, ids)
			return nil
		}
		var rows = make([][]string, 0, len(states))
		for _, state := range states {
			rows = append(rows, []string{
				firewallStateInterface(state), state.Proto, state.Direction,
				firewallStateEndpoint(state.SrcAddr, state.SrcPort), firewallStateEndpoint(state.DstAddr, state.DstPort),
				state.State, state.Age, state.Expires, strconv.FormatInt(state.TotalPackets(), 10),
				ifaceBytes(float64(state.TotalBytes())), firewallStateRule(state),
			})
		}
		c.Items(firewallStateHeaders, rows, ids)
		return nil
	})
}

func firewallStateFields(state diagnostics.FirewallState) [][2]string {
	var nat = ""
	if state.NatAddr != "" {
		nat = firewallStateEndpoint(state.NatAddr, state.NatPort)
	}
	return [][2]string{
		{"id", state.Id},
		{"interface", firewallStateInterface(state)},
		{"protocol", state.Proto},
		{"family", state.IpProto},
		{"direction", state.Direction},
		{"source", firewallStateEndpoint(state.SrcAddr, state.SrcPort)},
		{"destination", firewallStateEndpoint(state.DstAddr, state.DstPort)},
		{"nat", nat},
		{"gateway", state.Gateway},
		{"state", state.State},
		{"age", state.Age},
		{"expires", state.Expires},
		{"packets", firewallStatePair(state.Pkts)},
		{"bytes", firewallStatePair(state.Bytes)},
		{"rule", state.Rule},
		{"rule-id", state.Label},
		{"rule-description", state.Descr},
		{"flags", strings.Join(state.Flags, ",")},
	}
}

// firewallStateInterface shows the interface name with the device, like "WAN (vtnet1)"
func firewallStateInterface(state diagnostics.FirewallState) string {
	if state.Interface == "" || strings.EqualFold(state.Interface, state.Iface) {
		return state.Iface
	}
	return fmt.Sprintf("%s (%s)", state.Interface, state.Iface)
}

// firewallStateEndpoint renders address and port, IPv6 as [addr]:port; port 0 (ICMP and others) is left out
func firewallStateEndpoint(addr string, port string) string {
	if port == "" || port == "0" {
		return addr
	}
	if strings.Contains(addr, ":") {
		return fmt.Sprintf("[%s]:%s", addr, port)
	}
	return addr + ":" + port
}

func firewallStateRule(state diagnostics.FirewallState) string {
	if state.Descr != "" {
		return state.Descr
	}
	return state.Label
}

// firewallStatePair renders both directions as "sent:received" with the total
func firewallStatePair(values []int64) string {
	var parts = make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.FormatInt(value, 10))
	}
	if len(values) < 2 {
		return strings.Join(parts, ":")
	}
	var total int64
	for _, value := range values {
		total += value
	}
	return fmt.Sprintf("%d (%s)", total, strings.Join(parts, ":"))
}

// firewallStateSeconds parses pf durations like 00:01:26 or 123:04:05 (hours, minutes, seconds), -1 when invalid
func firewallStateSeconds(value string) int64 {
	var parts = strings.Split(value, ":")
	if len(parts) != 3 {
		return -1
	}
	var seconds int64
	for _, part := range parts {
		var number, err = strconv.ParseInt(part, 10, 64)
		if err != nil {
			return -1
		}
		seconds = seconds*60 + number
	}
	return seconds
}

// firewallStateSort orders the states by field (stable, "" keeps pfctl order)
func firewallStateSort(states []diagnostics.FirewallState, field string, reverse bool) {
	var compare func(a, b diagnostics.FirewallState) int
	switch field {
	case "":
		return
	case "interface":
		compare = func(a, b diagnostics.FirewallState) int {
			return cmp.Compare(firewallStateInterface(a), firewallStateInterface(b))
		}
	case "protocol":
		compare = func(a, b diagnostics.FirewallState) int { return cmp.Compare(a.Proto, b.Proto) }
	case "source":
		compare = func(a, b diagnostics.FirewallState) int {
			return firewallStateCompareEndpoint(a.SrcAddr, a.SrcPort, b.SrcAddr, b.SrcPort)
		}
	case "destination":
		compare = func(a, b diagnostics.FirewallState) int {
			return firewallStateCompareEndpoint(a.DstAddr, a.DstPort, b.DstAddr, b.DstPort)
		}
	case "state":
		compare = func(a, b diagnostics.FirewallState) int { return cmp.Compare(a.State, b.State) }
	case "age":
		compare = func(a, b diagnostics.FirewallState) int {
			return cmp.Compare(firewallStateSeconds(a.Age), firewallStateSeconds(b.Age))
		}
	case "expires":
		compare = func(a, b diagnostics.FirewallState) int {
			return cmp.Compare(firewallStateSeconds(a.Expires), firewallStateSeconds(b.Expires))
		}
	case "packets":
		compare = func(a, b diagnostics.FirewallState) int { return cmp.Compare(a.TotalPackets(), b.TotalPackets()) }
	case "bytes":
		compare = func(a, b diagnostics.FirewallState) int { return cmp.Compare(a.TotalBytes(), b.TotalBytes()) }
	case "rule":
		compare = func(a, b diagnostics.FirewallState) int {
			return cmp.Compare(firewallStateRule(a), firewallStateRule(b))
		}
	default:
		return
	}
	slices.SortStableFunc(states, func(a, b diagnostics.FirewallState) int {
		if reverse {
			return compare(b, a)
		}
		return compare(a, b)
	})
}

// firewallStateCompareEndpoint orders addresses numerically (IPv4 before IPv6), then by port
func firewallStateCompareEndpoint(addrA, portA, addrB, portB string) int {
	var a, errA = netip.ParseAddr(addrA)
	var b, errB = netip.ParseAddr(addrB)
	if errA == nil && errB == nil {
		if result := a.Compare(b); result != 0 {
			return result
		}
	} else if result := cmp.Compare(addrA, addrB); result != 0 {
		return result
	}
	var numberA, _ = strconv.Atoi(portA)
	var numberB, _ = strconv.Atoi(portB)
	return cmp.Compare(numberA, numberB)
}

// --- remove, kill, flush

func firewallStateRemove(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var states, listErr = systemActivityAwait(c, func() ([]diagnostics.FirewallState, error) {
		return api.FirewallStateList(diagnostics.FirewallStateQuery{})
	})
	if listErr != nil {
		return listErr
	}
	var state, selectErr = Select(c, args.String("item"), states, func(s diagnostics.FirewallState) string { return s.Id },
		func(diagnostics.FirewallState) []string { return nil })
	if selectErr != nil {
		return selectErr
	}
	return api.FirewallStateRemove(state.Id)
}

func firewallStateCheckKill(args *Args) error {
	if !firewallStateHasFilter(args) {
		return fmt.Errorf("give at least one filter (%s), flush drops all states", strings.Join(firewallStateFilterNames(), "=, ")+"=")
	}
	return nil
}

func firewallStateKill(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var filter, filterErr = firewallStateNewFilter(c, api, args)
	if filterErr != nil {
		return filterErr
	}
	var states, listErr = filter.list(c, api)
	if listErr != nil {
		return listErr
	}
	var dropped = 0
	for _, state := range states {
		if c.Err() != nil {
			c.Infof("interrupted, dropped %d of %d states", dropped, len(states))
			return nil
		}
		if err := api.FirewallStateRemove(state.Id); err != nil {
			if coreapi.IsNotFound(err) {
				continue // gone in the meantime
			}
			return fmt.Errorf("dropped %d of %d states, then: %w", dropped, len(states), err)
		}
		dropped++
	}
	c.Infof("dropped %d states", dropped)
	return nil
}

func firewallStateCheckFlush(args *Args) error {
	if !args.Bool(firewallStateFlushFlag) {
		return fmt.Errorf("this cuts every connection, including yours: add %s to really flush the state table", firewallStateFlushFlag)
	}
	return nil
}

func firewallStateFlush(c *Context, _ *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	return api.FirewallStateFlush()
}

func firewallStateFlushSources(c *Context, _ *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	return api.FirewallSourceFlush()
}

// --- rule ids

func firewallStateRuleIds(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var ids, listErr = api.FirewallRuleIds()
	if listErr != nil {
		return listErr
	}
	var phrase = strings.ToLower(args.String("search"))
	ids = coreapi.Filter(ids, func(id diagnostics.FirewallRuleId) bool {
		return strings.Contains(strings.ToLower(id.Id+"\n"+id.Descr), phrase)
	})
	if args.Bool("json") {
		for _, id := range ids {
			if err := c.JSON(id); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, 0, len(ids))
	for _, id := range ids {
		rows = append(rows, []string{id.Id, id.Descr})
	}
	c.Table([]string{"RULE-ID", "DESCRIPTION"}, rows)
	return nil
}
