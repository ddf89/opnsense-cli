package cli

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"opnsense-cli/opnsense/api/firewall"
)

// /firewall/shaper: the traffic shaper service (api/trafficshaper/service): statistics, reconfigure, flush-reload,
// and the helpers shared by /firewall/shaper/pipe, queue and rule

func init() {
	var menu = Root.Menu("firewall/shaper")
	menu.Help = "traffic shaper: pipes, queues, rules, statistics"
	menu.Add(
		&Command{
			Name: "status",
			Help: "show the live shaper statistics: pipes, queues, their flows and rules",
			Long: `Shows the pipes and queues dummynet runs with their active flows (packets, bytes, drops); detail lists
every flow and the rules sending traffic to a queue. The queue shown right after a pipe with "(direct)" carries the
traffic rules send to the pipe itself. Saved but not applied changes are not visible here.

follow repeats the query every interval until Ctrl-C.`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all values, the flows and the rules of every pipe and queue"},
				{Name: "json", Type: Bool, Help: "one JSON object per pipe / queue, as the API returns them"},
				{Name: "follow", Type: Bool, Help: "refresh until Ctrl-C"},
				{Name: "interval", Type: Duration, Default: "2s", Help: "pause between two refreshes of follow", Validate: systemActivityValidateInterval},
			},
			Run: firewallShaperStatus,
		},
		&Command{
			Name:    "reconfigure",
			Aliases: []string{"apply"},
			Help:    "apply the saved pipes, queues and rules (regenerate and reload dummynet and ipfw)",
			Run: func(c *Context, _ *Args) error {
				var api, err = firewallApi(c)
				if err != nil {
					return err
				}
				return api.ShaperReconfigure()
			},
		},
		&Command{
			Name: "flush-reload",
			Help: "flush all ipfw rules and reload the shaper and ipfw",
			Long: `Use this when the running shaper does not match the configuration after reconfigure: all ipfw rules
(traffic shaper and captive portal) are removed and loaded again.`,
			Confirm: "This flushes all ipfw rules (traffic shaper and captive portal) and loads them again, shaping and captive portal are interrupted briefly.",
			Run: func(c *Context, _ *Args) error {
				var api, err = firewallApi(c)
				if err != nil {
					return err
				}
				return api.ShaperFlushReload()
			},
		},
	)
}

// firewallShaperApplyHint ends the help of the commands that change the shaper configuration
const firewallShaperApplyHint = `Changes are only saved, run "/firewall/shaper reconfigure" to apply them.`

func firewallShaperStatus(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var asJSON = args.Bool("json")
	var refresh = systemActivityNewRefresher(c, args.Bool("follow") && !asJSON)
	return systemActivityPoll(c, args.Bool("follow"), args.Duration("interval"), func() error {
		var stats, getErr = systemActivityAwait(c, api.ShaperStatisticsGet)
		if getErr != nil {
			return getErr
		}
		if asJSON {
			for _, item := range stats.Items {
				if err := c.JSON(item.Raw); err != nil {
					return err
				}
			}
			return nil
		}
		refresh()
		firewallShaperShowStatistics(c, stats.Items, args.Bool("detail"))
		return nil
	})
}

func firewallShaperShowStatistics(c *Context, items []firewall.ShaperStatItem, detail bool) {
	// the automatic queue of a pipe follows the pipe and has no description of its own
	var descriptions = make([]string, len(items))
	var pipe string
	for i, item := range items {
		descriptions[i] = item.Description
		switch {
		case item.Type == "pipe":
			pipe = item.Description
		case item.Template:
			descriptions[i] = pipe + " (direct)"
		}
	}

	if detail {
		var blocks = make([][][2]string, len(items))
		var ids = make([]string, len(items))
		for i, item := range items {
			ids[i] = item.Id
			var packets, bytes, drops = item.Packets()
			var fields = [][2]string{
				{"type", item.Type}, {"id", item.Id}, {"uuid", item.Uuid}, {"description", descriptions[i]},
			}
			if item.Type == "pipe" {
				fields = append(fields, [2]string{"bandwidth", item.Bandwidth}, [2]string{"delay", item.Delay},
					[2]string{"burst", item.Burst}, [2]string{"scheduler", item.SchedulerType})
			} else {
				fields = append(fields, [2]string{"weight", item.Weight}, [2]string{"queue-size", item.QueueSize})
			}
			fields = append(fields, [2]string{"flows", strconv.Itoa(len(item.Flows))}, [2]string{"packets", strconv.FormatInt(packets, 10)},
				[2]string{"bytes", ifaceBytes(float64(bytes))}, [2]string{"drops", strconv.FormatInt(drops, 10)})
			for _, flow := range item.Flows {
				fields = append(fields, [2]string{"flow", fmt.Sprintf("%s %s -> %s, %d packets, %s, %d drops", flow.Proto, flow.Source,
					flow.Destination, flow.Packets, ifaceBytes(float64(flow.Bytes)), flow.DropPackets)})
			}
			for _, rule := range item.Rules {
				var accessed = "never"
				if rule.AccessedEpoch > 0 {
					accessed = time.Unix(rule.AccessedEpoch, 0).Local().Format(time.DateTime)
				}
				fields = append(fields, [2]string{"rule", fmt.Sprintf("%s %q, %d packets, %s, last %s", rule.Rule, rule.Description,
					rule.Packets, ifaceBytes(float64(rule.Bytes)), accessed)})
			}
			blocks[i] = fields
		}
		c.Details(blocks, ids)
		return
	}

	var rows = make([][]string, 0, len(items))
	for i, item := range items {
		var packets, bytes, drops = item.Packets()
		var bandwidth, weight, scheduler string
		if item.Type == "pipe" {
			bandwidth, scheduler = item.Bandwidth, item.SchedulerType
		} else if !item.Template {
			weight = item.Weight
		}
		rows = append(rows, []string{item.Type, item.Id, descriptions[i], bandwidth, weight, scheduler, strconv.Itoa(len(item.Flows)),
			strconv.FormatInt(packets, 10), ifaceBytes(float64(bytes)), strconv.FormatInt(drops, 10)})
	}
	c.Table([]string{"TYPE", "ID", "DESCRIPTION", "BANDWIDTH", "WEIGHT", "SCHEDULER", "FLOWS", "PACKETS", "BYTES", "DROPS"}, rows)
}

// --- helpers of the item menus

// firewallShaperKind ties the generic commands (select, remove, enable, disable) to a record type
type firewallShaperKind[T any] struct {
	what        string // "pipe", for messages
	list        func(api *firewall.FirewallApi) ([]T, error)
	uuid        func(T) string
	description func(T) string
	enabled     func(T) string
	remove      func(api *firewall.FirewallApi, uuid string) error
	setEnabled  func(api *firewall.FirewallApi, uuid string, enabled bool) (bool, error)
}

// selectItem loads all records and returns the one the selector refers to: # of print, uuid or description
func (k firewallShaperKind[T]) selectItem(c *Context, api *firewall.FirewallApi, selector string) (T, []T, error) {
	var items, err = k.list(api)
	if err != nil {
		var zero T
		return zero, nil, err
	}
	item, err := Select(c, selector, items, k.uuid, func(item T) []string { return []string{strings.TrimSpace(k.description(item))} })
	return item, items, err
}

// names completes the item argument: the descriptions
func (k firewallShaperKind[T]) names(c *Context) []string {
	var api, err = firewallApi(c)
	if err != nil {
		return nil
	}
	var items, listErr = k.list(api)
	if listErr != nil {
		return nil
	}
	var names []string
	for _, item := range items {
		if description := strings.TrimSpace(k.description(item)); description != "" {
			names = append(names, description)
		}
	}
	return names
}

// uuids returns the uuids of found records
func (k firewallShaperKind[T]) uuids(items []T, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	var uuids = make([]string, len(items))
	for i, item := range items {
		uuids[i] = k.uuid(item)
	}
	return uuids, nil
}

func (k firewallShaperKind[T]) itemArg() Arg {
	return Arg{Name: "item", Positional: true, Required: true, Help: fmt.Sprintf("the #, uuid or description of the %s", k.what),
		Complete: k.names}
}

func (k firewallShaperKind[T]) runRemove(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	item, _, err := k.selectItem(c, api, args.String("item"))
	if err != nil {
		return err
	}
	return k.remove(api, k.uuid(item))
}

func (k firewallShaperKind[T]) enabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = firewallApi(c)
		if err != nil {
			return err
		}
		item, _, err := k.selectItem(c, api, args.String("item"))
		if err != nil {
			return err
		}
		if (k.enabled(item) != "0") == enabled {
			c.Infof("the %s %s is already %s", k.what, k.description(item), EnabledWord(enabled))
			return nil
		}
		_, err = k.setEnabled(api, k.uuid(item), enabled)
		return err
	}
}

// commands returns print/show/add/set/remove/enable/disable for a record type
func (k firewallShaperKind[T]) commands(printArgs []Arg, print func(c *Context, args *Args) error,
	show func(c *Context, args *Args) error, addLong string, addArgs []Arg, add func(c *Context, args *Args) error,
	setArgs []Arg, set func(c *Context, args *Args) error) []*Command {
	var item = k.itemArg()
	return []*Command{
		{Name: "print", Help: fmt.Sprintf("list the %ss", k.what), Args: printArgs, Run: print},
		{Name: "show", Help: fmt.Sprintf("show all fields of one %s", k.what), Args: []Arg{item}, Run: show},
		{Name: "add", Help: fmt.Sprintf("add a %s, prints its uuid", k.what), Long: addLong + "\n" + firewallShaperApplyHint,
			Args: append(addArgs, Arg{Name: "replace", Type: Bool, Help: fmt.Sprintf("overwrite an existing %s with the same description", k.what)}),
			Run:  add},
		{Name: "set", Help: fmt.Sprintf("change fields of a %s, the others are kept", k.what),
			Long: "All named arguments are new values, an empty value clears a field.\n" + firewallShaperApplyHint,
			Args: append([]Arg{item}, setArgs...), Run: set},
		{Name: "remove", Help: "remove a " + k.what, Long: firewallShaperApplyHint, Args: []Arg{item}, Run: k.runRemove},
		{Name: "enable", Help: "enable a " + k.what, Long: firewallShaperApplyHint, Args: []Arg{item}, Run: k.enabler(true)},
		{Name: "disable", Help: "disable a " + k.what, Long: firewallShaperApplyHint, Args: []Arg{item}, Run: k.enabler(false)},
	}
}

// firewallShaperPrintArgs are the arguments of print
func firewallShaperPrintArgs(what string) []Arg {
	return []Arg{
		{Name: "detail", Type: Bool, Help: fmt.Sprintf("show all fields of every %s", what)},
		{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
		{Name: "search", Help: fmt.Sprintf("only %ss where any field contains this text", what)},
	}
}

// firewallShaperDisabled renders the enabled flag of the API as the disabled argument
func firewallShaperDisabled(enabled string) string {
	if enabled == "0" {
		return "yes"
	}
	return "no"
}

// firewallShaperArgField maps an argument to an API field: text (trimmed), flag ("1"/"0"), notFlag (disabled)
type firewallShaperArgField struct {
	arg, field, kind string
}

// firewallShaperFields returns the field arguments as API fields: all of them (add) or just the given ones (set)
func firewallShaperFields(args *Args, mapping []firewallShaperArgField, onlyGiven bool) firewall.ShaperFields {
	var fields = firewall.ShaperFields{}
	for _, m := range mapping {
		if onlyGiven && !args.Has(m.arg) {
			continue
		}
		switch m.kind {
		case "flag":
			fields[m.field] = Flag(args.Bool(m.arg))
		case "notFlag":
			fields[m.field] = Flag(!args.Bool(m.arg))
		default:
			fields[m.field] = strings.TrimSpace(args.String(m.arg))
		}
	}
	return fields
}

// firewallShaperCodelArgs are the CoDel / PIE arguments of pipes and queues
func firewallShaperCodelArgs() []Arg {
	return []Arg{
		{Name: "codel", Type: Bool, Help: "enable CoDel active queue management"},
		{Name: "codel-target", Type: Int, Help: "CoDel target delay in ms, empty for the default (5)", Validate: ValidateRange(1, 10000)},
		{Name: "codel-interval", Type: Int, Help: "CoDel interval in ms, empty for the default (100)", Validate: ValidateRange(1, 10000)},
		{Name: "codel-ecn", Type: Bool, Help: "mark packets with ECN instead of dropping them (CoDel)"},
		{Name: "pie", Type: Bool, Help: "enable PIE active queue management (not together with codel)"},
	}
}

var firewallShaperCodelFields = []firewallShaperArgField{
	{"codel", "codel_enable", "flag"}, {"codel-target", "codel_target", "text"}, {"codel-interval", "codel_interval", "text"},
	{"codel-ecn", "codel_ecn_enable", "flag"}, {"pie", "pie_enable", "flag"},
}

// firewallShaperCheckCodel refuses codel and pie together
func firewallShaperCheckCodel(args *Args) error {
	if args.Bool("codel") && args.Bool("pie") {
		return errors.New("codel and pie can not be combined")
	}
	return nil
}

// firewallShaperMaskValues are the mask choices
var firewallShaperMaskArg = Arg{Name: "mask", Values: firewall.ShaperMasks,
	Help: "share the bandwidth per address: a dynamic pipe / queue per source or destination (src-ip, dst-ip, src-ip6, dst-ip6)"}

// --- bandwidth

var firewallShaperBandwidthPattern = regexp.MustCompile(`^(\d+)\s*([A-Za-z]*?)(?:ps|/s)?$`)

// firewallShaperParseBandwidth splits "100Mbit", "100 Mbit/s", "100M" or "100" into the number and the metric
// (bit, Kbit, Mbit, Gbit; "" when not given)
func firewallShaperParseBandwidth(value string) (string, string, error) {
	var match = firewallShaperBandwidthPattern.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return "", "", fmt.Errorf("must be a bandwidth like 100Mbit, 512Kbit or 1Gbit, got %q", value)
	}
	var number, unit = strings.TrimLeft(match[1], "0"), strings.ToLower(match[2])
	if number == "" {
		return "", "", fmt.Errorf("must be at least 1, got %q", value)
	}
	switch unit {
	case "":
		return number, "", nil
	case "b", "bit":
		return number, "bit", nil
	case "k", "kb", "kbit":
		return number, "Kbit", nil
	case "m", "mb", "mbit":
		return number, "Mbit", nil
	case "g", "gb", "gbit":
		return number, "Gbit", nil
	}
	return "", "", fmt.Errorf("unknown bandwidth unit %q in %q, use bit, Kbit, Mbit or Gbit", match[2], value)
}

func firewallShaperValidateBandwidth(value string) error {
	if value == "" {
		return errors.New("must not be empty")
	}
	var _, _, err = firewallShaperParseBandwidth(value)
	return err
}

// firewallShaperBandwidthMultiplier returns the bit/s of one unit of metric
func firewallShaperBandwidthMultiplier(metric string) float64 {
	switch metric {
	case "bit":
		return 1
	case "Mbit":
		return 1e6
	case "Gbit":
		return 1e9
	default:
		return 1e3
	}
}

// firewallShaperBandwidth resolves the bandwidth and bandwidth-metric arguments to the API fields (a unit in the
// bandwidth sets the metric), checking the maximum of 4294967295 bit/s when the metric is known. defaultMetric is
// used when neither gives a unit ("" to leave the metric unchanged)
func firewallShaperBandwidth(args *Args, defaultMetric string) (firewall.ShaperFields, error) {
	var fields = firewall.ShaperFields{}
	var metric = firewallShaperMetricKey(args.String("bandwidth-metric"))
	if args.Has("bandwidth") {
		var number, unit, err = firewallShaperParseBandwidth(args.String("bandwidth"))
		if err != nil {
			return nil, err
		}
		if unit != "" && args.Has("bandwidth-metric") && unit != metric {
			return nil, fmt.Errorf("bandwidth=%s and bandwidth-metric=%s contradict each other", args.String("bandwidth"), metric)
		}
		if unit != "" {
			metric = unit
		}
		if metric == "" {
			metric = defaultMetric
		}
		fields["bandwidth"] = number
		if metric != "" {
			var value, _ = strconv.ParseFloat(number, 64)
			var maximum = math.Floor(firewall.ShaperMaxBandwidth / firewallShaperBandwidthMultiplier(metric))
			if value > maximum {
				return nil, fmt.Errorf("%s %s/s exceeds the maximum bandwidth of %.0f %s/s", number, metric, maximum, metric)
			}
		}
	}
	if metric != "" {
		fields["bandwidthMetric"] = metric
	}
	return fields, nil
}

// firewallShaperMetricKey maps a bandwidth-metric argument (matched case-insensitively) to the option key
func firewallShaperMetricKey(value string) string {
	for _, metric := range firewall.ShaperBandwidthMetrics {
		if strings.EqualFold(metric, value) {
			return metric
		}
	}
	return value
}

// firewallShaperBandwidthText renders a pipe's bandwidth like "100 Mbit/s"
func firewallShaperBandwidthText(bandwidth string, metric string) string {
	if bandwidth == "" {
		return ""
	}
	return fmt.Sprintf("%s %s/s", bandwidth, metric)
}

// --- addresses and ports of rules

// firewallShaperValidateNetworks accepts "any" or comma separated networks (CIDR) / addresses
func firewallShaperValidateNetworks(value string) error {
	var elements = splitList(value)
	for _, element := range elements {
		if strings.EqualFold(element, "any") {
			if len(elements) > 1 {
				return errors.New("any can not be combined with networks")
			}
			continue
		}
		if _, err := netip.ParsePrefix(element); err == nil {
			continue
		}
		if net.ParseIP(element) == nil {
			return fmt.Errorf("must be any or networks like 192.0.2.0/24 or addresses, got %q", element)
		}
	}
	return nil
}

// firewallShaperNetworks normalizes a network list, an empty list is any
func firewallShaperNetworks(values []string) string {
	var normalized = make([]string, 0, len(values))
	for _, value := range values {
		if strings.EqualFold(value, "any") {
			return "any"
		}
		normalized = append(normalized, openvpnClientOverrideNormalizeNetwork(value))
	}
	if len(normalized) == 0 {
		return "any"
	}
	return strings.Join(normalized, ",")
}

var firewallShaperServicePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// firewallShaperValidatePort accepts any, a port, a range 1000-2000 or a service name (http)
func firewallShaperValidatePort(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "any") || firewallShaperServicePattern.MatchString(value) {
		return nil
	}
	var ports = []string{value}
	if from, to, isRange := strings.Cut(value, "-"); isRange {
		ports = []string{from, to}
	}
	for _, port := range ports {
		if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
			return fmt.Errorf("must be any, a port 1-65535, a range like 1000-2000 or a service name like https, got %q", value)
		}
	}
	return nil
}

// firewallShaperPort returns a port argument for the API, "any" for empty
func firewallShaperPort(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "any") {
		return "any"
	}
	return value
}

// firewallShaperResolveOption maps a value to the key of an option: the key or the label (case-insensitive)
func firewallShaperResolveOption(what string, options []firewall.ShaperOption, value string) (string, error) {
	for _, option := range options {
		if strings.EqualFold(option.Key, value) {
			return option.Key, nil
		}
	}
	var matches []firewall.ShaperOption
	for _, option := range options {
		if strings.EqualFold(strings.TrimSpace(option.Label), strings.TrimSpace(value)) {
			matches = append(matches, option)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0].Key, nil
	case 0:
		var known = make([]string, 0, len(options))
		for _, option := range options {
			if option.Key == option.Label {
				known = append(known, option.Key)
			} else {
				known = append(known, fmt.Sprintf("%s (%s)", option.Label, option.Key))
			}
		}
		if len(known) == 0 {
			return "", fmt.Errorf("unknown %s %q, there are none", what, value)
		}
		return "", fmt.Errorf("unknown %s %q, choose one of %s", what, value, strings.Join(known, ", "))
	default:
		var keys = make([]string, 0, len(matches))
		for _, match := range matches {
			keys = append(keys, match.Key)
		}
		return "", fmt.Errorf("%d %ss are named %q (%s), use the uuid", len(matches), what, value, strings.Join(keys, ", "))
	}
}
