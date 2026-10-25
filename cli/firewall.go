package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"opnsense-cli/opnsense/api/diagnostics"
	"sort"
	"strconv"
	"strings"
)

// /firewall/log: the firewall (pf filterlog) log: tail, follow, filter choices and statistics

// firewallLogStatsFields are the record fields offered for stats by= (OPNsense accepts any field)
var firewallLogStatsFields = []string{"interface", "action", "dir", "protoname", "proto", "src", "dst", "srcport", "dstport",
	"label", "rule", "rid", "rulenr", "reason", "ipversion", "tcpflags"}

func init() {
	Root.Sub("firewall", "firewall diagnostics")
	var menu = Root.Menu("firewall/log")
	menu.Help = "the firewall (filter) log"

	menu.Add(
		&Command{
			Name: "print",
			Help: "show the newest firewall log records, optionally following new ones",
			Long: `Shows the newest firewall log records (oldest first), optionally following new ones until Ctrl-C.

Filters are applied client side and combined with AND. When filtering, the newest scan= records are searched
for the last lines= matches.

follow polls the log every interval= and shows every record. stream uses the OPNsense live stream instead:
lower latency, but OPNsense throttles it and silently drops records, so it is incomplete.`,
			Args: []Arg{
				{Name: "lines", Help: "number of records to show", Type: Int, Default: "50", Validate: firewallLogValidateNotNegative},
				{Name: "follow", Help: "keep showing new records until Ctrl-C", Type: Bool},
				{Name: "stream", Help: "follow using the OPNsense live stream (lossy, implies follow)", Type: Bool},
				{Name: "interval", Help: "poll interval for follow", Type: Duration, Default: "1s", Validate: firewallLogValidateInterval},
				{Name: "action", Help: "only records with this action: pass, block, rdr, nat, binat (as offered by OPNsense, see filters)",
					Complete: firewallLogCompleteActions},
				{Name: "interface", Help: "only records of this interface, by name (lan, wan, ...) or device (vtnet0)",
					Complete: firewallLogCompleteInterfaces},
				{Name: "dir", Help: "only records of this direction", Values: []string{"in", "out"}},
				{Name: "proto", Help: "only records of this protocol, by name (tcp, udp, icmp, ...) or number"},
				{Name: "src", Help: "only records from this address or network (CIDR)", Validate: firewallLogValidatePrefix},
				{Name: "dst", Help: "only records to this address or network (CIDR)", Validate: firewallLogValidatePrefix},
				{Name: "port", Help: "only records with this source or destination port", Validate: ValidatePort},
				{Name: "search", Help: "only records containing this text in any field (case-insensitive)"},
				{Name: "scan", Help: "number of newest records to search when filtering", Type: Int,
					Default: strconv.Itoa(diagnostics.FirewallLogDefaultLimit), Validate: firewallLogValidateNotNegative},
				{Name: "json", Help: "print the raw records as JSON, one per line", Type: Bool},
			},
			Check: firewallLogPrintCheck,
			Run:   firewallLogPrint,
		},
		&Command{
			Name: "filters",
			Help: "show the values the firewall log can be filtered by",
			Run:  firewallLogFilters,
		},
		&Command{
			Name: "stats",
			Help: "count the newest firewall log records grouped by a field (top 10 plus other)",
			Long: `by= takes any firewall log field, e.g. interface (default), action, dir, protoname, src, dst, srcport,
dstport, label, rid. proto and rule are accepted for protoname and label.`,
			Args: []Arg{
				{Name: "by", Help: "field to group by", Default: "interface",
					Complete: func(*Context) []string { return firewallLogStatsFields }},
				{Name: "scan", Help: "number of newest records to count (like print scan=)", Type: Int, Default: "5000", Validate: firewallLogValidateNotNegative},
				{Name: "json", Help: "print one JSON object per group", Type: Bool},
			},
			Run: firewallLogStats,
		},
	)
}

func firewallLogApi(c *Context) (*diagnostics.DiagnosticsApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &diagnostics.DiagnosticsApi{OPNsense: opn}, nil
}

// firewallLogPrintCheck rejects interval= where it has no effect: it is the poll interval of follow, stream does not poll
func firewallLogPrintCheck(args *Args) error {
	if !args.Has("interval") {
		return nil
	}
	if args.Bool("stream") {
		return fmt.Errorf("interval= does not apply to stream, which does not poll")
	}
	if !args.Bool("follow") {
		return fmt.Errorf("interval= only applies to follow")
	}
	return nil
}

func firewallLogValidateNotNegative(value string) error {
	if number, err := strconv.Atoi(value); err == nil && number < 0 {
		return fmt.Errorf("must not be negative, got %d", number)
	}
	return nil
}

func firewallLogValidateInterval(value string) error {
	if duration, err := parseDuration(value); err == nil && duration <= 0 {
		return fmt.Errorf("must be positive, got %q", value)
	}
	return nil
}

func firewallLogValidatePrefix(value string) error {
	var _, err = firewallLogParsePrefix(value)
	return err
}

// firewallLogParsePrefix parses an address or CIDR network, nil for ""
func firewallLogParsePrefix(value string) (*netip.Prefix, error) {
	if value == "" {
		return nil, nil
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		prefix = prefix.Masked()
		return &prefix, nil
	}
	var addr, err = netip.ParseAddr(value)
	if err != nil {
		return nil, fmt.Errorf("must be an address or a network (CIDR), got %q", value)
	}
	var prefix = netip.PrefixFrom(addr, addr.BitLen())
	return &prefix, nil
}

func firewallLogCompleteActions(c *Context) []string {
	var api, err = firewallLogApi(c)
	if err != nil {
		return nil
	}
	var filters, filtersErr = api.FirewallLogFilters()
	if filtersErr != nil {
		return nil
	}
	return filters.Action
}

func firewallLogCompleteInterfaces(c *Context) []string {
	var api, err = firewallLogApi(c)
	if err != nil {
		return nil
	}
	var names, namesErr = api.FirewallInterfaceNames()
	if namesErr != nil {
		return nil
	}
	var values = make([]string, 0, 2*len(names))
	for device, name := range names {
		values = append(values, device, strings.ToLower(name))
	}
	return values
}

// firewallLogFilter holds the parsed filter arguments
type firewallLogFilter struct {
	action, iface, dir, proto, port, search string
	src, dst                                *netip.Prefix
	names                                   map[string]string
}

func (filter firewallLogFilter) active() bool {
	return filter.action != "" || filter.iface != "" || filter.dir != "" || filter.proto != "" || filter.port != "" ||
		filter.search != "" || filter.src != nil || filter.dst != nil
}

func firewallLogMatchAddr(prefix *netip.Prefix, value string) bool {
	if prefix == nil {
		return true
	}
	var addr, err = netip.ParseAddr(value)
	return err == nil && prefix.Contains(addr.Unmap())
}

func (filter firewallLogFilter) match(entry diagnostics.FirewallLogEntry) bool {
	if filter.action != "" && !strings.EqualFold(entry.Action, filter.action) {
		return false
	}
	if filter.dir != "" && !strings.EqualFold(entry.Dir, filter.dir) {
		return false
	}
	if filter.iface != "" && !strings.EqualFold(entry.Interface, filter.iface) &&
		!strings.EqualFold(filter.names[entry.Interface], filter.iface) {
		return false
	}
	if filter.proto != "" && !strings.EqualFold(entry.ProtoName, filter.proto) && entry.ProtoNum != filter.proto {
		return false
	}
	if filter.port != "" && entry.SrcPort != filter.port && entry.DstPort != filter.port {
		return false
	}
	if !firewallLogMatchAddr(filter.src, entry.Src) || !firewallLogMatchAddr(filter.dst, entry.Dst) {
		return false
	}
	if filter.search != "" {
		var needle = strings.ToLower(filter.search)
		var haystack = []string{filter.names[entry.Interface]}
		for name, value := range entry.Fields() {
			if name != "__digest__" {
				haystack = append(haystack, value)
			}
		}
		if !strings.Contains(strings.ToLower(strings.Join(haystack, "\x00")), needle) {
			return false
		}
	}
	return true
}

func firewallLogEndpoint(addr string, port string) string {
	if port == "" {
		return addr
	}
	if strings.Contains(addr, ":") {
		return fmt.Sprintf("[%s]:%s", addr, port)
	}
	return addr + ":" + port
}

// firewallLogFormat renders a record as one line:
// 2026-10-25T00:03:19  pass   in   LAN       tcp    192.168.1.2:32972 -> 192.168.1.1:443  [anti-lockout rule]
func firewallLogFormat(entry diagnostics.FirewallLogEntry, names map[string]string) string {
	var iface = entry.Interface
	if name, ok := names[entry.Interface]; ok && name != "" {
		iface = name
	}
	var proto = entry.ProtoName
	if proto == "" {
		proto = entry.ProtoNum
	}
	var rule = entry.Label
	if rule == "" {
		rule = "rule " + entry.RuleNr
	}
	return fmt.Sprintf("%s  %-5s  %-3s  %-8s  %-5s  %s -> %s  [%s]",
		entry.Timestamp, entry.Action, entry.Dir, iface, proto,
		firewallLogEndpoint(entry.Src, entry.SrcPort), firewallLogEndpoint(entry.Dst, entry.DstPort), rule)
}

// firewallLogCheckAction fails when action is none of the actions OPNsense offers as filter, a typo would
// otherwise silently match nothing. When the actions cannot be read it only warns
func firewallLogCheckAction(c *Context, api *diagnostics.DiagnosticsApi, action string) error {
	var filters, err = api.FirewallLogFilters()
	if err != nil {
		c.Infof("warning: could not read the available actions, not checking action=: %v", err)
		return nil
	}
	for _, valid := range filters.Action {
		if strings.EqualFold(valid, action) {
			return nil
		}
	}
	return fmt.Errorf("action must be one of %s, got %q", strings.Join(filters.Action, ", "), action)
}

func firewallLogPrint(c *Context, args *Args) error {
	var lines = args.Int("lines")
	var stream = args.Bool("stream")
	var follow = args.Bool("follow") || stream
	var asJson = args.Bool("json")
	// validated by the argument spec, before any API call
	var src, _ = firewallLogParsePrefix(args.String("src"))
	var dst, _ = firewallLogParsePrefix(args.String("dst"))

	var api, err = firewallLogApi(c)
	if err != nil {
		return err
	}
	if action := args.String("action"); action != "" {
		if err := firewallLogCheckAction(c, api, action); err != nil {
			return err
		}
	}

	// device -> interface name, for display and interface=
	var names, namesErr = api.FirewallInterfaceNames()
	if namesErr != nil {
		c.Infof("warning: could not read interface names, showing devices: %v", namesErr)
		names = map[string]string{}
	}

	var filter = firewallLogFilter{
		action: args.String("action"),
		iface:  args.String("interface"),
		dir:    args.String("dir"),
		proto:  args.String("proto"),
		port:   args.String("port"),
		search: args.String("search"),
		src:    src,
		dst:    dst,
		names:  names,
	}

	var printEntry = func(entry diagnostics.FirewallLogEntry) error {
		if !asJson {
			c.Println(firewallLogFormat(entry, names))
			return nil
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, entry.Raw); err != nil {
			return err
		}
		c.Println(compact.String())
		return nil
	}

	// the newest record is needed as starting point for follow, even with lines=0
	var limit = lines
	if scan := args.Int("scan"); filter.active() && scan > limit {
		limit = scan
	}
	if limit == 0 && !follow {
		return nil
	}
	if limit == 0 {
		limit = 1
	}
	// the stream starts by replaying the last 5 records, which must be known to be skipped
	if stream && limit < 10 {
		limit = 10
	}

	var entries, _, logErr = api.FirewallLog(limit, "")
	if logErr != nil {
		return logErr
	}

	// newest first from OPNsense, shown oldest first
	var shown = make([]diagnostics.FirewallLogEntry, 0, lines)
	for _, entry := range entries {
		if len(shown) >= lines {
			break
		}
		if filter.match(entry) {
			shown = append(shown, entry)
		}
	}
	for i := len(shown) - 1; i >= 0; i-- {
		if err := printEntry(shown[i]); err != nil {
			return err
		}
	}

	if !follow {
		return nil
	}

	var options = diagnostics.FirewallFollowOptions{
		Seen:      entries,
		Stream:    stream,
		Interval:  args.Duration("interval"),
		OnWarning: func(err error) { c.Infof("warning: %v", err) },
	}
	if len(entries) > 0 {
		options.SinceDigest = entries[0].Digest
	}
	// returns nil when c is cancelled (Ctrl-C)
	return api.FirewallLogFollow(c.Context, options, func(entry diagnostics.FirewallLogEntry) error {
		if filter.match(entry) {
			return printEntry(entry)
		}
		return nil
	})
}

func firewallLogFilters(c *Context, _ *Args) error {
	var api, err = firewallLogApi(c)
	if err != nil {
		return err
	}
	var filters, filtersErr = api.FirewallLogFilters()
	if filtersErr != nil {
		return filtersErr
	}
	var names, namesErr = api.FirewallInterfaceNames()
	if namesErr != nil {
		return namesErr
	}

	var devices = make([]string, 0, len(names))
	for device, name := range names {
		devices = append(devices, fmt.Sprintf("%s (%s)", device, name))
	}
	sort.Strings(devices)

	c.Fields([][2]string{
		{"action", strings.Join(filters.Action, ", ")},
		{"interface", strings.Join(filters.InterfaceName, ", ")},
		{"devices", strings.Join(devices, ", ")},
		{"dir", strings.Join(filters.Dir, ", ")},
	})
	return nil
}

func firewallLogStats(c *Context, args *Args) error {
	var groupBy = args.String("by")
	switch groupBy {
	case "proto":
		groupBy = "protoname"
	case "rule":
		groupBy = "label"
	}

	var api, err = firewallLogApi(c)
	if err != nil {
		return err
	}
	var stats, statsErr = api.FirewallStats(groupBy, args.Int("scan"))
	if statsErr != nil {
		return statsErr
	}

	if args.Bool("json") {
		for _, stat := range stats {
			if err := c.JSON(stat); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, 0, len(stats))
	for _, stat := range stats {
		rows = append(rows, []string{stat.Label, strconv.Itoa(stat.Value)})
	}
	c.Table([]string{strings.ToUpper(groupBy), "COUNT"}, rows)
	return nil
}
