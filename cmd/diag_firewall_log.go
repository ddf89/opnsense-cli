package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"opnsense-cli/opnsense/api/diagnostics"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	diagFirewallLogLines     int
	diagFirewallLogScan      int
	diagFirewallLogFollow    bool
	diagFirewallLogStream    bool
	diagFirewallLogInterval  time.Duration
	diagFirewallLogAction    string
	diagFirewallLogInterface string
	diagFirewallLogDir       string
	diagFirewallLogProto     string
	diagFirewallLogSrc       string
	diagFirewallLogDst       string
	diagFirewallLogPort      string
	diagFirewallLogSearch    string
	diagFirewallLogJson      bool
)

var diagFirewallLogCmd = &cobra.Command{
	Use:   "log",
	Short: "Show the newest firewall log records, optionally following new ones",
	Long: `Show the newest firewall log records (oldest first), optionally following new ones until Ctrl-C.

Filters are applied client side and combined with AND. When filtering, the newest --scan
records are searched for the last --lines matches.

--follow polls the log every --interval and shows every record. --stream uses the
OPNsense live stream instead: lower latency, but OPNsense throttles it and silently
drops records, so it is incomplete.`,
	Args: cobra.NoArgs,
	Run:  diagFirewallLogRun,
}

func init() {
	var flags = diagFirewallLogCmd.Flags()
	flags.IntVarP(&diagFirewallLogLines, "lines", "n", 50, "number of records to show")
	flags.IntVar(&diagFirewallLogScan, "scan", diagnostics.FirewallLogDefaultLimit, "number of newest records to search when filtering")
	flags.BoolVarP(&diagFirewallLogFollow, "follow", "f", false, "keep showing new records until Ctrl-C")
	flags.BoolVar(&diagFirewallLogStream, "stream", false, "follow using the OPNsense live stream (lossy, implies --follow)")
	flags.DurationVar(&diagFirewallLogInterval, "interval", time.Second, "poll interval for --follow")
	flags.StringVar(&diagFirewallLogAction, "action", "", "only records with this action: pass, block, rdr, nat, binat")
	flags.StringVar(&diagFirewallLogInterface, "interface", "", "only records of this interface, by name (lan, wan, ...) or device (vtnet0)")
	flags.StringVar(&diagFirewallLogDir, "dir", "", "only records of this direction: in, out")
	flags.StringVar(&diagFirewallLogProto, "proto", "", "only records of this protocol, by name (tcp, udp, icmp, ...) or number")
	flags.StringVar(&diagFirewallLogSrc, "src", "", "only records from this address or network (CIDR)")
	flags.StringVar(&diagFirewallLogDst, "dst", "", "only records to this address or network (CIDR)")
	flags.StringVar(&diagFirewallLogPort, "port", "", "only records with this source or destination port")
	flags.StringVarP(&diagFirewallLogSearch, "search", "s", "", "only records containing this text in any field (case insensitive)")
	flags.BoolVar(&diagFirewallLogJson, "json", false, "print the raw records as JSON, one per line")
	diagFirewallCmd.AddCommand(diagFirewallLogCmd)
}

// diagFirewallLogFilter holds the parsed filter flags
type diagFirewallLogFilter struct {
	action, iface, dir, proto, port, search string
	src, dst                                *netip.Prefix
	names                                   map[string]string
}

func (filter diagFirewallLogFilter) active() bool {
	return filter.action != "" || filter.iface != "" || filter.dir != "" || filter.proto != "" || filter.port != "" ||
		filter.search != "" || filter.src != nil || filter.dst != nil
}

// diagFirewallLogPrefix parses an address or CIDR network
func diagFirewallLogPrefix(flag string, value string) *netip.Prefix {
	if value == "" {
		return nil
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		prefix = prefix.Masked()
		return &prefix
	}
	var addr, err = netip.ParseAddr(value)
	if err != nil {
		log.Fatalf("--%s: %q is neither an address nor a network", flag, value)
	}
	var prefix = netip.PrefixFrom(addr, addr.BitLen())
	return &prefix
}

func diagFirewallLogMatchAddr(prefix *netip.Prefix, value string) bool {
	if prefix == nil {
		return true
	}
	var addr, err = netip.ParseAddr(value)
	return err == nil && prefix.Contains(addr.Unmap())
}

func (filter diagFirewallLogFilter) match(entry diagnostics.FirewallLogEntry) bool {
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
	if !diagFirewallLogMatchAddr(filter.src, entry.Src) || !diagFirewallLogMatchAddr(filter.dst, entry.Dst) {
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

func diagFirewallLogEndpoint(addr string, port string) string {
	if port == "" {
		return addr
	}
	if strings.Contains(addr, ":") {
		return fmt.Sprintf("[%s]:%s", addr, port)
	}
	return addr + ":" + port
}

// diagFirewallLogFormat renders a record as one line:
// 2026-10-25T00:03:19  pass   in   LAN       tcp    192.168.1.2:32972 -> 192.168.1.1:443  [anti-lockout rule]
func diagFirewallLogFormat(entry diagnostics.FirewallLogEntry, names map[string]string) string {
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
		diagFirewallLogEndpoint(entry.Src, entry.SrcPort), diagFirewallLogEndpoint(entry.Dst, entry.DstPort), rule)
}

func diagFirewallLogPrint(entry diagnostics.FirewallLogEntry, names map[string]string) {
	if !diagFirewallLogJson {
		fmt.Println(diagFirewallLogFormat(entry, names))
		return
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, entry.Raw); err != nil {
		log.Fatal(err)
	}
	fmt.Println(compact.String())
}

// diagFirewallLogCheckAction exits when action is none of the actions OPNsense offers as filter, a typo would
// otherwise silently match nothing
func diagFirewallLogCheckAction(api *diagnostics.DiagnosticsApi, action string) {
	var filters, err = api.FirewallLogFilters()
	if err != nil {
		log.Printf("warning: could not read the available actions, not checking --action: %v", err)
		return
	}
	for _, valid := range filters.Action {
		if strings.EqualFold(valid, action) {
			return
		}
	}
	log.Fatalf("--action must be one of %s: %q", strings.Join(filters.Action, ", "), action)
}

func diagFirewallLogRun(_ *cobra.Command, _ []string) {
	if diagFirewallLogStream {
		diagFirewallLogFollow = true
	}
	if diagFirewallLogLines < 0 {
		log.Fatal("--lines must not be negative")
	}
	if diagFirewallLogInterval <= 0 {
		log.Fatal("--interval must be positive")
	}

	if diagFirewallLogDir != "" && !strings.EqualFold(diagFirewallLogDir, "in") && !strings.EqualFold(diagFirewallLogDir, "out") {
		log.Fatalf("--dir must be in or out: %q", diagFirewallLogDir)
	}
	// parse before any API call, so invalid values fail fast
	var src = diagFirewallLogPrefix("src", diagFirewallLogSrc)
	var dst = diagFirewallLogPrefix("dst", diagFirewallLogDst)

	var api = newDiagFirewallApi()
	if diagFirewallLogAction != "" {
		diagFirewallLogCheckAction(api, diagFirewallLogAction)
	}

	// device -> interface name, for display and --interface
	var names, namesErr = api.FirewallInterfaceNames()
	if namesErr != nil {
		log.Printf("warning: could not read interface names, showing devices: %v", namesErr)
		names = map[string]string{}
	}

	var filter = diagFirewallLogFilter{
		action: diagFirewallLogAction,
		iface:  diagFirewallLogInterface,
		dir:    diagFirewallLogDir,
		proto:  diagFirewallLogProto,
		port:   diagFirewallLogPort,
		search: diagFirewallLogSearch,
		src:    src,
		dst:    dst,
		names:  names,
	}

	// the newest record is needed as starting point for --follow, even with --lines 0
	var limit = diagFirewallLogLines
	if filter.active() && diagFirewallLogScan > limit {
		limit = diagFirewallLogScan
	}
	if limit == 0 && !diagFirewallLogFollow {
		return
	}
	if limit == 0 {
		limit = 1
	}
	// the stream starts by replaying the last 5 records, which must be known to be skipped
	if diagFirewallLogStream && limit < 10 {
		limit = 10
	}

	var entries, _, err = api.FirewallLog(limit, "")
	if err != nil {
		log.Fatal(err)
	}

	// newest first from OPNsense, shown oldest first
	var shown = make([]diagnostics.FirewallLogEntry, 0, diagFirewallLogLines)
	for _, entry := range entries {
		if len(shown) >= diagFirewallLogLines {
			break
		}
		if filter.match(entry) {
			shown = append(shown, entry)
		}
	}
	for i := len(shown) - 1; i >= 0; i-- {
		diagFirewallLogPrint(shown[i], names)
	}

	if !diagFirewallLogFollow {
		return
	}

	var ctx, cancel = diagStreamContext()
	defer cancel()

	var options = diagnostics.FirewallFollowOptions{
		Seen:      entries,
		Stream:    diagFirewallLogStream,
		Interval:  diagFirewallLogInterval,
		OnWarning: func(err error) { log.Printf("warning: %v", err) },
	}
	if len(entries) > 0 {
		options.SinceDigest = entries[0].Digest
	}
	err = api.FirewallLogFollow(ctx, options, func(entry diagnostics.FirewallLogEntry) error {
		if filter.match(entry) {
			diagFirewallLogPrint(entry, names)
		}
		return nil
	})
	if err != nil {
		cancel()
		log.Print(err)
		os.Exit(1)
	}
}
