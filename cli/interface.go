package cli

import (
	"errors"
	"fmt"
	"io"
	"opnsense-cli/opnsense/api/diagnostics"
	"sort"
	"strconv"
	"strings"
	"time"
)

// /interface: traffic counters since boot (print) and the live throughput (monitor-traffic), both from Reporting >
// Traffic (api/diagnostics/traffic). Also home of the helpers shared by /tool torch and /system/resource

func init() {
	var menu = Root.Menu("interface")
	menu.Help = "network interfaces: traffic counters and live throughput"
	menu.Add(
		&Command{
			Name: "print",
			Help: "show the traffic counters of every enabled interface since boot",
			Long: `Shows the counters since boot (or the last counter reset) of every enabled, non-virtual interface.
detail lists all counters OPNsense reports, json prints them as one object per interface (with the
interface name added as "interface").`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all counters of every interface"},
				{Name: "json", Type: Bool, Help: "print all counters as JSON, one object per interface"},
			},
			Run: ifacePrint,
		},
		&Command{
			Name: "monitor-traffic",
			Help: "show the live throughput per interface until Ctrl-C",
			Long: `Shows the throughput of the interfaces in bits/s and packets/s, measured by OPNsense over interval
(whole seconds). One line per interface and interval is printed until Ctrl-C, once prints a single
measurement as a table. json prints the raw OPNsense events instead (counter deltas of the interval plus
a unix timestamp), one JSON object per line. A dropped stream is reconnected.

  monitor-traffic interface=lan,wan interval=5
  monitor-traffic once`,
			Args: []Arg{
				{Name: "interface", Type: List, Help: "only these interfaces, by name (lan, wan, opt1) or description (default all)", Complete: ifaceComplete},
				{Name: "interval", Type: Duration, Default: "1s", Help: "measuring interval, whole seconds", Validate: ifaceValidateInterval},
				{Name: "once", Type: Bool, Help: "print one measurement and stop"},
				{Name: "json", Type: Bool, Help: "print the raw events as JSON, one per line"},
			},
			Run: ifaceMonitorTraffic,
		},
	)
}

// ifaceDiagnostics returns the diagnostics API of the connection
func ifaceDiagnostics(c *Context) (*diagnostics.DiagnosticsApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &diagnostics.DiagnosticsApi{OPNsense: opn}, nil
}

// ifaceComplete suggests the interface names for tab completion
func ifaceComplete(c *Context) []string {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return nil
	}
	var interfaces, listErr = api.TrafficInterfaces()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(interfaces))
	for key := range interfaces {
		names = append(names, key)
	}
	sort.Strings(names)
	return names
}

func ifaceValidateInterval(value string) error {
	var interval, err = parseDuration(value)
	if err != nil {
		return err
	}
	if interval < time.Second || interval%time.Second != 0 {
		return fmt.Errorf("must be whole seconds, at least 1, got %q", value)
	}
	return nil
}

// --- print

var ifacePrintHeaders = []string{"INTERFACE", "NAME", "DEVICE", "MTU", "IN", "OUT", "IN-PKTS", "OUT-PKTS", "ERRORS"}

func ifacePrint(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var interfaces, listErr = api.TrafficInterfaces()
	if listErr != nil {
		return listErr
	}
	var keys = make([]string, 0, len(interfaces))
	for key := range interfaces {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	switch {
	case args.Bool("json"):
		for _, key := range keys {
			var object = map[string]string{"interface": key}
			for field, value := range interfaces[key] {
				object[field] = value
			}
			if err := c.JSON(object); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var items = make([][][2]string, 0, len(keys))
		for _, key := range keys {
			var values = interfaces[key]
			var fields = make([]string, 0, len(values))
			for field := range values {
				fields = append(fields, field)
			}
			sort.Strings(fields)
			var item = [][2]string{{"interface", key}}
			for _, field := range fields {
				item = append(item, [2]string{field, values[field]})
			}
			items = append(items, item)
		}
		c.Details(items, keys)
	default:
		var rows = make([][]string, 0, len(keys))
		for _, key := range keys {
			var values = interfaces[key]
			rows = append(rows, []string{
				key, values["name"], values["device"], values["mtu"],
				ifaceBytesText(values["bytes received"]), ifaceBytesText(values["bytes transmitted"]),
				values["packets received"], values["packets transmitted"],
				ifaceSum(values, "input errors", "output errors", "collisions"),
			})
		}
		c.Items(ifacePrintHeaders, rows, keys)
	}
	return nil
}

func ifaceBytesText(value string) string {
	var number, err = strconv.ParseFloat(value, 64)
	if err != nil {
		return value
	}
	return ifaceBytes(number)
}

// ifaceSum adds up counters, "?" when one of them is not a number
func ifaceSum(values diagnostics.TrafficInterface, fields ...string) string {
	var sum int64
	for _, field := range fields {
		if values[field] == "" {
			continue
		}
		var number, err = strconv.ParseInt(values[field], 10, 64)
		if err != nil {
			return "?"
		}
		sum += number
	}
	return strconv.FormatInt(sum, 10)
}

// --- monitor-traffic

var errIfaceDone = errors.New("done")

var ifaceTrafficHeaders = []string{"INTERFACE", "NAME", "IN", "OUT", "IN-PKT/S", "OUT-PKT/S", "ERRORS"}

func ifaceMonitorTraffic(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var names = args.List("interface")
	var once = args.Bool("once")
	var asJSON = args.Bool("json")
	var seconds = int(args.Duration("interval") / time.Second)

	var selected map[string]bool // nil: all
	var line *ifaceTrafficLine
	err = api.TrafficWatch(c.Context, seconds, ifaceReconnect(c, "traffic"), func(sample diagnostics.TrafficSample, rates []diagnostics.TrafficRate) error {
		if selected == nil && len(names) > 0 {
			var selectErr error
			if selected, selectErr = ifaceSelect(sample, names); selectErr != nil {
				return selectErr
			}
		}
		if selected != nil {
			rates = ifaceFilter(rates, selected)
		}

		switch {
		case asJSON:
			if err := c.JSON(sample.Raw); err != nil {
				return err
			}
		case once:
			var rows = make([][]string, 0, len(rates))
			for _, rate := range rates {
				rows = append(rows, ifaceTrafficCells(rate))
			}
			c.Table(ifaceTrafficHeaders, rows)
		default:
			if line == nil {
				line = ifaceNewTrafficLine(rates)
				c.Println(line.header())
			}
			var timestamp = sample.Timestamp().Format("15:04:05")
			for _, rate := range rates {
				c.Println(line.format(timestamp, rate))
			}
		}
		if once {
			return errIfaceDone
		}
		return nil
	})
	if errors.Is(err, errIfaceDone) {
		return nil
	}
	return err
}

// ifaceReconnect reports the reconnects of a dropped stream
func ifaceReconnect(c *Context, what string) diagnostics.TrafficFollowOptions {
	return diagnostics.TrafficFollowOptions{
		OnReconnect: func(err error, delay time.Duration) {
			if err == io.EOF {
				c.Infof("%s stream closed by OPNsense, reconnecting in %s", what, delay)
				return
			}
			c.Infof("%s stream interrupted (%v), reconnecting in %s", what, err, delay)
		},
	}
}

// ifaceSelect maps the requested names (interface or description, case insensitive) to interface keys, unknown
// names fail with the list of available interfaces
func ifaceSelect(sample diagnostics.TrafficSample, names []string) (map[string]bool, error) {
	var selected = map[string]bool{}
	for _, name := range names {
		var found = false
		for key, counters := range sample.Interfaces {
			if strings.EqualFold(key, name) || strings.EqualFold(counters.Name, name) {
				selected[key] = true
				found = true
			}
		}
		if !found {
			var available = make([]string, 0, len(sample.Interfaces))
			for key := range sample.Interfaces {
				available = append(available, key)
			}
			sort.Strings(available)
			return nil, fmt.Errorf("unknown interface %q, available: %s", name, strings.Join(available, ", "))
		}
	}
	if len(selected) == 0 {
		return nil, nil
	}
	return selected, nil
}

func ifaceFilter(rates []diagnostics.TrafficRate, selected map[string]bool) []diagnostics.TrafficRate {
	var result = make([]diagnostics.TrafficRate, 0, len(selected))
	for _, rate := range rates {
		if selected[rate.Interface] {
			result = append(result, rate)
		}
	}
	return result
}

func ifaceTrafficCells(rate diagnostics.TrafficRate) []string {
	return []string{
		rate.Interface, rate.Name, ifaceBits(rate.InBitsPerSecond), ifaceBits(rate.OutBitsPerSecond),
		ifacePackets(rate.InPacketsPerSecond), ifacePackets(rate.OutPacketsPerSecond), strconv.FormatInt(rate.Errors, 10),
	}
}

// ifaceTrafficLine formats the streamed lines with fixed column widths (the interfaces of the first sample set the widths)
type ifaceTrafficLine struct {
	interfaceWidth, nameWidth int
}

func ifaceNewTrafficLine(rates []diagnostics.TrafficRate) *ifaceTrafficLine {
	var line = &ifaceTrafficLine{interfaceWidth: len("INTERFACE"), nameWidth: len("NAME")}
	for _, rate := range rates {
		line.interfaceWidth = max(line.interfaceWidth, len(rate.Interface))
		line.nameWidth = max(line.nameWidth, len(rate.Name))
	}
	return line
}

func (l *ifaceTrafficLine) row(cells []string) string {
	return strings.TrimRight(fmt.Sprintf("%-8s  %-*s  %-*s  %13s  %13s  %9s  %9s  %6s",
		cells[0], l.interfaceWidth, cells[1], l.nameWidth, cells[2], cells[3], cells[4], cells[5], cells[6], cells[7]), " ")
}

func (l *ifaceTrafficLine) header() string {
	return l.row(append([]string{"TIME"}, ifaceTrafficHeaders...))
}

func (l *ifaceTrafficLine) format(timestamp string, rate diagnostics.TrafficRate) string {
	return l.row(append([]string{timestamp}, ifaceTrafficCells(rate)...))
}

// --- units

// ifaceBits formats bits/s with SI units, e.g. "352.7 kbit/s"
func ifaceBits(bitsPerSecond float64) string {
	return ifaceSI(bitsPerSecond, []string{"bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"})
}

// ifaceBytes formats bytes with SI units, e.g. "1.2 MB"
func ifaceBytes(bytes float64) string {
	return ifaceSI(bytes, []string{"B", "kB", "MB", "GB", "TB", "PB"})
}

func ifaceSI(value float64, units []string) string {
	var unit = 0
	for value >= 1000 && unit < len(units)-1 {
		value /= 1000
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%.0f %s", value, units[unit])
	}
	return fmt.Sprintf("%.1f %s", value, units[unit])
}

func ifacePackets(perSecond float64) string {
	if perSecond == float64(int64(perSecond)) {
		return strconv.FormatInt(int64(perSecond), 10)
	}
	return fmt.Sprintf("%.1f", perSecond)
}
