package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"opnsense-cli/opnsense/api/diagnostics"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	diagTrafficInterval   int
	diagTrafficFollow     bool
	diagTrafficInterfaces []string
	diagTrafficJson       bool
)

var diagTrafficCmd = &cobra.Command{
	Use:   "traffic",
	Short: "Show the live throughput per interface, optionally streaming it",
	Long: `Show the throughput of every enabled interface (Reporting > Traffic) in bits/s and packets/s,
measured by OPNsense over --interval seconds.

Without --follow one measurement is printed (it takes --interval seconds), with --follow one
line per interface and interval is printed until Ctrl-C. --json prints the raw OPNsense events
instead (counter deltas of the interval plus a unix timestamp), one JSON object per line.`,
	Example: `  opn diag traffic
  opn diag traffic --follow --interface lan,wan --interval 5
  opn diag traffic top --interface wan
  opn diag traffic interfaces`,
	Args: cobra.NoArgs,
	Run:  diagTrafficRun,
}

func init() {
	var flags = diagTrafficCmd.Flags()
	flags.IntVar(&diagTrafficInterval, "interval", 1, "measuring interval in seconds")
	flags.BoolVarP(&diagTrafficFollow, "follow", "f", false, "keep streaming until Ctrl-C")
	flags.StringSliceVar(&diagTrafficInterfaces, "interface", nil, "only these interfaces, by name (lan, wan, opt1) or description, comma separated")
	flags.BoolVar(&diagTrafficJson, "json", false, "print the raw events as JSON, one per line")
	diagCmd.AddCommand(diagTrafficCmd)
}

func diagTrafficRun(_ *cobra.Command, _ []string) {
	if diagTrafficInterval < 1 {
		log.Fatal("--interval must be at least 1 (second)")
	}
	var api = diagActivityApi()
	var ctx, cancel = diagStreamContext()
	defer cancel()

	var options = diagTrafficOptions{
		Interval: diagTrafficInterval, Follow: diagTrafficFollow, Interfaces: diagTrafficInterfaces, Json: diagTrafficJson,
		Reconnect: diagTrafficReconnect("traffic"),
	}
	if err := diagTrafficExecute(ctx, api, os.Stdout, options); err != nil {
		log.Fatal(err)
	}
}

type diagTrafficOptions struct {
	Interval   int
	Follow     bool
	Interfaces []string
	Json       bool
	Reconnect  diagnostics.TrafficFollowOptions
}

// diagTrafficReconnect reports reconnects of a dropped stream on stderr
func diagTrafficReconnect(what string) diagnostics.TrafficFollowOptions {
	return diagnostics.TrafficFollowOptions{
		OnReconnect: func(err error, delay time.Duration) {
			if err == io.EOF {
				log.Printf("%s stream closed by OPNsense, reconnecting in %s", what, delay)
				return
			}
			log.Printf("%s stream interrupted (%v), reconnecting in %s", what, err, delay)
		},
	}
}

var errDiagTrafficDone = errors.New("done")

func diagTrafficExecute(ctx context.Context, api *diagnostics.DiagnosticsApi, out io.Writer, options diagTrafficOptions) error {
	var selected map[string]bool // nil: all
	var line *diagTrafficLine

	var err = api.TrafficWatch(ctx, options.Interval, options.Reconnect, func(sample diagnostics.TrafficSample, rates []diagnostics.TrafficRate) error {
		if selected == nil && len(options.Interfaces) > 0 {
			var err error
			if selected, err = diagTrafficSelect(sample, options.Interfaces); err != nil {
				return err
			}
		}
		if selected != nil {
			rates = diagTrafficFilter(rates, selected)
		}

		switch {
		case options.Json:
			_, _ = fmt.Fprintln(out, diagActivityCompact(sample.Raw))
		case options.Follow:
			if line == nil {
				line = diagTrafficNewLine(rates)
				_, _ = fmt.Fprintln(out, line.header())
			}
			var timestamp = sample.Timestamp().Format("15:04:05")
			for _, rate := range rates {
				_, _ = fmt.Fprintln(out, line.format(timestamp, rate))
			}
		default:
			var rows = make([][]string, 0, len(rates))
			for _, rate := range rates {
				rows = append(rows, diagTrafficCells(rate))
			}
			diagActivityTable(out, diagTrafficHeaders, rows)
		}

		if !options.Follow {
			return errDiagTrafficDone
		}
		return nil
	})
	switch {
	case errors.Is(err, errDiagTrafficDone):
		return nil
	}
	return err
}

// diagTrafficSelect maps the requested names (interface or description, case insensitive) to interface keys
func diagTrafficSelect(sample diagnostics.TrafficSample, names []string) (map[string]bool, error) {
	var selected = map[string]bool{}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
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

func diagTrafficFilter(rates []diagnostics.TrafficRate, selected map[string]bool) []diagnostics.TrafficRate {
	var result = make([]diagnostics.TrafficRate, 0, len(selected))
	for _, rate := range rates {
		if selected[rate.Interface] {
			result = append(result, rate)
		}
	}
	return result
}

var diagTrafficHeaders = []string{"INTERFACE", "NAME", "IN", "OUT", "IN PKT/S", "OUT PKT/S", "ERRORS"}

func diagTrafficCells(rate diagnostics.TrafficRate) []string {
	return []string{
		rate.Interface, rate.Name, diagTrafficBits(rate.InBitsPerSecond), diagTrafficBits(rate.OutBitsPerSecond),
		diagTrafficPackets(rate.InPacketsPerSecond), diagTrafficPackets(rate.OutPacketsPerSecond), fmt.Sprint(rate.Errors),
	}
}

// diagTrafficLine formats the --follow lines with fixed column widths (the interfaces of the first sample set the widths)
type diagTrafficLine struct {
	interfaceWidth, nameWidth int
}

func diagTrafficNewLine(rates []diagnostics.TrafficRate) *diagTrafficLine {
	var line = &diagTrafficLine{interfaceWidth: len("INTERFACE"), nameWidth: len("NAME")}
	for _, rate := range rates {
		line.interfaceWidth = max(line.interfaceWidth, len(rate.Interface))
		line.nameWidth = max(line.nameWidth, len(rate.Name))
	}
	return line
}

func (l *diagTrafficLine) row(cells []string) string {
	return strings.TrimRight(fmt.Sprintf("%-8s  %-*s  %-*s  %13s  %13s  %9s  %9s  %6s",
		cells[0], l.interfaceWidth, cells[1], l.nameWidth, cells[2], cells[3], cells[4], cells[5], cells[6], cells[7]), " ")
}

func (l *diagTrafficLine) header() string {
	return l.row(append([]string{"TIME"}, diagTrafficHeaders...))
}

func (l *diagTrafficLine) format(timestamp string, rate diagnostics.TrafficRate) string {
	return l.row(append([]string{timestamp}, diagTrafficCells(rate)...))
}

// diagTrafficBits formats bits/s with SI units, e.g. "352.7 kbit/s"
func diagTrafficBits(bitsPerSecond float64) string {
	var units = []string{"bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"}
	var value = bitsPerSecond
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

// diagTrafficBytes formats bytes with SI units, e.g. "1.2 MB"
func diagTrafficBytes(bytes float64) string {
	var units = []string{"B", "kB", "MB", "GB", "TB", "PB"}
	var value = bytes
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

func diagTrafficPackets(perSecond float64) string {
	if perSecond == float64(int64(perSecond)) {
		return fmt.Sprintf("%d", int64(perSecond))
	}
	return fmt.Sprintf("%.1f", perSecond)
}
