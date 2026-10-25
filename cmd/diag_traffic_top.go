package cmd

import (
	"context"
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
	diagTrafficTopInterfaces []string
	diagTrafficTopLines      int
	diagTrafficTopFollow     bool
	diagTrafficTopInterval   time.Duration
	diagTrafficTopJson       bool
)

var diagTrafficTopCmd = &cobra.Command{
	Use:   "top",
	Short: "Show the hosts with the most traffic per interface (top talkers)",
	Long: `Show the hosts with the most traffic (Reporting > Traffic > Top talkers), measured by OPNsense
with iftop over about 2 seconds per query. Rates are in bits/s, TOTAL is the data transferred
during the measurement. Without --interface all enabled interfaces are measured.

--follow repeats the query every --interval until Ctrl-C, on a terminal the screen is redrawn.
--json prints the raw answers, one JSON object per line.`,
	Example: `  opn diag traffic top
  opn diag traffic top --interface wan -n 5 --follow`,
	Args: cobra.NoArgs,
	Run:  diagTrafficTopRun,
}

func init() {
	var flags = diagTrafficTopCmd.Flags()
	flags.StringSliceVar(&diagTrafficTopInterfaces, "interface", nil, "interfaces to measure, by name (lan, wan, opt1) or description, comma separated (default all)")
	flags.IntVarP(&diagTrafficTopLines, "lines", "n", 10, "number of hosts to show per interface (0 for all)")
	flags.BoolVarP(&diagTrafficTopFollow, "follow", "f", false, "refresh until Ctrl-C")
	flags.DurationVar(&diagTrafficTopInterval, "interval", time.Second, "pause between two refreshes of --follow")
	flags.BoolVar(&diagTrafficTopJson, "json", false, "print the raw answer as JSON, one object per line")
	diagTrafficCmd.AddCommand(diagTrafficTopCmd)
}

func diagTrafficTopRun(_ *cobra.Command, _ []string) {
	if diagTrafficTopLines < 0 {
		log.Fatal("--lines must not be negative")
	}
	if diagTrafficTopInterval <= 0 {
		log.Fatal("--interval must be positive")
	}
	var api = diagActivityApi()
	var ctx, cancel = diagStreamContext()
	defer cancel()

	var options = diagTrafficTopOptions{
		Interfaces: diagTrafficTopInterfaces, Lines: diagTrafficTopLines, Follow: diagTrafficTopFollow,
		Interval: diagTrafficTopInterval, Json: diagTrafficTopJson, Clear: diagActivityIsTerminal(os.Stdout),
	}
	if err := diagTrafficTopExecute(ctx, api, os.Stdout, options); err != nil {
		log.Fatal(err)
	}
}

type diagTrafficTopOptions struct {
	Interfaces []string
	Lines      int
	Follow     bool
	Interval   time.Duration
	Json       bool
	Clear      bool
	Sleep      func(context.Context, time.Duration) bool
}

func diagTrafficTopExecute(ctx context.Context, api *diagnostics.DiagnosticsApi, out io.Writer, options diagTrafficTopOptions) error {
	var keys, err = diagTrafficTopResolve(api, options.Interfaces)
	if err != nil {
		return err
	}

	var first = true
	var show = func() error {
		var result, raw, err = api.TrafficTop(keys)
		if err != nil {
			return err
		}
		var missing []string
		for _, key := range keys {
			if _, found := result[key]; !found {
				missing = append(missing, key)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("OPNsense did not measure %s (unknown or disabled interface?)", strings.Join(missing, ", "))
		}

		if options.Json {
			_, _ = fmt.Fprintln(out, diagActivityCompact(raw))
			return nil
		}
		diagActivityRefresh(out, options.Follow, options.Clear, first)
		first = false
		diagTrafficTopPrint(out, keys, result, options.Lines)
		return nil
	}
	if !options.Follow {
		return show()
	}
	return diagActivityPollLoop(ctx, options.Interval, options.Sleep, show)
}

// diagTrafficTopResolve returns the interface keys to measure: all enabled interfaces when names is empty, otherwise
// names mapped by interface key or description (unknown names are passed on as they are, OPNsense decides)
func diagTrafficTopResolve(api *diagnostics.DiagnosticsApi, names []string) ([]string, error) {
	var interfaces, err = api.TrafficInterfaces()
	if err != nil {
		return nil, err
	}
	var keys []string
	var seen = map[string]bool{}
	var add = func(key string) {
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}

	if len(names) == 0 {
		for key := range interfaces {
			add(key)
		}
		sort.Strings(keys)
		if len(keys) == 0 {
			return nil, fmt.Errorf("OPNsense reported no interfaces")
		}
		return keys, nil
	}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		var found = false
		for key, values := range interfaces {
			if strings.EqualFold(key, name) || strings.EqualFold(values["name"], name) {
				add(key)
				found = true
			}
		}
		if !found {
			add(name)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no interface given")
	}
	return keys, nil
}

func diagTrafficTopPrint(out io.Writer, keys []string, result map[string]diagnostics.TrafficTopInterface, lines int) {
	for i, key := range keys {
		if i > 0 {
			_, _ = fmt.Fprintln(out)
		}
		var top = result[key]
		switch {
		case top.Status == "timeout":
			_, _ = fmt.Fprintf(out, "%s: measurement timed out\n", key)
			continue
		case top.Status != "ok":
			_, _ = fmt.Fprintf(out, "%s: unexpected status %q\n", key, top.Status)
			continue
		case len(top.Records) == 0:
			_, _ = fmt.Fprintf(out, "%s: no traffic\n", key)
			continue
		}

		_, _ = fmt.Fprintf(out, "%s:\n", key)
		var records = top.Records
		if lines > 0 && len(records) > lines {
			records = records[:lines]
		}
		var rows = make([][]string, 0, len(records))
		for _, host := range records {
			rows = append(rows, []string{
				host.Address, host.ReverseName,
				diagTrafficBits(float64(host.RateBitsIn)), diagTrafficBits(float64(host.RateBitsOut)),
				diagTrafficBits(float64(host.RateBits)), diagTrafficBytes(float64(host.CumulativeBytes)),
				strings.Join(host.Tags, ","),
			})
		}
		diagActivityTable(out, []string{"ADDRESS", "HOSTNAME", "IN", "OUT", "RATE", "TOTAL", "TAGS"}, rows)
	}
}
