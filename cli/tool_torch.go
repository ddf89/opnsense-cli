package cli

import (
	"encoding/json"
	"fmt"
	"opnsense-cli/opnsense/api/diagnostics"
	"sort"
	"strings"
)

// /tool torch: the hosts with the most traffic per interface (Reporting > Traffic > Top talkers,
// api/diagnostics/traffic/top/<interfaces>), measured by iftop over about 2 seconds per query

func init() {
	var menu = Root.Menu("tool")
	menu.Help = "network tools"
	menu.Add(&Command{
		Name: "torch",
		Help: "show the hosts with the most traffic per interface (top talkers) until Ctrl-C",
		Long: `Shows the hosts with the most traffic, measured by OPNsense with iftop over about 2 seconds per
query. Rates are in bits/s, TOTAL is the data transferred during the measurement. Without interface all
enabled interfaces are measured.

The query is repeated every interval until Ctrl-C, on a terminal the screen is redrawn, otherwise a
"--- time" line separates the refreshes. once queries a single time. json prints the raw answers, one
JSON object per line.

  torch interface=wan lines=5
  torch once`,
		Args: []Arg{
			{Name: "interface", Type: List, Help: "interfaces to measure, by name (lan, wan, opt1) or description (default all)", Complete: ifaceComplete},
			{Name: "lines", Type: Int, Default: "10", Help: "number of hosts to show per interface, 0 for all", Validate: ValidateRange(0, 1000000)},
			{Name: "once", Type: Bool, Help: "query once and stop"},
			{Name: "interval", Type: Duration, Default: "1s", Help: "pause between two queries", Validate: systemActivityValidateInterval},
			{Name: "json", Type: Bool, Help: "print the raw answer as JSON, one object per line"},
		},
		Run: torchRun,
	})
}

type torchResult struct {
	interfaces map[string]diagnostics.TrafficTopInterface
	raw        json.RawMessage
}

func torchRun(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var keys, resolveErr = torchResolve(api, args.List("interface"))
	if resolveErr != nil {
		return resolveErr
	}
	var follow = !args.Bool("once")
	var asJSON = args.Bool("json")
	var lines = args.Int("lines")
	var refresh = systemActivityNewRefresher(c, follow && !asJSON)

	return systemActivityPoll(c, follow, args.Duration("interval"), func() error {
		var result, queryErr = systemActivityAwait(c, func() (torchResult, error) {
			var interfaces, raw, err = api.TrafficTop(keys)
			return torchResult{interfaces, raw}, err
		})
		if queryErr != nil {
			return queryErr
		}
		var missing []string
		for _, key := range keys {
			if _, found := result.interfaces[key]; !found {
				missing = append(missing, key)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("OPNsense did not measure %s (unknown or disabled interface?)", strings.Join(missing, ", "))
		}
		if asJSON {
			return c.JSON(result.raw)
		}
		refresh()
		torchShow(c, keys, result.interfaces, lines)
		return nil
	})
}

// torchResolve returns the interface keys to measure: all enabled interfaces when names is empty, otherwise the
// names mapped by interface key or description (unknown names are passed on as they are, OPNsense decides)
func torchResolve(api *diagnostics.DiagnosticsApi, names []string) ([]string, error) {
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
	return keys, nil
}

func torchShow(c *Context, keys []string, result map[string]diagnostics.TrafficTopInterface, lines int) {
	for i, key := range keys {
		if i > 0 {
			c.Println()
		}
		var top = result[key]
		switch {
		case top.Status == "timeout":
			c.Printf("%s: measurement timed out\n", key)
			continue
		case top.Status != "ok":
			c.Printf("%s: unexpected status %q\n", key, top.Status)
			continue
		case len(top.Records) == 0:
			c.Printf("%s: no traffic\n", key)
			continue
		}

		c.Printf("%s:\n", key)
		var records = top.Records
		if lines > 0 && len(records) > lines {
			records = records[:lines]
		}
		var rows = make([][]string, 0, len(records))
		for _, host := range records {
			rows = append(rows, []string{
				host.Address, host.ReverseName,
				ifaceBits(float64(host.RateBitsIn)), ifaceBits(float64(host.RateBitsOut)),
				ifaceBits(float64(host.RateBits)), ifaceBytes(float64(host.CumulativeBytes)),
				strings.Join(host.Tags, ","),
			})
		}
		c.Table([]string{"ADDRESS", "HOSTNAME", "IN", "OUT", "RATE", "TOTAL", "TAGS"}, rows)
	}
}
