package cli

import (
	"fmt"
	"opnsense-cli/opnsense/api/diagnostics"
	"strconv"
	"strings"
)

// /firewall/statistics: the pf statistics of Firewall > Diagnostics > Statistics (api/diagnostics/firewall/pf_statistics)
// and the state table usage (pf_states)

func init() {
	var menu = Root.Menu("firewall/statistics")
	menu.Help = "pf statistics: counters, limits, timeouts, interfaces, rules, state table usage"
	menu.Add(
		&Command{
			Name: "print",
			Help: "show the pf statistics",
			Long: `Shows the pf statistics, by default every section, each under its name:

  info        state and source tracking table counters, packet counters (pfctl -si), RATE is per second
  memory      the hard limits (pfctl -sm)
  timeouts    the state timeouts (pfctl -st)
  interfaces  packets (bytes) per interface, IPv4 and IPv6 together (pfctl -vvsI)
  rules       evaluations, packets, bytes and states per filter and NAT rule of the running ruleset

json prints the sections as OPNsense returns them, one object per section and line.

  print section=info,memory`,
			Args: []Arg{
				{Name: "section", Type: List, Help: "only these sections", Values: diagnostics.FirewallStatisticsSections},
				{Name: "json", Type: Bool, Help: "print the raw sections as JSON, one object per line"},
			},
			Run: firewallStatisticsPrint,
		},
		&Command{
			Name: "states",
			Help: "show the number of states and the state table limit",
			Args: []Arg{{Name: "json", Type: Bool, Help: "print as one JSON object"}},
			Run:  firewallStatisticsStates,
		},
	)
}

func firewallStatisticsPrint(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var sections = diagnostics.FirewallStatisticsSections
	if args.Has("section") && len(args.List("section")) > 0 {
		sections = nil
		for _, section := range args.List("section") {
			sections = append(sections, strings.ToLower(section))
		}
	}
	var statistics, getErr = systemActivityAwait(c, func() (diagnostics.FirewallStatistics, error) {
		return api.FirewallStatisticsGet(sections...)
	})
	if getErr != nil {
		return getErr
	}

	if args.Bool("json") {
		for _, section := range sections {
			if err := c.JSON(statistics.Raw[section]); err != nil {
				return err
			}
		}
		return nil
	}
	for i, section := range sections {
		if len(sections) > 1 {
			if i > 0 {
				c.Println()
			}
			c.Println(section + ":")
		}
		firewallStatisticsShow(c, statistics, section)
	}
	return nil
}

func firewallStatisticsShow(c *Context, statistics diagnostics.FirewallStatistics, section string) {
	switch section {
	case "info":
		var rows = make([][]string, 0, len(statistics.Info))
		for _, counter := range statistics.Info {
			var rate = ""
			if counter.HasRate {
				rate = strconv.FormatFloat(counter.Rate, 'f', -1, 64) + "/s"
			}
			rows = append(rows, []string{counter.Table, counter.Name, strconv.FormatInt(counter.Total, 10), rate})
		}
		c.Table([]string{"TABLE", "COUNTER", "TOTAL", "RATE"}, rows)
	case "memory", "timeouts":
		var values = statistics.Memory
		var header = "LIMIT"
		if section == "timeouts" {
			values, header = statistics.Timeouts, "TIMEOUT"
		}
		var rows = make([][]string, 0, len(values))
		for _, value := range values {
			rows = append(rows, []string{value.Name, value.Value})
		}
		c.Table([]string{header, "VALUE"}, rows)
	case "interfaces":
		var cell = func(i diagnostics.FirewallStatisticsInterface, direction string, action string) string {
			return fmt.Sprintf("%d (%s)", i.Packets(direction, action), ifaceBytes(float64(i.Bytes(direction, action))))
		}
		var rows = make([][]string, 0, len(statistics.Interfaces))
		for _, i := range statistics.Interfaces {
			rows = append(rows, []string{i.Name, strconv.FormatInt(i.References, 10), cell(i, "in", "pass"), cell(i, "in", "block"),
				cell(i, "out", "pass"), cell(i, "out", "block"), i.Cleared})
		}
		c.Table([]string{"INTERFACE", "REFERENCES", "IN-PASS", "IN-BLOCK", "OUT-PASS", "OUT-BLOCK", "CLEARED"}, rows)
	case "rules":
		var rows = make([][]string, 0, len(statistics.Rules))
		for _, rule := range statistics.Rules {
			rows = append(rows, []string{strings.TrimSuffix(rule.Ruleset, " rules"), strconv.FormatInt(rule.Evaluations, 10),
				strconv.FormatInt(rule.Packets, 10), ifaceBytes(float64(rule.Bytes)), strconv.FormatInt(rule.States, 10), rule.Rule})
		}
		c.Table([]string{"RULESET", "EVALUATIONS", "PACKETS", "BYTES", "STATES", "RULE"}, rows)
	}
}

func firewallStatisticsStates(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var count, countErr = api.FirewallStateCountGet()
	if countErr != nil {
		return countErr
	}
	if args.Bool("json") {
		return c.JSON(map[string]int64{"current": count.Current, "limit": count.Limit})
	}
	var used = ""
	if count.Limit > 0 {
		used = strconv.FormatFloat(float64(count.Current)*100/float64(count.Limit), 'f', 1, 64) + "%"
	}
	c.Fields([][2]string{
		{"current", strconv.FormatInt(count.Current, 10)},
		{"limit", strconv.FormatInt(count.Limit, 10)},
		{"used", used},
	})
	return nil
}
