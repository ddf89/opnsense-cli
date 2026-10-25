package cli

import (
	"fmt"
	"opnsense-cli/opnsense/api/unbound"
	"strconv"
	"strings"
	"time"
)

// /unbound/statistics: the query statistics of Reporting > Unbound DNS (recorded when the general setting
// statistics is on) and the unbound-control counters
// /unbound/diagnostics: the unbound-control dumps of the cache, infrastructure cache and local zones / data

func init() {
	var menu = Root.Menu("unbound/statistics")
	menu.Help = "query statistics: totals, top (blocked) domains, recent queries, counters"
	menu.Add(
		&Command{Name: "print", Help: "show the query totals and the top queried and blocked domains",
			Long: `Needs the statistics to be recorded: "/unbound/settings set statistics=yes" and a reconfigure.`,
			Args: []Arg{
				{Name: "top", Type: Int, Default: "10", Help: "number of top domains to show", Validate: ValidateRange(1, 1000)},
				{Name: "json", Type: Bool, Help: "print the totals as one JSON object"},
			}, Run: unboundStatisticsPrint},
		&Command{Name: "queries", Help: "list the latest queries (newest first, at most 1000)", Args: []Arg{
			{Name: "search", Help: "only queries where any field (client, domain, action, ...) contains this text"},
			{Name: "limit", Type: Int, Default: "50", Help: "show at most this many queries, 0 for all", Validate: ValidateRange(0, 1000)},
			{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
		}, Run: unboundStatisticsQueries},
		&Command{Name: "history", Help: "show the query counters over time", Args: []Arg{
			{Name: "hours", Default: "1", Help: "the last 1 (per minute), 12 or 24 hours (per 10 minutes)", Values: []string{"1", "12", "24"}},
			{Name: "json", Type: Bool, Help: "one JSON object per interval"},
		}, Run: unboundStatisticsHistory},
		&Command{Name: "counters", Help: "show the unbound-control statistics counters (since the last restart)", Args: []Arg{
			{Name: "search", Help: "only counters whose name contains this text, like total.num"},
			{Name: "json", Type: Bool, Help: "print the counters as one JSON object"},
		}, Run: unboundStatisticsCounters},
		&Command{Name: "reset", Help: "delete the recorded query statistics", Confirm: "This deletes all recorded query statistics and restarts Unbound.",
			Run: unboundStatisticsReset},
	)

	var diagnostics = Root.Menu("unbound/diagnostics")
	diagnostics.Help = "the contents of the Unbound caches and local zones"
	var listArgs = []Arg{
		{Name: "search", Help: "only entries where any field contains this text"},
		{Name: "json", Type: Bool, Help: "one JSON object per line"},
	}
	diagnostics.Add(
		&Command{Name: "cache", Help: "list the records in the DNS cache", Args: listArgs, Run: unboundDiagnosticsCache},
		&Command{Name: "infra", Help: "list the infrastructure cache: upstream servers and their round trip times", Args: listArgs, Run: unboundDiagnosticsInfra},
		&Command{Name: "local-zones", Help: "list the local zones and their types", Args: listArgs, Run: unboundDiagnosticsLocalZones},
		&Command{Name: "local-data", Help: "list the local data (host overrides and the records of the local zones)", Args: listArgs, Run: unboundDiagnosticsLocalData},
		&Command{Name: "insecure", Help: "list the domains DNSSEC validation is disabled for", Args: listArgs, Run: unboundDiagnosticsInsecure},
	)
}

// unboundTime renders unix seconds as local time
func unboundTime(seconds int64) string {
	if seconds <= 0 {
		return ""
	}
	return time.Unix(seconds, 0).Format("2006-01-02 15:04:05")
}

func unboundCountCell(count unbound.Count) string {
	return fmt.Sprintf("%s (%s%%)", count.Total, unboundPercent(count.Percent))
}

func unboundPercent(percent unbound.Number) string {
	if percent == "" || percent == "0" {
		return "0.00"
	}
	return string(percent)
}

func unboundStatisticsPrint(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	enabled, err := api.StatisticsEnabled()
	if err != nil {
		return err
	}
	totals, err := api.StatisticsTotals(args.Int("top"))
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return c.JSON(map[string]any{"enabled": enabled, "available": totals.Available, "total": totals.Total,
			"passed": totals.Passed, "blocklist_size": totals.BlocklistSize, "resolved": totals.Resolved,
			"blocked": totals.Blocked, "local": totals.Local, "start_time": totals.StartTime, "top": totals.Top,
			"top_blocked": totals.TopBlocked})
	}
	if !totals.Available {
		c.Fields([][2]string{{"recording", YesNo(Flag(enabled))}})
		if !enabled {
			c.Infof(`no statistics: enable them with "/unbound/settings set statistics=yes" and "/unbound/service reconfigure general"`)
		} else {
			c.Infof("no statistics recorded yet")
		}
		return nil
	}
	c.Fields([][2]string{
		{"recording", YesNo(Flag(enabled))},
		{"since", unboundTime(totals.StartTime.Int())},
		{"total", string(totals.Total)},
		{"passed", string(totals.Passed)},
		{"resolved", unboundCountCell(totals.Resolved)},
		{"blocked", unboundCountCell(totals.Blocked)},
		{"local", unboundCountCell(totals.Local)},
		{"blocklist-size", string(totals.BlocklistSize)},
	})
	c.Println()
	var rows [][]string
	for _, domain := range totals.Top {
		rows = append(rows, []string{domain.Domain, string(domain.Total), unboundPercent(domain.Percent)})
	}
	c.Table([]string{"TOP DOMAIN", "QUERIES", "PERCENT"}, rows)
	c.Println()
	rows = nil
	for _, domain := range totals.TopBlocked {
		rows = append(rows, []string{domain.Domain, string(domain.Total), unboundPercent(domain.Percent), domain.Blocklist})
	}
	c.Table([]string{"TOP BLOCKED", "QUERIES", "PERCENT", "BLOCKLIST"}, rows)
	return nil
}

func unboundStatisticsQueries(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	queries, raws, err := api.StatisticsQueries(args.String("search"))
	if err != nil {
		return err
	}
	if limit := args.Int("limit"); limit > 0 && len(queries) > limit {
		queries, raws = queries[:limit], raws[:limit]
	}
	if args.Bool("json") {
		for _, raw := range raws {
			if err := c.JSON(raw); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, len(queries))
	for i, query := range queries {
		var blocklist = query.Blocklist
		if query.Policy != "" {
			blocklist = strings.TrimSpace(blocklist + " (" + query.Policy + ")")
		}
		rows[i] = []string{unboundTime(query.Time.Int()), query.Client, query.Type, query.Domain, query.Action,
			query.Source, query.Rcode, string(query.ResolveTimeMs), blocklist}
	}
	c.Table([]string{"TIME", "CLIENT", "TYPE", "DOMAIN", "ACTION", "SOURCE", "RCODE", "MS", "BLOCKLIST"}, rows)
	return nil
}

func unboundStatisticsHistory(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	var hours, _ = strconv.Atoi(args.String("hours"))
	intervals, err := api.StatisticsHistory(hours)
	if err != nil {
		return err
	}
	if args.Bool("json") {
		for _, interval := range intervals {
			if err := c.JSON(interval); err != nil {
				return err
			}
		}
		return nil
	}
	if len(intervals) == 0 {
		c.Infof("no statistics recorded")
	}
	var rows = make([][]string, len(intervals))
	for i, interval := range intervals {
		rows[i] = []string{unboundTime(interval.Start), string(interval.Total), string(interval.Passed), string(interval.Blocked),
			string(interval.Dropped), string(interval.Resolved), string(interval.Local), string(interval.Cached)}
	}
	c.Table([]string{"START", "TOTAL", "PASSED", "BLOCKED", "DROPPED", "RESOLVED", "LOCAL", "CACHED"}, rows)
	return nil
}

func unboundStatisticsCounters(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	counters, err := api.Counters()
	if err != nil {
		return err
	}
	var search = strings.ToLower(args.String("search"))
	var selected = map[string]string{}
	for name, value := range counters {
		if search == "" || strings.Contains(strings.ToLower(name), search) {
			selected[name] = value
		}
	}
	if args.Bool("json") {
		return c.JSON(selected)
	}
	var fields = make([][2]string, 0, len(selected))
	for _, name := range dnsSortedKeys(selected) {
		fields = append(fields, [2]string{name, selected[name]})
	}
	c.Fields(fields)
	return nil
}

func unboundStatisticsReset(c *Context, _ *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	return api.StatisticsReset()
}

// --- diagnostics

// unboundMatches tells whether any of the values contains the search text (case-insensitive)
func unboundMatches(search string, values ...string) bool {
	if search == "" {
		return true
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), strings.ToLower(search)) {
			return true
		}
	}
	return false
}

// unboundRecordTable prints cache / local data entries as table or JSON lines
func unboundRecordTable(c *Context, args *Args, entries []unbound.CacheEntry) error {
	var rows [][]string
	for _, entry := range entries {
		if !unboundMatches(args.String("search"), entry.Name, entry.Rrtype, entry.Value) {
			continue
		}
		if args.Bool("json") {
			if err := c.JSON(entry); err != nil {
				return err
			}
			continue
		}
		rows = append(rows, []string{entry.Name, entry.Ttl, entry.Rrtype, entry.Value})
	}
	if !args.Bool("json") {
		c.Table([]string{"NAME", "TTL", "TYPE", "VALUE"}, rows)
	}
	return nil
}

func unboundDiagnosticsCache(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	entries, err := api.CacheDump()
	if err != nil {
		return err
	}
	return unboundRecordTable(c, args, entries)
}

func unboundDiagnosticsLocalData(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	entries, err := api.LocalData()
	if err != nil {
		return err
	}
	return unboundRecordTable(c, args, entries)
}

func unboundDiagnosticsInfra(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	entries, err := api.InfraDump()
	if err != nil {
		return err
	}
	var rows [][]string
	for _, entry := range entries {
		if !unboundMatches(args.String("search"), entry.Ip, entry.Host) {
			continue
		}
		if args.Bool("json") {
			if err := c.JSON(map[string]any{"ip": entry.Ip, "host": entry.Host, "lame": entry.Lame, "stats": entry.Stats}); err != nil {
				return err
			}
			continue
		}
		rows = append(rows, []string{entry.Host, entry.Ip, entry.Stats["rtt"], entry.Stats["rto"], entry.Stats["ping"],
			entry.Stats["ttl"], YesNo(Flag(entry.Lame))})
	}
	if !args.Bool("json") {
		c.Table([]string{"ZONE", "SERVER", "RTT", "RTO", "PING", "TTL", "LAME"}, rows)
	}
	return nil
}

func unboundDiagnosticsLocalZones(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	zones, err := api.LocalZones()
	if err != nil {
		return err
	}
	var rows [][]string
	for _, zone := range zones {
		if !unboundMatches(args.String("search"), zone.Zone, zone.Type) {
			continue
		}
		if args.Bool("json") {
			if err := c.JSON(zone); err != nil {
				return err
			}
			continue
		}
		rows = append(rows, []string{zone.Zone, zone.Type})
	}
	if !args.Bool("json") {
		c.Table([]string{"ZONE", "TYPE"}, rows)
	}
	return nil
}

func unboundDiagnosticsInsecure(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	zones, err := api.InsecureZones()
	if err != nil {
		return err
	}
	for _, zone := range zones {
		if !unboundMatches(args.String("search"), zone) {
			continue
		}
		if args.Bool("json") {
			if err := c.JSON(map[string]string{"zone": zone}); err != nil {
				return err
			}
			continue
		}
		c.Println(zone)
	}
	return nil
}
