package cli

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/diagnostics"
)

// /tool/insight: the aggregated local NetFlow data of Reporting > Insight (api/diagnostics/networkinsight): top
// usage per interface, protocol, service, address and flow, the interface traffic over time and the CSV export.
// Needs local collection, see /tool/netflow

// toolInsightView is one value of print by= (and export by=)
type toolInsightView struct {
	name     string
	provider string
	fields   []string // group by
	filters  []string // the filter arguments the provider has
	portKey  string   // the field port= filters
	help     string
}

var toolInsightViews = []toolInsightView{
	{"interface", diagnostics.InsightInterfaceTotals, []string{"if", "direction"}, []string{"interface", "direction"}, "",
		"traffic per interface and direction (bytes and packets)"},
	{"protocol", diagnostics.InsightDstPortTotals, []string{"protocol"}, []string{"interface", "port", "protocol"}, "dst_port",
		"traffic per IP protocol"},
	{"service", diagnostics.InsightDstPortTotals, []string{"dst_port", "protocol"}, []string{"interface", "port", "protocol"}, "dst_port",
		"traffic per service (destination port and protocol)"},
	{"talker", diagnostics.InsightSourceAddrTotals, []string{"src_addr"}, []string{"interface", "direction", "source"}, "",
		"the addresses with the most traffic (top talkers)"},
	{"flow", diagnostics.InsightSourceAddrDetails, []string{"service_port", "protocol", "if", "src_addr", "dst_addr"},
		[]string{"interface", "direction", "port", "protocol", "source", "destination"}, "service_port",
		"traffic per source, destination and service (daily resolution only)"},
}

// toolInsightFilterArgs are the filter arguments, all views use a subset (toolInsightView.filters)
var toolInsightFilterArgs = []string{"interface", "direction", "port", "protocol", "source", "destination"}

func toolInsightViewNames(exportable bool) []string {
	var names []string
	for _, view := range toolInsightViews {
		if !exportable || view.name != "protocol" {
			names = append(names, view.name)
		}
	}
	return names
}

func toolInsightFindView(name string) toolInsightView {
	for _, view := range toolInsightViews {
		if strings.EqualFold(view.name, name) {
			return view
		}
	}
	return toolInsightViews[0]
}

func toolInsightViewHelp() string {
	var lines []string
	for _, view := range toolInsightViews {
		lines = append(lines, fmt.Sprintf("  %-10s %s, filters: %s", view.name, view.help, strings.Join(view.filters, ", ")))
	}
	return strings.Join(lines, "\n")
}

const toolInsightTimeHelp = `Times are a date and time (2026-10-25T14:00, 2026-10-25 14:00 in quotes, 2026-10-25, RFC 3339), a unix
timestamp, now, or a time span back from now (90m, 6h, 2d, 1w).`

func init() {
	var menu = Root.Menu("tool/insight")
	menu.Help = "NetFlow Insight: traffic per interface, protocol, service and address from the local NetFlow data"
	menu.Add(
		&Command{
			Name: "print",
			Help: "show the top traffic per interface, protocol, service, address or flow",
			Long: `Shows the traffic of the locally collected NetFlow data (see /tool/netflow, collect) from from= (default
the last 24 hours) to to= (default now), grouped by by=:

` + toolInsightViewHelp() + `

The groups with the most traffic come first, limit= of them; the rest is summed up in a row "(other)". measure=
packets ranks by packets instead of bytes. SHARE is the part of the total. The filters are interface= (name,
description or device), direction=in|out, port=, protocol= (name or number), source= and destination= (addresses);
each view accepts the ones listed. OPNsense picks the finest aggregation still holding from=, so old ranges are
less precise. ` + toolInsightTimeHelp + ` json prints the rows as OPNsense returns them.

  print
  print by=service interface=wan from=6h
  print by=talker limit=10 direction=in
  print by=flow port=443 from=7d`,
			Args: []Arg{
				{Name: "by", Default: "interface", Values: toolInsightViewNames(false), Help: "group the traffic by this"},
				{Name: "from", Help: "start of the time range (default 1d: the last 24 hours)", Validate: systemHealthValidateTime},
				{Name: "to", Help: "end of the time range (default now)", Validate: systemHealthValidateTime},
				{Name: "measure", Default: "bytes", Values: []string{"bytes", "packets"}, Help: "rank by bytes or packets"},
				{Name: "limit", Type: Int, Default: "25", Help: "show this many groups, the rest is summed up", Validate: ValidateRange(1, 10000)},
				{Name: "interface", Help: "only this interface (name, description or device)", Complete: toolInsightCompleteInterfaces},
				{Name: "direction", Values: []string{"in", "out"}, Help: "only incoming or outgoing traffic"},
				{Name: "port", Help: "only this port (service)", Validate: ValidatePort},
				{Name: "protocol", Help: "only this IP protocol, name (tcp) or number (6)", Validate: toolInsightValidateNoComma},
				{Name: "source", Help: "only this source address", Validate: ValidateIP},
				{Name: "destination", Help: "only this destination address", Validate: ValidateIP},
				{Name: "json", Type: Bool, Help: "print the rows as JSON, one object per line"},
			},
			Check: toolInsightCheckPrint,
			Run:   toolInsightPrint,
		},
		&Command{
			Name: "history",
			Help: "show the traffic of the interfaces over time",
			Long: `Shows the traffic of every interface and direction over time, one row per resolution= step (30s, 5m,
1h or 1d, default 5m) and one column per interface and direction. measure= is bps (bits per second, default),
pps (packets per second), bytes or packets (per step). from= defaults to 60 steps before to= (default now).
` + toolInsightTimeHelp + ` interface= shows only these interfaces. json prints one object per row with
the values keyed by "<device>,<direction>".

  history from=6h
  history interface=wan resolution=1h from=2d measure=bytes`,
			Args: []Arg{
				{Name: "from", Help: "start of the time range (default 60 steps before to)", Validate: systemHealthValidateTime},
				{Name: "to", Help: "end of the time range (default now)", Validate: systemHealthValidateTime},
				{Name: "resolution", Default: "5m", Help: "step between two rows: 30s, 5m, 1h or 1d", Validate: toolInsightValidateResolution},
				{Name: "measure", Default: "bps", Values: []string{"bps", "pps", "bytes", "packets"}, Help: "what to show"},
				{Name: "interface", Type: List, Help: "only these interfaces (name, description or device)", Complete: toolInsightCompleteInterfaces},
				{Name: "json", Type: Bool, Help: "print one JSON object per row"},
			},
			Check: systemHealthCheckRange,
			Run:   toolInsightHistory,
		},
		&Command{
			Name: "export",
			Help: "save the collected data of an aggregation as CSV (the export of the GUI)",
			Long: `Writes the aggregated records of by= (interface, service, talker or flow) between from= (default the last
24 hours) and to= (default now) at resolution= (seconds or 30s, 5m, 1h, 1d; default the finest the aggregation
has, flow only has 1d) as comma separated CSV with a header line to file (- for stdout). An existing file is only
replaced with overwrite. Without data nothing is written. ` + toolInsightTimeHelp + `

  export by=interface interfaces.csv resolution=1h from=7d
  export by=flow - from=2d`,
			Args: []Arg{
				{Name: "file", Positional: true, Required: true, Help: "the CSV file to write, - for stdout"},
				{Name: "by", Default: "interface", Values: toolInsightViewNames(true), Help: "the aggregation to export"},
				{Name: "from", Help: "start of the time range (default 1d: the last 24 hours)", Validate: systemHealthValidateTime},
				{Name: "to", Help: "end of the time range (default now)", Validate: systemHealthValidateTime},
				{Name: "resolution", Help: "resolution of the records (default the finest of the aggregation)", Validate: toolInsightValidateResolution},
				{Name: "overwrite", Type: Bool, Help: "replace an existing file"},
			},
			Check: func(args *Args) error {
				if err := systemHealthCheckOutput(args); err != nil {
					return err
				}
				return systemHealthCheckRange(args)
			},
			Run: toolInsightExport,
		},
	)
}

func toolInsightValidateNoComma(value string) error {
	if strings.Contains(value, ",") {
		return fmt.Errorf("must be one value, got %q", value)
	}
	return nil
}

// toolInsightParseResolution parses a resolution: seconds or a duration like 30s, 5m, 1h, 1d
func toolInsightParseResolution(value string) (int, error) {
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		return seconds, nil
	}
	var span time.Duration
	if days, found := strings.CutSuffix(value, "d"); found {
		if n, err := strconv.Atoi(days); err == nil && n > 0 {
			span = time.Duration(n) * 24 * time.Hour
		}
	} else if parsed, err := time.ParseDuration(value); err == nil {
		span = parsed
	}
	if span < time.Second || span%time.Second != 0 {
		return 0, fmt.Errorf("must be a resolution like 30s, 5m, 1h or 1d, got %q", value)
	}
	return int(span / time.Second), nil
}

func toolInsightValidateResolution(value string) error {
	var _, err = toolInsightParseResolution(value)
	return err
}

func toolInsightResolutionText(seconds int) string {
	return systemHealthStep(time.Duration(seconds) * time.Second)
}

func toolInsightCheckPrint(args *Args) error {
	var view = toolInsightFindView(args.String("by"))
	for _, filter := range toolInsightFilterArgs {
		if args.Has(filter) && !strings.Contains(","+strings.Join(view.filters, ",")+",", ","+filter+",") {
			return fmt.Errorf("by=%s can not filter by %s, only by %s", view.name, filter, strings.Join(view.filters, ", "))
		}
	}
	return systemHealthCheckRange(args)
}

func toolInsightCompleteInterfaces(c *Context) []string {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return nil
	}
	var interfaces, listErr = api.InsightInterfaces()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(interfaces))
	for _, name := range interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// toolInsightDevice maps an interface name, description or device to the device of the flow data
func toolInsightDevice(name string, interfaces map[string]string) (string, error) {
	for device, description := range interfaces {
		if strings.EqualFold(device, name) || strings.EqualFold(description, name) {
			return device, nil
		}
	}
	var available = make([]string, 0, len(interfaces))
	for device, description := range interfaces {
		available = append(available, description+" ("+device+")")
	}
	sort.Strings(available)
	return "", &coreapi.NotFoundError{Name: fmt.Sprintf("interface %q, known are %s", name, strings.Join(available, ", "))}
}

// toolInsightProtocol maps a protocol name or number to its number
func toolInsightProtocol(name string, protocols map[string]string) (string, error) {
	if _, err := strconv.Atoi(name); err == nil {
		return name, nil
	}
	for number, protocol := range protocols {
		if strings.EqualFold(protocol, name) {
			return number, nil
		}
	}
	return "", &coreapi.NotFoundError{Name: fmt.Sprintf("protocol %q, use a name of /etc/protocols or a number", name)}
}

// --- print

func toolInsightPrint(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var view = toolInsightFindView(args.String("by"))
	var from, to, rangeErr = systemHealthRange(args, 24*time.Hour)
	if rangeErr != nil {
		return rangeErr
	}
	var interfaces, listErr = api.InsightInterfaces()
	if listErr != nil {
		return listErr
	}

	var filters []diagnostics.InsightFilter
	if args.Has("interface") {
		var device, deviceErr = toolInsightDevice(args.String("interface"), interfaces)
		if deviceErr != nil {
			return deviceErr
		}
		filters = append(filters, diagnostics.InsightFilter{Field: "if", Value: device})
	}
	if args.Has("direction") {
		filters = append(filters, diagnostics.InsightFilter{Field: "direction", Value: strings.ToLower(args.String("direction"))})
	}
	if args.Has("port") {
		filters = append(filters, diagnostics.InsightFilter{Field: view.portKey, Value: args.String("port")})
	}
	if args.Has("protocol") {
		var protocols, protocolsErr = api.InsightProtocols()
		if protocolsErr != nil {
			return protocolsErr
		}
		var number, protocolErr = toolInsightProtocol(args.String("protocol"), protocols)
		if protocolErr != nil {
			return protocolErr
		}
		filters = append(filters, diagnostics.InsightFilter{Field: "protocol", Value: number})
	}
	if args.Has("source") {
		filters = append(filters, diagnostics.InsightFilter{Field: "src_addr", Value: args.String("source")})
	}
	if args.Has("destination") {
		filters = append(filters, diagnostics.InsightFilter{Field: "dst_addr", Value: args.String("destination")})
	}

	var measure = "octets"
	if args.String("measure") == "packets" {
		measure = "packets"
	}
	var query = diagnostics.InsightTopQuery{Provider: view.provider, From: from, To: to, Fields: view.fields, Measure: measure,
		MaxHits: args.Int("limit"), Filters: filters}
	var rows, topErr = api.InsightTop(query)
	if topErr != nil {
		return topErr
	}
	if args.Bool("json") {
		for _, row := range rows {
			if err := c.JSON(row.Raw); err != nil {
				return err
			}
		}
		return nil
	}

	var interfaceName = func(device string) string {
		if name, found := interfaces[device]; found {
			return name
		}
		return device
	}
	var amount = func(value float64) string {
		if measure == "packets" {
			return strconv.FormatFloat(value, 'f', 0, 64)
		}
		return ifaceBytes(value)
	}

	if view.name == "interface" {
		// like the GUI: bytes and packets of every interface and direction
		var otherMeasure = "packets"
		if measure == "packets" {
			otherMeasure = "octets"
		}
		query.Measure = otherMeasure
		var others, otherErr = api.InsightTop(query)
		if otherErr != nil {
			return otherErr
		}
		var otherTotals = map[string]float64{}
		for _, row := range others {
			otherTotals[row.Fields["if"]+","+row.Fields["direction"]] = row.Total
		}
		var table = make([][]string, 0, len(rows))
		for _, row := range rows {
			var bytes, packets = row.Total, otherTotals[row.Fields["if"]+","+row.Fields["direction"]]
			if measure == "packets" {
				bytes, packets = packets, bytes
			}
			var name, device = interfaceName(row.Fields["if"]), row.Fields["if"]
			if row.Rest {
				name, device = "(other)", ""
			}
			table = append(table, []string{name, device, row.Fields["direction"], ifaceBytes(bytes), strconv.FormatFloat(packets, 'f', 0, 64)})
		}
		c.Table([]string{"INTERFACE", "DEVICE", "DIRECTION", "BYTES", "PACKETS"}, table)
		toolInsightNoData(c, len(rows), from, to)
		return nil
	}

	var sum float64
	for _, row := range rows {
		sum += row.Total
	}
	var share = func(value float64) string {
		if sum <= 0 {
			return ""
		}
		return fmt.Sprintf("%.1f%%", value*100/sum)
	}
	var lastSeen = func(row diagnostics.InsightTopRow) string {
		if row.LastSeen.IsZero() {
			return ""
		}
		return row.LastSeen.Format(time.DateTime)
	}
	var totalHeader = "BYTES"
	if measure == "packets" {
		totalHeader = "PACKETS"
	}
	var protocols map[string]string
	if view.name == "protocol" {
		if protocols, err = api.InsightProtocols(); err != nil {
			return err
		}
	}

	var headers = map[string][]string{
		"protocol": {"PROTOCOL", "NUMBER"}, "service": {"SERVICE", "PORT"}, "talker": {"ADDRESS"},
		"flow": {"SERVICE", "INTERFACE", "SOURCE", "DESTINATION"},
	}[view.name]
	var table = make([][]string, 0, len(rows))
	for _, row := range rows {
		var cells []string
		switch view.name {
		case "protocol":
			var name = protocols[row.Fields["protocol"]]
			if row.Rest {
				name = "(other)"
			}
			cells = []string{name, row.Fields["protocol"]}
		case "service":
			var label = row.Label
			if row.Rest {
				label = "(other)"
			}
			cells = []string{label, row.Fields["dst_port"]}
		case "talker":
			var address = row.Fields["src_addr"]
			if row.Rest {
				address = "(other)"
			}
			cells = []string{address}
		case "flow":
			var label = row.Label
			if row.Rest {
				label = "(other)"
			}
			var name = ""
			if row.Fields["if"] != "" {
				name = interfaceName(row.Fields["if"])
			}
			cells = []string{label, name, row.Fields["src_addr"], row.Fields["dst_addr"]}
		}
		table = append(table, append(cells, amount(row.Total), share(row.Total), lastSeen(row)))
	}
	c.Table(append(headers, totalHeader, "SHARE", "LAST-SEEN"), table)
	toolInsightNoData(c, len(rows), from, to)
	return nil
}

// toolInsightNoData explains an empty result
func toolInsightNoData(c *Context, rows int, from time.Time, to time.Time) {
	if rows == 0 {
		c.Infof("no traffic from %s to %s (local collection enabled? see /tool/netflow status)", from.Format("2006-01-02 15:04"),
			to.Format("2006-01-02 15:04"))
	}
}

// --- history

func toolInsightHistory(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var resolution, _ = toolInsightParseResolution(args.String("resolution"))
	var metadata, metadataErr = api.InsightMetadata()
	if metadataErr != nil {
		return metadataErr
	}
	if err := toolInsightCheckResolution(metadata, diagnostics.InsightInterfaceTotals, resolution); err != nil {
		return err
	}
	var from, to, rangeErr = systemHealthRange(args, 60*time.Duration(resolution)*time.Second)
	if rangeErr != nil {
		return rangeErr
	}
	var interfaces, listErr = api.InsightInterfaces()
	if listErr != nil {
		return listErr
	}
	var selected = map[string]bool{}
	for _, name := range args.List("interface") {
		var device, deviceErr = toolInsightDevice(name, interfaces)
		if deviceErr != nil {
			return deviceErr
		}
		selected[device] = true
	}

	var measure = map[string]string{"bps": "bps", "pps": "packets_ps", "bytes": "octets", "packets": "packets"}[args.String("measure")]
	var series, seriesErr = api.InsightTimeseries(diagnostics.InsightInterfaceTotals, measure, from, to, resolution, []string{"if", "direction"})
	if seriesErr != nil {
		return seriesErr
	}
	var kept []diagnostics.InsightSeries
	for _, s := range series {
		var device, _, _ = strings.Cut(s.Key, ",")
		if len(selected) == 0 || selected[device] {
			kept = append(kept, s)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].Key < kept[j].Key })

	// the series share their time steps (OPNsense fills in zeros), merge them by time anyway
	var byTime = map[int64][]float64{}
	for column, s := range kept {
		for _, point := range s.Points {
			var row, found = byTime[point.Time.Unix()]
			if !found {
				row = make([]float64, len(kept))
				for i := range row {
					row[i] = math.NaN()
				}
				byTime[point.Time.Unix()] = row
			}
			row[column] = point.Value
		}
	}
	var times = make([]int64, 0, len(byTime))
	for t := range byTime {
		times = append(times, t)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })

	if args.Bool("json") {
		for _, t := range times {
			var values = map[string]any{}
			for column, s := range kept {
				if !math.IsNaN(byTime[t][column]) {
					values[s.Key] = byTime[t][column]
				}
			}
			if err := c.JSON(map[string]any{"time": time.Unix(t, 0).Format(time.RFC3339), "values": values}); err != nil {
				return err
			}
		}
		return nil
	}
	if len(times) == 0 {
		toolInsightNoData(c, 0, from, to)
		return nil
	}

	var format = func(value float64) string {
		if math.IsNaN(value) {
			return ""
		}
		switch args.String("measure") {
		case "bps":
			return ifaceBits(value)
		case "pps":
			return strconv.FormatFloat(math.Round(value*10)/10, 'f', -1, 64)
		case "bytes":
			return ifaceBytes(value)
		}
		return strconv.FormatFloat(value, 'f', 0, 64)
	}
	var headers = []string{"TIME"}
	for _, s := range kept {
		var device, direction, _ = strings.Cut(s.Key, ",")
		var name = s.Interface
		if name == "" {
			name = interfaces[device]
		}
		if name == "" {
			name = device
		}
		headers = append(headers, strings.ToUpper(name+"-"+direction))
	}
	var layout = "2006-01-02 15:04"
	if resolution%60 != 0 {
		layout = time.DateTime
	}
	var table = make([][]string, 0, len(times))
	for _, t := range times {
		var cells = []string{time.Unix(t, 0).Format(layout)}
		for _, value := range byTime[t] {
			cells = append(cells, format(value))
		}
		table = append(table, cells)
	}
	c.Table(headers, table)
	return nil
}

// toolInsightCheckResolution fails when the provider does not aggregate at resolution (OPNsense would answer empty)
func toolInsightCheckResolution(metadata *diagnostics.InsightMetadata, provider string, resolution int) error {
	var resolutions = metadata.Resolutions[provider]
	for _, r := range resolutions {
		if r == resolution {
			return nil
		}
	}
	var names = make([]string, 0, len(resolutions))
	for _, r := range resolutions {
		names = append(names, toolInsightResolutionText(r))
	}
	if len(names) == 0 {
		return fmt.Errorf("OPNsense does not report resolutions for %s", provider)
	}
	return fmt.Errorf("resolution %s is not available here, use %s", toolInsightResolutionText(resolution), strings.Join(names, ", "))
}

// --- export

func toolInsightExport(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var view = toolInsightFindView(args.String("by"))
	var metadata, metadataErr = api.InsightMetadata()
	if metadataErr != nil {
		return metadataErr
	}
	var resolution int
	if args.Has("resolution") {
		resolution, _ = toolInsightParseResolution(args.String("resolution"))
		if err := toolInsightCheckResolution(metadata, view.provider, resolution); err != nil {
			return err
		}
	} else if resolutions := metadata.Resolutions[view.provider]; len(resolutions) > 0 {
		resolution = resolutions[0]
	} else {
		return fmt.Errorf("OPNsense does not report resolutions for %s", view.provider)
	}
	var from, to, rangeErr = systemHealthRange(args, 24*time.Hour)
	if rangeErr != nil {
		return rangeErr
	}
	var content, exportErr = api.InsightExportCsv(view.provider, from, to, resolution)
	if exportErr != nil {
		return exportErr
	}
	if content == nil {
		c.Infof("no %s data from %s to %s, nothing exported", view.name, from.Format("2006-01-02 15:04"), to.Format("2006-01-02 15:04"))
		return nil
	}
	return systemHealthSave(c, content, args.String("file"), args.Bool("overwrite"))
}
