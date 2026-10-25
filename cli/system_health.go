package cli

import (
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"opnsense-cli/opnsense/api/diagnostics"
)

// /system/health: the RRD graphs of Reporting > Health (api/diagnostics/systemhealth): list the reports, print the
// values of one over a time range, CSV export, delete collected data; /system/health/settings: whether the data is
// collected

func init() {
	var menu = Root.Menu("system/health")
	menu.Help = "system health history: the RRD graphs of CPU, memory, states, traffic, gateway quality..."
	menu.Add(
		&Command{
			Name: "print",
			Help: "list the health reports, or show the values of one (metric=)",
			Long: `Without metric= lists the reports OPNsense collects (RRD files): METRIC is the report name, TOPIC its
group (system, traffic, packets, quality, services...). topic= lists only one group.

With metric= shows the values of that report as a table, one row per time step and one column per value (e.g.
user, nice, system for the processor). The report is the # of the last print, its METRIC, its file name
(system-processor) or topic/item (system/processor). resolution= picks the archive: 1m (default), 5m, 1h or 1d,
coarser archives reach further back. from= and to= limit the time range, default the last 60 steps. Times are a date and time
(2026-10-25T14:00, 2026-10-25 14:00 in quotes, 2026-10-25, RFC 3339), a unix timestamp, now, or a time span
back from now (90m, 6h, 2d, 1w). Unknown values are shown as -.

json prints the reports, or the values one row per line as {"time":"<RFC 3339>","<column>":<value or null>,...}.

  print
  print metric=processor-system from=6h resolution=5m
  print metric=wan-traffic from=2026-10-24 to=2026-10-25 resolution=1h`,
			Args: []Arg{
				{Name: "metric", Help: "show the values of this report: #, METRIC, file name or topic/item", Complete: systemHealthComplete},
				{Name: "topic", Help: "list only the reports of this topic (system, traffic, packets, quality, ...)"},
				{Name: "resolution", Default: "1m", Values: systemHealthResolutionNames(), Help: "the archive (step between two values) of metric="},
				{Name: "from", Help: "first time of metric= (default 60 steps before to)", Validate: systemHealthValidateTime},
				{Name: "to", Help: "last time of metric= (default now)", Validate: systemHealthValidateTime},
				{Name: "json", Type: Bool, Help: "print JSON, one object per line"},
			},
			Check: func(args *Args) error {
				if !args.Has("metric") {
					for _, name := range []string{"resolution", "from", "to"} {
						if args.Has(name) {
							return fmt.Errorf("%s only with metric=", name)
						}
					}
				} else if args.Has("topic") {
					return errors.New("topic= only lists reports, it can not be combined with metric=")
				}
				return systemHealthCheckRange(args)
			},
			Run: systemHealthPrint,
		},
		&Command{
			Name: "export",
			Help: "save the values of a report as CSV (the export of the GUI)",
			Long: `Writes the whole archive of a report (resolution=, default 1m) as ";" separated CSV with the columns
iso_time and one per value, as exported by the GUI, to file (- for stdout). An existing file is only replaced
with overwrite. Without data nothing is written.

  export metric=processor-system cpu.csv
  export metric=wan-traffic resolution=1h - `,
			Args: []Arg{
				{Name: "file", Positional: true, Required: true, Help: "the CSV file to write, - for stdout"},
				{Name: "metric", Required: true, Help: "the report: #, METRIC, file name or topic/item", Complete: systemHealthComplete},
				{Name: "resolution", Default: "1m", Values: systemHealthResolutionNames(), Help: "the archive (step between two values)"},
				{Name: "overwrite", Type: Bool, Help: "replace an existing file"},
			},
			Check: systemHealthCheckOutput,
			Run:   systemHealthExport,
		},
		&Command{
			Name: "reset-data",
			Help: "delete the collected data of one report, or of all",
			Long: `Deletes the RRD file of the report given by metric=, or of all reports. Collection starts again with
empty graphs (while it is enabled, see /system/health/settings).`,
			Args: []Arg{
				{Name: "metric", Help: "only this report: #, METRIC, file name or topic/item (default all)", Complete: systemHealthComplete},
			},
			Confirm: "This deletes the collected health data (RRD files) of the report given by metric=, or of all reports.",
			Run:     systemHealthResetData,
		},
	)

	var settings = Root.Menu("system/health/settings")
	settings.Help = "whether the system health data is collected"
	settings.Add(
		&Command{
			Name: "print",
			Help: "show the system health settings",
			Args: []Arg{{Name: "json", Type: Bool, Help: "print the settings as OPNsense returns them"}},
			Run:  systemHealthSettingsPrint,
		},
		&Command{
			Name: "set",
			Help: "enable or disable the collection of the health data",
			Long: `enabled=no stops collecting new values, the collected data is kept. ` + systemHealthApplyHint,
			Args: []Arg{{Name: "enabled", Type: Bool, Required: true, Help: "collect the health data (RRD graphs)"}},
			Run:  systemHealthSettingsSet,
		},
		&Command{
			Name:    "reconfigure",
			Aliases: []string{"apply"},
			Help:    "apply the settings (reconfigures the gateway monitors and restarts cron)",
			Long: `Applies the saved settings like the Apply button of the GUI: OPNsense regenerates the gateway monitor
configuration and restarts cron, which runs the collection.`,
			Run: func(c *Context, _ *Args) error {
				var api, err = ifaceDiagnostics(c)
				if err != nil {
					return err
				}
				return api.HealthReconfigure()
			},
		},
	)
}

const systemHealthApplyHint = `Changes are only saved, run "/system/health/settings reconfigure" to apply them.`

func systemHealthResolutionNames() []string {
	var names = make([]string, 0, len(diagnostics.HealthResolutions))
	for _, resolution := range diagnostics.HealthResolutions {
		names = append(names, resolution.Name)
	}
	return names
}

func systemHealthResolution(name string) diagnostics.HealthResolution {
	for _, resolution := range diagnostics.HealthResolutions {
		if strings.EqualFold(resolution.Name, name) {
			return resolution
		}
	}
	return diagnostics.HealthResolutions[0]
}

// --- time arguments, shared with /tool/insight

var systemHealthSpanPattern = regexp.MustCompile(`^(\d+(?:\.\d+)?)([dw])$`)

// systemHealthTimeLayouts are the accepted absolute times, in local time unless they carry a zone
var systemHealthTimeLayouts = []string{
	time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04:05", "2006-01-02 15:04", time.DateOnly,
}

// systemHealthParseTime parses a time argument: an absolute date / time, a unix timestamp, "now" or a span back
// from now (90m, 6h, 2d, 1w, 1h30m)
func systemHealthParseTime(value string, now time.Time) (time.Time, error) {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "now") {
		return now, nil
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Unix(seconds, 0), nil
	}
	if match := systemHealthSpanPattern.FindStringSubmatch(value); match != nil {
		var number, _ = strconv.ParseFloat(match[1], 64)
		var unit = 24 * time.Hour
		if match[2] == "w" {
			unit *= 7
		}
		return now.Add(-time.Duration(number * float64(unit))), nil
	}
	if span, err := time.ParseDuration(value); err == nil && span >= 0 {
		return now.Add(-span), nil
	}
	for _, layout := range systemHealthTimeLayouts {
		if parsed, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("must be a time like 2026-10-25T14:00, a unix timestamp, now or a span like 6h or 2d, got %q", value)
}

func systemHealthValidateTime(value string) error {
	var _, err = systemHealthParseTime(value, time.Now())
	return err
}

// systemHealthRange resolves from= and to= of args, from defaults to defaultSpan before to, to to now
func systemHealthRange(args *Args, defaultSpan time.Duration) (time.Time, time.Time, error) {
	var now = time.Now()
	var to = now
	var err error
	if args.Has("to") {
		if to, err = systemHealthParseTime(args.String("to"), now); err != nil {
			return time.Time{}, time.Time{}, err
		}
	}
	var from = to.Add(-defaultSpan)
	if args.Has("from") {
		if from, err = systemHealthParseTime(args.String("from"), now); err != nil {
			return time.Time{}, time.Time{}, err
		}
	}
	if from.After(to) {
		return time.Time{}, time.Time{}, fmt.Errorf("from (%s) is after to (%s)", from.Format(time.DateTime), to.Format(time.DateTime))
	}
	return from, to, nil
}

// systemHealthCheckRange fails when from= is after to= (both given), for Command.Check
func systemHealthCheckRange(args *Args) error {
	if !args.Has("from") || !args.Has("to") {
		return nil
	}
	var _, _, err = systemHealthRange(args, 0)
	return err
}

// --- reports

func systemHealthReportNames(report diagnostics.HealthReport) []string {
	return []string{report.Key, report.Topic + "/" + report.Item}
}

// systemHealthSelect resolves a report selector
func systemHealthSelect(c *Context, api *diagnostics.DiagnosticsApi, selector string) (diagnostics.HealthReport, error) {
	var reports, _, err = api.HealthReports()
	if err != nil {
		return diagnostics.HealthReport{}, err
	}
	return Select(c, selector, reports, func(r diagnostics.HealthReport) string { return r.Metric }, systemHealthReportNames)
}

func systemHealthComplete(c *Context) []string {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return nil
	}
	var reports, _, listErr = api.HealthReports()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(reports))
	for _, report := range reports {
		names = append(names, report.Metric)
	}
	return names
}

func systemHealthPrint(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	if args.Has("metric") {
		return systemHealthPrintValues(c, api, args)
	}

	var reports, _, listErr = api.HealthReports()
	if listErr != nil {
		return listErr
	}
	if topic := args.String("topic"); topic != "" {
		var filtered []diagnostics.HealthReport
		for _, report := range reports {
			if strings.EqualFold(report.Topic, topic) {
				filtered = append(filtered, report)
			}
		}
		reports = filtered
	}
	if args.Bool("json") {
		for _, report := range reports {
			if err := c.JSON(map[string]string{"metric": report.Metric, "topic": report.Topic, "item": report.Item,
				"key": report.Key, "filename": report.Filename, "description": report.Description}); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, 0, len(reports))
	var metrics = make([]string, 0, len(reports))
	for _, report := range reports {
		var description = report.Description
		if description == report.Item {
			description = ""
		}
		rows = append(rows, []string{report.Metric, report.Topic, report.Item, description})
		metrics = append(metrics, report.Metric)
	}
	c.Items([]string{"METRIC", "TOPIC", "ITEM", "DESCRIPTION"}, rows, metrics)
	if len(reports) == 0 && !args.Has("topic") {
		c.Infof(`no health data collected yet, see "/system/health/settings print"`)
	}
	return nil
}

func systemHealthPrintValues(c *Context, api *diagnostics.DiagnosticsApi, args *Args) error {
	var report, err = systemHealthSelect(c, api, args.String("metric"))
	if err != nil {
		return err
	}
	var resolution = systemHealthResolution(args.String("resolution"))
	var series, fetchErr = api.HealthFetch(report.Metric, resolution.Detail)
	if fetchErr != nil {
		return fetchErr
	}
	var step = resolution.Step
	if series.StepSize > 0 {
		step = time.Duration(series.StepSize) * time.Second
	}
	from, to, err := systemHealthRange(args, 60*step)
	if err != nil {
		return err
	}

	var rows []diagnostics.HealthRow
	for _, row := range series.Rows {
		if !row.Time.Before(from) && !row.Time.After(to) {
			rows = append(rows, row)
		}
	}

	if args.Bool("json") {
		for _, row := range rows {
			var object = map[string]any{"time": row.Time.Format(time.RFC3339)}
			for i, column := range series.Columns {
				if math.IsNaN(row.Values[i]) {
					object[column] = nil
				} else {
					object[column] = row.Values[i]
				}
			}
			if err := c.JSON(object); err != nil {
				return err
			}
		}
		return nil
	}

	var title = series.Title
	if series.YAxisLabel != "" {
		title += " (" + series.YAxisLabel + ")"
	}
	c.Infof("%s, one value per %s", title, systemHealthStep(step))
	if len(rows) == 0 {
		c.Infof("no values from %s to %s", from.Format("2006-01-02 15:04"), to.Format("2006-01-02 15:04"))
		return nil
	}
	var headers = []string{"TIME"}
	for _, column := range series.Columns {
		headers = append(headers, strings.ToUpper(column))
	}
	var table = make([][]string, 0, len(rows))
	for _, row := range rows {
		var cells = []string{row.Time.Format("2006-01-02 15:04")}
		for _, value := range row.Values {
			cells = append(cells, systemHealthValue(value))
		}
		table = append(table, cells)
	}
	c.Table(headers, table)
	return nil
}

// systemHealthValue renders a value with at most 3 decimals, "" (shown as -) when unknown
func systemHealthValue(value float64) string {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return ""
	}
	return strconv.FormatFloat(math.Round(value*1000)/1000, 'f', -1, 64)
}

func systemHealthStep(step time.Duration) string {
	switch {
	case step%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", step/(24*time.Hour))
	case step%time.Hour == 0:
		return fmt.Sprintf("%dh", step/time.Hour)
	case step%time.Minute == 0:
		return fmt.Sprintf("%dm", step/time.Minute)
	}
	return step.String()
}

// --- export

func systemHealthCheckOutput(args *Args) error {
	if args.Bool("overwrite") && args.String("file") == "-" {
		return errors.New("overwrite has no effect with file=- (stdout)")
	}
	return nil
}

// systemHealthSave writes content to file (- for stdout), an existing file only with overwrite
func systemHealthSave(c *Context, content []byte, file string, overwrite bool) error {
	if file == "-" {
		_, err := c.Out.Write(content)
		return err
	}
	var flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if overwrite {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	var handle, err = os.OpenFile(file, flags, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists, add overwrite to replace it", file)
		}
		return err
	}
	if _, err := handle.Write(content); err != nil {
		_ = handle.Close()
		return err
	}
	if err := handle.Close(); err != nil {
		return err
	}
	c.Infof("saved %s (%d bytes)", file, len(content))
	return nil
}

func systemHealthExport(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var report, selectErr = systemHealthSelect(c, api, args.String("metric"))
	if selectErr != nil {
		return selectErr
	}
	var content, exportErr = api.HealthExportCsv(report.Metric, systemHealthResolution(args.String("resolution")).Detail)
	if exportErr != nil {
		return exportErr
	}
	if content == nil {
		c.Infof("%s has no data at resolution %s, nothing exported", report.Metric, args.String("resolution"))
		return nil
	}
	return systemHealthSave(c, content, args.String("file"), args.Bool("overwrite"))
}

func systemHealthResetData(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	if !args.Has("metric") {
		return api.HealthReset("")
	}
	var report, selectErr = systemHealthSelect(c, api, args.String("metric"))
	if selectErr != nil {
		return selectErr
	}
	return api.HealthReset(report.Key)
}

// --- settings

func systemHealthSettingsPrint(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var enabled, raw, getErr = api.HealthSettings()
	if getErr != nil {
		return getErr
	}
	if args.Bool("json") {
		return c.JSON(raw)
	}
	c.Fields([][2]string{{"enabled", YesNo(Flag(enabled))}})
	return nil
}

func systemHealthSettingsSet(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	return api.HealthSetEnabled(args.Bool("enabled"))
}
