package cli

import (
	"fmt"
	"math"
	"opnsense-cli/opnsense/api/system"
	"sort"
	"strings"
)

// /system/logging: the general syslog-ng settings of System > Settings > Logging and its statistics. The remote
// destinations are in /system/logging/destination, the service in /system/logging/service

const systemLoggingApplyHint = `Changes are only saved, run "/system/logging/service reconfigure" to apply them.`

func init() {
	var menu = Root.Menu("system/logging")
	menu.Help = "logging (syslog-ng): general settings, statistics, remote destinations, service"
	menu.Add(
		&Command{
			Name: "print",
			Help: "show the general logging settings",
			Args: []Arg{{Name: "json", Type: Bool, Help: "print the raw settings as one JSON object"}},
			Run:  systemLoggingPrint,
		},
		&Command{
			Name: "set",
			Help: "change the general logging settings, the others are kept",
			Long: systemLoggingApplyHint,
			Args: []Arg{
				{Name: "enabled", Type: Bool, Help: "enable the logging service"},
				{Name: "local", Type: Bool, Help: "write logs to the local disk"},
				{Name: "max-preserve", Type: Int, Help: "number of rotated log files to keep (OPNsense default 31)",
					Validate: systemLoggingRequired(ValidateRange(0, math.MaxInt32))},
				{Name: "max-file-size", Type: Int, Help: `rotate a log file early once it exceeds this size, "" for no size limit`,
					Validate: ValidateRange(0, math.MaxInt)},
			},
			Run: systemLoggingSet,
		},
		&Command{
			Name: "stats",
			Help: "show the syslog-ng statistics (messages processed / dropped / queued per source and destination)",
			Args: []Arg{
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
				{Name: "search", Help: "only counters where any field contains this text"},
			},
			Run: systemLoggingStats,
		},
	)
}

// systemLoggingApi returns the system API on the session's connection
func systemLoggingApi(c *Context) (*system.SystemApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &system.SystemApi{OPNsense: opn}, nil
}

// systemLoggingRequired rejects an empty (or blank) value and otherwise applies validate (nil for none)
func systemLoggingRequired(validate func(string) error) func(string) error {
	return func(value string) error {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("must not be empty")
		}
		if validate != nil {
			return validate(value)
		}
		return nil
	}
}

func systemLoggingPrint(c *Context, args *Args) error {
	var api, err = systemLoggingApi(c)
	if err != nil {
		return err
	}
	var general, getErr = api.LoggingGeneralGet()
	if getErr != nil {
		return getErr
	}
	if args.Bool("json") {
		return c.JSON(general)
	}
	c.Fields([][2]string{
		{"enabled", YesNo(general.Enabled)},
		{"local", YesNo(general.LogLocal)},
		{"max-preserve", general.MaxPreserve},
		{"max-file-size", general.MaxFileSize},
	})
	return nil
}

func systemLoggingSet(c *Context, args *Args) error {
	var fields system.LoggingGeneralFields
	var value = func(name string) *string {
		if !args.Has(name) {
			return nil
		}
		var v = strings.TrimSpace(args.String(name))
		return &v
	}
	var flag = func(name string) *string {
		if !args.Has(name) {
			return nil
		}
		var v = Flag(args.Bool(name))
		return &v
	}
	fields.Enabled = flag("enabled")
	fields.LogLocal = flag("local")
	fields.MaxPreserve = value("max-preserve")
	fields.MaxFileSize = value("max-file-size")
	if fields == (system.LoggingGeneralFields{}) {
		return fmt.Errorf("set: nothing to change, give at least one of enabled=, local=, max-preserve=, max-file-size= (type \"set ?\" for help)")
	}

	var api, err = systemLoggingApi(c)
	if err != nil {
		return err
	}
	return api.LoggingGeneralSet(fields)
}

func systemLoggingStats(c *Context, args *Args) error {
	var api, err = systemLoggingApi(c)
	if err != nil {
		return err
	}
	var stats, statsErr = api.LoggingStats(args.String("search"))
	if statsErr != nil {
		return statsErr
	}

	// OPNsense returns the counters in random order
	var key = func(s system.LoggingStat) []string {
		return []string{s.SourceName, s.SourceId, s.SourceInstance, s.State, s.Type}
	}
	sort.SliceStable(stats, func(i, j int) bool {
		var a, b = key(stats[i]), key(stats[j])
		for column := range a {
			if a[column] != b[column] {
				return a[column] < b[column]
			}
		}
		return false
	})

	if args.Bool("json") {
		for _, stat := range stats {
			if err := c.JSON(stat); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, 0, len(stats))
	for _, s := range stats {
		rows = append(rows, []string{s.SourceName, s.SourceId, s.SourceInstance, s.State, s.Type, s.Number})
	}
	c.Table([]string{"SOURCE", "ID", "INSTANCE", "STATE", "TYPE", "NUMBER"}, rows)
	return nil
}
