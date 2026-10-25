package cli

import (
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/diagnostics"
	"strings"
	"time"
)

// /log: the log files of the firewall and its services (System > Log Files and the "Log File" pages of the services)

const logFileNameHelp = "the log: a scope like system, configd, dnsmasq or <module>/<scope> like core/system, see files"

func init() {
	var menu = Root.Menu("log")
	menu.Help = "log files of the firewall and its services"

	menu.Add(
		&Command{
			Name: "print",
			Help: "show the newest lines of a log (like tail), optionally following new lines",
			Long: `Prints the newest lines of a log, oldest first, as "timestamp severity process[pid]: message".
A log is named by its scope like system, configd or dnsmasq, or as <module>/<scope> like core/system (plugins use
their own module), "files" lists them.

Filters are applied by OPNsense: search= matches lines containing every given word (case-insensitive),
severity= keeps lines with one of the given severities (lines without severity, like the boot log, always match).

With follow new lines are streamed until Ctrl-C. A dropped stream is reconnected automatically, lines logged in
the meantime are printed once (up to 1000 lines).`,
			Args: []Arg{
				{Name: "log", Help: logFileNameHelp, Positional: true, Default: "system", Complete: logFileComplete},
				{Name: "lines", Help: "number of lines to print (0-9999), with follow 0 prints only new lines", Type: Int, Default: "50",
					Validate: ValidateRange(0, 9999)},
				{Name: "follow", Help: "stream new lines until Ctrl-C", Type: Bool},
				{Name: "search", Help: "only lines containing all of these space separated words (case-insensitive)"},
				{Name: "severity", Help: "only lines with one of these severities: emergency, alert, critical, error, warning, notice, " +
					"informational, debug (or emerg, crit, err, warn, info)", Type: List, Validate: logFileValidateSeverities,
					Complete: logFileCompleteSeverities},
				{Name: "json", Help: "print the raw records as JSON, one per line", Type: Bool},
			},
			Run: logFilePrint,
		},
		&Command{
			Name: "files",
			Help: "list the available logs (as linked in the OPNsense menu)",
			Args: []Arg{{Name: "json", Type: Bool, Help: "print one JSON object per log"}},
			Run:  logFileList,
		},
		&Command{
			Name:    "clear",
			Help:    "empty a log on the firewall (for everyone, cannot be undone)",
			Args:    []Arg{{Name: "log", Help: logFileNameHelp, Positional: true, Required: true, Complete: logFileComplete}},
			Confirm: "This removes all lines of the log on the firewall, for everyone. It cannot be undone.",
			Run:     logFileClear,
		},
	)
}

func logFileApi(c *Context) (*diagnostics.DiagnosticsApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &diagnostics.DiagnosticsApi{OPNsense: opn}, nil
}

// logFileResolve turns a log name into module and scope (module/scope as is, a plain name via the menu)
func logFileResolve(api *diagnostics.DiagnosticsApi, name string) (string, string, error) {
	var module, scope, err = api.LogResolve(name)
	var notFound *coreapi.NotFoundError
	if errors.As(err, &notFound) {
		// the library points to the old command
		return "", "", &coreapi.NotFoundError{Name: fmt.Sprintf(
			"log %q, see /log files, logs without a menu entry can be given as <module>/<scope>", name)}
	}
	return module, scope, err
}

// logFileComplete offers the log names of the menu for TAB
func logFileComplete(c *Context) []string {
	var api, err = logFileApi(c)
	if err != nil {
		return nil
	}
	var logFiles, listErr = api.LogList()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(logFiles))
	for _, logFile := range logFiles {
		names = append(names, logFile.Name)
	}
	return names
}

func logFileValidateSeverities(value string) error {
	for _, severity := range splitList(value) {
		if _, err := diagnostics.LogNormalizeSeverity(severity); err != nil {
			return err
		}
	}
	return nil
}

func logFileCompleteSeverities(_ *Context) []string {
	var names = make([]string, 0, len(diagnostics.LogSeverities))
	for _, name := range diagnostics.LogSeverities {
		names = append(names, strings.ToLower(name))
	}
	return names
}

// logFileSeverities returns the OPNsense names of the (validated) severity argument
func logFileSeverities(args *Args) []string {
	var severities = make([]string, 0)
	for _, severity := range args.List("severity") {
		var name, _ = diagnostics.LogNormalizeSeverity(severity)
		severities = append(severities, name)
	}
	return severities
}

// logFileFormat renders a record like "2026-10-25T00:03:13 Notice dhcp6c[31413]: Sending Solicit on vtnet1"
func logFileFormat(record diagnostics.LogRecord) string {
	var severity = record.Severity
	if severity == "" {
		severity = "-"
	}
	var process = ""
	if record.ProcessName != "" {
		process = record.ProcessName
		if record.Pid != "" {
			process = fmt.Sprintf("%s[%s]", process, record.Pid)
		}
		process += ": "
	}
	return fmt.Sprintf("%s %s %s%s", record.Timestamp, severity, process, record.Line)
}

func logFilePrint(c *Context, args *Args) error {
	var lines = args.Int("lines")
	var asJson = args.Bool("json")
	var filter = diagnostics.LogFilter{SearchPhrase: args.String("search"), Severities: logFileSeverities(args)}

	var api, err = logFileApi(c)
	if err != nil {
		return err
	}
	var module, scope, resolveErr = logFileResolve(api, args.String("log"))
	if resolveErr != nil {
		return resolveErr
	}

	var printRecord = func(record diagnostics.LogRecord) error {
		if asJson {
			return c.JSON(record)
		}
		c.Println(logFileFormat(record))
		return nil
	}

	if !args.Bool("follow") {
		var records, tailErr = api.LogTail(module, scope, lines, filter)
		if tailErr != nil {
			return tailErr
		}
		if len(records) == 0 && lines > 0 {
			c.Infof("no lines found in log %s/%s", module, scope)
		}
		for _, record := range records {
			if err := printRecord(record); err != nil {
				return err
			}
		}
		return nil
	}

	// the live stream sends the tail itself, so there is no gap between the tail and the new lines.
	// LogFollow returns nil when c is cancelled (Ctrl-C)
	return api.LogFollow(c.Context, module, scope, diagnostics.LogFollowOptions{
		Lines:  lines,
		Filter: filter,
		OnReconnect: func(err error, delay time.Duration) {
			c.Infof("log stream interrupted (%v), reconnecting in %s", err, delay)
		},
	}, printRecord)
}

func logFileList(c *Context, args *Args) error {
	var api, err = logFileApi(c)
	if err != nil {
		return err
	}
	var logFiles, listErr = api.LogList()
	if listErr != nil {
		return listErr
	}
	if args.Bool("json") {
		for _, logFile := range logFiles {
			var object = map[string]string{"name": logFile.Name, "module": logFile.Module, "scope": logFile.Scope, "menu": logFile.MenuPath}
			if err := c.JSON(object); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, 0, len(logFiles))
	for _, logFile := range logFiles {
		rows = append(rows, []string{logFile.Name, logFile.Module, logFile.Scope, logFile.MenuPath})
	}
	c.Table([]string{"NAME", "MODULE", "SCOPE", "MENU"}, rows)
	return nil
}

func logFileClear(c *Context, args *Args) error {
	var api, err = logFileApi(c)
	if err != nil {
		return err
	}
	var module, scope, resolveErr = logFileResolve(api, args.String("log"))
	if resolveErr != nil {
		return resolveErr
	}
	return api.LogClear(module, scope)
}
