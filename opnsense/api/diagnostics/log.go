package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LogRecord is one parsed log line as returned by api/diagnostics/log/<module>/<scope> (and its /live stream)
type LogRecord struct {
	Timestamp string `json:"timestamp"` // local time of the firewall, like 2026-10-25T00:03:13
	Parser    string `json:"parser"`    // e.g. SysLogFormatRFC5424, ServiceLogFormat
	Facility  *int   `json:"facility"`  // syslog facility number, nil when the format has none
	// Severity is one of LogSeverities, empty when the format has none (e.g. the boot log)
	Severity    string `json:"severity"`
	ProcessName string `json:"process_name"`
	Pid         string `json:"pid"`
	// Rnum is the row number counted from the newest line, 0 for lines from the live stream
	Rnum int    `json:"rnum"`
	Line string `json:"line"` // the message, surrounding whitespace removed
}

// LogFilter is applied by OPNsense on queries and live streams
type LogFilter struct {
	// SearchPhrase is split on spaces, a line must contain every word (case-insensitive substring)
	SearchPhrase string
	// Severities only returns lines with one of these severities (see LogSeverities), lines without severity always match
	Severities []string
}

// LogFile is a log available in the GUI menu (/ui/diagnostics/log/<module>/<scope>)
type LogFile struct {
	Name     string // scope, or module/scope when the scope is not unique
	Module   string // "core" for OPNsense core logs, the plugin name otherwise
	Scope    string // the log file name, e.g. system, configd, dnsmasq
	MenuPath string // e.g. "System > Log Files > Backend"
}

// LogSeverities are the severity names OPNsense uses, from most to least severe
var LogSeverities = []string{"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"}

// logSeverityAliases maps common short names (syslog keywords) to LogSeverities
var logSeverityAliases = map[string]string{
	"emerg": "Emergency", "panic": "Emergency", "crit": "Critical", "err": "Error", "warn": "Warning", "info": "Informational",
}

// LogNormalizeSeverity returns the OPNsense name of a severity given case-insensitive, also accepting
// syslog short names like err, warn, info, crit, emerg
func LogNormalizeSeverity(severity string) (string, error) {
	var lower = strings.ToLower(strings.TrimSpace(severity))
	for _, name := range LogSeverities {
		if strings.ToLower(name) == lower {
			return name, nil
		}
	}
	if name, found := logSeverityAliases[lower]; found {
		return name, nil
	}
	return "", fmt.Errorf("unknown severity %q, valid are: %s", severity, strings.Join(LogSeverities, ", "))
}

var logMenuUrlPattern = regexp.MustCompile(`^/ui/diagnostics/log/([^/?#]+)/([^/?#]+)`)

// LogList returns the logs linked in the GUI menu (core logs and the ones of installed plugins), in menu order
func (opn *DiagnosticsApi) LogList() ([]LogFile, error) {
	type menuItem struct {
		VisibleName string            `json:"VisibleName"`
		Url         string            `json:"Url"`
		Children    []json.RawMessage `json:"Children"`
	}
	var roots []json.RawMessage
	if err := opn.DoJSON("GET", opn.EndpointForPluginControllerMethod("core", "menu", "tree"), nil, &roots); err != nil {
		return nil, err
	}

	var logFiles = make([]LogFile, 0)
	var seen = map[string]bool{}
	var walk func(items []json.RawMessage, path []string) error
	walk = func(items []json.RawMessage, path []string) error {
		for _, raw := range items {
			var item menuItem
			if err := json.Unmarshal(raw, &item); err != nil {
				return fmt.Errorf("could not decode menu: %w", err)
			}
			var itemPath = append(append([]string{}, path...), item.VisibleName)
			if match := logMenuUrlPattern.FindStringSubmatch(item.Url); match != nil && !seen[match[1]+"/"+match[2]] {
				seen[match[1]+"/"+match[2]] = true
				logFiles = append(logFiles, LogFile{Module: match[1], Scope: match[2], MenuPath: strings.Join(itemPath, " > ")})
			}
			if err := walk(item.Children, itemPath); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(roots, nil); err != nil {
		return nil, err
	}

	// short names: the scope when it is unique, module/scope otherwise
	var scopeCount = map[string]int{}
	for _, logFile := range logFiles {
		scopeCount[logFile.Scope]++
	}
	for i := range logFiles {
		logFiles[i].Name = logFiles[i].Scope
		if scopeCount[logFiles[i].Scope] > 1 {
			logFiles[i].Name = logFiles[i].Module + "/" + logFiles[i].Scope
		}
	}
	return logFiles, nil
}

// LogResolve turns a log name into module and scope: "module/scope" is used as is, a plain name is looked up
// as scope in the menu (LogList), preferring the core log when several modules have it, and falls back to core/<name>
func (opn *DiagnosticsApi) LogResolve(name string) (string, string, error) {
	if module, scope, hasModule := strings.Cut(name, "/"); hasModule {
		if module == "" || scope == "" || strings.Contains(scope, "/") {
			return "", "", fmt.Errorf("invalid log name %q, use <scope> or <module>/<scope> like system or core/system", name)
		}
		return module, scope, nil
	}
	if name == "" {
		return "", "", fmt.Errorf("log name must not be empty")
	}

	var logFiles, err = opn.LogList()
	if err != nil {
		return "", "", err
	}
	var candidates = coreapi.Filter(logFiles, func(l LogFile) bool { return l.Scope == name })
	switch {
	case len(candidates) == 1:
		return candidates[0].Module, candidates[0].Scope, nil
	case len(candidates) > 1:
		for _, candidate := range candidates {
			if candidate.Module == "core" {
				return candidate.Module, candidate.Scope, nil
			}
		}
		var names = make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			names = append(names, candidate.Module+"/"+candidate.Scope)
		}
		return "", "", &coreapi.TooManyFoundError{Name: fmt.Sprintf("log %q, use one of: %s", name, strings.Join(names, ", "))}
	default:
		return "", "", &coreapi.NotFoundError{Name: fmt.Sprintf(
			"log %q, see \"opn diag log list\", logs without a menu entry can be given as <module>/<scope>", name)}
	}
}

func (opn *DiagnosticsApi) logEndpoint(module string, scope string) string {
	return opn.endpoint("log", url.PathEscape(module)+"/"+url.PathEscape(scope))
}

// LogTail returns the newest lines (at most 9999) of the log module/scope matching filter, oldest first.
// Unknown logs return no lines (OPNsense does not distinguish them from empty logs)
func (opn *DiagnosticsApi) LogTail(module string, scope string, lines int, filter LogFilter) ([]LogRecord, error) {
	if lines <= 0 {
		return []LogRecord{}, nil
	}
	var body = map[string]any{
		"current":      1,
		"rowCount":     lines,
		"searchPhrase": filter.SearchPhrase,
		"severity":     strings.Join(filter.Severities, ","),
	}
	var container struct {
		Rows []LogRecord `json:"rows"`
	}
	if err := opn.DoJSON("POST", opn.logEndpoint(module, scope), body, &container); err != nil {
		return nil, err
	}

	// OPNsense returns the newest line first
	var records = make([]LogRecord, 0, len(container.Rows))
	for i := len(container.Rows) - 1; i >= 0; i-- {
		records = append(records, logCleanRecord(container.Rows[i]))
	}
	return records, nil
}

// LogClear empties the log module/scope on the firewall (for all users!)
func (opn *DiagnosticsApi) LogClear(module string, scope string) error {
	var container struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.logEndpoint(module, scope)+"/clear", map[string]any{}, &container); err != nil {
		return err
	}
	if container.Status != "ok" {
		return fmt.Errorf("clearing log %s/%s failed: status %q", module, scope, container.Status)
	}
	return nil
}

// LogLive streams the log module/scope (GET .../live) until ctx is cancelled (nil) or the stream ends (io.EOF).
// OPNsense first sends the newest backlog lines matching filter (oldest first, SSE event "message", backlog=true),
// then every new matching line (SSE event "log", backlog=false)
func (opn *DiagnosticsApi) LogLive(ctx context.Context, module string, scope string, backlog int, filter LogFilter, handle func(record LogRecord, backlog bool) error) error {
	var query = url.Values{}
	query.Set("offset", strconv.Itoa(max(backlog, 0)))
	if filter.SearchPhrase != "" {
		query.Set("searchPhrase", filter.SearchPhrase)
	}
	if len(filter.Severities) > 0 {
		query.Set("severity", strings.Join(filter.Severities, ","))
	}

	var endpoint = fmt.Sprintf("%s/live?%s", opn.logEndpoint(module, scope), query.Encode())
	return opn.Stream(ctx, endpoint, func(event coreapi.StreamEvent) error {
		if event.Event != "message" && event.Event != "log" {
			return nil
		}
		var record LogRecord
		if err := json.Unmarshal([]byte(event.Data), &record); err != nil {
			return fmt.Errorf("could not decode live log event %q: %w", event.Data, err)
		}
		return handle(logCleanRecord(record), event.Event == "message")
	})
}

// LogFollowOptions configures LogFollow
type LogFollowOptions struct {
	// Lines is the number of existing lines to pass on first (the tail), 0 for only new lines
	Lines  int
	Filter LogFilter
	// OnReconnect is called (when not nil) before waiting delay to reconnect after the stream failed or ended
	OnReconnect func(err error, delay time.Duration)
	// MinDelay / MaxDelay bound the exponential reconnect backoff (defaults 1s / 30s)
	MinDelay time.Duration
	MaxDelay time.Duration
}

// logFollowMemory is the number of recently passed on lines LogFollow remembers to skip duplicates after a reconnect
const logFollowMemory = 1000

// LogFollow passes the newest opts.Lines lines and then every new line of the log module/scope to handle, oldest first,
// until ctx is cancelled (returns nil) or handle returns an error. Dropped streams are reconnected with backoff,
// lines logged meanwhile are recovered from the backlog of the new stream without passing on lines twice
// (up to logFollowMemory lines; if more were logged during the outage some may be missed)
func (opn *DiagnosticsApi) LogFollow(ctx context.Context, module string, scope string, opts LogFollowOptions, handle func(LogRecord) error) error {
	var minDelay, maxDelay = opts.MinDelay, opts.MaxDelay
	if minDelay <= 0 {
		minDelay = time.Second
	}
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second
	}

	var follower = &logFollower{handle: handle}
	var delay = minDelay
	var backlog = opts.Lines
	var first = true
	for {
		follower.startConnection(backlog)
		var started = time.Now()
		var err = opn.LogLive(ctx, module, scope, backlog, opts.Filter, follower.receive)
		if ctx.Err() != nil {
			return nil
		}
		var handleErr *logHandleError
		if errors.As(err, &handleErr) {
			return handleErr.err
		}
		// errors that a reconnect will not fix: client errors like 401 / 403 / 404, or a first connection that
		// fails right away (e.g. no event stream because the endpoint is not supported)
		var httpErr *coreapi.HttpError
		if errors.As(err, &httpErr) && httpErr.StatusCode < 500 {
			return err
		}
		if err != nil && !errors.Is(err, io.EOF) && first && !follower.receivedOnConnection && time.Since(started) < 5*time.Second {
			return err
		}
		first = false
		// a stream that ran for a while (or delivered lines) was healthy, reconnect quickly
		if follower.receivedOnConnection || time.Since(started) > maxDelay {
			delay = minDelay
		}
		if err == nil {
			err = io.EOF
		}
		if opts.OnReconnect != nil {
			opts.OnReconnect(err, delay)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		delay = min(delay*2, maxDelay)

		// ask for as many backlog lines as remembered, to find where the previous stream stopped
		backlog = len(follower.recent)
	}
}

// logHandleError marks errors of the caller's handle function, these end LogFollow instead of reconnecting
type logHandleError struct {
	err error
}

func (e *logHandleError) Error() string {
	return e.err.Error()
}

// logFollower de-duplicates the backlog of a reconnected stream against the lines already passed on
type logFollower struct {
	handle func(LogRecord) error
	// recent are the last passed on lines (at most logFollowMemory), oldest first
	recent []LogRecord
	// expected is the number of backlog lines requested from the current connection, 0 on the first connection
	expected  int
	buffer    []LogRecord
	reconnect bool
	// receivedOnConnection is set when the current connection delivered any line
	receivedOnConnection bool
}

func (f *logFollower) startConnection(backlog int) {
	f.reconnect = f.reconnect || f.expected > 0 || len(f.recent) > 0
	f.expected = backlog
	f.buffer = nil
	f.receivedOnConnection = false
}

func (f *logFollower) receive(record LogRecord, backlog bool) error {
	f.receivedOnConnection = true
	if !f.reconnect {
		// first connection: the backlog is the requested tail
		return f.pass(record)
	}

	if backlog {
		f.buffer = append(f.buffer, record)
		if len(f.buffer) < f.expected {
			return nil
		}
	}
	// the backlog is complete (or a live line proves it ended early, e.g. the log was cleared)
	if err := f.flush(); err != nil {
		return err
	}
	if !backlog {
		return f.pass(record)
	}
	return nil
}

// flush passes on the buffered backlog lines that come after the last line passed on before the reconnect
func (f *logFollower) flush() error {
	if f.buffer == nil {
		return nil
	}
	var buffer = f.buffer
	f.buffer = nil
	f.expected = 0

	// the backlog starts with the newest k remembered lines followed by new lines: find the largest such overlap
	var overlap = 0
	for k := min(len(buffer), len(f.recent)); k > 0; k-- {
		if logRecordsEqual(buffer[:k], f.recent[len(f.recent)-k:]) {
			overlap = k
			break
		}
	}
	for _, record := range buffer[overlap:] {
		if err := f.pass(record); err != nil {
			return err
		}
	}
	return nil
}

func (f *logFollower) pass(record LogRecord) error {
	f.recent = append(f.recent, record)
	if len(f.recent) > logFollowMemory {
		f.recent = f.recent[len(f.recent)-logFollowMemory:]
	}
	if err := f.handle(record); err != nil {
		return &logHandleError{err: err}
	}
	return nil
}

// logRecordsEqual compares lines ignoring Rnum, which differs between backlog and live lines
func logRecordsEqual(a []LogRecord, b []LogRecord) bool {
	for i := range a {
		var x, y = a[i], b[i]
		if x.Timestamp != y.Timestamp || x.Severity != y.Severity || x.ProcessName != y.ProcessName || x.Pid != y.Pid || x.Line != y.Line {
			return false
		}
	}
	return true
}

// logCleanRecord trims the line, OPNsense keeps the leading space of the syslog message and live lines end with "\n"
func logCleanRecord(record LogRecord) LogRecord {
	record.Line = strings.TrimSpace(record.Line)
	return record
}
