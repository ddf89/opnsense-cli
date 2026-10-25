//go:build integration

package integration

// Read-only tests of the diagnostics streams (log files, firewall live log, traffic). Every follow is bounded by a
// context timeout, so the suite can not hang. Nothing destructive (e.g. log clear) is ever called.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/diagnostics"
	"opnsense-cli/opnsense/api/dnsmasq"
)

// generateActivity calls the dnsmasq status endpoint every 300ms until ctx is done. Every call writes
// "Request Dnsmasq status" to the configd log and an audit line. Each call uses a new client and so a new TCP
// connection, which pf logs as a pass entry (a kept-alive connection would only be logged once)
func generateActivity(ctx context.Context, t *testing.T) *sync.WaitGroup {
	t.Helper()
	requireLive(t)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var ticker = time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if core, err := api.ConfigureFromEnv(); err == nil {
					_, _ = (&dnsmasq.DnsmasqApi{OPNsense: core}).ServiceStatus()
				}
			}
		}
	}()
	return &wg
}

type streamResult struct {
	events  []api.StreamEvent
	err     error
	elapsed time.Duration // from the cancel (or the stop condition) to Stream returning
}

// collectStream streams endpoint until stop returns true for the collected events or timeout passes,
// then cancels and measures how fast Stream returns
func collectStream(t *testing.T, core *api.OPNsense, endpoint string, timeout time.Duration, stop func([]api.StreamEvent) bool) streamResult {
	t.Helper()
	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	var mutex sync.Mutex
	var result streamResult
	var stopped = make(chan struct{})
	var stopOnce sync.Once
	var done = make(chan error, 1)
	go func() {
		done <- core.Stream(ctx, endpoint, func(event api.StreamEvent) error {
			mutex.Lock()
			defer mutex.Unlock()
			result.events = append(result.events, event)
			if stop != nil && stop(result.events) {
				stopOnce.Do(func() { close(stopped) })
			}
			return nil
		})
	}()

	select {
	case <-stopped:
	case <-time.After(timeout):
	case err := <-done: // the stream ended on its own
		mutex.Lock()
		defer mutex.Unlock()
		result.err = err
		return result
	}

	var cancelledAt = time.Now()
	cancel()
	select {
	case result.err = <-done:
		result.elapsed = time.Since(cancelledAt)
	case <-time.After(10 * time.Second):
		t.Fatalf("Stream %s did not return within 10s after the context was cancelled", endpoint)
	}
	mutex.Lock()
	defer mutex.Unlock()
	return result
}

func requireCancelledCleanly(t *testing.T, result streamResult) {
	t.Helper()
	if result.err != nil {
		t.Errorf("Stream after cancel: want nil, got %T: %v", result.err, result.err)
	}
	if result.elapsed > 3*time.Second {
		t.Errorf("Stream took %s to return after cancel", result.elapsed)
	}
}

// --- core: (*OPNsense).Stream against the raw endpoints ---

func TestStreamTraffic(t *testing.T) {
	var core = coreApi(t)
	var result = collectStream(t, core, core.EndpointForPluginControllerMethod("diagnostics", "traffic", "stream/1"), 3500*time.Millisecond, nil)
	requireCancelledCleanly(t, result)

	if len(result.events) < 2 {
		t.Fatalf("want at least 2 traffic events in 3.5s, got %d: %+v", len(result.events), result.events)
	}
	for _, event := range result.events {
		if event.Event == api.StreamKeepalive {
			t.Errorf("keepalive was passed on: %+v", event)
		}
		var sample struct {
			Interfaces map[string]struct {
				Name     string `json:"name"`
				Inbytes  int64  `json:"inbytes"`
				Outbytes int64  `json:"outbytes"`
			} `json:"interfaces"`
			Time float64 `json:"time"`
		}
		if err := json.Unmarshal([]byte(event.Data), &sample); err != nil {
			t.Errorf("traffic event is no JSON: %v: %q", err, event.Data)
			continue
		}
		if _, ok := sample.Interfaces["lan"]; !ok {
			t.Errorf("traffic event lacks the lan interface: %q", event.Data)
		}
		if sample.Time <= 0 {
			t.Errorf("traffic event without time: %q", event.Data)
		}
	}
}

func TestStreamLogFollow(t *testing.T) {
	var core = coreApi(t)
	var ctx, stopActivity = context.WithCancel(context.Background())
	var activity = generateActivity(ctx, t)
	defer func() { stopActivity(); activity.Wait() }()

	var result = collectStream(t, core, core.EndpointForPluginControllerMethod("diagnostics", "log", "core/configd/live"), 10*time.Second,
		func(events []api.StreamEvent) bool {
			return strings.Contains(events[len(events)-1].Data, "Request Dnsmasq status")
		})
	requireCancelledCleanly(t, result)

	var found bool
	for _, event := range result.events {
		var line struct {
			Timestamp   string `json:"timestamp"`
			Severity    string `json:"severity"`
			ProcessName string `json:"process_name"`
			Line        string `json:"line"`
		}
		if err := json.Unmarshal([]byte(event.Data), &line); err != nil {
			t.Errorf("log event is no JSON: %v: %q", err, event.Data)
			continue
		}
		if event.Event != "log" || line.Timestamp == "" || line.ProcessName == "" {
			t.Errorf("unexpected log event: %+v", event)
		}
		found = found || strings.Contains(line.Line, "Request Dnsmasq status")
	}
	if !found {
		t.Errorf("no \"Request Dnsmasq status\" line within 10s while calling the status endpoint, got %d events", len(result.events))
	}
}

func TestStreamFirewallLog(t *testing.T) {
	var core = coreApi(t)
	var ctx, stopActivity = context.WithCancel(context.Background())
	var activity = generateActivity(ctx, t)
	defer func() { stopActivity(); activity.Wait() }()

	var result = collectStream(t, core, core.EndpointForPluginControllerMethod("diagnostics", "firewall", "stream_log"), 10*time.Second,
		func(events []api.StreamEvent) bool { return len(events) >= 3 })
	requireCancelledCleanly(t, result)
	if len(result.events) == 0 {
		t.Fatalf("no firewall log entry within 10s while calling the API")
	}
	for _, event := range result.events {
		var entry map[string]any
		if err := json.Unmarshal([]byte(event.Data), &entry); err != nil {
			t.Errorf("firewall event is no JSON: %v: %q", err, event.Data)
			continue
		}
		for _, field := range []string{"action", "interface", "src", "dst", "__timestamp__"} {
			if _, ok := entry[field]; !ok {
				t.Errorf("firewall event lacks %q: %q", field, event.Data)
			}
		}
	}
}

func TestStreamHandlerErrorStops(t *testing.T) {
	var core = coreApi(t)
	var stopErr = errors.New("enough")
	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var calls int
	var err = core.Stream(ctx, core.EndpointForPluginControllerMethod("diagnostics", "traffic", "stream/1"), func(api.StreamEvent) error {
		calls++
		return stopErr
	})
	if !errors.Is(err, stopErr) {
		t.Errorf("want the handler error, got %T: %v", err, err)
	}
	if calls != 1 {
		t.Errorf("want exactly one handler call, got %d", calls)
	}
	if ctx.Err() != nil {
		t.Errorf("Stream only returned at the timeout")
	}
}

func TestStreamErrors(t *testing.T) {
	var core = coreApi(t)
	var ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	t.Run("unknown endpoint", func(t *testing.T) {
		var err = core.Stream(ctx, core.EndpointForPluginControllerMethod("diagnostics", "traffic", "does_not_exist"), func(api.StreamEvent) error { return nil })
		var httpErr *api.HttpError
		if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusNotFound {
			t.Errorf("want *api.HttpError 404, got %T: %v", err, err)
		}
	})

	t.Run("no event stream", func(t *testing.T) {
		// a normal JSON endpoint must not be read as an (empty) stream
		var err = core.Stream(ctx, core.EndpointForPluginControllerMethod("dnsmasq", "service", "status"), func(api.StreamEvent) error { return nil })
		if err == nil || errors.Is(err, io.EOF) {
			t.Errorf("want a content type error, got %v", err)
		}
	})

	t.Run("bad credentials", func(t *testing.T) {
		var bad = &api.OPNsense{BaseUrl: core.BaseUrl, ApiKey: "invalid-key", ApiSecret: "invalid-secret", NoSslVerify: core.NoSslVerify}
		var err = bad.Stream(ctx, bad.EndpointForPluginControllerMethod("diagnostics", "traffic", "stream/1"), func(api.StreamEvent) error { return nil })
		var httpErr *api.HttpError
		if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusUnauthorized {
			t.Errorf("want *api.HttpError 401, got %T: %v", err, err)
		}
	})
	if ctx.Err() != nil {
		t.Errorf("the error cases took until the timeout")
	}
}

// --- library: opnsense/api/diagnostics ---

func diagApi(t *testing.T) *diagnostics.DiagnosticsApi {
	t.Helper()
	return &diagnostics.DiagnosticsApi{OPNsense: coreApi(t)}
}

// startActivity generates activity (see generateActivity) until the test ends
func startActivity(t *testing.T) {
	t.Helper()
	var ctx, stop = context.WithCancel(context.Background())
	var activity = generateActivity(ctx, t)
	t.Cleanup(func() { stop(); activity.Wait() })
}

// boundedFollow runs follow with a context that is cancelled when stop() is called or after timeout and returns
// how long follow took to return after the cancel and its error
func boundedFollow(t *testing.T, timeout time.Duration, follow func(ctx context.Context, stop func()) error) (time.Duration, error) {
	t.Helper()
	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	var stopped = make(chan struct{})
	var stopOnce sync.Once
	var stop = func() { stopOnce.Do(func() { close(stopped) }) }

	var done = make(chan error, 1)
	go func() { done <- follow(ctx, stop) }()
	select {
	case <-stopped:
	case <-time.After(timeout):
	case err := <-done:
		return 0, err
	}
	var cancelledAt = time.Now()
	cancel()
	select {
	case err := <-done:
		return time.Since(cancelledAt), err
	case <-time.After(10 * time.Second):
		t.Fatalf("follow did not return within 10s after the context was cancelled")
		return 0, nil
	}
}

func TestDiagLogList(t *testing.T) {
	var diagApi = diagApi(t)
	var logFiles, err = diagApi.LogList()
	if err != nil {
		t.Fatalf("LogList: %v", err)
	}
	var byName = map[string]diagnostics.LogFile{}
	for _, logFile := range logFiles {
		if logFile.Name == "" || logFile.Module == "" || logFile.Scope == "" || logFile.MenuPath == "" {
			t.Errorf("incomplete log file: %+v", logFile)
		}
		byName[logFile.Name] = logFile
	}
	for _, name := range []string{"system", "configd", "audit", "dnsmasq"} {
		if _, found := byName[name]; !found {
			t.Errorf("log list lacks %s: %+v", name, logFiles)
		}
	}
	if configd := byName["configd"]; configd.Module != "core" || configd.Scope != "configd" {
		t.Errorf("configd should be core/configd: %+v", configd)
	}

	for name, want := range map[string]string{"system": "core/system", "core/configd": "core/configd", "dnsmasq": byName["dnsmasq"].Module + "/dnsmasq"} {
		var module, scope, resolveErr = diagApi.LogResolve(name)
		if resolveErr != nil || module+"/"+scope != want {
			t.Errorf("LogResolve(%q): want %s, got %s/%s (%v)", name, want, module, scope, resolveErr)
		}
	}
	if _, _, err := diagApi.LogResolve("a/b/c"); err == nil {
		t.Errorf("LogResolve(a/b/c): want an error")
	}
}

func TestDiagLogTail(t *testing.T) {
	var diagApi = diagApi(t)
	// make sure there are a few matching lines
	var dnsmasqApi = dnsmasqApi(t)
	for i := 0; i < 3; i++ {
		_, _ = dnsmasqApi.ServiceStatus()
	}

	var records, err = diagApi.LogTail("core", "configd", 5, diagnostics.LogFilter{})
	if err != nil {
		t.Fatalf("LogTail: %v", err)
	}
	if len(records) == 0 || len(records) > 5 {
		t.Fatalf("want 1-5 records, got %d", len(records))
	}
	for i, record := range records {
		if record.Timestamp == "" || record.ProcessName == "" || record.Line == "" || record.Severity == "" {
			t.Errorf("incomplete record: %+v", record)
		}
		if record.Line != strings.TrimSpace(record.Line) {
			t.Errorf("line not trimmed: %q", record.Line)
		}
		if i > 0 && record.Timestamp < records[i-1].Timestamp {
			t.Errorf("not oldest first: %s after %s", record.Timestamp, records[i-1].Timestamp)
		}
	}

	t.Run("search phrase", func(t *testing.T) {
		var matching, err = diagApi.LogTail("core", "configd", 20, diagnostics.LogFilter{SearchPhrase: "dnsmasq REQUEST"})
		if err != nil {
			t.Fatalf("LogTail: %v", err)
		}
		if len(matching) == 0 {
			t.Fatalf("no line contains \"dnsmasq request\" after three status calls")
		}
		for _, record := range matching {
			if lower := strings.ToLower(record.Line); !strings.Contains(lower, "dnsmasq") || !strings.Contains(lower, "request") {
				t.Errorf("line does not match the search phrase: %q", record.Line)
			}
		}
	})

	t.Run("severity", func(t *testing.T) {
		var severity, err = diagnostics.LogNormalizeSeverity("info")
		if err != nil || severity != "Informational" {
			t.Fatalf("LogNormalizeSeverity(info): %q %v", severity, err)
		}
		// the audit log has Informational lines (action allowed ...) for every API call
		records, err := diagApi.LogTail("core", "audit", 10, diagnostics.LogFilter{Severities: []string{"Informational"}})
		if err != nil {
			t.Fatalf("LogTail: %v", err)
		}
		if len(records) == 0 {
			t.Fatalf("no Informational line in the audit log")
		}
		for _, record := range records {
			if record.Severity != "Informational" {
				t.Errorf("want only Informational, got %+v", record)
			}
		}
	})

	t.Run("zero lines and unknown log", func(t *testing.T) {
		if records, err := diagApi.LogTail("core", "configd", 0, diagnostics.LogFilter{}); err != nil || len(records) != 0 {
			t.Errorf("LogTail 0 lines: %d records, %v", len(records), err)
		}
		if records, err := diagApi.LogTail("core", "nosuchlog"+runDomain, 5, diagnostics.LogFilter{}); err != nil || len(records) != 0 {
			t.Errorf("LogTail of an unknown log: %d records, %v", len(records), err)
		}
	})
}

func TestDiagLogFollow(t *testing.T) {
	var diagApi = diagApi(t)
	startActivity(t)

	t.Run("new lines", func(t *testing.T) {
		var started = time.Now().Add(-2 * time.Second).Format("2006-01-02T15:04:05")
		var mutex sync.Mutex
		var records []diagnostics.LogRecord
		var elapsed, err = boundedFollow(t, 12*time.Second, func(ctx context.Context, stop func()) error {
			return diagApi.LogFollow(ctx, "core", "configd", diagnostics.LogFollowOptions{}, func(record diagnostics.LogRecord) error {
				mutex.Lock()
				defer mutex.Unlock()
				records = append(records, record)
				if strings.Contains(record.Line, "Request Dnsmasq status") {
					stop()
				}
				return nil
			})
		})
		if err != nil || elapsed > 3*time.Second {
			t.Errorf("LogFollow after cancel: want nil promptly, got %v after %s", err, elapsed)
		}
		mutex.Lock()
		defer mutex.Unlock()
		var found bool
		for _, record := range records {
			if record.Timestamp < started {
				t.Errorf("LogFollow without Lines passed an old line: %+v", record)
			}
			found = found || strings.Contains(record.Line, "Request Dnsmasq status")
		}
		if !found {
			t.Errorf("no new \"Request Dnsmasq status\" line within 12s, got %d records", len(records))
		}
	})

	t.Run("tail first", func(t *testing.T) {
		var count int
		var _, err = boundedFollow(t, 10*time.Second, func(ctx context.Context, stop func()) error {
			return diagApi.LogFollow(ctx, "core", "configd", diagnostics.LogFollowOptions{Lines: 3}, func(diagnostics.LogRecord) error {
				if count++; count >= 3 {
					stop()
				}
				return nil
			})
		})
		if err != nil || count < 3 {
			t.Errorf("want the 3 tail lines, got %d (%v)", count, err)
		}
	})

	t.Run("live with filter", func(t *testing.T) {
		var mismatches []string
		var count int
		var _, err = boundedFollow(t, 12*time.Second, func(ctx context.Context, stop func()) error {
			return diagApi.LogLive(ctx, "core", "configd", 2, diagnostics.LogFilter{SearchPhrase: "dnsmasq status"},
				func(record diagnostics.LogRecord, backlog bool) error {
					if !strings.Contains(strings.ToLower(record.Line), "dnsmasq status") {
						mismatches = append(mismatches, record.Line)
					}
					if count++; !backlog && count >= 3 {
						stop()
					}
					return nil
				})
		})
		if err != nil {
			t.Errorf("LogLive: %v", err)
		}
		if count < 3 || len(mismatches) > 0 {
			t.Errorf("want only matching lines (incl. a new one), got %d lines, mismatches %q", count, mismatches)
		}
	})

	t.Run("handler error is returned", func(t *testing.T) {
		var stopErr = errors.New("enough")
		var _, err = boundedFollow(t, 12*time.Second, func(ctx context.Context, _ func()) error {
			return diagApi.LogFollow(ctx, "core", "configd", diagnostics.LogFollowOptions{Lines: 1}, func(diagnostics.LogRecord) error { return stopErr })
		})
		if !errors.Is(err, stopErr) {
			t.Errorf("want the handler error, got %v", err)
		}
	})
}

func TestDiagFirewall(t *testing.T) {
	var diagApi = diagApi(t)
	startActivity(t)
	time.Sleep(time.Second)

	var entries, _, err = diagApi.FirewallLog(5, "")
	if err != nil {
		t.Fatalf("FirewallLog: %v", err)
	}
	if len(entries) == 0 || len(entries) > 5 {
		t.Fatalf("want 1-5 entries, got %d", len(entries))
	}
	for i, entry := range entries {
		if entry.Action == "" || entry.Interface == "" || entry.Timestamp == "" || entry.Digest == "" || entry.Src == "" || len(entry.Raw) == 0 {
			t.Errorf("incomplete entry: %+v", entry)
		}
		if i > 0 && entry.Timestamp > entries[i-1].Timestamp {
			t.Errorf("FirewallLog is not newest first: %s after %s", entry.Timestamp, entries[i-1].Timestamp)
		}
	}

	t.Run("since digest", func(t *testing.T) {
		var newer, found, err = diagApi.FirewallLog(100, entries[len(entries)-1].Digest)
		if err != nil || !found {
			t.Fatalf("FirewallLog since a recent digest: found=%v err=%v", found, err)
		}
		for _, entry := range newer {
			if entry.Digest == entries[len(entries)-1].Digest {
				t.Errorf("the since digest record itself was returned")
			}
		}
	})

	t.Run("filters", func(t *testing.T) {
		var filters, err = diagApi.FirewallLogFilters()
		if err != nil {
			t.Fatalf("FirewallLogFilters: %v", err)
		}
		if !slices.Contains(filters.Action, "pass") || !slices.Contains(filters.Dir, "in") || !slices.Contains(filters.InterfaceName, "lan") {
			t.Errorf("unexpected filters: %+v", filters)
		}
		var names, namesErr = diagApi.FirewallInterfaceNames()
		if namesErr != nil || len(names) == 0 {
			t.Errorf("FirewallInterfaceNames: %v (%v)", names, namesErr)
		}
	})

	t.Run("follow", func(t *testing.T) {
		for _, stream := range []bool{false, true} {
			var count int
			var elapsed, err = boundedFollow(t, 12*time.Second, func(ctx context.Context, stop func()) error {
				return diagApi.FirewallLogFollow(ctx, diagnostics.FirewallFollowOptions{SinceDigest: entries[0].Digest, Stream: stream},
					func(entry diagnostics.FirewallLogEntry) error {
						if entry.Action == "" || entry.Digest == "" {
							t.Errorf("incomplete entry: %+v", entry)
						}
						if count++; count >= 2 {
							stop()
						}
						return nil
					})
			})
			if err != nil || elapsed > 3*time.Second {
				t.Errorf("FirewallLogFollow (stream %v) after cancel: want nil promptly, got %v after %s", stream, err, elapsed)
			}
			if count < 2 {
				t.Errorf("FirewallLogFollow (stream %v): want at least 2 new entries within 12s while calling the API, got %d", stream, count)
			}
		}
	})

	t.Run("stats", func(t *testing.T) {
		var stats, err = diagApi.FirewallStats("interface", 200)
		if err != nil || len(stats) == 0 {
			t.Errorf("FirewallStats: %+v (%v)", stats, err)
		}
	})
}

func TestDiagTraffic(t *testing.T) {
	var diagApi = diagApi(t)

	var samples []diagnostics.TrafficSample
	var elapsed, err = boundedFollow(t, 3500*time.Millisecond, func(ctx context.Context, _ func()) error {
		return diagApi.TrafficStream(ctx, 1, func(sample diagnostics.TrafficSample) error {
			samples = append(samples, sample)
			return nil
		})
	})
	if err != nil || elapsed > 3*time.Second {
		t.Errorf("TrafficStream after cancel: want nil promptly, got %v after %s", err, elapsed)
	}
	if len(samples) < 2 {
		t.Fatalf("want at least 2 samples in 3.5s, got %d", len(samples))
	}
	for _, sample := range samples {
		if lan, ok := sample.Interfaces["lan"]; !ok || lan.Name == "" {
			t.Errorf("sample lacks lan: %s", sample.Raw)
		}
		if since := time.Since(sample.Timestamp()); since < -time.Hour || since > time.Hour {
			t.Errorf("sample time is off by %s", since)
		}
	}

	var rates [][]diagnostics.TrafficRate
	_, err = boundedFollow(t, 3500*time.Millisecond, func(ctx context.Context, stop func()) error {
		return diagApi.TrafficWatch(ctx, 1, diagnostics.TrafficFollowOptions{}, func(_ diagnostics.TrafficSample, rate []diagnostics.TrafficRate) error {
			if rates = append(rates, rate); len(rates) >= 2 {
				stop()
			}
			return nil
		})
	})
	if err != nil || len(rates) == 0 {
		t.Fatalf("TrafficWatch: %d rates, %v", len(rates), err)
	}
	for _, rate := range rates[0] {
		if rate.Seconds < 0.5 || rate.Seconds > 2 || rate.InBitsPerSecond < 0 || rate.OutBitsPerSecond < 0 {
			t.Errorf("implausible rate: %+v", rate)
		}
	}

	var interfaces, interfacesErr = diagApi.TrafficInterfaces()
	if _, ok := interfaces["lan"]; interfacesErr != nil || !ok {
		t.Errorf("TrafficInterfaces lacks lan: %v (%v)", interfaces, interfacesErr)
	}
}

func TestDiagCpuActivitySystem(t *testing.T) {
	var diagApi = diagApi(t)

	t.Run("cpu", func(t *testing.T) {
		var usages []diagnostics.CpuUsage
		var _, err = boundedFollow(t, 5*time.Second, func(ctx context.Context, stop func()) error {
			return diagApi.CpuStream(ctx, func(usage diagnostics.CpuUsage) error {
				if usages = append(usages, usage); len(usages) >= 2 {
					stop()
				}
				return nil
			})
		})
		if err != nil || len(usages) < 2 {
			t.Fatalf("CpuStream: %d events, %v", len(usages), err)
		}
		for _, usage := range usages {
			if usage.Total < 0 || usage.Total > 100 || usage.Idle < 0 || usage.Idle > 100 {
				t.Errorf("implausible cpu usage: %+v", usage)
			}
		}
		if cpuType, err := diagApi.CpuType(); err != nil || cpuType == "" {
			t.Errorf("CpuType: %q %v", cpuType, err)
		}
	})

	t.Run("activity", func(t *testing.T) {
		var activity, err = diagApi.ActivityGet()
		if err != nil {
			t.Fatalf("ActivityGet: %v", err)
		}
		if len(activity.Headers) == 0 || len(activity.Threads) == 0 || activity.Threads[0].Pid == "" || activity.Threads[0].Command == "" {
			t.Errorf("unexpected activity: headers %q, %d threads", activity.Headers, len(activity.Threads))
		}
	})

	t.Run("system", func(t *testing.T) {
		if information, _, err := diagApi.SystemResourceInformation(); err != nil || information.Name == "" || len(information.Versions) == 0 {
			t.Errorf("SystemResourceInformation: %+v %v", information, err)
		}
		if memory, _, err := diagApi.SystemResourceMemory(); err != nil || memory.Total.Value <= 0 || memory.Used.Value <= 0 {
			t.Errorf("SystemResourceMemory: %+v %v", memory, err)
		}
		if systemTime, _, err := diagApi.SystemResourceTime(); err != nil || systemTime.Uptime == "" {
			t.Errorf("SystemResourceTime: %+v %v", systemTime, err)
		}
		if disks, _, err := diagApi.SystemResourceDisks(); err != nil || len(disks) == 0 {
			t.Errorf("SystemResourceDisks: %+v %v", disks, err)
		}
	})
}

// --- CLI: opn diag ---

// runningOpn is a CLI process whose stdout lines are collected while it runs
type runningOpn struct {
	command *exec.Cmd
	mutex   sync.Mutex
	lines   []string
	stderr  strings.Builder
	exited  chan struct{}
}

func startOpn(t *testing.T, args ...string) *runningOpn {
	t.Helper()
	requireLive(t)
	if opnBuildErr != nil {
		t.Fatalf("the opn binary could not be built: %v", opnBuildErr)
	}
	var running = &runningOpn{command: exec.Command(opnBinary, args...), exited: make(chan struct{})}
	running.command.Dir = t.TempDir()
	running.command.Env = os.Environ()
	running.command.Stderr = &running.stderr
	var stdout, err = running.command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := running.command.Start(); err != nil {
		t.Fatalf("starting opn %v: %v", args, err)
	}
	go func() {
		var scanner = bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			running.mutex.Lock()
			running.lines = append(running.lines, scanner.Text())
			running.mutex.Unlock()
		}
		_ = running.command.Wait()
		close(running.exited)
	}()
	// never leave a process behind
	t.Cleanup(func() {
		select {
		case <-running.exited:
		default:
			_ = running.command.Process.Kill()
			<-running.exited
		}
	})
	return running
}

// waitFor polls until done returns true for the lines printed so far, the process exits or timeout passes
func (r *runningOpn) waitFor(timeout time.Duration, done func(lines []string) bool) bool {
	var deadline = time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r.mutex.Lock()
		var ok = done(r.lines)
		r.mutex.Unlock()
		if ok {
			return true
		}
		select {
		case <-r.exited:
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
	return false
}

// interrupt sends SIGINT (like Ctrl-C) and returns the exit code and all stdout lines
func (r *runningOpn) interrupt(t *testing.T) (int, []string) {
	t.Helper()
	_ = r.command.Process.Signal(os.Interrupt)
	select {
	case <-r.exited:
	case <-time.After(10 * time.Second):
		_ = r.command.Process.Kill()
		<-r.exited
		t.Errorf("opn %v did not exit within 10s after SIGINT", r.command.Args[1:])
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.command.ProcessState.ExitCode(), append([]string{}, r.lines...)
}

func (r *runningOpn) String() string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return fmt.Sprintf("opn %s\nstdout:\n%s\nstderr:\n%s", strings.Join(r.command.Args[1:], " "), strings.Join(r.lines, "\n"), r.stderr.String())
}

func nonEmptyLines(output string) []string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// requireJsonLines checks that every line is a JSON object and returns them
func requireJsonLines(t *testing.T, lines []string) []map[string]any {
	t.Helper()
	var objects []map[string]any
	for _, line := range lines {
		var object map[string]any
		if err := json.Unmarshal([]byte(line), &object); err != nil {
			t.Errorf("not a JSON object line: %v: %q", err, line)
			continue
		}
		objects = append(objects, object)
	}
	return objects
}

func TestCliDiagLog(t *testing.T) {
	var listed = mustOpn(t, "diag", "log", "list")
	requireContains(t, listed, listed.stdout, "NAME", "configd", "system", "audit", "dnsmasq")

	t.Run("show", func(t *testing.T) {
		var shown = mustOpn(t, "diag", "log", "show", "configd", "-n", "3")
		if lines := nonEmptyLines(shown.stdout); len(lines) == 0 || len(lines) > 3 {
			t.Errorf("want 1-3 lines:\n%s", shown)
		}
		shown = mustOpn(t, "diag", "log", "show", "core/configd", "-n", "5", "--json")
		var records = requireJsonLines(t, nonEmptyLines(shown.stdout))
		if len(records) == 0 || len(records) > 5 {
			t.Errorf("want 1-5 JSON lines:\n%s", shown)
		}
		for i, record := range records {
			if record["timestamp"] == nil || record["line"] == nil {
				t.Errorf("record lacks timestamp / line: %v", record)
			}
			if i > 0 && fmt.Sprint(record["timestamp"]) < fmt.Sprint(records[i-1]["timestamp"]) {
				t.Errorf("not oldest first:\n%s", shown)
			}
		}
	})

	t.Run("filters", func(t *testing.T) {
		var shown = mustOpn(t, "diag", "log", "show", "audit", "-n", "10", "--severity", "info", "--json")
		for _, record := range requireJsonLines(t, nonEmptyLines(shown.stdout)) {
			if record["severity"] != "Informational" {
				t.Errorf("--severity info returned %v", record)
			}
		}
		shown = mustOpn(t, "diag", "log", "show", "configd", "-n", "10", "--search", "dnsmasq status", "--json")
		for _, record := range requireJsonLines(t, nonEmptyLines(shown.stdout)) {
			if !strings.Contains(strings.ToLower(fmt.Sprint(record["line"])), "dnsmasq status") {
				t.Errorf("--search returned %v", record)
			}
		}
		mustFailOpn(t, "diag", "log", "show", "configd", "--severity", "bogus")
	})

	t.Run("follow until SIGINT", func(t *testing.T) {
		startActivity(t)
		var running = startOpn(t, "diag", "log", "show", "configd", "-n", "0", "-f", "--json")
		var found = running.waitFor(15*time.Second, func(lines []string) bool {
			return slices.ContainsFunc(lines, func(line string) bool { return strings.Contains(line, "Request Dnsmasq status") })
		})
		var exitCode, lines = running.interrupt(t)
		if !found {
			t.Errorf("no new \"Request Dnsmasq status\" line within 15s:\n%s", running)
		}
		if exitCode != 0 {
			t.Errorf("want exit code 0 after SIGINT, got %d:\n%s", exitCode, running)
		}
		requireJsonLines(t, lines)
	})
}

func TestCliDiagFirewall(t *testing.T) {
	startActivity(t)
	time.Sleep(time.Second)

	var filters = mustOpn(t, "diag", "firewall", "filters")
	requireContains(t, filters, filters.stdout, "pass", "lan")

	var shown = mustOpn(t, "diag", "firewall", "log", "-n", "3", "--json")
	var entries = requireJsonLines(t, nonEmptyLines(shown.stdout))
	if len(entries) == 0 || len(entries) > 3 {
		t.Errorf("want 1-3 JSON lines:\n%s", shown)
	}

	shown = mustOpn(t, "diag", "firewall", "log", "-n", "5", "--action", "pass", "--interface", "lan", "--dir", "in", "--json")
	var filtered = requireJsonLines(t, nonEmptyLines(shown.stdout))
	if len(filtered) == 0 {
		t.Errorf("no pass/in record on lan although the API calls create them:\n%s", shown)
	}
	for _, entry := range filtered {
		if entry["action"] != "pass" || entry["dir"] != "in" || entry["interface"] != "vtnet0" {
			t.Errorf("filter not applied: %v", entry)
		}
	}
	shown = mustOpn(t, "diag", "firewall", "log", "-n", "3")
	if lines := nonEmptyLines(shown.stdout); len(lines) == 0 || len(lines) > 3 {
		t.Errorf("want 1-3 lines:\n%s", shown)
	}

	for _, mode := range [][]string{{"-f"}, {"--stream"}} {
		t.Run("follow "+mode[0], func(t *testing.T) {
			var running = startOpn(t, append([]string{"diag", "firewall", "log", "-n", "0", "--json"}, mode...)...)
			var printed = running.waitFor(15*time.Second, func(lines []string) bool { return len(lines) >= 2 })
			var exitCode, lines = running.interrupt(t)
			if !printed {
				t.Errorf("want at least 2 new records within 15s while calling the API:\n%s", running)
			}
			if exitCode != 0 {
				t.Errorf("want exit code 0 after SIGINT, got %d:\n%s", exitCode, running)
			}
			requireJsonLines(t, lines)
		})
	}
}

func TestCliDiagTraffic(t *testing.T) {
	var once = mustOpn(t, "diag", "traffic")
	requireContains(t, once, once.stdout, "INTERFACE", "lan")

	var running = startOpn(t, "diag", "traffic", "-f", "--json")
	var printed = running.waitFor(6*time.Second, func(lines []string) bool { return len(lines) >= 2 })
	var exitCode, lines = running.interrupt(t)
	if !printed {
		t.Errorf("want at least 2 samples within 6s:\n%s", running)
	}
	if exitCode != 0 {
		t.Errorf("want exit code 0 after SIGINT, got %d:\n%s", exitCode, running)
	}
	for _, sample := range requireJsonLines(t, lines) {
		if interfaces, ok := sample["interfaces"].(map[string]any); !ok || interfaces["lan"] == nil {
			t.Errorf("sample lacks interfaces.lan: %v", sample)
		}
	}

	var filtered = mustOpn(t, "diag", "traffic", "--interface", "lan")
	if strings.Contains(filtered.stdout, "wan") {
		t.Errorf("--interface lan also shows wan:\n%s", filtered)
	}
	var interfaces = mustOpn(t, "diag", "traffic", "interfaces")
	requireContains(t, interfaces, interfaces.stdout, "lan")
}

func TestCliDiagCpuActivitySystem(t *testing.T) {
	var cpu = mustOpn(t, "diag", "cpu")
	requireContains(t, cpu, cpu.stdout, "total")

	var running = startOpn(t, "diag", "cpu", "-f", "--json")
	var printed = running.waitFor(6*time.Second, func(lines []string) bool { return len(lines) >= 2 })
	var exitCode, lines = running.interrupt(t)
	if !printed || exitCode != 0 {
		t.Errorf("want at least 2 lines and exit code 0 after SIGINT, got %d lines, exit code %d:\n%s", len(lines), exitCode, running)
	}
	requireJsonLines(t, lines)

	var activity = mustOpn(t, "diag", "activity", "-n", "3")
	requireContains(t, activity, activity.stdout, "PID", "COMMAND")

	var system = mustOpn(t, "diag", "system", "--json")
	var object map[string]any
	if err := json.Unmarshal([]byte(system.stdout), &object); err != nil || object["information"] == nil || object["memory"] == nil {
		t.Errorf("want one JSON object with information and memory (%v):\n%s", err, system)
	}
	system = mustOpn(t, "diag", "system")
	requireContains(t, system, system.stdout, "OPNsense", "uptime", "memory")
}
