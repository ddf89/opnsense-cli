//go:build integration

package integrationmonitoring

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type opnResult struct {
	args     []string
	stdout   string
	stderr   string
	exitCode int
}

func (r opnResult) String() string {
	return fmt.Sprintf("opn %s\nexit code %d\nstdout:\n%s\nstderr:\n%s", strings.Join(r.args, " "), r.exitCode, r.stdout, r.stderr)
}

// runOpnIn runs the CLI in dir (an empty temp dir when "") with the current environment
func runOpnIn(t *testing.T, dir string, args ...string) opnResult {
	t.Helper()
	requireLive(t)
	if opnBuildErr != nil {
		t.Fatalf("the opn binary could not be built: %v", opnBuildErr)
	}
	if dir == "" {
		dir = t.TempDir() // so a .env file in the checkout can not interfere
	}
	var ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var command = exec.CommandContext(ctx, opnBinary, args...)
	command.Dir = dir
	command.Env = os.Environ()
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	var err = command.Run()
	var result = opnResult{args: args, stdout: stdout.String(), stderr: stderr.String()}
	if exitErr, ok := err.(*exec.ExitError); ok {
		result.exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running opn %v: %v", args, err)
	}
	return result
}

func mustOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	var result = runOpnIn(t, "", args...)
	if result.exitCode != 0 {
		t.Fatalf("want exit code 0, got:\n%s", result)
	}
	return result
}

func mustFailOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	var result = runOpnIn(t, "", args...)
	if result.exitCode != 1 || !strings.HasPrefix(result.stderr, "error: ") {
		t.Errorf("want exit code 1 and an \"error: \" message, got:\n%s", result)
	}
	return result
}

func requireContains(t *testing.T, result opnResult, output string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(output, w) {
			t.Errorf("output lacks %q:\n%s", w, result)
		}
	}
}

func TestCliSystemHealthLive(t *testing.T) {
	var before = restoreAfter(t)
	var r = mustOpn(t, "/system/health", "print")
	requireContains(t, r, r.stdout, "METRIC", "TOPIC")
	mustOpn(t, "/system/health", "print", "json")
	mustFailOpn(t, "/system/health", "print", "metric="+runPrefix)
	mustFailOpn(t, "/system/health", "export", "metric="+runPrefix, "-")
	// reset-data needs a confirmation, it is never run live
	r = mustFailOpn(t, "/system/health", "reset-data")
	requireContains(t, r, r.stderr, "confirm=yes")

	r = mustOpn(t, "/system/health/settings", "print")
	requireContains(t, r, r.stdout, "enabled:")
	// toggle and restore without applying
	var enabled = before.HealthEnabled == "1"
	mustOpn(t, "/system/health/settings", "set", fmt.Sprintf("enabled=%v", !enabled))
	if now := snapshot(t); now.HealthEnabled == before.HealthEnabled {
		t.Errorf("set did not change the setting: %+v", now)
	}
	mustOpn(t, "/system/health/settings", "set", fmt.Sprintf("enabled=%v", enabled))
	if now := snapshot(t); now.HealthEnabled != before.HealthEnabled {
		t.Errorf("set did not restore the setting: %+v", now)
	}

	// with data: print and export the first report
	r = mustOpn(t, "/system/health", "print", "json")
	if strings.TrimSpace(r.stdout) == "" {
		t.Log("no RRD data on this box, the data checks are skipped")
		return
	}
	r = mustOpn(t, "/system/health", "print", "metric=0", "from=1d")
	requireContains(t, r, r.stdout, "TIME")
	var dir = t.TempDir()
	runOpnIn(t, dir, "/system/health", "export", "metric=0", "health.csv")
	if content, err := os.ReadFile(filepath.Join(dir, "health.csv")); err == nil && !strings.HasPrefix(string(content), "iso_time;") {
		t.Errorf("export: %q", content)
	}
}

func TestCliSystemMemoryLive(t *testing.T) {
	var r = mustOpn(t, "/system/memory", "print", "limit=5")
	requireContains(t, r, r.stdout, "TYPE", "IN-USE", "MEMORY")
	requireContains(t, r, r.stderr, "malloc types")
	if lines := strings.Split(strings.TrimSpace(r.stdout), "\n"); len(lines) != 6 {
		t.Errorf("want 5 rows:\n%s", r)
	}
	r = mustOpn(t, "/system/memory", "print", "zone", "search=mbuf")
	requireContains(t, r, r.stdout, "ZONE", "mbuf")
	r = mustOpn(t, "/system/memory", "print", "zone", "limit=1", "json")
	requireContains(t, r, r.stdout, `"name":`)
}

func TestCliNetflowLive(t *testing.T) {
	var before = restoreAfter(t)
	var r = mustOpn(t, "/tool/netflow", "print")
	requireContains(t, r, r.stdout, "interfaces:", "version:", "targets:", "collect:", "active-timeout:  ")
	r = mustOpn(t, "/tool/netflow", "status")
	requireContains(t, r, r.stdout, "status:", "capture-configured:", "last-aggregation:")
	mustOpn(t, "/tool/netflow", "status", "json")
	r = mustOpn(t, "/tool/netflow/cache", "print")
	requireContains(t, r, r.stdout, "DEVICE")

	// harmless changes (never applied), then restore
	r = mustOpn(t, "/tool/netflow", "set", "active-timeout=4321", "inactive-timeout=21", "interfaces=lan")
	if r.stdout != "" {
		t.Errorf("set must be silent:\n%s", r)
	}
	if now := snapshot(t); now.ActiveTimeout != "4321" || now.InactiveTimeout != "21" || now.Interfaces != "lan" || now.Targets != before.Targets {
		t.Errorf("after set: %+v", now)
	}
	mustOpn(t, "/tool/netflow", "set", "active-timeout="+before.ActiveTimeout, "inactive-timeout="+before.InactiveTimeout,
		"interfaces="+before.Interfaces)
	if now := snapshot(t); now != before {
		t.Errorf("not restored: %+v, want %+v", now, before)
	}

	// refused before anything is sent
	mustFailOpn(t, "/tool/netflow", "set", "interfaces="+runPrefix)
	mustFailOpn(t, "/tool/netflow", "set", "targets=192.0.2.1")
	r = mustFailOpn(t, "/tool/netflow", "reset-data")
	requireContains(t, r, r.stderr, "confirm=yes")
	if now := snapshot(t); now != before {
		t.Errorf("a refused command changed the settings: %+v", now)
	}

	if netflowIdle(t, before) {
		mustOpn(t, "/tool/netflow", "reconfigure")
		r = mustOpn(t, "/tool/netflow", "status")
		requireContains(t, r, r.stdout, "inactive")
	}
}

func TestCliInsightLive(t *testing.T) {
	for _, by := range []string{"interface", "protocol", "service", "talker", "flow"} {
		var r = mustOpn(t, "/tool/insight", "print", "by="+by, "from=7d", "limit=5")
		if !strings.Contains(r.stdout, "BYTES") {
			t.Errorf("no table for by=%s:\n%s", by, r)
		}
	}
	mustOpn(t, "/tool/insight", "print", "by=service", "interface=lan", "protocol=tcp", "port=443")
	mustOpn(t, "/tool/insight", "print", "by=talker", "json")
	mustOpn(t, "/tool/insight", "history", "from=2h")
	mustOpn(t, "/tool/insight", "history", "resolution=1h", "from=2d", "interface=lan", "json")
	mustFailOpn(t, "/tool/insight", "print", "interface="+runPrefix)
	mustFailOpn(t, "/tool/insight", "history", "resolution=7m")
	mustFailOpn(t, "/tool/insight", "export", "-", "by=flow", "resolution=5m")

	var dir = t.TempDir()
	var r = runOpnIn(t, dir, "/tool/insight", "export", "by=interface", "insight.csv", "from=1d")
	if r.exitCode != 0 {
		t.Fatalf("export failed:\n%s", r)
	}
	if _, err := os.Stat(filepath.Join(dir, "insight.csv")); err != nil && !strings.Contains(r.stderr, "nothing exported") {
		t.Errorf("neither a file nor 'nothing exported':\n%s", r)
	}
}
