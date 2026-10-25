//go:build integration

// Package integrationmonitoring runs the monitoring parts of the diagnostics library (system health, memory,
// NetFlow, Insight in opnsense/api/diagnostics) and the opn /system/health, /system/memory, /tool/netflow and
// /tool/insight menus against a live OPNsense (26.7) instance.
//
//	go test -tags integration ./integration/monitoring/... -count=1 -v
//
// Configuration (first match wins):
//   - OPN_URL / OPN_APIKEY / OPN_APISECRET / OPN_NOSSLVERIFY, like the CLI
//   - OPNSENSE_API_KEY / OPNSENSE_API_SECRET (devcontainer, see ~/.opnsense-env) with https://opnsense-dev and no
//     TLS verification
//
// Every test is skipped when there are no credentials or the instance is unreachable.
//
// Safety: nothing is created. The NetFlow settings and the system health setting are snapshotted by TestMain;
// tests change only harmless fields (timeouts, version, capture interface lan WITHOUT targets, so nothing is ever
// exported) and restore them, TestMain restores the snapshot if a test did not and then fails the run. NetFlow
// reconfigure runs only while nothing is configured (a no-op), the system health reconfigure (gateway monitors,
// cron) and every reset-data (deletes collected data) are never run live.
package integrationmonitoring

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
)

const (
	defaultUrl = "https://opnsense-dev"
	basePrefix = "a10-mon-"
)

var (
	// skipReason is set by TestMain when the live instance can not be used, every test skips with it
	skipReason string
	// runPrefix tags the names this run uses in probes, e.g. a10-mon-1a2b3c4d
	runPrefix string
	// opnBinary is the CLI built once by TestMain, opnBuildErr is set when that failed
	opnBinary   string
	opnBuildErr error
)

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	var random = make([]byte, 4)
	_, _ = rand.Read(random)
	runPrefix = basePrefix + hex.EncodeToString(random)

	skipReason = configureEnv()
	if skipReason == "" {
		skipReason = probe()
	}
	if skipReason != "" {
		fmt.Fprintf(os.Stderr, "integration/monitoring: skipping all tests: %s\n", skipReason)
		return m.Run()
	}
	fmt.Fprintf(os.Stderr, "integration/monitoring: using %s, run %s\n", os.Getenv("OPN_URL"), runPrefix)

	var core, _ = api.ConfigureFromEnv()
	var before, snapshotErr = takeSnapshot(core)
	if snapshotErr != nil {
		fmt.Fprintf(os.Stderr, "integration/monitoring: could not snapshot the settings: %v\n", snapshotErr)
		return 1
	}

	var tmpDir, err = os.MkdirTemp("", "opn-integration-monitoring-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration/monitoring: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	opnBinary, opnBuildErr = buildOpn(tmpDir)

	var code = m.Run()

	var after, afterErr = takeSnapshot(core)
	if afterErr != nil || !reflect.DeepEqual(before, after) {
		fmt.Fprintf(os.Stderr, "integration/monitoring: the settings changed (%v), restoring\n  before %+v\n  after  %+v\n", afterErr, before, after)
		if err := restoreSnapshot(core, before); err != nil {
			fmt.Fprintf(os.Stderr, "integration/monitoring: RESTORE FAILED: %v\n", err)
		}
		if code == 0 {
			code = 1
		}
	}
	return code
}

// configureEnv maps the devcontainer variables to the OPN_* variables the library and the CLI read
func configureEnv() string {
	var fallback = func(name string, value string) {
		if os.Getenv(name) == "" && value != "" {
			_ = os.Setenv(name, value)
		}
	}
	var usingDefaultUrl = os.Getenv("OPN_URL") == ""
	fallback("OPN_APIKEY", os.Getenv("OPNSENSE_API_KEY"))
	fallback("OPN_APISECRET", os.Getenv("OPNSENSE_API_SECRET"))
	fallback("OPN_URL", defaultUrl)
	if usingDefaultUrl {
		fallback("OPN_NOSSLVERIFY", "1") // the devcontainer instance uses a self-signed certificate
	}
	if os.Getenv("OPN_APIKEY") == "" || os.Getenv("OPN_APISECRET") == "" {
		return "no credentials, set OPN_URL / OPN_APIKEY / OPN_APISECRET (or OPNSENSE_API_KEY / OPNSENSE_API_SECRET)"
	}
	if parsed, err := url.Parse(os.Getenv("OPN_URL")); err != nil || parsed.Hostname() == "" {
		return fmt.Sprintf("invalid OPN_URL %q", os.Getenv("OPN_URL"))
	}
	return ""
}

// probe checks quickly that the instance answers authenticated API calls of the netflow module
func probe() string {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return err.Error()
	}
	var host = core.BaseUrl.Host
	if core.BaseUrl.Port() == "" {
		host = net.JoinHostPort(core.BaseUrl.Hostname(), map[bool]string{true: "443", false: "80"}[core.BaseUrl.Scheme == "https"])
	}
	var conn, dialErr = net.DialTimeout("tcp", host, 5*time.Second)
	if dialErr != nil {
		return fmt.Sprintf("%s is unreachable: %v", host, dialErr)
	}
	_ = conn.Close()
	var answer map[string]any
	if err := core.DoJSON("GET", core.EndpointForModule("diagnostics/netflow/status"), nil, &answer); err != nil {
		return fmt.Sprintf("netflow probe failed: %v", err)
	}
	return ""
}

func buildOpn(dir string) (string, error) {
	var binary = filepath.Join(dir, "opn")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	var build = exec.Command("go", "build", "-o", binary, ".")
	build.Dir = filepath.Join("..", "..") // module root
	if output, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build failed: %v\n%s", err, output)
	}
	return binary, nil
}

// --- raw access for the snapshot and for independent verification (deliberately not the library under test)

// settingsSnapshot are the settings the tests may change
type settingsSnapshot struct {
	Interfaces, EgressOnly, Version, Targets string // comma separated selected keys
	Collect, ActiveTimeout, InactiveTimeout  string
	HealthEnabled                            string
}

type rawOption struct {
	Selected json.RawMessage `json:"selected"`
}

func rawSelected(options map[string]rawOption) string {
	var keys []string
	for key, option := range options {
		if key != "" && strings.Trim(string(option.Selected), `"`) == "1" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func takeSnapshot(core *api.OPNsense) (settingsSnapshot, error) {
	var netflow struct {
		Netflow struct {
			Capture struct {
				Interfaces map[string]rawOption `json:"interfaces"`
				EgressOnly map[string]rawOption `json:"egress_only"`
				Version    map[string]rawOption `json:"version"`
				Targets    map[string]rawOption `json:"targets"`
			} `json:"capture"`
			Collect struct {
				Enable string `json:"enable"`
			} `json:"collect"`
			ActiveTimeout   string `json:"activeTimeout"`
			InactiveTimeout string `json:"inactiveTimeout"`
		} `json:"netflow"`
	}
	if err := core.DoJSON("GET", core.EndpointForModule("diagnostics/netflow/getconfig"), nil, &netflow); err != nil {
		return settingsSnapshot{}, err
	}
	var health struct {
		Systemhealth struct {
			Enabled string `json:"enabled"`
		} `json:"systemhealth"`
	}
	if err := core.DoJSON("GET", core.EndpointForModule("diagnostics/systemhealth/get"), nil, &health); err != nil {
		return settingsSnapshot{}, err
	}
	var n = netflow.Netflow
	return settingsSnapshot{
		Interfaces: rawSelected(n.Capture.Interfaces), EgressOnly: rawSelected(n.Capture.EgressOnly),
		Version: rawSelected(n.Capture.Version), Targets: rawSelected(n.Capture.Targets),
		Collect: n.Collect.Enable, ActiveTimeout: n.ActiveTimeout, InactiveTimeout: n.InactiveTimeout,
		HealthEnabled: health.Systemhealth.Enabled,
	}, nil
}

func restoreSnapshot(core *api.OPNsense, s settingsSnapshot) error {
	if _, err := core.Mutate(core.EndpointForModule("diagnostics/netflow/setconfig"), map[string]any{"netflow": map[string]any{
		"capture": map[string]string{"interfaces": s.Interfaces, "egress_only": s.EgressOnly, "version": s.Version, "targets": s.Targets},
		"collect": map[string]string{"enable": s.Collect}, "activeTimeout": s.ActiveTimeout, "inactiveTimeout": s.InactiveTimeout,
	}}); err != nil {
		return fmt.Errorf("netflow: %w", err)
	}
	if _, err := core.Mutate(core.EndpointForModule("diagnostics/systemhealth/set"), map[string]any{
		"systemhealth": map[string]string{"enabled": s.HealthEnabled}}); err != nil {
		return fmt.Errorf("system health: %w", err)
	}
	return nil
}

// --- helpers shared by the tests

// requireLive skips the test when the instance is not usable
func requireLive(t *testing.T) {
	t.Helper()
	if skipReason != "" {
		t.Skip(skipReason)
	}
}

func coreApi(t *testing.T) *api.OPNsense {
	t.Helper()
	requireLive(t)
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		t.Fatalf("ConfigureFromEnv: %v", err)
	}
	return core
}

// snapshot returns the current settings, failing the test on errors
func snapshot(t *testing.T) settingsSnapshot {
	t.Helper()
	var s, err = takeSnapshot(coreApi(t))
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return s
}

// restoreAfter restores the settings of now when the test ends (also when it failed)
func restoreAfter(t *testing.T) settingsSnapshot {
	t.Helper()
	var before = snapshot(t)
	t.Cleanup(func() {
		var core, _ = api.ConfigureFromEnv()
		if after, err := takeSnapshot(core); err == nil && reflect.DeepEqual(before, after) {
			return
		}
		if err := restoreSnapshot(core, before); err != nil {
			t.Errorf("restoring the settings failed: %v", err)
		}
	})
	return before
}

// netflowIdle tells whether NetFlow does nothing on the box: not running, no capture interfaces, no targets, no
// local collection. Only then a NetFlow reconfigure is a no-op
func netflowIdle(t *testing.T, s settingsSnapshot) bool {
	t.Helper()
	var status struct {
		Status string `json:"status"`
	}
	var core = coreApi(t)
	if err := core.DoJSON("GET", core.EndpointForModule("diagnostics/netflow/status"), nil, &status); err != nil {
		t.Fatalf("netflow status: %v", err)
	}
	return status.Status == "inactive" && s.Interfaces == "" && s.Targets == "" && s.EgressOnly == "" && s.Collect != "1"
}
