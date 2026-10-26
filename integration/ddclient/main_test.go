//go:build integration

// Package integrationddclient runs the Dynamic DNS library (opnsense/api/ddclient) and the opn /ddclient menus
// against a live OPNsense (26.7) with the os-ddclient plugin.
//
//	go test -tags integration ./integration/ddclient/... -count=1 -v
//
// Configuration: OPN_URL / OPN_APIKEY / OPN_APISECRET / OPN_NOSSLVERIFY like the CLI. Every test is skipped without
// credentials, when the instance is unreachable or when os-ddclient is not installed.
//
// Safety: ddclient contacts real DDNS providers. Test accounts are always disabled (only enabled accounts are
// written to the configuration) and use documentation domains (example.com/.net/.org); they are described
// ddc-<random run id>-... and removed by uuid, TestMain finally sweeps the accounts with this run's prefix and fails
// the run if it found any. The service is only started, refreshed or reconfigured when the firewall has no enabled
// account at all. TestMain snapshots the general settings and the service state and restores both at the end.
package integrationddclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/ddclient"
)

var (
	skipReason  string
	runPrefix   string
	opnBinary   string
	opnBuildErr error
)

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	var random = make([]byte, 4)
	_, _ = rand.Read(random)
	runPrefix = "ddc-" + hex.EncodeToString(random)

	skipReason = probe()
	if skipReason != "" {
		fmt.Fprintf(os.Stderr, "integration/ddclient: skipping all tests: %s\n", skipReason)
		return m.Run()
	}
	fmt.Fprintf(os.Stderr, "integration/ddclient: using %s, accounts are described %s-...\n", os.Getenv("OPN_URL"), runPrefix)

	var lib = libApi()
	var settings, settingsErr = lib.SettingsGet()
	var status, statusErr = lib.ServiceStatus()
	if settingsErr != nil || statusErr != nil {
		fmt.Fprintf(os.Stderr, "integration/ddclient: snapshot failed: %v %v\n", settingsErr, statusErr)
		return 1
	}

	var tmpDir, err = os.MkdirTemp("", "opn-integration-ddclient-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration/ddclient: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	opnBinary, opnBuildErr = buildOpn(tmpDir)

	var code = m.Run()
	if leftovers := sweep(lib); len(leftovers) > 0 {
		fmt.Fprintf(os.Stderr, "integration/ddclient: the final sweep removed accounts the tests did not clean up: %s\n", strings.Join(leftovers, ", "))
		if code == 0 {
			code = 1
		}
	}
	if err := restore(lib, settings, status); err != nil {
		fmt.Fprintf(os.Stderr, "integration/ddclient: restoring the settings / service state failed: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

func probe() string {
	if os.Getenv("OPN_URL") == "" || os.Getenv("OPN_APIKEY") == "" || os.Getenv("OPN_APISECRET") == "" {
		return "no credentials, set OPN_URL / OPN_APIKEY / OPN_APISECRET"
	}
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
	if _, err := (&ddclient.DdclientApi{OPNsense: core}).ServiceStatus(); err != nil {
		if ddclient.IsNotInstalled(err) {
			return ddclient.PluginName + " is not installed"
		}
		return fmt.Sprintf("ddclient probe failed: %v", err)
	}
	return ""
}

func libApi() *ddclient.DdclientApi {
	var core, _ = api.ConfigureFromEnv()
	return &ddclient.DdclientApi{OPNsense: core}
}

func buildOpn(dir string) (string, error) {
	var binary = filepath.Join(dir, "opn")
	var build = exec.Command("go", "build", "-o", binary, ".")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build failed: %v\n%s", err, output)
	}
	return binary, nil
}

// sweep removes the accounts described with this run's prefix (raw API, not the library under test)
func sweep(lib *ddclient.DdclientApi) []string {
	var rows, err = api.Search[struct {
		Uuid        string `json:"uuid"`
		Description string `json:"description"`
	}](lib.OPNsense, lib.EndpointForModule("dyndns/accounts/search_item"), runPrefix)
	if err != nil {
		return nil
	}
	var removed []string
	for _, row := range rows {
		if !strings.HasPrefix(row.Description, runPrefix) {
			continue
		}
		if _, err := lib.Mutate(lib.EndpointForModule("dyndns/accounts/del_item/"+row.Uuid), nil); err == nil {
			removed = append(removed, row.Description+" "+row.Uuid)
		}
	}
	return removed
}

// restore puts the general settings back and the service into its state before the run (running or not)
func restore(lib *ddclient.DdclientApi, settings ddclient.Settings, status string) error {
	var current, err = lib.SettingsGet()
	if err != nil {
		return err
	}
	if !maps.Equal(current.SettingsFields(), settings.SettingsFields()) {
		if err := lib.SettingsSet(settings.SettingsFields()); err != nil {
			return err
		}
	}
	var now, statusErr = lib.ServiceStatus()
	if statusErr != nil {
		return statusErr
	}
	switch {
	case now == "running" && status != "running":
		return lib.ServiceStop()
	case now != "running" && status == "running":
		return lib.ServiceStart()
	}
	return nil
}

func requireLive(t *testing.T) {
	t.Helper()
	if skipReason != "" {
		t.Skip(skipReason)
	}
}

func ddclientApi(t *testing.T) *ddclient.DdclientApi {
	t.Helper()
	requireLive(t)
	return libApi()
}

// requireNoEnabledAccounts skips a test that runs the service when the firewall has an enabled account: the
// service would update it at its provider
func requireNoEnabledAccounts(t *testing.T, lib *ddclient.DdclientApi) {
	t.Helper()
	var accounts, _, err = lib.AccountList("")
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range accounts {
		if account.Enabled == "1" {
			t.Skipf("the account %q is enabled, the service is not run by the tests", account.Description)
		}
	}
}

// --- running the CLI

var uuidPattern = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

type opnResult struct {
	args     []string
	stdout   string
	stderr   string
	exitCode int
}

func (r opnResult) String() string {
	return fmt.Sprintf("opn %s\nexit code %d\nstdout:\n%s\nstderr:\n%s", strings.Join(r.args, " "), r.exitCode, r.stdout, r.stderr)
}

func runOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	requireLive(t)
	if opnBuildErr != nil {
		t.Fatalf("the opn binary could not be built: %v", opnBuildErr)
	}
	var ctx, cancel = context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var command = exec.CommandContext(ctx, opnBinary, args...)
	command.Dir = t.TempDir()
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
	var result = runOpn(t, args...)
	if result.exitCode != 0 {
		t.Fatalf("want exit code 0, got:\n%s", result)
	}
	return result
}

func mustFailOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	var result = runOpn(t, args...)
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

func uuidFrom(t *testing.T, result opnResult) string {
	t.Helper()
	var uuid = uuidPattern.FindString(result.stdout)
	if uuid == "" {
		t.Fatalf("no uuid in the output:\n%s", result)
	}
	return uuid
}
