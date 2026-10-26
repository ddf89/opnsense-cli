//go:build integration

// Package integrationnodeexporter runs the node exporter library (opnsense/api/nodeexporter) and the opn
// /node-exporter menus against a live OPNsense (26.7) instance with the plugin os-node_exporter.
//
//	go test -tags integration ./integration/nodeexporter/... -count=1 -v
//
// Configuration: OPN_URL / OPN_APIKEY / OPN_APISECRET / OPN_NOSSLVERIFY like the CLI, or OPNSENSE_API_KEY /
// OPNSENSE_API_SECRET with https://opnsense-dev. Every test is skipped without credentials, when the instance is
// unreachable or when the plugin is not installed (the tests never install it).
//
// Safety: the plugin has no records, only settings and a service. TestMain snapshots the settings (including
// enabled) and the service state before the tests and restores both afterwards when a test left them changed (the
// tests restore them themselves too). While enabled, the exporter only listens on 127.0.0.1 on a high port.
package integrationnodeexporter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/nodeexporter"
)

const defaultUrl = "https://opnsense-dev"

var (
	skipReason  string
	runId       string
	opnBinary   string
	opnBuildErr error
)

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	var random = make([]byte, 4)
	_, _ = rand.Read(random)
	runId = "nex-" + hex.EncodeToString(random)

	skipReason = configureEnv()
	if skipReason == "" {
		skipReason = probe()
	}
	if skipReason != "" {
		fmt.Fprintf(os.Stderr, "integration/nodeexporter: skipping all tests: %s\n", skipReason)
		return m.Run()
	}
	var lib, _ = newApi()
	var before, beforeErr = snapshot(lib)
	if beforeErr != nil {
		fmt.Fprintf(os.Stderr, "integration/nodeexporter: snapshot failed: %v\n", beforeErr)
		return 1
	}
	fmt.Fprintf(os.Stderr, "integration/nodeexporter: using %s (run %s), before: %s\n", os.Getenv("OPN_URL"), runId, before)

	var tmpDir, err = os.MkdirTemp("", "opn-integration-nodeexporter-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration/nodeexporter: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	opnBinary, opnBuildErr = buildOpn(tmpDir)

	var code = m.Run()
	// the final check: settings and service state as before, restore them otherwise
	if after, err := snapshot(lib); err != nil || after.String() != before.String() {
		fmt.Fprintf(os.Stderr, "integration/nodeexporter: the tests left %s (%v), restoring %s\n", after, err, before)
		if err := restore(lib, before); err != nil {
			fmt.Fprintf(os.Stderr, "integration/nodeexporter: RESTORE FAILED: %v\n", err)
		}
		if code == 0 {
			code = 1
		}
	}
	return code
}

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
		fallback("OPN_NOSSLVERIFY", "1")
	}
	if os.Getenv("OPN_APIKEY") == "" || os.Getenv("OPN_APISECRET") == "" {
		return "no credentials, set OPN_URL / OPN_APIKEY / OPN_APISECRET (or OPNSENSE_API_KEY / OPNSENSE_API_SECRET)"
	}
	if parsed, err := url.Parse(os.Getenv("OPN_URL")); err != nil || parsed.Hostname() == "" {
		return fmt.Sprintf("invalid OPN_URL %q", os.Getenv("OPN_URL"))
	}
	return ""
}

func newApi() (*nodeexporter.NodeExporterApi, error) {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return nil, err
	}
	return &nodeexporter.NodeExporterApi{OPNsense: core}, nil
}

func probe() string {
	var lib, err = newApi()
	if err != nil {
		return err.Error()
	}
	var host = lib.BaseUrl.Host
	if lib.BaseUrl.Port() == "" {
		host = net.JoinHostPort(lib.BaseUrl.Hostname(), map[bool]string{true: "443", false: "80"}[lib.BaseUrl.Scheme == "https"])
	}
	var conn, dialErr = net.DialTimeout("tcp", host, 5*time.Second)
	if dialErr != nil {
		return fmt.Sprintf("%s is unreachable: %v", host, dialErr)
	}
	_ = conn.Close()
	if _, err := lib.SettingsGet(); err != nil {
		var httpErr *api.HttpError
		if errors.As(err, &httpErr) && httpErr.StatusCode == 404 {
			return nodeexporter.Plugin + " is not installed"
		}
		return fmt.Sprintf("node exporter probe failed: %v", err)
	}
	return ""
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

// state is the snapshot of the settings and the service state
type state struct {
	settings nodeexporter.Settings
	status   string
}

func (s state) String() string {
	return fmt.Sprintf("%+v status=%s", s.settings, s.status)
}

func snapshot(lib *nodeexporter.NodeExporterApi) (state, error) {
	var settings, err = lib.SettingsGet()
	if err != nil {
		return state{}, err
	}
	var status, statusErr = lib.ServiceStatus()
	return state{settings, status}, statusErr
}

// restore writes all settings back, reconfigures (which starts the exporter when enabled, stops it otherwise) and
// stops it again when it was enabled but stopped before
func restore(lib *nodeexporter.NodeExporterApi, s state) error {
	var enabled = s.settings.Enabled == "1"
	var address = s.settings.ListenAddress
	var port int
	if _, err := fmt.Sscan(s.settings.ListenPort, &port); err != nil {
		return fmt.Errorf("listen port %q: %w", s.settings.ListenPort, err)
	}
	if err := lib.SettingsSet(nodeexporter.SettingsUpdate{Enabled: &enabled, ListenAddress: &address, ListenPort: &port,
		Collectors: s.settings.Collectors()}); err != nil {
		return err
	}
	if err := lib.ServiceReconfigure(); err != nil {
		return err
	}
	if s.status == nodeexporter.StatusStopped {
		return lib.ServiceStop()
	}
	return nil
}

func requireLive(t *testing.T) {
	t.Helper()
	if skipReason != "" {
		t.Skip(skipReason)
	}
}

func liveApi(t *testing.T) *nodeexporter.NodeExporterApi {
	t.Helper()
	requireLive(t)
	var lib, err = newApi()
	if err != nil {
		t.Fatalf("ConfigureFromEnv: %v", err)
	}
	return lib
}

// --- running the CLI

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
	var ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
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
