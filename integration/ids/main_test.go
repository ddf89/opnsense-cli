//go:build integration

// Package integrationids runs the IDS library (opnsense/api/ids) and the opn /ids menus against a live OPNsense
// (26.7) instance.
//
//	go test -tags integration ./integration/ids/... -count=1 -v
//
// Configuration: OPN_URL / OPN_APIKEY / OPN_APISECRET / OPN_NOSSLVERIFY like the CLI, or OPNSENSE_API_KEY /
// OPNSENSE_API_SECRET with https://opnsense-dev. Every test is skipped without credentials or when the instance is
// unreachable.
//
// Safety: Suricata is never enabled, started or reconfigured (IPS mode could drop the management traffic), the
// general settings tests only change logging values and restore them. Policies and user rules are created disabled
// with the description prefix a8-ids-<random run id> and removed by uuid; rule adjustments are only made for a rule
// without one and reset afterwards. The rule download enables the small abuse.ch Feodo Tracker rule set when needed
// (and disables it again) and skips when the firewall has no internet access. TestMain finally sweeps the records
// carrying this run's prefix and fails the run if it found any.
package integrationids

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/ids"
)

const defaultUrl = "https://opnsense-dev"

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
	runPrefix = "a8-ids-" + hex.EncodeToString(random)

	skipReason = configureEnv()
	if skipReason == "" {
		skipReason = probe()
	}
	if skipReason != "" {
		fmt.Fprintf(os.Stderr, "integration/ids: skipping all tests: %s\n", skipReason)
		return m.Run()
	}
	fmt.Fprintf(os.Stderr, "integration/ids: using %s, records are tagged %s\n", os.Getenv("OPN_URL"), runPrefix)

	var tmpDir, err = os.MkdirTemp("", "opn-integration-ids-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration/ids: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	opnBinary, opnBuildErr = buildOpn(tmpDir)

	var code = m.Run()
	if leftovers := sweep(); len(leftovers) > 0 {
		fmt.Fprintf(os.Stderr, "integration/ids: the final sweep removed records the tests did not clean up: %s\n", strings.Join(leftovers, ", "))
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
	if _, err := (&ids.IdsApi{OPNsense: core}).ServiceStatus(); err != nil {
		return fmt.Sprintf("ids probe failed: %v", err)
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

// sweep removes the policies and user rules with this run's prefix (raw API, not the library under test)
func sweep() []string {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return nil
	}
	var removed []string
	for _, kind := range []struct{ what, search, del string }{
		{"policy", "ids/settings/search_policy", "ids/settings/del_policy"},
		{"user rule", "ids/settings/search_user_rule", "ids/settings/del_user_rule"},
	} {
		var rows, searchErr = api.Search[struct {
			Uuid        string `json:"uuid"`
			Description string `json:"description"`
		}](core, core.EndpointForModule(kind.search), runPrefix)
		if searchErr != nil {
			continue
		}
		for _, row := range rows {
			if !strings.HasPrefix(row.Description, runPrefix) {
				continue
			}
			if _, err := core.Mutate(core.EndpointForModule(kind.del+"/"+row.Uuid), nil); err == nil {
				removed = append(removed, kind.what+" "+row.Uuid)
			}
		}
	}
	return removed
}

func requireLive(t *testing.T) {
	t.Helper()
	if skipReason != "" {
		t.Skip(skipReason)
	}
}

func idsApi(t *testing.T) *ids.IdsApi {
	t.Helper()
	requireLive(t)
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		t.Fatalf("ConfigureFromEnv: %v", err)
	}
	return &ids.IdsApi{OPNsense: core}
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
