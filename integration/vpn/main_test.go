//go:build integration

// Package integrationvpn runs the OpenVPN library (opnsense/api/openvpn) and the opn /vpn menus against a live
// OPNsense (26.7) instance.
//
//	go test -tags integration ./integration/vpn/... -count=1 -v
//
// Configuration (first match wins):
//   - OPN_URL / OPN_APIKEY / OPN_APISECRET / OPN_NOSSLVERIFY, like the CLI
//   - OPNSENSE_API_KEY / OPNSENSE_API_SECRET (devcontainer, see ~/.opnsense-env) with https://opnsense-dev and no
//     TLS verification
//
// Every test is skipped when there are no credentials or the instance is unreachable.
//
// Safety (the instance is shared): records are only created with the description prefix a8-vpn-<random run id>,
// OpenVPN instances and client specific overrides are always created disabled, so nothing listens or starts.
// TestMain finally sweeps (only) records carrying this run's prefix and fails the run if it found any: client
// specific overrides, instances, static keys, then certificates and CAs (in this order, because of references).
package integrationvpn

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
)

const (
	defaultUrl = "https://opnsense-dev"
	basePrefix = "a8-vpn-"
)

var (
	// skipReason is set by TestMain when the live instance can not be used, every test skips with it
	skipReason string
	// runPrefix is the description prefix of every record this run creates, e.g. a8-sys-1a2b3c4d
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
		fmt.Fprintf(os.Stderr, "integration/vpn: skipping all tests: %s\n", skipReason)
		return m.Run()
	}
	fmt.Fprintf(os.Stderr, "integration/vpn: using %s, records are tagged %s\n", os.Getenv("OPN_URL"), runPrefix)

	var tmpDir, err = os.MkdirTemp("", "opn-integration-vpn-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration/vpn: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	opnBinary, opnBuildErr = buildOpn(tmpDir)

	var code = m.Run()

	if leftovers := sweep(); len(leftovers) > 0 {
		fmt.Fprintf(os.Stderr, "integration/vpn: the final sweep removed records the tests did not clean up: %s\n",
			strings.Join(leftovers, ", "))
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

// probe checks quickly that the instance answers authenticated API calls of the openvpn module
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

	if _, err := api.Search[map[string]any](core, core.EndpointForPluginControllerMethod("openvpn", "instances", "search"), ""); err != nil {
		return fmt.Sprintf("openvpn probe failed: %v", err)
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

// --- raw access used by the sweep and for independent verification (deliberately not the library under test)

type rawRow struct {
	Uuid        string `json:"uuid"`
	Description string `json:"description"`
	Descr       string `json:"descr"`
}

func rawSearch(core *api.OPNsense, endpoint string, phrase string) ([]rawRow, error) {
	return api.Search[rawRow](core, core.EndpointForModule(endpoint), phrase)
}

// ownedByRun reports whether a description carries this run's prefix
func ownedByRun(description string) bool {
	return runPrefix != "" && strings.HasPrefix(description, runPrefix)
}

// sweep removes every record (and only those) tagged with runPrefix and returns what it removed
func sweep() []string {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return nil
	}
	var removed []string
	// referencing records first: overrides and instances use static keys, certificates and CAs
	for _, kind := range []struct{ what, search, del string }{
		{"client specific override", "openvpn/client_overwrites/search", "openvpn/client_overwrites/del"},
		{"openvpn instance", "openvpn/instances/search", "openvpn/instances/del"},
		{"static key", "openvpn/instances/search_static_key", "openvpn/instances/del_static_key"},
		{"certificate", "trust/cert/search", "trust/cert/del"},
		{"ca", "trust/ca/search", "trust/ca/del"},
	} {
		var rows, searchErr = rawSearch(core, kind.search, runPrefix)
		if searchErr != nil {
			continue
		}
		for _, row := range rows {
			if !ownedByRun(row.Description) && !ownedByRun(row.Descr) {
				continue
			}
			if _, err := core.Mutate(core.EndpointForModule(kind.del+"/"+row.Uuid), nil); err == nil {
				removed = append(removed, kind.what+" "+row.Uuid)
			} else {
				fmt.Fprintf(os.Stderr, "integration/vpn: sweep could not remove %s %s: %v\n", kind.what, row.Uuid, err)
			}
		}
	}
	return removed
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

// testDescription returns a description for one test, e.g. "a8-vpn-1a2b3c4d instance-lifecycle"
func testDescription(label string) string {
	return runPrefix + " " + label
}
