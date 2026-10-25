//go:build integration

// Package integrationwireguard runs the WireGuard library (opnsense/api/wireguard) and the opn /vpn/wireguard menus
// against a live OPNsense (26.7) instance.
//
//	go test -tags integration ./integration/wireguard/... -count=1 -v
//
// Configuration: OPN_URL / OPN_APIKEY / OPN_APISECRET / OPN_NOSSLVERIFY like the CLI, or OPNSENSE_API_KEY /
// OPNSENSE_API_SECRET with https://opnsense-dev. Every test is skipped without credentials or when unreachable.
//
// Safety (the instance is shared): instances and peers are only created disabled, named a9-wg-<random run id>...,
// with documentation tunnel addresses (192.0.2.0/24, 2001:db8::/32) and unused high ports. WireGuard is never enabled
// globally, never started, stopped or reconfigured. TestMain finally sweeps (only) peers and instances carrying this
// run's prefix and fails the run if it found any.
package integrationwireguard

import (
	"crypto/rand"
	"encoding/hex"
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
	"opnsense-cli/opnsense/api/wireguard"
)

const (
	defaultUrl = "https://opnsense-dev"
	basePrefix = "a9-wg-"
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
	runPrefix = basePrefix + hex.EncodeToString(random)

	skipReason = configureEnv()
	if skipReason == "" {
		skipReason = probe()
	}
	if skipReason != "" {
		fmt.Fprintf(os.Stderr, "integration/wireguard: skipping all tests: %s\n", skipReason)
		return m.Run()
	}
	fmt.Fprintf(os.Stderr, "integration/wireguard: using %s, records are named %s...\n", os.Getenv("OPN_URL"), runPrefix)

	var tmpDir, err = os.MkdirTemp("", "opn-integration-wireguard-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration/wireguard: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	opnBinary, opnBuildErr = buildOpn(tmpDir)

	var code = m.Run()
	if leftovers := sweep(); len(leftovers) > 0 {
		fmt.Fprintf(os.Stderr, "integration/wireguard: the final sweep removed records the tests did not clean up: %s\n",
			strings.Join(leftovers, ", "))
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
	if _, err := (&wireguard.WireguardApi{OPNsense: core}).InstanceList(""); err != nil {
		return fmt.Sprintf("wireguard probe failed: %v", err)
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

// sweep removes the peers and instances (and only those) named with runPrefix, peers first
func sweep() []string {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return nil
	}
	var removed []string
	for _, kind := range []struct{ what, search, del string }{
		{"peer", "wireguard/client/search_client", "wireguard/client/del_client"},
		{"instance", "wireguard/server/search_server", "wireguard/server/del_server"},
	} {
		var rows, searchErr = api.Search[struct {
			Uuid string `json:"uuid"`
			Name string `json:"name"`
		}](core, core.EndpointForModule(kind.search), runPrefix)
		if searchErr != nil {
			continue
		}
		for _, row := range rows {
			if !strings.HasPrefix(row.Name, runPrefix) {
				continue
			}
			if _, err := core.Mutate(core.EndpointForModule(kind.del+"/"+row.Uuid), nil); err == nil {
				removed = append(removed, kind.what+" "+row.Uuid)
			} else {
				fmt.Fprintf(os.Stderr, "integration/wireguard: sweep could not remove %s %s: %v\n", kind.what, row.Uuid, err)
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

func testApi(t *testing.T) *wireguard.WireguardApi {
	t.Helper()
	requireLive(t)
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		t.Fatalf("ConfigureFromEnv: %v", err)
	}
	return &wireguard.WireguardApi{OPNsense: core}
}

// testName returns a name for one test, e.g. "a9-wg-1a2b3c4d-lib-i1"
func testName(label string) string {
	return runPrefix + "-" + label
}
