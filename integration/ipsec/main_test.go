//go:build integration

// Package integrationipsec runs the IPsec library (opnsense/api/ipsec) and the opn /vpn/ipsec menus against a
// live OPNsense (26.7) instance.
//
//	go test -tags integration ./integration/ipsec/... -count=1 -v
//
// Configuration (first match wins):
//   - OPN_URL / OPN_APIKEY / OPN_APISECRET / OPN_NOSSLVERIFY, like the CLI
//   - OPNSENSE_API_KEY / OPNSENSE_API_SECRET (devcontainer, see ~/.opnsense-env) with https://opnsense-dev and no
//     TLS verification
//
// Every test is skipped when there are no credentials or the instance is unreachable.
//
// Safety (the instance is shared): records are only created with the prefix ipsec-<random run id> (descriptions,
// pool and key pair names), always disabled and with documentation addresses (192.0.2.0/24, 198.51.100.0/24,
// 2001:db8::/32). IPsec is never switched on, nothing is reconfigured, started, connected or removed from the
// kernel; those commands are covered by the unit tests only. The settings test snapshots and restores what it
// changes. TestMain finally sweeps (only) records carrying this run's prefix and fails the run if it found any.
package integrationipsec

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
	"opnsense-cli/opnsense/api/ipsec"
)

const (
	defaultUrl = "https://opnsense-dev"
	basePrefix = "ipsec-"
)

var (
	skipReason  string
	runPrefix   string // e.g. ipsec-1a2b3c4d
	runReqid    int    // a reqid base for VTIs and children of this run, 60000-64999
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
	runReqid = 60000 + (int(random[0])<<8|int(random[1]))%4900

	skipReason = configureEnv()
	if skipReason == "" {
		skipReason = probe()
	}
	if skipReason != "" {
		fmt.Fprintf(os.Stderr, "integration/ipsec: skipping all tests: %s\n", skipReason)
		return m.Run()
	}
	fmt.Fprintf(os.Stderr, "integration/ipsec: using %s, records are tagged %s\n", os.Getenv("OPN_URL"), runPrefix)

	var tmpDir, err = os.MkdirTemp("", "opn-integration-ipsec-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration/ipsec: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	opnBinary, opnBuildErr = buildOpn(tmpDir)

	var code = m.Run()
	if leftovers := sweep(); len(leftovers) > 0 {
		fmt.Fprintf(os.Stderr, "integration/ipsec: the final sweep removed records the tests did not clean up: %s\n",
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
	if _, err := (&ipsec.IPsecApi{OPNsense: core}).ConnectionList(""); err != nil {
		return fmt.Sprintf("ipsec probe failed: %v", err)
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

// sweep removes every record (and only those) tagged with runPrefix, referencing lists first. Raw endpoints,
// deliberately not the library under test
func sweep() []string {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return nil
	}
	var removed []string
	for _, kind := range []struct{ what, search, del, field string }{
		{"manual spd entry", "ipsec/manual_spd/search", "ipsec/manual_spd/del", "description"},
		{"connection", "ipsec/connections/search_connection", "ipsec/connections/del_connection", "description"},
		{"local", "ipsec/connections/search_local", "ipsec/connections/del_local", "description"},
		{"remote", "ipsec/connections/search_remote", "ipsec/connections/del_remote", "description"},
		{"child", "ipsec/connections/search_child", "ipsec/connections/del_child", "description"},
		{"pool", "ipsec/pools/search", "ipsec/pools/del", "name"},
		{"vti", "ipsec/vti/search", "ipsec/vti/del", "description"},
		{"pre-shared key", "ipsec/pre_shared_keys/search_item", "ipsec/pre_shared_keys/del_item", "description"},
		{"key pair", "ipsec/key_pairs/search_item", "ipsec/key_pairs/del_item", "name"},
	} {
		var rows, searchErr = api.Search[map[string]any](core, core.EndpointForModule(kind.search), runPrefix)
		if searchErr != nil {
			continue
		}
		for _, row := range rows {
			var value, _ = row[kind.field].(string)
			var uuid, _ = row["uuid"].(string)
			if !ownedByRun(value) || uuid == "" {
				continue
			}
			if _, err := core.Mutate(core.EndpointForModule(kind.del+"/"+uuid), nil); err == nil {
				removed = append(removed, kind.what+" "+uuid)
			} else {
				fmt.Fprintf(os.Stderr, "integration/ipsec: sweep could not remove %s %s: %v\n", kind.what, uuid, err)
			}
		}
	}
	return removed
}

func ownedByRun(value string) bool {
	return runPrefix != "" && strings.HasPrefix(value, runPrefix)
}

func requireLive(t *testing.T) {
	t.Helper()
	if skipReason != "" {
		t.Skip(skipReason)
	}
}

func ipsecApi(t *testing.T) *ipsec.IPsecApi {
	t.Helper()
	requireLive(t)
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		t.Fatalf("ConfigureFromEnv: %v", err)
	}
	return &ipsec.IPsecApi{OPNsense: core}
}

// testName returns a description for one test, e.g. "ipsec-1a2b3c4d lifecycle"
func testName(label string) string {
	return runPrefix + " " + label
}

// requireIPsecOff skips tests that must not run while IPsec is enabled on the shared box
func requireIPsecOff(t *testing.T, vpn *ipsec.IPsecApi) {
	t.Helper()
	if enabled, err := vpn.IsEnabled(); err != nil {
		t.Fatalf("IsEnabled: %v", err)
	} else if enabled {
		t.Skip("IPsec is enabled on this instance, the tests only run while it is off")
	}
}
