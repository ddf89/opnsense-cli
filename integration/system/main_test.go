//go:build integration

// Package integrationsystem runs the System library (opnsense/api/system) and the opn /system menus against
// a live OPNsense (26.7) instance.
//
//	go test -tags integration ./integration/system/... -count=1 -v
//
// Configuration (first match wins):
//   - OPN_URL / OPN_APIKEY / OPN_APISECRET / OPN_NOSSLVERIFY, like the CLI
//   - OPNSENSE_API_KEY / OPNSENSE_API_SECRET (devcontainer, see ~/.opnsense-env) with https://opnsense-dev and no
//     TLS verification
//
// Every test is skipped when there are no credentials or the instance is unreachable.
//
// Safety (the instance is shared): records are only created with the description prefix a8-sys-<random run id>,
// cron jobs and syslog destinations are always disabled, tunables are only set to their current runtime value,
// logging settings are restored exactly. Test gateways and static routes are never the default and are never
// applied (the dynamic WAN gateways are never changed), only certificates, CAs and CRLs created here are touched.
// Factory reset, backup revert and wizard set are never called.
// TestMain finally sweeps (only) records carrying this run's prefix and fails the run if it found any.
package integrationsystem

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
	basePrefix = "a8-sys-"
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
		fmt.Fprintf(os.Stderr, "integration/system: skipping all tests: %s\n", skipReason)
		return m.Run()
	}
	fmt.Fprintf(os.Stderr, "integration/system: using %s, records are tagged %s\n", os.Getenv("OPN_URL"), runPrefix)

	var tmpDir, err = os.MkdirTemp("", "opn-integration-system-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration/system: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	opnBinary, opnBuildErr = buildOpn(tmpDir)

	var code = m.Run()

	if leftovers := sweep(); len(leftovers) > 0 {
		fmt.Fprintf(os.Stderr, "integration/system: the final sweep removed records the tests did not clean up: %s\n",
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

// probe checks quickly that the instance answers authenticated API calls of the syslog module
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

	var status struct {
		Status string `json:"status"`
	}
	if err := core.DoJSON("GET", core.EndpointForPluginControllerMethod("syslog", "service", "status"), nil, &status); err != nil {
		return fmt.Sprintf("status probe failed: %v", err)
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
	Tunable     string `json:"tunable"`
	Refid       string `json:"refid"`
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
	var del = func(what string, endpoint string, uuid string) {
		if _, err := core.Mutate(core.EndpointForModule(endpoint+"/"+uuid), nil); err == nil {
			removed = append(removed, what+" "+uuid)
		} else {
			fmt.Fprintf(os.Stderr, "integration/system: sweep could not remove %s %s: %v\n", what, uuid, err)
		}
	}

	var cronRemoved, tunablesRemoved, destinationsRemoved bool
	if rows, err := rawSearch(core, "cron/settings/search_jobs", runPrefix); err == nil {
		for _, row := range rows {
			if ownedByRun(row.Description) {
				del("cron job", "cron/settings/del_job", row.Uuid)
				cronRemoved = true
			}
		}
	}
	if rows, err := rawSearch(core, "core/tunables/search_item", runPrefix); err == nil {
		for _, row := range rows {
			if ownedByRun(row.Descr) {
				del("tunable "+row.Tunable, "core/tunables/del_item", row.Uuid)
				tunablesRemoved = true
			}
		}
	}
	if rows, err := rawSearch(core, "syslog/settings/search_destinations", runPrefix); err == nil {
		for _, row := range rows {
			if ownedByRun(row.Description) {
				del("syslog destination", "syslog/settings/del_destination", row.Uuid)
				destinationsRemoved = true
			}
		}
	}

	// routes and groups first, a gateway in use can not be deleted. Never applied, the routes stay untouched
	for _, kind := range []struct{ what, search, del string }{
		{"static route", "routes/routes/searchroute", "routes/routes/delroute"},
		{"gateway group", "routing/group_settings/search", "routing/group_settings/del"},
		{"gateway", "routing/settings/search_gateway", "routing/settings/del_gateway"},
	} {
		if rows, err := rawSearch(core, kind.search, runPrefix); err == nil {
			for _, row := range rows {
				if ownedByRun(row.Descr) {
					del(kind.what, kind.del, row.Uuid)
				}
			}
		}
	}

	// certificates, then the revocation lists and the authorities that issued them
	if rows, err := rawSearch(core, "trust/cert/search", runPrefix); err == nil {
		for _, row := range rows {
			if ownedByRun(row.Descr) {
				del("certificate", "trust/cert/del", row.Uuid)
			}
		}
	}
	if rows, err := rawSearch(core, "trust/ca/search", runPrefix); err == nil {
		for _, row := range rows {
			if ownedByRun(row.Descr) {
				var deleted map[string]any
				_ = core.DoJSON("POST", core.EndpointForModule("trust/crl/del/"+row.Refid), nil, &deleted)
				del("ca", "trust/ca/del", row.Uuid)
			}
		}
	}

	var reconfigure = func(endpoint string) {
		var status map[string]any
		_ = core.DoJSON("POST", core.EndpointForModule(endpoint), nil, &status)
	}
	if cronRemoved {
		reconfigure("cron/service/reconfigure")
	}
	if tunablesRemoved {
		reconfigure("core/tunables/reconfigure")
	}
	if destinationsRemoved {
		reconfigure("syslog/service/reconfigure")
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

// testDescription returns a description for one test, e.g. "a8-sys-1a2b3c4d cron-lifecycle"
func testDescription(label string) string {
	return runPrefix + " " + label
}
