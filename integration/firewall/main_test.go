//go:build integration

// Package integrationfirewall runs the firewall library (opnsense/api/firewall, the firewall parts of
// opnsense/api/diagnostics) and the opn /firewall menus against a live OPNsense (26.7) instance.
//
//	go test -tags integration ./integration/firewall/... -count=1 -v
//
// Configuration (first match wins):
//   - OPN_URL / OPN_APIKEY / OPN_APISECRET / OPN_NOSSLVERIFY, like the CLI
//   - OPNSENSE_API_KEY / OPNSENSE_API_SECRET (devcontainer, see ~/.opnsense-env) with https://opnsense-dev and no
//     TLS verification
//
// Every test is skipped when there are no credentials or the instance is unreachable.
//
// Safety (the instance is shared, and a firewall mistake can lock everybody out): records are only created with
// the description (or name) prefix a8-fw-<random run id> / a8fw_<random run id>, filter, NAT and shaper rules are
// always created disabled, nothing is ever applied (no filter apply, no alias / shaper reconfigure), states are
// never killed or flushed. Existing records are never changed. TestMain finally sweeps (only) records carrying
// this run's prefix and fails the run if it found any.
package integrationfirewall

import (
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
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
	basePrefix = "a8-fw-"
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
		fmt.Fprintf(os.Stderr, "integration/firewall: skipping all tests: %s\n", skipReason)
		return m.Run()
	}
	fmt.Fprintf(os.Stderr, "integration/firewall: using %s, records are tagged %s\n", os.Getenv("OPN_URL"), runPrefix)

	var tmpDir, err = os.MkdirTemp("", "opn-integration-firewall-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration/firewall: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	opnBinary, opnBuildErr = buildOpn(tmpDir)

	var code = m.Run()

	if leftovers := sweep(); len(leftovers) > 0 {
		fmt.Fprintf(os.Stderr, "integration/firewall: the final sweep removed records the tests did not clean up: %s\n",
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

// probe checks quickly that the instance answers authenticated API calls of the firewall module
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

	if _, err := api.Search[map[string]any](core, core.EndpointForPluginControllerMethod("firewall", "alias", "search_item"), ""); err != nil {
		return fmt.Sprintf("firewall probe failed: %v", err)
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
	Name        string `json:"name"`
	Ifname      string `json:"ifname"`
}

func rawSearch(core *api.OPNsense, endpoint string, phrase string) ([]rawRow, error) {
	return api.Search[rawRow](core, core.EndpointForModule(endpoint), phrase)
}

// namePrefix is runPrefix in the form allowed for names (aliases, groups, categories): a8fw_<random run id>
func namePrefix() string {
	return strings.ReplaceAll(strings.ReplaceAll(runPrefix, "-", "_"), "a8_fw_", "a8fw_")
}

// ownedByRun reports whether a description or name carries this run's prefix
func ownedByRun(text string) bool {
	return runPrefix != "" && (strings.HasPrefix(text, runPrefix) || strings.HasPrefix(text, namePrefix()))
}

// sweep removes every record (and only those) tagged with this run's prefix and returns what it removed. Nothing
// is applied, the removed records were never active
func sweep() []string {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return nil
	}
	var removed []string
	// rules first (they reference aliases, groups and categories), shaper rules before queues before pipes
	for _, kind := range []struct{ what, search, del string }{
		{"filter rule", "firewall/filter/search_rule", "firewall/filter/del_rule"},
		{"source nat rule", "firewall/source_nat/search_rule", "firewall/source_nat/del_rule"},
		{"destination nat rule", "firewall/d_nat/search_rule", "firewall/d_nat/del_rule"},
		{"one-to-one nat rule", "firewall/one_to_one/search_rule", "firewall/one_to_one/del_rule"},
		{"npt rule", "firewall/npt/search_rule", "firewall/npt/del_rule"},
		{"shaper rule", "trafficshaper/settings/search_rules", "trafficshaper/settings/del_rule"},
		{"shaper queue", "trafficshaper/settings/search_queues", "trafficshaper/settings/del_queue"},
		{"shaper pipe", "trafficshaper/settings/search_pipes", "trafficshaper/settings/del_pipe"},
		{"alias", "firewall/alias/search_item", "firewall/alias/del_item"},
		{"group", "firewall/group/search_item", "firewall/group/del_item"},
		{"category", "firewall/category/search_item", "firewall/category/del_item"},
	} {
		var rows, searchErr = rawSearch(core, kind.search, "")
		if searchErr != nil {
			continue
		}
		if kind.what == "source nat rule" {
			// in automatic outbound NAT mode search_rule hides the manual rules, the CSV export lists them all
			rows = append(rows, rawDownloadRows(core, "firewall/source_nat/download_rules")...)
		}
		var seen = map[string]bool{}
		for _, row := range rows {
			if seen[row.Uuid] {
				continue
			}
			seen[row.Uuid] = true
			if !ownedByRun(row.Description) && !ownedByRun(row.Descr) && !ownedByRun(row.Name) && !ownedByRun(row.Ifname) {
				continue
			}
			if _, err := core.Mutate(core.EndpointForModule(kind.del+"/"+row.Uuid), nil); err == nil {
				removed = append(removed, kind.what+" "+row.Uuid)
			} else {
				fmt.Fprintf(os.Stderr, "integration/firewall: sweep could not remove %s %s: %v\n", kind.what, row.Uuid, err)
			}
		}
	}
	return removed
}

// rawDownloadRows reads the uuid and description columns of a download_rules CSV export (";" separated, "@uuid"
// first), nil on any error
func rawDownloadRows(core *api.OPNsense, endpoint string) []rawRow {
	var request, err = http.NewRequest("GET", core.EndpointForModule(endpoint), nil)
	if err != nil {
		return nil
	}
	var response, sendErr = core.Send(request)
	if sendErr != nil {
		return nil
	}
	defer func() { _ = response.Body.Close() }()
	var body, readErr = io.ReadAll(response.Body)
	if readErr != nil || response.StatusCode != http.StatusOK || len(body) == 0 {
		return nil
	}
	var reader = csv.NewReader(strings.NewReader(string(body)))
	reader.Comma = ';'
	var records, csvErr = reader.ReadAll()
	if csvErr != nil || len(records) < 2 {
		return nil
	}
	var uuidColumn, descriptionColumn = -1, -1
	for i, name := range records[0] {
		switch name {
		case "@uuid":
			uuidColumn = i
		case "description":
			descriptionColumn = i
		}
	}
	if uuidColumn < 0 || descriptionColumn < 0 {
		return nil
	}
	var rows []rawRow
	for _, record := range records[1:] {
		rows = append(rows, rawRow{Uuid: record[uuidColumn], Description: record[descriptionColumn]})
	}
	return rows
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

// testDescription returns a description for one test, e.g. "a8-fw-1a2b3c4d alias-lifecycle"
func testDescription(label string) string {
	return runPrefix + " " + label
}
