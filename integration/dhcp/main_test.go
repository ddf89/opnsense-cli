//go:build integration

// Package integrationdhcp runs the DHCP services library (opnsense/api/dhcp: Kea, DHCP relay, radvd) and the opn
// /kea, /dhcrelay and /radvd menus against a live OPNsense (26.7) instance.
//
//	go test -tags integration ./integration/dhcp/... -count=1 -v
//
// Configuration (first match wins):
//   - OPN_URL / OPN_APIKEY / OPN_APISECRET / OPN_NOSSLVERIFY, like the CLI
//   - OPNSENSE_API_KEY / OPNSENSE_API_SECRET (devcontainer, see ~/.opnsense-env) with https://opnsense-dev and no
//     TLS verification
//
// Every test is skipped when there are no credentials or the instance is unreachable.
//
// Safety (the instance is shared; a second DHCP server or router advertisements on LAN/WAN would disturb it): Kea
// stays disabled (the settings are snapshotted at the start and restored, and only changed while Kea is disabled),
// subnets and reservations use documentation networks (198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), relays and
// radvd entries are created disabled. Nothing is started; the only applies are "/kea/service reconfigure" while both
// Kea servers are disabled (it stops Kea and rewrites its configuration files) and "/dhcrelay/service reconfigure"
// while every relay is disabled (it stops relays that do not run). radvd is never reconfigured, started or stopped.
// Records carry the prefix a5-dhcp-<random run id> (in the description, name, hostname or DNS search domain);
// TestMain sweeps (only) records with this run's prefix and fails the run if it found any or if the settings
// differ from the snapshot.
package integrationdhcp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dhcp"
)

const (
	defaultUrl = "https://opnsense-dev"
	basePrefix = "a5-dhcp-"
)

var (
	// skipReason is set by TestMain when the live instance can not be used, every test skips with it
	skipReason string
	// runPrefix tags every record this run creates, e.g. a5-dhcp-1a2b3c4d
	runPrefix string
	// opnBinary is the CLI built once by TestMain, opnBuildErr is set when that failed
	opnBinary   string
	opnBuildErr error
	// settingsAtStart are the Kea settings before any test, restored by TestMain if a test did not
	settingsAtStart map[string]dhcp.Fields
)

// keaSettingsSpecs are the settings the tests may change
var keaSettingsSpecs = map[string]dhcp.SettingsSpec{
	"dhcpv4": dhcp.KeaDhcp4Settings, "dhcpv6": dhcp.KeaDhcp6Settings, "ctrlagent": dhcp.KeaCtrlAgentSettings, "ddns": dhcp.KeaDdnsSettings,
}

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
		fmt.Fprintf(os.Stderr, "integration/dhcp: skipping all tests: %s\n", skipReason)
		return m.Run()
	}
	fmt.Fprintf(os.Stderr, "integration/dhcp: using %s, records are tagged %s\n", os.Getenv("OPN_URL"), runPrefix)

	var tmpDir, err = os.MkdirTemp("", "opn-integration-dhcp-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration/dhcp: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	opnBinary, opnBuildErr = buildOpn(tmpDir)

	var code = m.Run()

	if leftovers := sweep(); len(leftovers) > 0 {
		fmt.Fprintf(os.Stderr, "integration/dhcp: the final sweep removed records the tests did not clean up: %s\n", strings.Join(leftovers, ", "))
		if code == 0 {
			code = 1
		}
	}
	if changed := restoreSettings(); len(changed) > 0 {
		fmt.Fprintf(os.Stderr, "integration/dhcp: the Kea settings %s differed from the start and were restored\n", strings.Join(changed, ", "))
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
	return ""
}

// probe checks that the instance answers the Kea API and snapshots the Kea settings
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

	var dhcpApi = &dhcp.DhcpApi{OPNsense: core}
	settingsAtStart = map[string]dhcp.Fields{}
	for name, spec := range keaSettingsSpecs {
		var form, getErr = dhcpApi.SettingsGet(spec)
		if getErr != nil {
			return fmt.Sprintf("kea probe failed: %v", getErr)
		}
		settingsAtStart[name] = form.Fields()
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

// --- sweep and settings restore (raw calls, deliberately not the menus under test)

// ownedByRun reports whether a text carries this run's prefix
func ownedByRun(text string) bool {
	return runPrefix != "" && strings.Contains(text, runPrefix)
}

// sweep removes every record (and only those) tagged with this run's prefix and returns what it removed:
// reservations and pd pools before subnets before options (they refer to each other), relays before destinations
func sweep() []string {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return nil
	}
	var removed []string
	for _, kind := range []struct {
		what   string
		search string
		del    string
		fields []string
	}{
		{"kea dhcpv4 reservation", "kea/dhcpv4/search_reservation", "kea/dhcpv4/del_reservation", []string{"description", "hostname"}},
		{"kea dhcpv6 reservation", "kea/dhcpv6/search_reservation", "kea/dhcpv6/del_reservation", []string{"description", "hostname"}},
		{"kea dhcpv6 pd pool", "kea/dhcpv6/search_pd_pool", "kea/dhcpv6/del_pd_pool", []string{"description"}},
		{"kea dhcpv4 subnet", "kea/dhcpv4/search_subnet", "kea/dhcpv4/del_subnet", []string{"description"}},
		{"kea dhcpv6 subnet", "kea/dhcpv6/search_subnet", "kea/dhcpv6/del_subnet", []string{"description"}},
		{"kea dhcpv4 option", "kea/dhcpv4/search_option", "kea/dhcpv4/del_option", []string{"description"}},
		{"kea dhcpv6 option", "kea/dhcpv6/search_option", "kea/dhcpv6/del_option", []string{"description"}},
		{"kea dhcpv4 peer", "kea/dhcpv4/search_peer", "kea/dhcpv4/del_peer", []string{"name"}},
		{"kea dhcpv6 peer", "kea/dhcpv6/search_peer", "kea/dhcpv6/del_peer", []string{"name"}},
		{"dhcrelay relay", "dhcrelay/settings/search_relay", "dhcrelay/settings/del_relay", []string{"%destination"}},
		{"dhcrelay destination", "dhcrelay/settings/search_dest", "dhcrelay/settings/del_dest", []string{"name"}},
		{"radvd entry", "radvd/settings/search_entry", "radvd/settings/del_entry", []string{"DNSSL"}},
	} {
		var rows, searchErr = api.Search[map[string]any](core, core.EndpointForModule(kind.search), "")
		if searchErr != nil {
			continue
		}
		for _, row := range rows {
			var owned = false
			for _, field := range kind.fields {
				if text, isText := row[field].(string); isText && ownedByRun(text) {
					owned = true
				}
			}
			var uuid, _ = row["uuid"].(string)
			if !owned || uuid == "" {
				continue
			}
			if _, err := core.Mutate(core.EndpointForModule(kind.del+"/"+uuid), nil); err == nil {
				removed = append(removed, kind.what+" "+uuid)
			} else {
				fmt.Fprintf(os.Stderr, "integration/dhcp: sweep could not remove %s %s: %v\n", kind.what, uuid, err)
			}
		}
	}
	return removed
}

// restoreSettings writes back the Kea settings of the start where they differ and returns the names of those
func restoreSettings() []string {
	var core, err = api.ConfigureFromEnv()
	if err != nil || settingsAtStart == nil {
		return nil
	}
	var dhcpApi = &dhcp.DhcpApi{OPNsense: core}
	var changed []string
	for name, spec := range keaSettingsSpecs {
		var form, getErr = dhcpApi.SettingsGet(spec)
		if getErr != nil || reflect.DeepEqual(form.Fields(), settingsAtStart[name]) {
			continue
		}
		changed = append(changed, name)
		if err := dhcpApi.SettingsSet(spec, settingsAtStart[name]); err != nil {
			fmt.Fprintf(os.Stderr, "integration/dhcp: restoring the %s failed: %v\n", spec.What(), err)
		}
	}
	return changed
}

// --- helpers shared by the tests

// requireLive skips the test when the instance is not usable
func requireLive(t *testing.T) {
	t.Helper()
	if skipReason != "" {
		t.Skip(skipReason)
	}
}

func dhcpApi(t *testing.T) *dhcp.DhcpApi {
	t.Helper()
	requireLive(t)
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		t.Fatalf("ConfigureFromEnv: %v", err)
	}
	return &dhcp.DhcpApi{OPNsense: core}
}

// testLabel returns a description for one test, e.g. "a5-dhcp-1a2b3c4d subnet-lifecycle"
func testLabel(label string) string {
	return runPrefix + " " + label
}

// testHostname returns a host name tagged with the run prefix, e.g. "a5-dhcp-1a2b3c4d-printer"
func testHostname(label string) string {
	return runPrefix + "-" + label
}

// requireKeaDisabled skips tests that change Kea settings unless both Kea servers are disabled (so the changes can
// not reach a running server)
func requireKeaDisabled(t *testing.T, dhcpApi *dhcp.DhcpApi) {
	t.Helper()
	for _, spec := range []dhcp.SettingsSpec{dhcp.KeaDhcp4Settings, dhcp.KeaDhcp6Settings} {
		var form, err = dhcpApi.SettingsGet(spec)
		if err != nil {
			t.Fatal(err)
		}
		if form.Value("general.enabled") != "0" {
			t.Skipf("the %s are enabled, the tests only change Kea while it is disabled", spec.What())
		}
	}
}

// keaDhcp6WithInterface selects iface in the DHCPv6 interfaces (a DHCPv6 subnet needs it) while DHCPv6 stays
// disabled, and restores the interfaces when the test ends
func keaDhcp6WithInterface(t *testing.T, dhcpApi *dhcp.DhcpApi, iface string) {
	t.Helper()
	requireKeaDisabled(t, dhcpApi)
	var form, err = dhcpApi.SettingsGet(dhcp.KeaDhcp6Settings)
	if err != nil {
		t.Fatal(err)
	}
	var before = form.Value("general.interfaces")
	var selected = before
	if !strings.Contains(","+before+",", ","+iface+",") {
		selected = strings.Trim(before+","+iface, ",")
	}
	if err := dhcpApi.SettingsSet(dhcp.KeaDhcp6Settings, dhcp.Fields{"general.interfaces": selected}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := dhcpApi.SettingsSet(dhcp.KeaDhcp6Settings, dhcp.Fields{"general.interfaces": before}); err != nil {
			t.Errorf("restoring the DHCPv6 interfaces %q: %v", before, err)
		}
	})
}
