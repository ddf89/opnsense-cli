//go:build integration

// Package integrationinterfaces runs the interfaces library (opnsense/api/interfaces) and the opn /interface
// menus against a live OPNsense (26.7) instance.
//
//	go test -tags integration ./integration/interfaces/... -count=1 -v
//
// Configuration (first match wins):
//   - OPN_URL / OPN_APIKEY / OPN_APISECRET / OPN_NOSSLVERIFY, like the CLI
//   - OPNSENSE_API_KEY / OPNSENSE_API_SECRET (devcontainer, see ~/.opnsense-env) with https://opnsense-dev and no
//     TLS verification
//
// Every test is skipped when there are no credentials or the instance is unreachable.
//
// Safety (the instance is shared, and an interface mistake can cut everybody off): records carry the description
// prefix a5-if-<random run id> (VXLANs, which have no description, a VNI of this run), use documentation addresses
// (192.0.2.0/24, 198.51.100.0/24) and never the WAN subnet; VLANs are created on vtnet0 (LAN) with a tag of 4000 or
// higher, virtual IPs only on lo0, GIF/GRE tunnels with a documentation local address. Nothing is ever put into a
// LAGG or bridge (the only candidates are the LAN/WAN devices), the interface settings are never changed (settings:
// one field is set and restored without applying). Assignments: only a loopback of this run is assigned (description
// a5_if_<run id>…), lan and wan are never touched, and the assignment apply only runs when nothing but this run's
// assignment is staged (see assignmentOnlyOwnStaged). Apply is only run for VLANs, loopbacks,
// VXLANs, virtual IPs and neighbors (scoped to their own device type, see the OPNsense scripts) and only while every
// configured item of that type belongs to this run; LAGG, bridge, GIF, GRE and settings apply and the interface
// reload are tested with fakes only. TestMain finally sweeps (only) the records of this run.
package integrationinterfaces

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/interfaces"
)

const (
	defaultUrl = "https://opnsense-dev"
	basePrefix = "a5-if-"
	// vniCount VNIs from runVni on belong to this run
	vniCount = 10
)

var (
	// skipReason is set by TestMain when the live instance can not be used, every test skips with it
	skipReason string
	// runPrefix is the description prefix of every record this run creates, e.g. a5-if-1a2b3c4d
	runPrefix string
	// runVni is the first VXLAN network identifier of this run
	runVni int
	// opnBinary is the CLI built once by TestMain, opnBuildErr is set when that failed
	opnBinary   string
	opnBuildErr error
)

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	var random = make([]byte, 8)
	_, _ = rand.Read(random)
	runPrefix = basePrefix + hex.EncodeToString(random[:4])
	runVni = 10_000_000 + int(binary.BigEndian.Uint32(random[4:])%6_000_000)

	skipReason = configureEnv()
	if skipReason == "" {
		skipReason = probe()
	}
	if skipReason != "" {
		fmt.Fprintf(os.Stderr, "integration/interfaces: skipping all tests: %s\n", skipReason)
		return m.Run()
	}
	fmt.Fprintf(os.Stderr, "integration/interfaces: using %s, records are tagged %s, VNIs %d-%d\n", os.Getenv("OPN_URL"),
		runPrefix, runVni, runVni+vniCount-1)

	var tmpDir, err = os.MkdirTemp("", "opn-integration-interfaces-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration/interfaces: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	opnBinary, opnBuildErr = buildOpn(tmpDir)
	assignmentBaseline()

	var code = m.Run()

	if leftovers := sweep(); len(leftovers) > 0 {
		fmt.Fprintf(os.Stderr, "integration/interfaces: the final sweep removed records the tests did not clean up: %s\n",
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

// probe checks quickly that the instance answers authenticated API calls of the interfaces module and has the
// expected LAN device vtnet0 (the VLAN tests use it as parent)
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

	var assignments, listErr = (&interfaces.InterfacesApi{OPNsense: core}).Assignments()
	if listErr != nil {
		return fmt.Sprintf("interfaces probe failed: %v", listErr)
	}
	for _, assignment := range assignments {
		if assignment.Identifier == "lan" && assignment.Device == "vtnet0" {
			return ""
		}
	}
	return "the instance has no LAN on vtnet0, the VLAN tests need it"
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

// ownedByRun tells whether an item belongs to this run: its description carries the run prefix, a VXLAN has a VNI
// of this run
func ownedByRun(kind interfaces.Kind, item interfaces.Item) bool {
	if kind.Name == interfaces.Vxlans.Name {
		var vni, err = strconv.Atoi(item.Get("vxlanid"))
		return err == nil && vni >= runVni && vni < runVni+vniCount
	}
	for _, field := range []string{"descr", "description"} {
		if strings.HasPrefix(item.Get(field), runPrefix) {
			return true
		}
	}
	return false
}

// liveApplied are the kinds the tests apply live, the sweep applies them again after removing leftovers when no
// other items of the kind exist
var liveApplied = []interfaces.Kind{interfaces.Vlans, interfaces.Loopbacks, interfaces.Vxlans, interfaces.Vips, interfaces.Neighbors}

// sweep removes every item (and only those) of this run and returns what it removed
func sweep() []string {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return nil
	}
	var ifApi = &interfaces.InterfacesApi{OPNsense: core}
	// assignments first, an assigned device can not be removed
	var removed = sweepAssignments(ifApi)
	for _, kind := range interfaces.Kinds {
		var items, listErr = ifApi.List(kind)
		if listErr != nil {
			continue
		}
		var removedHere, others = 0, 0
		for _, item := range items {
			if !ownedByRun(kind, item) {
				others++
				continue
			}
			if err := ifApi.Remove(kind, item.Uuid); err != nil {
				fmt.Fprintf(os.Stderr, "integration/interfaces: sweep could not remove %s %s: %v\n", kind.Name, item.Uuid, err)
				continue
			}
			removed = append(removed, kind.Name+" "+item.Uuid)
			removedHere++
		}
		if removedHere > 0 && others == 0 && isLiveApplied(kind) {
			if err := ifApi.Reconfigure(kind); err != nil {
				fmt.Fprintf(os.Stderr, "integration/interfaces: sweep could not apply the %s removal: %v\n", kind.Name, err)
			}
		}
	}
	return removed
}

func isLiveApplied(kind interfaces.Kind) bool {
	for _, applied := range liveApplied {
		if applied.Name == kind.Name {
			return true
		}
	}
	return false
}

// --- helpers shared by the tests

// requireLive skips the test when the instance is not usable
func requireLive(t *testing.T) {
	t.Helper()
	if skipReason != "" {
		t.Skip(skipReason)
	}
}

func ifApi(t *testing.T) *interfaces.InterfacesApi {
	t.Helper()
	requireLive(t)
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		t.Fatalf("ConfigureFromEnv: %v", err)
	}
	return &interfaces.InterfacesApi{OPNsense: core}
}

// testDescription returns a description for one test, e.g. "a5-if-1a2b3c4d vlan"
func testDescription(label string) string {
	return runPrefix + " " + label
}

// removeCleanup removes the item when the test ends (it may be removed already)
func removeCleanup(t *testing.T, ifs *interfaces.InterfacesApi, kind interfaces.Kind, uuid string) {
	t.Helper()
	t.Cleanup(func() {
		if err := ifs.Remove(kind, uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of %s %s: %v", kind.Name, uuid, err)
		}
	})
}

// onlyOwnItems tells whether every configured item of the kind belongs to this run, apply is only run live then
func onlyOwnItems(t *testing.T, ifs *interfaces.InterfacesApi, kind interfaces.Kind) bool {
	t.Helper()
	var items, err = ifs.List(kind)
	if err != nil {
		t.Fatalf("list %s: %v", kind.Name, err)
	}
	for _, item := range items {
		if !ownedByRun(kind, item) {
			t.Logf("not applying %s changes live: %s %s belongs to someone else", kind.Name, kind.Name, item.Uuid)
			return false
		}
	}
	return true
}

// freeVlanTag returns a tag of 4000 or higher that no VLAN on vtnet0 uses, offset spreads parallel tests
func freeVlanTag(t *testing.T, ifs *interfaces.InterfacesApi, offset int) string {
	t.Helper()
	var items, err = ifs.List(interfaces.Vlans)
	if err != nil {
		t.Fatalf("list VLANs: %v", err)
	}
	var used = map[string]bool{}
	for _, item := range items {
		if item.Get("if") == "vtnet0" {
			used[item.Get("tag")] = true
		}
	}
	for i := 0; i < 95; i++ {
		var candidate = strconv.Itoa(4000 + (runVni+offset*7+i)%95)
		if !used[candidate] {
			return candidate
		}
	}
	t.Fatal("no free VLAN tag from 4000 on vtnet0")
	return ""
}

// overviewDevice returns the overview entry of a device, ok false when it does not exist
func overviewDevice(t *testing.T, ifs *interfaces.InterfacesApi, device string) (interfaces.OverviewInterface, bool) {
	t.Helper()
	var list, err = ifs.Overview("")
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	for _, entry := range list {
		if entry.Device == device {
			return entry, true
		}
	}
	return interfaces.OverviewInterface{}, false
}
