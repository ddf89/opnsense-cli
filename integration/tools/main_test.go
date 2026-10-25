//go:build integration

// Package integrationtools runs the interactive diagnostics of the library (opnsense/api/diagnostics: ping,
// traceroute, port probe, DNS lookup, packet capture, ARP/NDP, netstat, CARP status) and the opn /tool and
// /interface/{arp,ndp,netstat,vip-status} menus against a live OPNsense (26.7) instance.
//
//	go test -tags integration ./integration/tools/... -count=1 -v
//
// Configuration (first match wins):
//   - OPN_URL / OPN_APIKEY / OPN_APISECRET / OPN_NOSSLVERIFY, like the CLI
//   - OPNSENSE_API_KEY / OPNSENSE_API_SECRET (devcontainer, see ~/.opnsense-env) with https://opnsense-dev and no
//     TLS verification
//
// Every test is skipped when there are no credentials or the instance is unreachable.
//
// Safety: pings, traceroutes and port probes only go to 127.0.0.1, 192.168.1.1 (the firewall's LAN address) and
// 10.0.2.2 (the qemu gateway), DNS lookups ask 127.0.0.1 for localhost, packet captures run on lo0 only with a
// packet limit. The ARP table is never flushed and the CARP state never changed (only the refusals without
// confirmation are run). Ping and capture jobs carry the description prefix a7-tools-<random run id>; TestMain
// finally removes (only) jobs with this run's prefix and fails the run if it found any.
package integrationtools

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
	"opnsense-cli/opnsense/api/diagnostics"
)

const (
	defaultUrl = "https://opnsense-dev"
	basePrefix = "a7-tools-"
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
		fmt.Fprintf(os.Stderr, "integration/tools: skipping all tests: %s\n", skipReason)
		return m.Run()
	}
	fmt.Fprintf(os.Stderr, "integration/tools: using %s, jobs are tagged %s\n", os.Getenv("OPN_URL"), runPrefix)

	var tmpDir, err = os.MkdirTemp("", "opn-integration-tools-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration/tools: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	opnBinary, opnBuildErr = buildOpn(tmpDir)

	var code = m.Run()

	if leftovers := sweep(); len(leftovers) > 0 {
		fmt.Fprintf(os.Stderr, "integration/tools: the final sweep removed jobs the tests did not clean up: %s\n", strings.Join(leftovers, ", "))
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
	if _, err := (&diagnostics.DiagnosticsApi{OPNsense: core}).PingJobs(); err != nil {
		return fmt.Sprintf("ping job probe failed: %v", err)
	}
	return ""
}

func buildOpn(dir string) (string, error) {
	var binary = filepath.Join(dir, "opn")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	var build = exec.Command("go", "build", "-o", binary, ".")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build failed: %v\n%s", err, output)
	}
	return binary, nil
}

func requireLive(t *testing.T) {
	t.Helper()
	if skipReason != "" {
		t.Skip(skipReason)
	}
}

// diagApi returns the library under test
func diagApi(t *testing.T) *diagnostics.DiagnosticsApi {
	t.Helper()
	requireLive(t)
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	return &diagnostics.DiagnosticsApi{OPNsense: core}
}

// sweep removes the ping and capture jobs (and only those) with this run's prefix, by raw API calls
func sweep() []string {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return nil
	}
	var removed []string
	for _, controller := range []string{"ping", "packet_capture"} {
		var rows, searchErr = api.Search[struct {
			Id          string `json:"id"`
			Description string `json:"description"`
		}](core, core.EndpointForPluginControllerMethod("diagnostics", controller, "search_jobs"), "")
		if searchErr != nil {
			continue
		}
		for _, row := range rows {
			if !strings.HasPrefix(row.Description, runPrefix) {
				continue
			}
			var answer struct {
				Status string `json:"status"`
			}
			if err := core.DoJSON("POST", core.EndpointForPluginControllerMethod("diagnostics", controller, "remove/"+row.Id), map[string]any{}, &answer); err == nil && answer.Status == "ok" {
				removed = append(removed, controller+" job "+row.Id)
			} else {
				fmt.Fprintf(os.Stderr, "integration/tools: sweep could not remove %s job %s: %v %s\n", controller, row.Id, err, answer.Status)
			}
		}
	}
	return removed
}
