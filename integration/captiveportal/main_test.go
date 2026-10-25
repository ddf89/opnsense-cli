//go:build integration

// Package integrationcaptiveportal runs the captive portal library (opnsense/api/captiveportal) and the opn
// /captive-portal menus against a live OPNsense (26.7) instance.
//
//	go test -tags integration ./integration/captiveportal/... -count=1 -v
//
// Configuration: OPN_URL / OPN_APIKEY / OPN_APISECRET / OPN_NOSSLVERIFY like the CLI, or OPNSENSE_API_KEY /
// OPNSENSE_API_SECRET with https://opnsense-dev. Every test is skipped without credentials or when unreachable.
//
// Safety (the instance is shared): zones are only created DISABLED (a disabled zone has no effect: no pf or ipfw
// rules, no service; checked in the OPNsense 26.7 source), they are never enabled and the captive portal is never
// reconfigured, started or stopped (reconfigure also reloads ipfw). Zones are described a9-cp-<run id> ..., templates
// named a9_cp_<run id> ... (template names allow no dashes). Vouchers are only generated when a voucher provider
// exists, into a group named after the run, which is dropped afterwards. TestMain finally sweeps (only) zones and
// templates of this run and fails the run if it found any.
package integrationcaptiveportal

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
	"opnsense-cli/opnsense/api/captiveportal"
)

const (
	defaultUrl = "https://opnsense-dev"
	basePrefix = "a9-cp-"
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
		fmt.Fprintf(os.Stderr, "integration/captiveportal: skipping all tests: %s\n", skipReason)
		return m.Run()
	}
	fmt.Fprintf(os.Stderr, "integration/captiveportal: using %s, records are named %s...\n", os.Getenv("OPN_URL"), runPrefix)

	var tmpDir, err = os.MkdirTemp("", "opn-integration-captiveportal-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration/captiveportal: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	opnBinary, opnBuildErr = buildOpn(tmpDir)

	var code = m.Run()
	if leftovers := sweep(); len(leftovers) > 0 {
		fmt.Fprintf(os.Stderr, "integration/captiveportal: the final sweep removed records the tests did not clean up: %s\n",
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
	if _, err := (&captiveportal.CaptivePortalApi{OPNsense: core}).ZoneList(""); err != nil {
		return fmt.Sprintf("captive portal probe failed: %v", err)
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

// templatePrefix is runPrefix in the spelling template names allow
func templatePrefix() string {
	return strings.ReplaceAll(runPrefix, "-", "_")
}

// sweep removes the zones and templates (and only those) of this run, zones first
func sweep() []string {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return nil
	}
	var removed []string
	for _, kind := range []struct{ what, search, del, prefix string }{
		{"zone", "captiveportal/settings/search_zones", "captiveportal/settings/del_zone", runPrefix},
		{"template", "captiveportal/template/search_templates", "captiveportal/template/del_template", templatePrefix()},
	} {
		var rows, searchErr = api.Search[struct {
			Uuid        string `json:"uuid"`
			Name        string `json:"name"`
			Description string `json:"description"`
		}](core, core.EndpointForModule(kind.search), kind.prefix)
		if searchErr != nil {
			continue
		}
		for _, row := range rows {
			if !strings.HasPrefix(row.Name+row.Description, kind.prefix) {
				continue
			}
			if _, err := core.Mutate(core.EndpointForModule(kind.del+"/"+row.Uuid), nil); err == nil {
				removed = append(removed, kind.what+" "+row.Uuid)
			} else {
				fmt.Fprintf(os.Stderr, "integration/captiveportal: sweep could not remove %s %s: %v\n", kind.what, row.Uuid, err)
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

func testApi(t *testing.T) *captiveportal.CaptivePortalApi {
	t.Helper()
	requireLive(t)
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		t.Fatalf("ConfigureFromEnv: %v", err)
	}
	return &captiveportal.CaptivePortalApi{OPNsense: core}
}

// testDescription returns a zone description for one test, e.g. "a9-cp-1a2b3c4d lib"
func testDescription(label string) string {
	return runPrefix + " " + label
}

// testTemplateName returns a template name for one test, e.g. "a9_cp_1a2b3c4d lib"
func testTemplateName(label string) string {
	return templatePrefix() + " " + label
}
