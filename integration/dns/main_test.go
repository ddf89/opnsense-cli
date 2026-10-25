//go:build integration

// Package integrationdns runs the Dnsmasq DHCP / settings and Unbound ACL / forward / blocklist / alias /
// settings / statistics parts of the library and the opn CLI against a live OPNsense (26.7) instance.
//
//	go test -tags integration ./integration/dns/... -count=1 -v
//
// Configuration like the other integration packages: OPN_URL / OPN_APIKEY / OPN_APISECRET / OPN_NOSSLVERIFY, or
// OPNSENSE_API_KEY / OPNSENSE_API_SECRET with https://opnsense-dev. Every test skips without a usable instance.
//
// Safety (Unbound is the resolver of the box, Dnsmasq may be its DHCP server): records carry the prefix
// a9-dns-<random run id> (tags a9dns-<run id>, domains <run id>.a9-dns.test), Unbound records are created
// disabled, DHCP ranges only in 192.0.2.0/24 without interface, DHCP options and boot entries only for the run's
// own tag, which no client gets. Nothing is applied: no reconfigure of Dnsmasq or Unbound, no blocklist update.
// Changed settings are harmless ones and are restored. TestMain finally sweeps the run's records.
package integrationdns

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dnsmasq"
	"opnsense-cli/opnsense/api/unbound"
)

var (
	skipReason  string
	runId       string
	opnBinary   string
	opnBuildErr error
)

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	var random = make([]byte, 4)
	_, _ = rand.Read(random)
	runId = hex.EncodeToString(random)

	skipReason = configureEnv()
	if skipReason == "" {
		if core, err := api.ConfigureFromEnv(); err != nil {
			skipReason = err.Error()
		} else if _, err := (&unbound.UnboundApi{OPNsense: core}).ServiceStatus(); err != nil {
			skipReason = fmt.Sprintf("status probe failed: %v", err)
		}
	}
	if skipReason != "" {
		fmt.Fprintf(os.Stderr, "integration/dns: skipping all tests: %s\n", skipReason)
		return m.Run()
	}
	fmt.Fprintf(os.Stderr, "integration/dns: using %s, records are tagged %s\n", os.Getenv("OPN_URL"), prefix())

	var tmpDir, err = os.MkdirTemp("", "opn-integration-dns-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration/dns: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	opnBinary = filepath.Join(tmpDir, "opn")
	var build = exec.Command("go", "build", "-o", opnBinary, ".")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		opnBuildErr = fmt.Errorf("go build failed: %v\n%s", err, output)
	}

	var code = m.Run()
	if leftovers := sweep(); len(leftovers) > 0 {
		fmt.Fprintf(os.Stderr, "integration/dns: the final sweep removed: %s\n", strings.Join(leftovers, ", "))
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
	fallback("OPN_URL", "https://opnsense-dev")
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

// prefix is the description prefix of the run's records, tagName the run's tag prefix, domain the run's domain
func prefix() string  { return "a9-dns-" + runId }
func tagName() string { return "a9dns-" + runId }
func domain() string  { return runId + ".a9-dns.test" }

func owned(text string) bool {
	return runId != "" && (strings.HasPrefix(text, prefix()) || strings.HasPrefix(text, tagName()) ||
		strings.HasSuffix(strings.TrimSuffix(text, "."), domain()))
}

// sweep removes the run's records (dependents first) and returns what it removed
func sweep() []string {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return nil
	}
	var removed []string
	for _, kind := range []struct{ what, search, del string }{
		{"dnsmasq option", "dnsmasq/settings/search_option", "dnsmasq/settings/del_option"},
		{"dnsmasq boot", "dnsmasq/settings/search_boot", "dnsmasq/settings/del_boot"},
		{"dnsmasq range", "dnsmasq/settings/search_range", "dnsmasq/settings/del_range"},
		{"dnsmasq tag", "dnsmasq/settings/search_tag", "dnsmasq/settings/del_tag"},
		{"unbound acl", "unbound/settings/search_acl", "unbound/settings/del_acl"},
		{"unbound forward", "unbound/settings/search_forward", "unbound/settings/del_forward"},
		{"unbound dot", "unbound/settings/search_dot", "unbound/settings/del_forward"},
		{"unbound blocklist", "unbound/settings/search_dnsbl", "unbound/settings/del_dnsbl"},
		{"unbound host alias", "unbound/settings/search_host_alias", "unbound/settings/del_host_alias"},
		{"unbound host override", "unbound/settings/search_host_override", "unbound/settings/del_host_override"},
	} {
		var rows, searchErr = api.Search[map[string]any](core, core.EndpointForModule(kind.search), "")
		if searchErr != nil {
			continue
		}
		for _, row := range rows {
			var mine = false
			for _, field := range []string{"description", "tag", "name", "domain"} {
				if text, ok := row[field].(string); ok && owned(text) {
					mine = true
				}
			}
			var uuid, _ = row["uuid"].(string)
			if !mine || uuid == "" {
				continue
			}
			if _, err := core.Mutate(core.EndpointForModule(kind.del+"/"+uuid), nil); err == nil {
				removed = append(removed, kind.what+" "+uuid)
			} else {
				fmt.Fprintf(os.Stderr, "integration/dns: sweep could not remove %s %s: %v\n", kind.what, uuid, err)
			}
		}
	}
	return removed
}

// --- helpers

func coreApi(t *testing.T) *api.OPNsense {
	t.Helper()
	if skipReason != "" {
		t.Skip(skipReason)
	}
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		t.Fatalf("ConfigureFromEnv: %v", err)
	}
	return core
}

func dnsmasqApi(t *testing.T) *dnsmasq.DnsmasqApi {
	t.Helper()
	return &dnsmasq.DnsmasqApi{OPNsense: coreApi(t)}
}

func unboundApi(t *testing.T) *unbound.UnboundApi {
	t.Helper()
	return &unbound.UnboundApi{OPNsense: coreApi(t)}
}

// cleanupRemove registers a removal that tolerates the record being gone already
func cleanupRemove(t *testing.T, what string, uuid string, remove func(string) error) {
	t.Helper()
	if uuid == "" {
		return
	}
	t.Cleanup(func() {
		if err := remove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of %s %s failed: %v", what, uuid, err)
		}
	})
}

// opn runs the CLI and returns stdout, failing the test on a non-zero exit
func opn(t *testing.T, args ...string) string {
	t.Helper()
	var stdout, stderr, err = opnRun(t, args...)
	if err != nil {
		t.Fatalf("opn %s: %v\nstdout: %s\nstderr: %s", strings.Join(args, " "), err, stdout, stderr)
	}
	return stdout
}

// opnFails runs the CLI expecting a failure whose output contains want
func opnFails(t *testing.T, want string, args ...string) {
	t.Helper()
	var stdout, stderr, err = opnRun(t, args...)
	if err == nil || !strings.Contains(stdout+stderr, want) {
		t.Errorf("opn %s: want a failure containing %q, got %v\nstdout: %s\nstderr: %s", strings.Join(args, " "), want, err, stdout, stderr)
	}
}

func opnRun(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	coreApi(t)
	if opnBuildErr != nil {
		t.Fatal(opnBuildErr)
	}
	var command = exec.Command(opnBinary, args...)
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	var err = command.Run()
	return stdout.String(), stderr.String(), err
}
