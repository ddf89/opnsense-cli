//go:build integration

// Package integration runs the library and the opn CLI against a live OPNsense (26.7) instance.
//
//	go test -tags integration ./integration/... -count=1 -v
//
// Configuration (first match wins):
//   - OPN_URL / OPN_APIKEY / OPN_APISECRET / OPN_NOSSLVERIFY, like the CLI
//   - OPNSENSE_API_KEY / OPNSENSE_API_SECRET (devcontainer, see ~/.opnsense-env) with https://opnsense-dev and no TLS verification
//
// Every test is skipped when there are no credentials or the instance is unreachable.
//
// Isolation: the tests only create records below run<random>.a7-it.test, register a cleanup by uuid right after
// every create and finally sweep (only) that per-run domain, so concurrent users of the instance are not affected.
// Services are never stopped; unbound is restarted at most once per run.
package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dnsmasq"
	"opnsense-cli/opnsense/api/unbound"
)

const (
	baseDomain     = "a7-it.test"
	defaultUrl     = "https://opnsense-dev"
	dnsmasqDnsPort = "53053"
	unboundDnsPort = "53"
)

var (
	// skipReason is set by TestMain when the live instance can not be used, every test skips with it
	skipReason string
	// runDomain is the per-run domain all records are created in, e.g. run1a2b3c4d.a7-it.test
	runDomain string
	// opnBinary is the CLI built once by TestMain, opnBuildErr is set when that failed
	opnBinary   string
	opnBuildErr error
	// opnHost is the host name of OPN_URL, used for the DNS checks
	opnHost string
)

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	var random = make([]byte, 4)
	_, _ = rand.Read(random)
	runDomain = fmt.Sprintf("run%s.%s", hex.EncodeToString(random), baseDomain)

	skipReason = configureEnv()
	if skipReason == "" {
		skipReason = probe()
	}
	if skipReason != "" {
		fmt.Fprintf(os.Stderr, "integration: skipping all tests: %s\n", skipReason)
		return m.Run()
	}
	fmt.Fprintf(os.Stderr, "integration: using %s, records are created below %s\n", os.Getenv("OPN_URL"), runDomain)

	var tmpDir, err = os.MkdirTemp("", "opn-integration-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	opnBinary, opnBuildErr = buildOpn(tmpDir)

	var code = m.Run()

	if leftovers := sweep(); len(leftovers) > 0 {
		fmt.Fprintf(os.Stderr, "integration: the final sweep removed records the tests did not clean up: %s\n", strings.Join(leftovers, ", "))
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
		// the devcontainer instance uses a self-signed certificate
		fallback("OPN_NOSSLVERIFY", "1")
	}

	if os.Getenv("OPN_APIKEY") == "" || os.Getenv("OPN_APISECRET") == "" {
		return "no credentials, set OPN_URL / OPN_APIKEY / OPN_APISECRET (or OPNSENSE_API_KEY / OPNSENSE_API_SECRET)"
	}

	var parsed, err = url.Parse(os.Getenv("OPN_URL"))
	if err != nil || parsed.Hostname() == "" {
		return fmt.Sprintf("invalid OPN_URL %q", os.Getenv("OPN_URL"))
	}
	opnHost = parsed.Hostname()
	return ""
}

// probe checks quickly that the instance answers authenticated API calls
func probe() string {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return err.Error()
	}

	var conn net.Conn
	var host = core.BaseUrl.Host
	if core.BaseUrl.Port() == "" {
		host = net.JoinHostPort(core.BaseUrl.Hostname(), map[bool]string{true: "443", false: "80"}[core.BaseUrl.Scheme == "https"])
	}
	if conn, err = net.DialTimeout("tcp", host, 5*time.Second); err != nil {
		return fmt.Sprintf("%s is unreachable: %v", host, err)
	}
	_ = conn.Close()

	var status struct {
		Status string `json:"status"`
	}
	if err := core.DoJSON("GET", core.EndpointForPluginControllerMethod("dnsmasq", "service", "status"), nil, &status); err != nil {
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
	build.Dir = ".." // module root
	if output, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build failed: %v\n%s", err, output)
	}
	return binary, nil
}

// sweep removes everything that is still left below runDomain (and only that) and returns what it removed
func sweep() []string {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return nil
	}
	var removed []string
	var dnsmasqApi = &dnsmasq.DnsmasqApi{OPNsense: core}
	var unboundApi = &unbound.UnboundApi{OPNsense: core}

	if hosts, err := dnsmasqApi.HostList(runDomain); err == nil {
		for _, host := range hosts {
			if inRunDomain(host.Domain) && dnsmasqApi.HostRemove(host.Uuid) == nil {
				removed = append(removed, "dnsmasq host "+host.FQDN())
			}
		}
	}
	if domains, err := dnsmasqApi.DomainOverrideList(runDomain); err == nil {
		for _, domain := range domains {
			if inRunDomain(domain.Domain) && dnsmasqApi.DomainOverrideRemove(domain.Uuid) == nil {
				removed = append(removed, "dnsmasq domain "+domain.Domain)
			}
		}
	}
	if overrides, err := unboundApi.HostOverrideSearch(runDomain); err == nil {
		for _, override := range overrides {
			if inRunDomain(override.Domain) && unboundApi.HostEntryRemove(override.Uuid) == nil {
				removed = append(removed, fmt.Sprintf("unbound host override %s.%s", override.Host, override.Domain))
			}
		}
	}
	return removed
}

func inRunDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	return domain == runDomain || strings.HasSuffix(domain, "."+runDomain)
}

// --- helpers shared by the tests ---

// requireLive skips the test when the instance is not usable
func requireLive(t *testing.T) {
	t.Helper()
	if skipReason != "" {
		t.Skip(skipReason)
	}
}

// testDomain returns a fresh domain below runDomain for one test, e.g. "uho.run1a2b3c4d.a7-it.test"
func testDomain(label string) string {
	return fmt.Sprintf("%s.%s", label, runDomain)
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

func dnsmasqApi(t *testing.T) *dnsmasq.DnsmasqApi {
	t.Helper()
	return &dnsmasq.DnsmasqApi{OPNsense: coreApi(t)}
}

func unboundApi(t *testing.T) *unbound.UnboundApi {
	t.Helper()
	return &unbound.UnboundApi{OPNsense: coreApi(t)}
}

// cleanupRemove registers a removal that tolerates the entry being gone already (e.g. removed by the test itself)
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

func asValidationError(t *testing.T, err error, wantFields ...string) {
	t.Helper()
	var validationErr *api.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("want *api.ValidationError, got %T: %v", err, err)
	}
	for _, field := range wantFields {
		if _, ok := validationErr.Validations[field]; !ok {
			t.Errorf("validation error lacks field %q: %v", field, validationErr.Validations)
		}
	}
}

func requireNotFound(t *testing.T, err error, what string) {
	t.Helper()
	if !api.IsNotFound(err) {
		t.Errorf("%s: want *api.NotFoundError, got %T: %v", what, err, err)
	}
}

func requireTooManyFound(t *testing.T, err error, what string) {
	t.Helper()
	var tooMany *api.TooManyFoundError
	if !errors.As(err, &tooMany) {
		t.Errorf("%s: want *api.TooManyFoundError, got %T: %v", what, err, err)
	}
}

// resolverFor returns a resolver that sends every query to opnHost:port via UDP
func resolverFor(port string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
			var dialer = net.Dialer{Timeout: 2 * time.Second}
			return dialer.DialContext(ctx, "udp", net.JoinHostPort(opnHost, port))
		},
	}
}

// dnsUnreachable caches the result of the DNS probe per port, "" when reachable
var (
	dnsProbeMutex  sync.Mutex
	dnsUnreachable = map[string]*string{}
)

// requireDnsReachable skips the test unless a DNS server answers on opnHost:port. Any DNS answer (also NXDOMAIN)
// proves the server is reachable, a timeout or ICMP port unreachable does not. Probed once per port and run
func requireDnsReachable(t *testing.T, port string) {
	t.Helper()
	dnsProbeMutex.Lock()
	defer dnsProbeMutex.Unlock()

	if dnsUnreachable[port] == nil {
		var reason = ""
		var ctx, cancel = context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		// a trailing dot avoids the search domains of resolv.conf
		var _, err = resolverFor(port).LookupHost(ctx, "probe."+runDomain+".")
		var dnsErr *net.DNSError
		if err != nil && (!errors.As(err, &dnsErr) || !dnsErr.IsNotFound) {
			reason = fmt.Sprintf("no DNS server reachable on %s:%s from here: %v", opnHost, port, err)
		}
		dnsUnreachable[port] = &reason
	}
	if *dnsUnreachable[port] != "" {
		t.Skip(*dnsUnreachable[port])
	}
}

// requireResolves polls the DNS server on opnHost:port until fqdn resolves to wantIp (reconfigure is asynchronous)
func requireResolves(t *testing.T, port string, fqdn string, wantIp string) {
	t.Helper()
	var deadline = time.Now().Add(20 * time.Second)
	var lastIps []string
	var lastErr error
	for time.Now().Before(deadline) {
		var ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
		lastIps, lastErr = resolverFor(port).LookupHost(ctx, strings.TrimSuffix(fqdn, ".")+".")
		cancel()
		for _, ip := range lastIps {
			if net.ParseIP(ip).Equal(net.ParseIP(wantIp)) {
				return
			}
		}
		time.Sleep(time.Second)
	}
	t.Errorf("%s did not resolve to %s via %s:%s, last answer %v, error %v", fqdn, wantIp, opnHost, port, lastIps, lastErr)
}
