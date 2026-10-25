//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

var uuidPattern = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

type opnResult struct {
	args     []string
	stdout   string
	stderr   string
	exitCode int
}

func (r opnResult) String() string {
	return fmt.Sprintf("opn %s\nexit code %d\nstdout:\n%s\nstderr:\n%s", strings.Join(r.args, " "), r.exitCode, r.stdout, r.stderr)
}

// runOpnEnv runs the CLI with the current environment plus extraEnv ("NAME=value", "NAME=" to unset)
func runOpnEnv(t *testing.T, extraEnv []string, args ...string) opnResult {
	t.Helper()
	requireLive(t)
	if opnBuildErr != nil {
		t.Fatalf("the opn binary could not be built: %v", opnBuildErr)
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var command = exec.CommandContext(ctx, opnBinary, args...)
	// an empty working directory, so a .env file in the checkout can not interfere
	command.Dir = t.TempDir()
	command.Env = os.Environ()
	for _, env := range extraEnv {
		var name, value, _ = strings.Cut(env, "=")
		command.Env = filterEnv(command.Env, name)
		if value != "" {
			command.Env = append(command.Env, name+"="+value)
		}
	}

	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	var err = command.Run()
	var result = opnResult{args: args, stdout: stdout.String(), stderr: stderr.String()}
	if exitErr, ok := err.(*exec.ExitError); ok {
		result.exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running opn %v: %v", args, err)
	}
	return result
}

func filterEnv(env []string, name string) []string {
	var filtered = make([]string, 0, len(env))
	for _, entry := range env {
		if !strings.HasPrefix(entry, name+"=") {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func runOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	return runOpnEnv(t, nil, args...)
}

// mustOpn runs the CLI and fails the test unless it exits with 0
func mustOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	var result = runOpn(t, args...)
	if result.exitCode != 0 {
		t.Fatalf("want exit code 0, got:\n%s", result)
	}
	return result
}

// mustFailOpn runs the CLI and fails the test unless it exits with a non zero code
func mustFailOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	var result = runOpn(t, args...)
	if result.exitCode == 0 {
		t.Errorf("want a non zero exit code, got:\n%s", result)
	}
	return result
}

func requireContains(t *testing.T, result opnResult, output string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(output, w) {
			t.Errorf("output lacks %q:\n%s", w, result)
		}
	}
}

func uuidFrom(t *testing.T, result opnResult) string {
	t.Helper()
	var uuid = uuidPattern.FindString(result.stdout)
	if uuid == "" {
		t.Fatalf("no uuid in the output:\n%s", result)
	}
	return uuid
}

func randomUuid() string {
	var b = make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func TestCliDnsmasqHost(t *testing.T) {
	var dnsmasqApi = dnsmasqApi(t)
	var domain = testDomain("ch")

	var created = mustOpn(t, "dnsmasq", "host", "create", "--host", "web", "--domain", domain,
		"--ip", "10.6.6.6", "--ip", "fd00::66", "--cname", "www."+domain, "--description", "cli web")
	var uuid = uuidFrom(t, created)
	cleanupRemove(t, "dnsmasq host", uuid, dnsmasqApi.HostRemove)
	if strings.TrimSpace(created.stdout) != uuid {
		t.Errorf("create should print only the uuid:\n%s", created)
	}

	var listed = mustOpn(t, "dnsmasq", "host", "list", "--search", domain)
	requireContains(t, listed, listed.stdout, "UUID", uuid, "web", domain, "10.6.6.6, fd00::66", "www."+domain, "cli web")

	var shown = mustOpn(t, "dnsmasq", "host", "show", "--host", "web", "--domain", domain)
	requireContains(t, shown, shown.stdout, uuid, "10.6.6.6,fd00::66", "cli web")
	shown = mustOpn(t, "dnsmasq", "host", "show", "--uuid", uuid)
	requireContains(t, shown, shown.stdout, "web", domain)

	t.Run("update changes only the given fields", func(t *testing.T) {
		var updated = mustOpn(t, "dnsmasq", "host", "update", "--host", "web", "--domain", domain, "--description", "cli changed")
		requireContains(t, updated, updated.stdout, uuid)
		var host, err = dnsmasqApi.HostGet(uuid)
		if err != nil {
			t.Fatalf("HostGet: %v", err)
		}
		if host.Description != "cli changed" || host.Ip != "10.6.6.6,fd00::66" || host.Cnames != "www."+domain {
			t.Errorf("update changed more than the description: %+v", host)
		}
	})

	t.Run("create on an existing FQDN updates it", func(t *testing.T) {
		var again = mustOpn(t, "dnsmasq", "host", "create", "--host", "web", "--domain", domain, "--ip", "10.6.6.7")
		var againUuid = uuidFrom(t, again)
		if againUuid != uuid {
			cleanupRemove(t, "dnsmasq host", againUuid, dnsmasqApi.HostRemove)
			t.Errorf("create of an existing FQDN created %s instead of updating %s", againUuid, uuid)
		}
		requireContains(t, again, again.stderr, "updated")
		var matches, _ = dnsmasqApi.HostFindByFQDN("web", domain)
		if len(matches) != 1 || matches[0].Ip != "10.6.6.7" {
			t.Errorf("want one web with ip 10.6.6.7, got %+v", matches)
		}
	})

	t.Run("invalid ip is rejected", func(t *testing.T) {
		mustFailOpn(t, "dnsmasq", "host", "create", "--host", "bad", "--domain", domain, "--ip", "10.6.6.999")
		if matches, _ := dnsmasqApi.HostFindByFQDN("bad", domain); len(matches) != 0 {
			for _, match := range matches {
				cleanupRemove(t, "dnsmasq host", match.Uuid, dnsmasqApi.HostRemove)
			}
			t.Errorf("an invalid host was created: %+v", matches)
		}
	})

	t.Run("update of an unknown uuid fails and creates nothing", func(t *testing.T) {
		var ghostUuid = randomUuid()
		cleanupRemove(t, "dnsmasq host", ghostUuid, dnsmasqApi.HostRemove)
		mustFailOpn(t, "dnsmasq", "host", "update", "--uuid", ghostUuid, "--host", "ghost", "--domain", domain, "--ip", "10.6.9.9")
		if ghost, err := dnsmasqApi.HostGet(ghostUuid); err == nil {
			t.Errorf("update --uuid of an unknown uuid created the host: %+v", ghost)
		}
	})

	t.Run("reconfigure and resolve", func(t *testing.T) {
		var reconfigured = mustOpn(t, "dnsmasq", "service", "reconfigure")
		requireContains(t, reconfigured, reconfigured.stderr, "reconfigured")
		requireDnsReachable(t, dnsmasqDnsPort)
		requireResolves(t, dnsmasqDnsPort, "web."+domain, "10.6.6.7")
	})

	var removed = mustOpn(t, "dnsmasq", "host", "rm", "--host", "web", "--domain", domain)
	requireContains(t, removed, removed.stdout, "deleted", uuid)
	var notFound = mustFailOpn(t, "dnsmasq", "host", "show", "--host", "web", "--domain", domain)
	requireContains(t, notFound, notFound.stdout+notFound.stderr, "not found")
	mustFailOpn(t, "dnsmasq", "host", "rm", "--uuid", uuid)
}

func TestCliDnsmasqDomain(t *testing.T) {
	var dnsmasqApi = dnsmasqApi(t)
	var domain = testDomain("cd")
	var fwd = "fwd." + domain

	var created = mustOpn(t, "dnsmasq", "domain", "create", "--domain", fwd, "--ip", "10.7.7.7", "--port", "5353", "--description", "cli fwd")
	var uuid = uuidFrom(t, created)
	cleanupRemove(t, "dnsmasq domain override", uuid, dnsmasqApi.DomainOverrideRemove)

	var listed = mustOpn(t, "dnsmasq", "domain", "list", "--search", domain)
	requireContains(t, listed, listed.stdout, uuid, fwd, "10.7.7.7", "5353", "cli fwd")

	var shown = mustOpn(t, "dnsmasq", "domain", "show", "--domain", fwd)
	requireContains(t, shown, shown.stdout, uuid, "10.7.7.7", "5353")

	var updated = mustOpn(t, "dnsmasq", "domain", "update", "--domain", fwd, "--description", "cli changed")
	requireContains(t, updated, updated.stdout, uuid)
	if domainOverride, err := dnsmasqApi.DomainOverrideGet(uuid); err != nil || domainOverride.Description != "cli changed" || domainOverride.Port != "5353" || domainOverride.Ip != "10.7.7.7" {
		t.Errorf("update changed more than the description: %+v (%v)", domainOverride, err)
	}

	// same domain and ip: update instead of a duplicate
	var again = mustOpn(t, "dnsmasq", "domain", "create", "--domain", fwd, "--ip", "10.7.7.7", "--port", "5300")
	if againUuid := uuidFrom(t, again); againUuid != uuid {
		cleanupRemove(t, "dnsmasq domain override", againUuid, dnsmasqApi.DomainOverrideRemove)
		t.Errorf("create with the same domain and ip created %s instead of updating %s", againUuid, uuid)
	}

	mustFailOpn(t, "dnsmasq", "domain", "create", "--domain", "bad."+domain, "--ip", "10.7.7.7", "--port", "99999")

	var removed = mustOpn(t, "dnsmasq", "domain", "rm", "--domain", fwd)
	requireContains(t, removed, removed.stdout, "deleted", uuid)
	mustFailOpn(t, "dnsmasq", "domain", "rm", "--domain", fwd)
	mustFailOpn(t, "dnsmasq", "domain", "show", "--uuid", uuid)
}

func TestCliUnboundHostOverride(t *testing.T) {
	var unboundApi = unboundApi(t)
	var domain = testDomain("cu")

	var created = mustOpn(t, "unbound", "hostoverride", "create", "--host", "web", "--domain", domain, "--ip", "10.8.8.8", "--description", "cli web")
	requireContains(t, created, created.stdout, "Created successfully")
	var uuid = uuidFrom(t, created)
	cleanupRemove(t, "unbound host override", uuid, unboundApi.HostEntryRemove)

	var shown = mustOpn(t, "unbound", "hostoverride", "show", "--host", "web", "--domain", domain)
	requireContains(t, shown, shown.stdout, uuid, "10.8.8.8", "cli web")

	var listed = mustOpn(t, "unbound", "hostoverride", "list", "--search", domain)
	requireContains(t, listed, listed.stdout, uuid, "web", "10.8.8.8")

	// update changes only the given flags
	var updated = mustOpn(t, "unbound", "hostoverride", "update", "--host", "web", "--domain", domain, "--ttl", "300")
	requireContains(t, updated, updated.stdout, "Updated successfully", uuid)
	if matches, _ := unboundApi.HostOverrideFindByFQDN("web", domain, ""); len(matches) != 1 || matches[0].Ip != "10.8.8.8" || matches[0].Ttl != "300" || matches[0].Description != "cli web" {
		t.Errorf("want one web with ip 10.8.8.8, ttl 300 and the description kept, got %+v", matches)
	}
	// update does not create
	mustFailOpn(t, "unbound", "hostoverride", "update", "--host", "nothere", "--domain", domain, "--ip", "10.8.8.1")
	if matches, _ := unboundApi.HostOverrideFindByFQDN("nothere", domain, ""); len(matches) != 0 {
		for _, match := range matches {
			cleanupRemove(t, "unbound host override", match.Uuid, unboundApi.HostEntryRemove)
		}
		t.Errorf("update of a missing FQDN created it: %+v", matches)
	}

	// create on the same FQDN and record type replaces the entry (flags not given are reset)
	var again = mustOpn(t, "unbound", "hostoverride", "create", "--host", "web", "--domain", domain, "--ip", "10.8.8.9")
	requireContains(t, again, again.stdout, "Updated successfully", uuid)
	if matches, _ := unboundApi.HostOverrideFindByFQDN("web", domain, ""); len(matches) != 1 || matches[0].Ip != "10.8.8.9" || matches[0].Ttl != "" || matches[0].Description != "" {
		t.Errorf("want one web with ip 10.8.8.9 and ttl / description reset, got %+v", matches)
	}

	var txt = mustOpn(t, "unbound", "hostoverride", "create", "--host", "web", "--domain", domain, "--rr", "TXT", "--txtdata", "cli txt", "--ttl", "60")
	var txtUuid = uuidFrom(t, txt)
	cleanupRemove(t, "unbound host override", txtUuid, unboundApi.HostEntryRemove)
	if txtUuid == uuid {
		t.Errorf("the TXT record overwrote the A record")
	}
	// two records for the FQDN: rm needs --rr
	mustFailOpn(t, "unbound", "hostoverride", "rm", "--host", "web", "--domain", domain)
	mustOpn(t, "unbound", "hostoverride", "rm", "--host", "web", "--domain", domain, "--rr", "TXT")

	mustFailOpn(t, "unbound", "hostoverride", "create", "--host", "bad", "--domain", domain, "--ip", "10.8.8.999")

	t.Run("reconfigure and resolve", func(t *testing.T) {
		mustOpn(t, "unbound", "service", "reconfigure")
		requireDnsReachable(t, unboundDnsPort)
		requireResolves(t, unboundDnsPort, "web."+domain, "10.8.8.9")
	})

	var removed = mustOpn(t, "unbound", "hostoverride", "rm", "--host", "web", "--domain", domain)
	requireContains(t, removed, removed.stdout, "deleted", uuid)
	var notFound = mustFailOpn(t, "unbound", "hostoverride", "show", "--host", "web", "--domain", domain)
	requireContains(t, notFound, notFound.stdout+notFound.stderr, "not found")
	mustFailOpn(t, "unbound", "hostoverride", "rm", "--uuid", uuid)
}

func TestCliServiceStatus(t *testing.T) {
	for _, service := range []string{"dnsmasq", "unbound"} {
		t.Run(service, func(t *testing.T) {
			var status = mustOpn(t, service, "service", "status")
			requireContains(t, status, status.stdout+status.stderr, "running")
		})
	}
}

func TestCliDnsmasqLeases(t *testing.T) {
	var leases = mustOpn(t, "dnsmasq", "leases", "list")
	requireContains(t, leases, leases.stdout, "ADDRESS")
}

func TestCliErrors(t *testing.T) {
	t.Run("bad credentials", func(t *testing.T) {
		var result = runOpnEnv(t, []string{"OPN_APIKEY=invalid-key", "OPN_APISECRET=invalid-secret"}, "dnsmasq", "host", "list")
		if result.exitCode == 0 {
			t.Errorf("want a non zero exit code:\n%s", result)
		}
		requireContains(t, result, result.stdout+result.stderr, "401")
	})

	t.Run("missing configuration", func(t *testing.T) {
		var result = runOpnEnv(t, []string{"OPN_URL="}, "unbound", "service", "status")
		if result.exitCode == 0 {
			t.Errorf("want a non zero exit code:\n%s", result)
		}
		requireContains(t, result, result.stdout+result.stderr, "OPN_URL")
	})

	t.Run("show of an unknown host", func(t *testing.T) {
		var result = mustFailOpn(t, "dnsmasq", "host", "show", "--host", "nothere", "--domain", testDomain("ce"))
		requireContains(t, result, result.stdout+result.stderr, "not found")
	})
}
