//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"opnsense-cli/opnsense/api/dnsmasq"
)

var uuidPattern = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

type opnResult struct {
	args     []string
	stdin    string
	stdout   string
	stderr   string
	exitCode int
}

func (r opnResult) String() string {
	var script string
	if r.stdin != "" {
		script = fmt.Sprintf("stdin:\n%s\n", r.stdin)
	}
	return fmt.Sprintf("opn %s\n%sexit code %d\nstdout:\n%s\nstderr:\n%s", strings.Join(r.args, " "), script, r.exitCode, r.stdout, r.stderr)
}

// opnOptions are the optional parts of an opn invocation
type opnOptions struct {
	env   []string // "NAME=value" added to the environment, "NAME=" unsets
	stdin string   // fed to stdin (a script when no command is given)
	dir   string   // working directory, an empty temp dir when ""
}

// runOpnWith runs the CLI with the current environment and the given options. stdin is never a terminal, so opn
// without a command runs stdin as a script
func runOpnWith(t *testing.T, options opnOptions, args ...string) opnResult {
	t.Helper()
	requireLive(t)
	if opnBuildErr != nil {
		t.Fatalf("the opn binary could not be built: %v", opnBuildErr)
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var command = exec.CommandContext(ctx, opnBinary, args...)
	// an empty working directory, so a .env file in the checkout can not interfere
	command.Dir = options.dir
	if command.Dir == "" {
		command.Dir = t.TempDir()
	}
	command.Env = os.Environ()
	for _, env := range options.env {
		var name, value, _ = strings.Cut(env, "=")
		command.Env = filterEnv(command.Env, name)
		if value != "" {
			command.Env = append(command.Env, name+"="+value)
		}
	}
	command.Stdin = strings.NewReader(options.stdin)

	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	var err = command.Run()
	var result = opnResult{args: args, stdin: options.stdin, stdout: stdout.String(), stderr: stderr.String()}
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

func runOpnEnv(t *testing.T, extraEnv []string, args ...string) opnResult {
	t.Helper()
	return runOpnWith(t, opnOptions{env: extraEnv}, args...)
}

func runOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	return runOpnWith(t, opnOptions{}, args...)
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

// mustFailOpn runs the CLI and fails the test unless it exits with 1 (an error, nothing done)
func mustFailOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	var result = runOpn(t, args...)
	if result.exitCode != 1 {
		t.Errorf("want exit code 1, got:\n%s", result)
	}
	if !strings.HasPrefix(result.stderr, "error: ") {
		t.Errorf("want an \"error: \" message on stderr, got:\n%s", result)
	}
	return result
}

// mustScript runs stdin as a script and fails the test unless it exits with 0
func mustScript(t *testing.T, script string) opnResult {
	t.Helper()
	var result = runOpnWith(t, opnOptions{stdin: script})
	if result.exitCode != 0 {
		t.Fatalf("want exit code 0, got:\n%s", result)
	}
	return result
}

// requireSilent fails unless a mutation printed nothing (RouterOS style)
func requireSilent(t *testing.T, result opnResult) {
	t.Helper()
	if result.stdout != "" || result.stderr != "" {
		t.Errorf("want no output:\n%s", result)
	}
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

// uuidsFrom returns every uuid on stdout in order (the uuids printed by the adds of a script)
func uuidsFrom(result opnResult) []string {
	return uuidPattern.FindAllString(result.stdout, -1)
}

func randomUuid() string {
	var b = make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// tableRows returns the rows of a print table below the header (lines starting with the # index)
func tableRows(output string) []string {
	var rows []string
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		if line != "" && line[0] >= '0' && line[0] <= '9' {
			rows = append(rows, line)
		}
	}
	return rows
}

func TestCliDnsmasqHost(t *testing.T) {
	var dnsmasqApi = dnsmasqApi(t)
	var domain = testDomain("ch")
	var fqdn = "web." + domain

	var created = mustOpn(t, "/dnsmasq/host", "add", "host=web", "domain="+domain,
		"ip=10.6.6.6,fd00::66", "cname=www."+domain, "description=cli web")
	var uuid = uuidFrom(t, created)
	cleanupRemove(t, "dnsmasq host", uuid, dnsmasqApi.HostRemove)
	if strings.TrimSpace(created.stdout) != uuid || created.stderr != "" {
		t.Errorf("add should print only the uuid:\n%s", created)
	}

	var printed = mustOpn(t, "/dnsmasq/host", "print", "search="+domain)
	requireContains(t, printed, printed.stdout, "#", "HOST", "web", domain, "10.6.6.6, fd00::66", "www."+domain, "cli web")
	if rows := tableRows(printed.stdout); len(rows) != 1 || !strings.HasPrefix(rows[0], "0 ") {
		t.Errorf("want one row #0:\n%s", printed)
	}
	var detail = mustOpn(t, "/dnsmasq/host", "print", "search="+domain, "detail")
	requireContains(t, detail, detail.stdout, uuid, "cli web")
	var jsonLines = mustOpn(t, "/dnsmasq/host", "print", "search="+domain, "json")
	if objects := requireJsonLines(t, nonEmptyLines(jsonLines.stdout)); len(objects) != 1 || objects[0]["uuid"] != uuid || objects[0]["descr"] != "cli web" {
		t.Errorf("want one raw JSON object of the host:\n%s", jsonLines)
	}

	var shown = mustOpn(t, "/dnsmasq/host", "show", fqdn)
	requireContains(t, shown, shown.stdout, "uuid:", uuid, "10.6.6.6,fd00::66", "cli web")
	shown = mustOpn(t, "/dnsmasq/host", "show", "item="+uuid)
	requireContains(t, shown, shown.stdout, "host:", "web", domain)

	t.Run("set changes only the given fields", func(t *testing.T) {
		requireSilent(t, mustOpn(t, "/dnsmasq/host", "set", fqdn, "description=cli changed"))
		var host, err = dnsmasqApi.HostGet(uuid)
		if err != nil {
			t.Fatalf("HostGet: %v", err)
		}
		if host.Description != "cli changed" || host.Ip != "10.6.6.6,fd00::66" || host.Cnames != "www."+domain {
			t.Errorf("set changed more than the description: %+v", host)
		}
	})

	t.Run("add of an existing FQDN fails without replace", func(t *testing.T) {
		var exists = mustFailOpn(t, "/dnsmasq/host", "add", "host=web", "domain="+domain, "ip=10.6.6.7")
		requireContains(t, exists, exists.stderr, "exists already", "replace")
		if host, _ := dnsmasqApi.HostGet(uuid); host.Ip != "10.6.6.6,fd00::66" {
			t.Errorf("a failed add changed the host: %+v", host)
		}
	})

	t.Run("add replace overwrites the host completely", func(t *testing.T) {
		var again = mustOpn(t, "/dnsmasq/host", "add", "host=web", "domain="+domain, "ip=10.6.6.7", "replace")
		var againUuid = uuidFrom(t, again)
		if againUuid != uuid {
			cleanupRemove(t, "dnsmasq host", againUuid, dnsmasqApi.HostRemove)
			t.Errorf("add replace of an existing FQDN created %s instead of replacing %s", againUuid, uuid)
		}
		requireContains(t, again, again.stderr, "replaced")
		var matches, _ = dnsmasqApi.HostFindByFQDN("web", domain)
		if len(matches) != 1 || matches[0].Ip != "10.6.6.7" || matches[0].Cnames != "" || matches[0].Description != "" {
			t.Errorf("want one web with ip 10.6.6.7 and the other fields cleared, got %+v", matches)
		}
	})

	t.Run("invalid ip is rejected", func(t *testing.T) {
		var invalid = mustFailOpn(t, "/dnsmasq/host", "add", "host=bad", "domain="+domain, "ip=10.6.6.999")
		requireContains(t, invalid, invalid.stderr, "10.6.6.999")
		if matches, _ := dnsmasqApi.HostFindByFQDN("bad", domain); len(matches) != 0 {
			for _, match := range matches {
				cleanupRemove(t, "dnsmasq host", match.Uuid, dnsmasqApi.HostRemove)
			}
			t.Errorf("an invalid host was created: %+v", matches)
		}
	})

	t.Run("set of an unknown uuid fails and creates nothing", func(t *testing.T) {
		var ghostUuid = randomUuid()
		cleanupRemove(t, "dnsmasq host", ghostUuid, dnsmasqApi.HostRemove)
		var notFound = mustFailOpn(t, "/dnsmasq/host", "set", ghostUuid, "host=ghost", "domain="+domain, "ip=10.6.9.9")
		requireContains(t, notFound, notFound.stderr, "not found")
		if ghost, err := dnsmasqApi.HostGet(ghostUuid); err == nil {
			t.Errorf("set of an unknown uuid created the host: %+v", ghost)
		}
	})

	t.Run("reconfigure and resolve", func(t *testing.T) {
		mustOpn(t, "/dnsmasq/service", "reconfigure")
		requireDnsReachable(t, dnsmasqDnsPort)
		requireResolves(t, dnsmasqDnsPort, fqdn, "10.6.6.7")
	})

	requireSilent(t, mustOpn(t, "/dnsmasq/host", "remove", fqdn))
	if _, err := dnsmasqApi.HostGet(uuid); err == nil {
		t.Errorf("the host still exists after remove")
	}
	var notFound = mustFailOpn(t, "/dnsmasq/host", "show", fqdn)
	requireContains(t, notFound, notFound.stderr, "not found")
	mustFailOpn(t, "/dnsmasq/host", "remove", uuid)
}

func TestCliDnsmasqDomain(t *testing.T) {
	var dnsmasqApi = dnsmasqApi(t)
	var domain = testDomain("cd")
	var fwd = "fwd." + domain

	var created = mustOpn(t, "/dnsmasq/domain", "add", "domain="+fwd, "ip=10.7.7.7", "port=5353", "description=cli fwd")
	var uuid = uuidFrom(t, created)
	cleanupRemove(t, "dnsmasq domain override", uuid, dnsmasqApi.DomainOverrideRemove)

	var printed = mustOpn(t, "/dnsmasq/domain", "print", "search="+domain)
	requireContains(t, printed, printed.stdout, fwd, "10.7.7.7", "5353", "cli fwd")

	var shown = mustOpn(t, "/dnsmasq/domain", "show", fwd)
	requireContains(t, shown, shown.stdout, uuid, "10.7.7.7", "5353")

	requireSilent(t, mustOpn(t, "/dnsmasq/domain", "set", fwd, "description=cli changed"))
	if domainOverride, err := dnsmasqApi.DomainOverrideGet(uuid); err != nil || domainOverride.Description != "cli changed" || domainOverride.Port != "5353" || domainOverride.Ip != "10.7.7.7" {
		t.Errorf("set changed more than the description: %+v (%v)", domainOverride, err)
	}

	// same domain and ip: refused without replace, replaced with it
	mustFailOpn(t, "/dnsmasq/domain", "add", "domain="+fwd, "ip=10.7.7.7", "port=5300")
	var again = mustOpn(t, "/dnsmasq/domain", "add", "domain="+fwd, "ip=10.7.7.7", "port=5300", "replace")
	if againUuid := uuidFrom(t, again); againUuid != uuid {
		cleanupRemove(t, "dnsmasq domain override", againUuid, dnsmasqApi.DomainOverrideRemove)
		t.Errorf("add replace with the same domain and ip created %s instead of replacing %s", againUuid, uuid)
	}
	if domainOverride, err := dnsmasqApi.DomainOverrideGet(uuid); err != nil || domainOverride.Port != "5300" || domainOverride.Description != "" {
		t.Errorf("add replace did not replace the entry completely: %+v (%v)", domainOverride, err)
	}

	mustFailOpn(t, "/dnsmasq/domain", "add", "domain=bad."+domain, "ip=10.7.7.7", "port=99999")
	if matches, _ := dnsmasqApi.DomainOverrideFindAll("bad."+domain, ""); len(matches) != 0 {
		t.Errorf("an invalid domain override was created: %+v", matches)
	}

	requireSilent(t, mustOpn(t, "/dnsmasq/domain", "remove", fwd))
	mustFailOpn(t, "/dnsmasq/domain", "remove", fwd)
	mustFailOpn(t, "/dnsmasq/domain", "show", uuid)
}

func TestCliUnboundHostOverride(t *testing.T) {
	var unboundApi = unboundApi(t)
	var domain = testDomain("cu")
	var fqdn = "web." + domain

	var created = mustOpn(t, "/unbound/host-override", "add", "host=web", "domain="+domain, "ip=10.8.8.8", "description=cli web")
	var uuid = uuidFrom(t, created)
	cleanupRemove(t, "unbound host override", uuid, unboundApi.HostEntryRemove)
	if strings.TrimSpace(created.stdout) != uuid {
		t.Errorf("add should print only the uuid:\n%s", created)
	}

	var shown = mustOpn(t, "/unbound/host-override", "show", fqdn)
	requireContains(t, shown, shown.stdout, uuid, "10.8.8.8", "cli web", "disabled:")

	var printed = mustOpn(t, "/unbound/host-override", "print", "search="+domain)
	requireContains(t, printed, printed.stdout, "DISABLED", "web", "10.8.8.8")

	// set changes only the given arguments
	requireSilent(t, mustOpn(t, "/unbound/host-override", "set", fqdn, "ttl=300"))
	if matches, _ := unboundApi.HostOverrideFindByFQDN("web", domain, ""); len(matches) != 1 || matches[0].Ip != "10.8.8.8" || matches[0].Ttl != "300" || matches[0].Description != "cli web" {
		t.Errorf("want one web with ip 10.8.8.8, ttl 300 and the description kept, got %+v", matches)
	}
	// set does not create
	mustFailOpn(t, "/unbound/host-override", "set", "nothere."+domain, "ip=10.8.8.1")
	if matches, _ := unboundApi.HostOverrideFindByFQDN("nothere", domain, ""); len(matches) != 0 {
		for _, match := range matches {
			cleanupRemove(t, "unbound host override", match.Uuid, unboundApi.HostEntryRemove)
		}
		t.Errorf("set of a missing FQDN created it: %+v", matches)
	}

	// add on the same FQDN and record type: refused, with replace the entry is replaced (arguments not given are reset)
	mustFailOpn(t, "/unbound/host-override", "add", "host=web", "domain="+domain, "ip=10.8.8.9")
	var again = mustOpn(t, "/unbound/host-override", "add", "host=web", "domain="+domain, "ip=10.8.8.9", "replace")
	if againUuid := uuidFrom(t, again); againUuid != uuid {
		cleanupRemove(t, "unbound host override", againUuid, unboundApi.HostEntryRemove)
		t.Errorf("add replace created %s instead of replacing %s", againUuid, uuid)
	}
	if matches, _ := unboundApi.HostOverrideFindByFQDN("web", domain, ""); len(matches) != 1 || matches[0].Ip != "10.8.8.9" || matches[0].Ttl != "" || matches[0].Description != "" {
		t.Errorf("want one web with ip 10.8.8.9 and ttl / description reset, got %+v", matches)
	}

	var txt = mustOpn(t, "/unbound/host-override", "add", "host=web", "domain="+domain, "rr=TXT", "txtdata=cli txt", "ttl=60")
	var txtUuid = uuidFrom(t, txt)
	cleanupRemove(t, "unbound host override", txtUuid, unboundApi.HostEntryRemove)
	if txtUuid == uuid {
		t.Errorf("the TXT record overwrote the A record")
	}

	t.Run("disable and enable", func(t *testing.T) {
		requireSilent(t, mustOpn(t, "/unbound/host-override", "disable", fqdn+"/TXT"))
		if override, err := unboundApi.HostOverrideGet(txtUuid); err != nil || override.Enabled != "0" {
			t.Errorf("after disable: %+v (%v)", override, err)
		}
		var disabled = mustOpn(t, "/unbound/host-override", "print", "search="+domain)
		var disabledRows []string
		for _, row := range tableRows(disabled.stdout) {
			if fields := strings.Fields(row); len(fields) > 1 && fields[1] == "yes" {
				disabledRows = append(disabledRows, row)
			}
		}
		if len(tableRows(disabled.stdout)) != 2 || len(disabledRows) != 1 || !strings.Contains(disabledRows[0], "TXT") {
			t.Errorf("want 2 rows, the TXT one disabled:\n%s", disabled)
		}
		mustOpn(t, "/unbound/host-override", "enable", txtUuid)
		if override, err := unboundApi.HostOverrideGet(txtUuid); err != nil || override.Enabled != "1" {
			t.Errorf("after enable: %+v (%v)", override, err)
		}
	})

	// two records for the FQDN: the name is ambiguous, host.domain/RR selects one
	var ambiguous = mustFailOpn(t, "/unbound/host-override", "remove", fqdn)
	requireContains(t, ambiguous, ambiguous.stderr, txtUuid)
	requireSilent(t, mustOpn(t, "/unbound/host-override", "remove", fqdn+"/TXT"))

	mustFailOpn(t, "/unbound/host-override", "add", "host=bad", "domain="+domain, "ip=10.8.8.999")
	mustFailOpn(t, "/unbound/host-override", "add", "host=bad", "domain="+domain, "rr=MX")

	t.Run("reconfigure and resolve", func(t *testing.T) {
		mustOpn(t, "/unbound/service", "reconfigure")
		requireDnsReachable(t, unboundDnsPort)
		requireResolves(t, unboundDnsPort, fqdn, "10.8.8.9")
	})

	requireSilent(t, mustOpn(t, "/unbound/host-override", "remove", fqdn))
	var notFound = mustFailOpn(t, "/unbound/host-override", "show", fqdn)
	requireContains(t, notFound, notFound.stderr, "not found")
	mustFailOpn(t, "/unbound/host-override", "remove", uuid)
}

func TestCliServiceStatus(t *testing.T) {
	for _, service := range []string{"dnsmasq", "unbound"} {
		t.Run(service, func(t *testing.T) {
			var status = mustOpn(t, "/"+service+"/service", "status")
			requireContains(t, status, status.stdout, "running")
		})
	}
}

func TestCliDnsmasqLeases(t *testing.T) {
	var leases = mustOpn(t, "/dnsmasq/lease", "print")
	requireContains(t, leases, leases.stdout, "#", "ADDRESS", "HWADDR")
	mustOpn(t, "/dnsmasq/lease", "print", "json")
}

// TestCliPathForms runs the same print in every one-shot form a path can be written in
func TestCliPathForms(t *testing.T) {
	var dnsmasqApi = dnsmasqApi(t)
	var domain = testDomain("cp")
	var uuid, err = dnsmasqApi.HostCreate(dnsmasq.Host{Host: "pf", Domain: domain, Ip: "10.6.7.1"})
	if err != nil {
		t.Fatalf("HostCreate: %v", err)
	}
	cleanupRemove(t, "dnsmasq host", uuid, dnsmasqApi.HostRemove)

	var want = mustOpn(t, "/dnsmasq", "host", "print", "search="+domain)
	requireContains(t, want, want.stdout, "pf", "10.6.7.1")
	for _, args := range [][]string{
		{"/dnsmasq/host", "print", "search=" + domain},
		{"dnsmasq/host", "print", "search=" + domain},
		{"dnsmasq", "host", "print", "search=" + domain},
		{"/dnsmasq/host/print", "search=" + domain},
		{"/dnsmasq host print search=" + domain},               // one quoted argument is split like a shell line
		{"/dns", "ho", "pr", "search=" + domain},               // abbreviations
		{"/dnsmasq/host/../host", "print", "search=" + domain}, // .. goes up
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var got = mustOpn(t, args...)
			if got.stdout != want.stdout {
				t.Errorf("want the same output as %q:\n%s", strings.Join(want.args, " "), got)
			}
		})
	}

	t.Run("quoted values in a single argument", func(t *testing.T) {
		requireSilent(t, mustOpn(t, `/dnsmasq host set pf.`+domain+` description="two words"`))
		if host, err := dnsmasqApi.HostGet(uuid); err != nil || host.Description != "two words" {
			t.Errorf("description not set from the quoted value: %+v (%v)", host, err)
		}
	})

	t.Run("menu path alone shows the menu", func(t *testing.T) {
		var menu = mustOpn(t, "/dnsmasq/host")
		requireContains(t, menu, menu.stdout, "/dnsmasq/host", "add", "print", "remove", "set", "show")
	})
}

func TestCliHelp(t *testing.T) {
	var root = mustOpn(t, "-h")
	requireContains(t, root, root.stdout, "usage: opn", "dnsmasq", "unbound", "system", "import")
	root = mustOpn(t, "/", "?")
	requireContains(t, root, root.stdout, "menus:", "dnsmasq", "firewall", "interface", "log", "system", "tool", "unbound")

	var menu = mustOpn(t, "/unbound", "host-override", "?")
	requireContains(t, menu, menu.stdout, "commands:", "add", "disable", "enable", "print", "remove", "set", "show")

	var command = mustOpn(t, "/dnsmasq/host", "add", "?")
	requireContains(t, command, command.stdout, "arguments:", "host=", "ip=<list>", "replace", "required")
	// ? anywhere on the line shows the help instead of running the command
	command = mustOpn(t, "/dnsmasq/host", "add", "host=nothere."+testDomain("help"), "?")
	requireContains(t, command, command.stdout, "arguments:")
	command = mustOpn(t, "/dnsmasq/host", "help")
	requireContains(t, command, command.stdout, "commands:", "print")

	var dangerous = mustOpn(t, "/system", "reboot", "?")
	requireContains(t, dangerous, dangerous.stdout, "confirm")
}

// TestCliScript runs a script on stdin: navigation lines, # comments, # indexes of the last print
func TestCliScript(t *testing.T) {
	var dnsmasqApi = dnsmasqApi(t)
	var domain = testDomain("cs")

	var script = strings.Join([]string{
		"# a comment",
		"/dnsmasq/host",
		"add host=s1 domain=" + domain + " ip=10.6.8.1",
		"add host=s2 domain=" + domain + " ip=10.6.8.2 description=\"second host\"",
		"print search=" + domain,
		"set 1 description=\"via index\"",
		"remove 0",
		"..",
		"domain",
		"add domain=fwd." + domain + " ip=10.6.8.53",
		"/",
		"dnsmasq host print search=" + domain,
	}, "\n")
	var result = mustScript(t, script)
	var uuids = uuidsFrom(result)
	for _, uuid := range uuids {
		cleanupRemove(t, "dnsmasq host", uuid, dnsmasqApi.HostRemove)
		cleanupRemove(t, "dnsmasq domain override", uuid, dnsmasqApi.DomainOverrideRemove)
	}
	if len(uuids) < 3 {
		t.Fatalf("want the uuids of the three adds:\n%s", result)
	}
	if _, err := dnsmasqApi.HostGet(uuids[0]); err == nil {
		t.Errorf("remove 0 did not remove s1 (#0 of the print)")
	}
	if host, err := dnsmasqApi.HostGet(uuids[1]); err != nil || host.Description != "via index" {
		t.Errorf("set 1 did not change s2 (#1 of the print): %+v (%v)", host, err)
	}
	if domainOverride, err := dnsmasqApi.DomainOverrideGet(uuids[2]); err != nil || domainOverride.Domain != "fwd."+domain {
		t.Errorf("the add after the navigation to ../domain did not add the domain override: %+v (%v)", domainOverride, err)
	}
	// the last print (from the root, with a path) shows only s2
	var lastPrint = result.stdout[strings.LastIndex(result.stdout, "#  "):]
	if rows := tableRows(lastPrint); len(rows) != 1 || !strings.Contains(rows[0], "s2") {
		t.Errorf("want only s2 in the last print:\n%s", result)
	}

	t.Run("an error stops the script and names the line", func(t *testing.T) {
		var failing = runOpnWith(t, opnOptions{stdin: strings.Join([]string{
			"/dnsmasq/host",
			"print search=" + domain,
			"remove 5",
			"add host=never domain=" + domain + " ip=10.6.8.9",
		}, "\n")})
		if failing.exitCode != 1 {
			t.Errorf("want exit code 1:\n%s", failing)
		}
		requireContains(t, failing, failing.stderr, "stdin:3:", "#5")
		if matches, _ := dnsmasqApi.HostFindByFQDN("never", domain); len(matches) != 0 {
			for _, match := range matches {
				cleanupRemove(t, "dnsmasq host", match.Uuid, dnsmasqApi.HostRemove)
			}
			t.Errorf("the line after the error was run: %+v", matches)
		}
	})

	t.Run("an index removed since the print is refused", func(t *testing.T) {
		var stale = runOpnWith(t, opnOptions{stdin: "/dnsmasq/host\nprint search=" + domain + "\nremove 0\nremove 0\n"})
		requireContains(t, stale, stale.stderr, "stdin:4:", "removed since the last print")
		// remove 0 removed s2, the second one must not remove anything else
		if _, err := dnsmasqApi.HostGet(uuids[1]); err == nil {
			t.Errorf("s2 still exists after remove 0")
		}
	})

	t.Run("dangerous commands are refused without confirm", func(t *testing.T) {
		// stdin is not a terminal, so there is nobody to ask: a following "y" line is not an answer
		var refused = runOpnWith(t, opnOptions{stdin: "/log clear system\ny\n"})
		if refused.exitCode != 1 {
			t.Errorf("want exit code 1:\n%s", refused)
		}
		requireContains(t, refused, refused.stderr, "stdin:1:", "confirm=yes")
	})
}

// TestCliImport runs a script file with /import
func TestCliImport(t *testing.T) {
	var dnsmasqApi = dnsmasqApi(t)
	var domain = testDomain("ci")
	var dir = t.TempDir()
	var script = strings.Join([]string{
		"# opn script",
		"/dnsmasq host",
		"add host=i1 domain=" + domain + " ip=10.6.9.1",
		"add host=i2 domain=" + domain + " ip=10.6.9.2",
		"print search=" + domain,
		"remove 1",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "setup.rsc"), []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}

	var result = runOpnWith(t, opnOptions{dir: dir}, "/import", "setup.rsc")
	var uuids = uuidsFrom(result)
	for _, uuid := range uuids {
		cleanupRemove(t, "dnsmasq host", uuid, dnsmasqApi.HostRemove)
	}
	if result.exitCode != 0 || len(uuids) != 2 {
		t.Fatalf("want exit code 0 and two uuids:\n%s", result)
	}
	if _, err := dnsmasqApi.HostGet(uuids[0]); err != nil {
		t.Errorf("i1 is missing: %v", err)
	}
	if _, err := dnsmasqApi.HostGet(uuids[1]); err == nil {
		t.Errorf("remove 1 did not remove i2")
	}

	t.Run("import from a script on stdin, errors name file and line", func(t *testing.T) {
		var broken = "/dnsmasq/host\nadd host=i3 domain=" + domain + " ip=10.6.9.999\n"
		if err := os.WriteFile(filepath.Join(dir, "broken.rsc"), []byte(broken), 0o600); err != nil {
			t.Fatal(err)
		}
		var failing = runOpnWith(t, opnOptions{dir: dir, stdin: "/dnsmasq/lease\n/import file=broken.rsc\nprint\n"})
		if failing.exitCode != 1 {
			t.Errorf("want exit code 1:\n%s", failing)
		}
		requireContains(t, failing, failing.stderr, "stdin:2:", "broken.rsc:2:", "10.6.9.999")
		if failing.stdout != "" {
			t.Errorf("the line after the failed import was run:\n%s", failing)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		var missing = runOpnWith(t, opnOptions{dir: dir}, "/import", "nothere.rsc")
		if missing.exitCode != 1 || !strings.Contains(missing.stderr, "nothere.rsc") {
			t.Errorf("want exit code 1 naming the file:\n%s", missing)
		}
	})
}

func TestCliErrors(t *testing.T) {
	t.Run("bad credentials", func(t *testing.T) {
		var result = runOpnEnv(t, []string{"OPN_APIKEY=invalid-key", "OPN_APISECRET=invalid-secret"}, "/dnsmasq/host", "print")
		if result.exitCode != 1 {
			t.Errorf("want exit code 1:\n%s", result)
		}
		requireContains(t, result, result.stderr, "401")
	})

	t.Run("missing configuration", func(t *testing.T) {
		var result = runOpnEnv(t, []string{"OPN_URL="}, "/unbound/service", "status")
		if result.exitCode != 1 {
			t.Errorf("want exit code 1:\n%s", result)
		}
		requireContains(t, result, result.stderr, "OPN_URL")
	})

	t.Run("show of an unknown host", func(t *testing.T) {
		var result = mustFailOpn(t, "/dnsmasq/host", "show", "nothere."+testDomain("ce"))
		requireContains(t, result, result.stderr, "not found")
	})

	t.Run("unknown menu or command", func(t *testing.T) {
		var result = mustFailOpn(t, "/dnsmasq/nothere", "print")
		requireContains(t, result, result.stderr, "nothere")
		result = mustFailOpn(t, "/dnsmasq/host", "create", "host=x")
		requireContains(t, result, result.stderr, "create")
	})

	t.Run("ambiguous abbreviation", func(t *testing.T) {
		var result = mustFailOpn(t, "/system", "re")
		requireContains(t, result, result.stderr, "ambiguous", "reboot", "resource")
	})

	t.Run("argument errors send nothing", func(t *testing.T) {
		var domain = testDomain("ce")
		var result = mustFailOpn(t, "/dnsmasq/host", "add", "domain="+domain)
		requireContains(t, result, result.stderr, "host", "required")
		result = mustFailOpn(t, "/dnsmasq/host", "add", "host=x", "domain="+domain, "bogus=1")
		requireContains(t, result, result.stderr, "bogus")
		result = mustFailOpn(t, "/dnsmasq/host", "add", "host=x", "domain="+domain, "local=maybe")
		requireContains(t, result, result.stderr, "local")
		if matches, _ := dnsmasqApi(t).HostFindByFQDN("x", domain); len(matches) != 0 {
			t.Errorf("a failed add created %+v", matches)
		}
	})

	t.Run("unknown option", func(t *testing.T) {
		var result = runOpn(t, "--nothere")
		if result.exitCode != 2 || !strings.Contains(result.stderr, "usage: opn") {
			t.Errorf("want exit code 2 and the usage:\n%s", result)
		}
	})

	t.Run("unterminated quote", func(t *testing.T) {
		var result = mustFailOpn(t, `/dnsmasq host set x description="open`)
		requireContains(t, result, result.stderr, "quote")
	})
}
