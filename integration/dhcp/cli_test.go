//go:build integration

package integrationdhcp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The opn /kea, /dhcrelay and /radvd menus through the binary against the live box

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

// runOpn runs the CLI in an empty temp dir with the current environment, stdin feeds a script
func runOpn(t *testing.T, stdin string, args ...string) opnResult {
	t.Helper()
	requireLive(t)
	if opnBuildErr != nil {
		t.Fatalf("the opn binary could not be built: %v", opnBuildErr)
	}
	var ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var command = exec.CommandContext(ctx, opnBinary, args...)
	command.Dir = t.TempDir()
	command.Env = os.Environ()
	command.Stdin = strings.NewReader(stdin)
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	var err = command.Run()
	var result = opnResult{args: args, stdout: stdout.String(), stderr: stderr.String()}
	if exitErr, ok := err.(*exec.ExitError); ok {
		result.exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running opn %v: %v", args, err)
	}
	return result
}

func mustOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	var result = runOpn(t, "", args...)
	if result.exitCode != 0 {
		t.Fatalf("want exit code 0, got:\n%s", result)
	}
	return result
}

func mustFailOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	var result = runOpn(t, "", args...)
	if result.exitCode != 1 || !strings.HasPrefix(result.stderr, "error: ") {
		t.Errorf("want exit code 1 and an \"error: \" message, got:\n%s", result)
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

func TestCliKeaDhcp4(t *testing.T) {
	var option = testLabel("cli-option")
	var subnet = testLabel("cli-subnet")
	var host = testHostname("cli-host")
	var optionUuid = uuidFrom(t, mustOpn(t, "/kea/dhcp4/option", "add", "description="+option, "code=224", "data=0a0b0c"))
	t.Cleanup(func() { runOpn(t, "", "/kea/dhcp4/option", "remove", optionUuid) })
	var subnetUuid = uuidFrom(t, mustOpn(t, "/kea/dhcp4/subnet", "add", "subnet=203.0.113.0/24", "description="+subnet,
		"pools=203.0.113.10-203.0.113.20,203.0.113.64/26", "auto-options=no", "routers=203.0.113.1", "options="+option,
		"ddns-key-name=k", "ddns-key-secret=c2VjcmV0", "ddns-key-algorithm=hmac-sha256"))
	t.Cleanup(func() { runOpn(t, "", "/kea/dhcp4/subnet", "remove", subnetUuid) })

	// the TSIG secret is never shown
	var show = mustOpn(t, "/kea/dhcp4/subnet", "show", subnet)
	requireContains(t, show, show.stdout, "203.0.113.10-203.0.113.20,203.0.113.64/26", "options:", option, "ddns-key-secret:", "********")
	var asJSON = mustOpn(t, "/kea/dhcp4/subnet", "print", "json", "search="+runPrefix)
	if strings.Contains(show.stdout+asJSON.stdout, "c2VjcmV0") || !strings.Contains(asJSON.stdout, "********") {
		t.Errorf("the secret leaked or is missing:\n%s\n%s", show, asJSON)
	}
	mustFailOpn(t, "/kea/dhcp4/subnet", "add", "subnet=203.0.113.5/24")

	// the subnet is found from the address; # indexes, set, the duplicate check and the in use refusal in a script
	var reservationUuid = uuidFrom(t, mustOpn(t, "/kea/dhcp4/reservation", "add", "ip-address=203.0.113.50", "mac-address=02:00:5e:10:00:a5", "hostname="+host))
	t.Cleanup(func() { runOpn(t, "", "/kea/dhcp4/reservation", "remove", reservationUuid) })
	var script = runOpn(t, fmt.Sprintf("/kea/dhcp4/reservation\nprint search=%s\nset 0 description=%q\nshow %s\n", runPrefix, testLabel("cli-res"), host))
	if script.exitCode != 0 {
		t.Fatalf("script failed:\n%s", script)
	}
	requireContains(t, script, script.stdout, "203.0.113.0/24", "203.0.113.50", "02:00:5e:10:00:a5", testLabel("cli-res"))
	var duplicate = mustFailOpn(t, "/kea/dhcp4/reservation", "add", "ip-address=203.0.113.51", "mac-address=02-00-5E-10-00-A5")
	requireContains(t, duplicate, duplicate.stderr, "exists already", reservationUuid)
	var outside = mustFailOpn(t, "/kea/dhcp4/reservation", "add", "subnet="+subnet, "ip-address=192.0.2.9", "mac-address=02:00:5e:10:00:a6")
	requireContains(t, outside, outside.stderr, "ip-address: Address not in specified subnet")
	var inUse = mustFailOpn(t, "/kea/dhcp4/subnet", "remove", subnet)
	requireContains(t, inUse, inUse.stderr, "in use by", reservationUuid)

	mustOpn(t, "/kea/dhcp4/reservation", "remove", host)
	mustOpn(t, "/kea/dhcp4/subnet", "remove", subnet)
	mustOpn(t, "/kea/dhcp4/option", "remove", option)
	var after = mustOpn(t, "/kea/dhcp4/subnet", "print", "search="+runPrefix)
	if strings.Contains(after.stdout, runPrefix) {
		t.Errorf("not removed:\n%s", after)
	}
}

func TestCliKeaDhcp6(t *testing.T) {
	var dhcpApi = dhcpApi(t)
	keaDhcp6WithInterface(t, dhcpApi, "lan")
	var subnet = testLabel("cli-v6")
	var subnetUuid = uuidFrom(t, mustOpn(t, "/kea/dhcp6/subnet", "add", "subnet=2001:db8:a6::/64", "interface=lan", "description="+subnet,
		"pools=2001:db8:a6::100-2001:db8:a6::1ff"))
	t.Cleanup(func() { runOpn(t, "", "/kea/dhcp6/subnet", "remove", subnetUuid) })
	var poolUuid = uuidFrom(t, mustOpn(t, "/kea/dhcp6/pd-pool", "add", "subnet=2001:db8:a6::/64", "prefix=2001:db8:a600::/48",
		"delegated-length=56", "description="+testLabel("cli-pd")))
	t.Cleanup(func() { runOpn(t, "", "/kea/dhcp6/pd-pool", "remove", poolUuid) })
	var pools = mustOpn(t, "/kea/dhcp6/pd-pool", "print", "search="+runPrefix)
	requireContains(t, pools, pools.stdout, "2001:db8:a600::/48", "56")
	var reservationUuid = uuidFrom(t, mustOpn(t, "/kea/dhcp6/reservation", "add", "ip-address=2001:db8:a6::50", "duid=00:01:00:01:aa:bb:cc:a5",
		"hostname="+testHostname("cli-v6host")))
	t.Cleanup(func() { runOpn(t, "", "/kea/dhcp6/reservation", "remove", reservationUuid) })
	mustOpn(t, "/kea/dhcp6/reservation", "remove", reservationUuid)
	mustOpn(t, "/kea/dhcp6/pd-pool", "remove", "2001:db8:a600::/48")
	mustOpn(t, "/kea/dhcp6/subnet", "remove", subnet)
}

func TestCliKeaSettingsAndService(t *testing.T) {
	var dhcpApi = dhcpApi(t)
	requireKeaDisabled(t, dhcpApi)
	var printed = mustOpn(t, "/kea/dhcp4/settings", "print")
	requireContains(t, printed, printed.stdout, "enabled:", "no", "valid-lifetime:", "socket-type:")
	var before = regexp.MustCompile(`valid-lifetime:\s+(\d*)`).FindStringSubmatch(printed.stdout)
	if before == nil {
		t.Fatalf("no valid-lifetime:\n%s", printed)
	}
	t.Cleanup(func() { runOpn(t, "", "/kea/dhcp4/settings", "set", "valid-lifetime="+before[1]) })
	mustOpn(t, "/kea/dhcp4/settings", "set", "valid-lifetime=3602")
	var changed = mustOpn(t, "/kea/dhcp4/settings", "print", "json")
	requireContains(t, changed, changed.stdout, `"general.valid_lifetime":"3602"`, `"general.enabled":"0"`)
	mustOpn(t, "/kea/dhcp4/settings", "set", "valid-lifetime="+before[1])
	mustFailOpn(t, "/kea/dhcp4/settings", "set", "socket-type=tcp")
	mustOpn(t, "/kea/ctrl-agent", "print")
	mustOpn(t, "/kea/ddns", "print")
	mustOpn(t, "/kea/dhcp6/settings", "print")
	mustOpn(t, "/kea/dhcp4/lease", "print")
	mustOpn(t, "/kea/dhcp6/lease", "print", "interface=lan")

	var status = mustOpn(t, "/kea/service", "status")
	requireContains(t, status, status.stdout, "status:")
	// stop needs a confirmation, it is refused without one
	mustFailOpn(t, "/kea/service", "stop")
	// with both servers disabled reconfigure only stops Kea and rewrites its configuration files
	requireKeaDisabled(t, dhcpApi)
	mustOpn(t, "/kea/service", "reconfigure")
}

func TestCliDhcrelay(t *testing.T) {
	var destination = testHostname("cli-dest")
	var destUuid = uuidFrom(t, mustOpn(t, "/dhcrelay/destination", "add", "name="+destination, "servers=198.51.100.67,198.51.100.68"))
	t.Cleanup(func() { runOpn(t, "", "/dhcrelay/destination", "remove", destUuid) })
	mustFailOpn(t, "/dhcrelay/destination", "add", "name="+testHostname("mixed"), "servers=198.51.100.67,2001:db8::67")
	var relayUuid = uuidFrom(t, mustOpn(t, "/dhcrelay/relay", "add", "interface=lan", "destination="+destination, "disabled", "agent-info"))
	t.Cleanup(func() { runOpn(t, "", "/dhcrelay/relay", "remove", relayUuid) })
	var show = mustOpn(t, "/dhcrelay/relay", "show", relayUuid)
	requireContains(t, show, show.stdout, "interface:", "lan", "destination:", destination, "disabled:", "yes", "agent-info:")
	var disable = mustOpn(t, "/dhcrelay/relay", "disable", relayUuid)
	requireContains(t, disable, disable.stderr, "already disabled")
	var inUse = mustFailOpn(t, "/dhcrelay/destination", "remove", destination)
	requireContains(t, inUse, inUse.stderr, "in use by")

	// reconfigure only stops relays when none is enabled
	var relays, err = dhcpApi(t).Relays().List("")
	if err != nil {
		t.Fatal(err)
	}
	var enabled = false
	for _, relay := range relays {
		enabled = enabled || relay.Enabled != "0"
	}
	if enabled {
		t.Log("an enabled relay exists, reconfigure is not run")
	} else {
		mustOpn(t, "/dhcrelay/service", "reconfigure")
	}
	mustOpn(t, "/dhcrelay/relay", "remove", relayUuid)
	mustOpn(t, "/dhcrelay/destination", "remove", destination)
}

func TestCliRadvd(t *testing.T) {
	var entries = mustOpn(t, "/radvd/entry", "print")
	if strings.Contains(entries.stdout, " lan ") {
		t.Skip("lan has a radvd entry already, the interface is unique")
	}
	var uuid = uuidFrom(t, mustOpn(t, "/radvd/entry", "add", "interface=lan", "disabled", "mode=managed", "dns-servers=2001:db8::53",
		"dns-search="+runPrefix+".example"))
	t.Cleanup(func() { runOpn(t, "", "/radvd/entry", "remove", uuid) })
	var show = mustOpn(t, "/radvd/entry", "show", "lan")
	requireContains(t, show, show.stdout, "disabled:", "yes", "mode:", "managed", "2001:db8::53", "min-interval:", "200")
	mustOpn(t, "/radvd/entry", "set", "lan", "max-interval=300", "min-interval=200")
	var invalid = mustFailOpn(t, "/radvd/entry", "set", "lan", "min-interval=290")
	requireContains(t, invalid, invalid.stderr, "min-interval")
	mustFailOpn(t, "/radvd/entry", "add", "interface=lan", "disabled")
	mustOpn(t, "/radvd/entry", "remove", "lan")
	mustOpn(t, "/radvd/service", "status")
	mustFailOpn(t, "/radvd/service", "stop")
}
