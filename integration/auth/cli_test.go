//go:build integration

package integrationauth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"opnsense-cli/opnsense/api/hostdiscovery"
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

// runOpn runs the CLI in an empty temp dir with the current environment (stdin is never a terminal)
func runOpn(t *testing.T, args ...string) opnResult {
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

func mustOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	var result = runOpn(t, args...)
	if result.exitCode != 0 {
		t.Fatalf("want exit code 0, got:\n%s", result)
	}
	return result
}

func mustFailOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	var result = runOpn(t, args...)
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

// TestCliUserGroupPrivilege drives /system/user, /system/user/api-key, /system/group and /system/privilege
func TestCliUserGroupPrivilege(t *testing.T) {
	var opn = authApi(t)
	var group = testName("cli-ops")
	var user = testName("cli-alice")

	var groupUuid = uuidFrom(t, mustOpn(t, "/system/group", "add", "name="+group, "description=cli test", "privileges=page-status-ntp"))
	t.Cleanup(func() { removeGroup(t, groupUuid) })
	var added = mustOpn(t, "/system/user", "add", "name="+user, "full-name=Cli Alice", "groups="+group, "disabled", "expires=2099-12-31")
	var userUuid = uuidFrom(t, added)
	t.Cleanup(func() { removeUser(t, userUuid) })
	if strings.TrimSpace(added.stdout) != userUuid {
		t.Errorf("add must print only the uuid:\n%s", added)
	}
	requireContains(t, added, added.stderr, "random password")

	t.Run("print and show", func(t *testing.T) {
		var printed = mustOpn(t, "/system/user", "print", "search="+user)
		requireContains(t, printed, printed.stdout, user, group, "Cli Alice", "12/31/2099")
		var asJSON = mustOpn(t, "/system/user", "print", "json", "search="+user)
		var row map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(asJSON.stdout)), &row); err != nil || row["uuid"] != userUuid {
			t.Fatalf("json: %v\n%s", err, asJSON)
		}
		for _, secret := range []string{"password", "apikeys", "otp_seed"} {
			if _, found := row[secret]; found {
				t.Errorf("json contains %s", secret)
			}
		}
		var shown = mustOpn(t, "/system/user", "show", user)
		requireContains(t, shown, shown.stdout, "disabled:          yes", "groups:            "+group, "scope:             user")
		var groups = mustOpn(t, "/system/group", "show", group)
		requireContains(t, groups, groups.stdout, "members:          "+user, "privileges:       page-status-ntp")
	})

	t.Run("set, enable, disable", func(t *testing.T) {
		mustOpn(t, "/system/user", "set", user, "email=cli@example.com", "password=Cli-Test-Pass-12345")
		mustOpn(t, "/system/user", "enable", user)
		if got, _ := opn.UserGet(userUuid); got.Disabled || got.Email != "cli@example.com" || got.PasswordChangedAt == "" {
			t.Errorf("after set/enable %+v", got)
		}
		mustOpn(t, "/system/user", "disable", user)
		if got, _ := opn.UserGet(userUuid); !got.Disabled {
			t.Errorf("after disable %+v", got)
		}
		mustFailOpn(t, "/system/user", "set", user, "expires=soon")
		mustFailOpn(t, "/system/user", "set", user, "groups="+testName("nosuch"))
		mustFailOpn(t, "/system/user", "password", user) // no terminal
		var exists = mustFailOpn(t, "/system/user", "add", "name="+user)
		requireContains(t, exists, exists.stderr, "exists already")
	})

	t.Run("privileges", func(t *testing.T) {
		mustOpn(t, "/system/privilege", "grant", "page-diagnostics-ping", "user="+user, "group="+group)
		var printed = mustOpn(t, "/system/privilege", "print", "user="+user)
		requireContains(t, printed, printed.stdout, "page-diagnostics-ping")
		var shown = mustOpn(t, "/system/privilege", "show", "page-diagnostics-ping")
		requireContains(t, shown, shown.stdout, user, group, "match:")
		mustOpn(t, "/system/privilege", "revoke", "page-diagnostics-ping", "user="+user, "group="+group)
		var after = mustOpn(t, "/system/privilege", "print", "group="+group)
		if strings.Contains(after.stdout, "page-diagnostics-ping") || !strings.Contains(after.stdout, "page-status-ntp") {
			t.Errorf("after revoke:\n%s", after)
		}
		mustFailOpn(t, "/system/privilege", "grant", "page-a4au-nosuch", "user="+user)
	})

	t.Run("api keys", func(t *testing.T) {
		var file = filepath.Join(t.TempDir(), "apikey.txt")
		var created = mustOpn(t, "/system/user/api-key", "add", user, "file="+file)
		var content, err = os.ReadFile(file)
		if err != nil || !strings.HasPrefix(string(content), "key=") || !strings.Contains(string(content), "\nsecret=") {
			t.Fatalf("key file: %v", err)
		}
		if strings.Contains(created.stdout, "secret") {
			t.Errorf("the secret must only go to the file:\n%s", created)
		}
		var key = strings.TrimPrefix(strings.TrimSpace(created.stdout), "key=")
		var listed = mustOpn(t, "/system/user/api-key", "print", "user="+user)
		requireContains(t, listed, listed.stdout, key)
		mustFailOpn(t, "/system/user/api-key", "remove", "item="+key) // no confirm
		mustOpn(t, "/system/user/api-key", "remove", "item="+key, "confirm=yes")
		if again := mustOpn(t, "/system/user/api-key", "print", "user="+user); strings.Contains(again.stdout, key) {
			t.Errorf("the key is still listed:\n%s", again)
		}
	})

	t.Run("refused by OPNsense too", func(t *testing.T) {
		// root and admins are system scope: OPNsense refuses these as well, so the client side guards can be run live
		var root = mustFailOpn(t, "/system/user", "remove", "root", "confirm=yes")
		requireContains(t, root, root.stderr, "refusing")
		var admins = mustFailOpn(t, "/system/group", "remove", "admins", "confirm=yes")
		requireContains(t, admins, admins.stderr, "refusing")
	})

	t.Run("remove", func(t *testing.T) {
		mustFailOpn(t, "/system/user", "remove", user) // no confirm
		mustOpn(t, "/system/user", "remove", user, "confirm=yes")
		if got, _ := opn.GroupGet(groupUuid); len(got.Members) != 0 {
			t.Errorf("the removed user stayed a member: %+v", got)
		}
		mustOpn(t, "/system/group", "remove", group, "confirm=yes")
		mustFailOpn(t, "/system/group", "show", group)
	})
}

// TestCliHostDiscoveryAndNtp reads /interface/host-discovery and /system/ntp and changes and restores a setting
func TestCliHostDiscoveryAndNtp(t *testing.T) {
	var discovery = &hostdiscovery.HostDiscoveryApi{OPNsense: coreApi(t)}
	var before, err = discovery.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var restore = hostdiscovery.SettingsFields{Verbose: &before.Verbose, Expire6Interval: &before.Expire6Interval}
		if err := discovery.SettingsSet(restore); err != nil {
			t.Errorf("restoring: %v", err)
		}
	})

	var hosts = mustOpn(t, "/interface/host-discovery", "print")
	requireContains(t, hosts, hosts.stdout, "INTERFACE", "IP", "MAC")
	var status = mustOpn(t, "/interface/host-discovery", "status")
	requireContains(t, status, status.stdout, "status:")
	var settings = mustOpn(t, "/interface/host-discovery/settings", "print")
	requireContains(t, settings, settings.stdout, "enabled:", "interfaces:", "expire-ipv4:")

	mustOpn(t, "/interface/host-discovery/settings", "set", "verbose", "expire-ipv6=3h")
	if changed, _ := discovery.SettingsGet(); changed.Verbose != "1" || changed.Expire6Interval != "10800" || changed.Enabled != before.Enabled {
		t.Errorf("after set %+v", changed)
	}
	mustFailOpn(t, "/interface/host-discovery/settings", "set", "expire-ipv6=10m")
	mustFailOpn(t, "/interface/host-discovery/settings", "set", "interfaces="+testName("nosuch"))

	var ntp = mustOpn(t, "/system/ntp", "status")
	requireContains(t, ntp, ntp.stdout, "SERVER", "STRATUM"[:2], "OFFSET")
	var ntpJSON = mustOpn(t, "/system/ntp", "status", "json")
	for _, line := range strings.Split(strings.TrimSpace(ntpJSON.stdout), "\n") {
		var row map[string]any
		if line != "" && json.Unmarshal([]byte(line), &row) != nil {
			t.Errorf("not JSON: %q", line)
		}
	}
}
