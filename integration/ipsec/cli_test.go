//go:build integration

package integrationipsec

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Live tests of the opn /vpn/ipsec menus

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

func runOpn(t *testing.T, dir string, args ...string) opnResult {
	t.Helper()
	requireLive(t)
	if opnBuildErr != nil {
		t.Fatalf("the opn binary could not be built: %v", opnBuildErr)
	}
	if dir == "" {
		dir = t.TempDir()
	}
	var ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var command = exec.CommandContext(ctx, opnBinary, args...)
	command.Dir = dir
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
	var result = runOpn(t, "", args...)
	if result.exitCode != 0 {
		t.Fatalf("want exit code 0, got:\n%s", result)
	}
	return result
}

func mustFailOpn(t *testing.T, want string, args ...string) {
	t.Helper()
	var result = runOpn(t, "", args...)
	if result.exitCode != 1 || !strings.HasPrefix(result.stderr, "error: ") || !strings.Contains(result.stderr, want) {
		t.Errorf("want exit code 1 and an error with %q, got:\n%s", want, result)
	}
}

func requireContains(t *testing.T, result opnResult, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(result.stdout, w) {
			t.Errorf("output lacks %q:\n%s", w, result)
		}
	}
}

func TestCliConnectionTree(t *testing.T) {
	var vpn = ipsecApi(t)
	requireIPsecOff(t, vpn)
	var conn = testName("cli conn")
	var created = mustOpn(t, "/vpn/ipsec/connection", "add", "description="+conn, "disabled", "version=ikev2",
		"local-addresses=198.51.100.20", "remote-addresses=192.0.2.20", "proposals=aes256gcm16-sha256-x25519,default", "send-cert=always")
	var uuid = uuidPattern.FindString(created.stdout)
	if uuid == "" {
		t.Fatalf("no uuid:\n%s", created)
	}
	t.Cleanup(func() { _ = vpn.ConnectionRemove(uuid) })
	mustFailOpn(t, "exists already", "/vpn/ipsec/connection", "add", "description="+conn)
	requireContains(t, mustOpn(t, "/vpn/ipsec/connection", "show", conn), "version:            ikev2\n", "disabled:           yes\n",
		"proposals:          aes256gcm16-sha256-x25519,default\n", "send-cert:          always\n")
	mustFailOpn(t, "remote-addresses", "/vpn/ipsec/connection", "set", conn, "remote-addresses=bad addr!")

	mustOpn(t, "/vpn/ipsec/local", "add", "connection="+conn, "disabled", "id=fw.example.com", "description="+testName("cli local"))
	mustFailOpn(t, "exists already", "/vpn/ipsec/local", "add", "connection="+conn, "auth=pubkey")
	mustOpn(t, "/vpn/ipsec/remote", "add", "connection="+conn, "disabled", "id=192.0.2.20")
	mustOpn(t, "/vpn/ipsec/child", "add", "connection="+conn, "disabled", "description="+testName("cli child"),
		"local-ts=198.51.100.0/24", "remote-ts=192.0.2.0/24", "start-action=trap+start")
	requireContains(t, mustOpn(t, "/vpn/ipsec/local", "print", "connection="+conn), "fw.example.com")
	requireContains(t, mustOpn(t, "/vpn/ipsec/child", "show", testName("cli child")), "start-action:   trap+start\n", "disabled:       yes\n")

	var pool = runPrefix + "-clipool"
	mustOpn(t, "/vpn/ipsec/pool", "add", "name="+pool, "network=198.51.100.128/25", "disabled")
	mustOpn(t, "/vpn/ipsec/connection", "set", conn, "pools="+pool)
	mustFailOpn(t, "used by", "/vpn/ipsec/pool", "remove", pool)
	mustOpn(t, "/vpn/ipsec/manual-spd", "add", "child="+conn+" - "+testName("cli child"), "source=198.51.100.0/24", "disabled",
		"description="+testName("cli spd"))
	mustFailOpn(t, "manual SPD", "/vpn/ipsec/connection", "remove", conn)
	mustOpn(t, "/vpn/ipsec/manual-spd", "remove", testName("cli spd"))

	mustOpn(t, "/vpn/ipsec/connection", "remove", conn)
	if out := mustOpn(t, "/vpn/ipsec/child", "print", "search="+runPrefix); strings.Contains(out.stdout, "cli child") {
		t.Errorf("the child must be removed with the connection:\n%s", out)
	}
	mustOpn(t, "/vpn/ipsec/pool", "remove", pool)
}

func TestCliVtiKeys(t *testing.T) {
	var vpn = ipsecApi(t)
	requireIPsecOff(t, vpn)
	var reqid = fmt.Sprint(runReqid + 2)
	mustOpn(t, "/vpn/ipsec/vti", "add", "reqid="+reqid, "tunnel-local=198.51.100.211", "tunnel-remote=198.51.100.212", "disabled",
		"description="+testName("cli vti"))
	requireContains(t, mustOpn(t, "/vpn/ipsec/vti", "show", "ipsec"+reqid), "tunnel-remote:   198.51.100.212\n")
	mustFailOpn(t, "exists already", "/vpn/ipsec/vti", "add", "reqid="+reqid, "tunnel-local=198.51.100.1", "tunnel-remote=198.51.100.2")
	mustOpn(t, "/vpn/ipsec/vti", "remove", "ipsec"+reqid)

	var ident = runPrefix + ".example.com"
	mustOpn(t, "/vpn/ipsec/pre-shared-key", "add", "local-id="+ident, "remote-id=192.0.2.20", "key=cli-probe-secret", "description="+testName("cli psk"))
	for _, args := range [][]string{{"print", "json"}, {"print", "detail"}, {"show", ident}} {
		var out = mustOpn(t, append([]string{"/vpn/ipsec/pre-shared-key"}, args...)...)
		if strings.Contains(out.stdout, "cli-probe-secret") {
			t.Errorf("the key must never be shown:\n%s", out)
		}
	}
	mustOpn(t, "/vpn/ipsec/pre-shared-key", "remove", ident+"/192.0.2.20")

	var name = testName("cli key")
	mustOpn(t, "/vpn/ipsec/key-pair", "generate", "name="+name, "type=ecdsa", "size=256")
	for _, args := range [][]string{{"print", "json"}, {"print", "detail"}, {"show", name}} {
		var out = mustOpn(t, append([]string{"/vpn/ipsec/key-pair"}, args...)...)
		if strings.Contains(out.stdout, "PRIVATE KEY") {
			t.Errorf("the private key must never be shown:\n%s", out)
		}
	}
	var file = filepath.Join(t.TempDir(), "pub.pem")
	mustOpn(t, "/vpn/ipsec/key-pair", "export", name, "file="+file)
	if content, err := os.ReadFile(file); err != nil || !strings.HasPrefix(string(content), "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("export: %q %v", content, err)
	}
	mustOpn(t, "/vpn/ipsec/key-pair", "add", "name="+testName("cli peer"), "type=ecdsa", "public-key-file="+file)
	mustOpn(t, "/vpn/ipsec/key-pair", "remove", testName("cli peer"))
	mustOpn(t, "/vpn/ipsec/key-pair", "remove", name)
}

func TestCliReadOnlyMenus(t *testing.T) {
	requireLive(t)
	requireContains(t, mustOpn(t, "/vpn/ipsec/settings", "print"), "threads:")
	requireContains(t, mustOpn(t, "/vpn/ipsec/service", "status"), "enabled:", "status:")
	for _, menu := range []string{"session", "sad", "spd", "lease"} {
		mustOpn(t, "/vpn/ipsec/"+menu, "print")
	}
	mustOpn(t, "/vpn/ipsec/lease", "pools")
	// dangerous commands refuse to run without confirmation, before any request
	mustFailOpn(t, "confirm=yes", "/vpn/ipsec/service", "stop")
	mustFailOpn(t, "confirm=yes", "/vpn/ipsec/session", "disconnect", "0")
}
