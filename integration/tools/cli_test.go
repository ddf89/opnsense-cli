//go:build integration

package integrationtools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
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

func opnCommand(t *testing.T, ctx context.Context, dir string, args ...string) *exec.Cmd {
	t.Helper()
	requireLive(t)
	if opnBuildErr != nil {
		t.Fatalf("the opn binary could not be built: %v", opnBuildErr)
	}
	if dir == "" {
		dir = t.TempDir()
	}
	var command = exec.CommandContext(ctx, opnBinary, args...)
	command.Dir = dir
	command.Env = os.Environ()
	return command
}

func runOpnIn(t *testing.T, dir string, args ...string) opnResult {
	t.Helper()
	var ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var command = opnCommand(t, ctx, dir, args...)
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
	var result = runOpnIn(t, "", args...)
	if result.exitCode != 0 {
		t.Fatalf("want exit code 0, got:\n%s", result)
	}
	return result
}

func mustFailOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	var result = runOpnIn(t, "", args...)
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

// requireNoJobs fails when a job with this description is left on the firewall
func requireNoJobs(t *testing.T, description string) {
	t.Helper()
	var diag = diagApi(t)
	pings, err := diag.PingJobs()
	if err != nil {
		t.Fatal(err)
	}
	captures, err := diag.PacketCaptureJobs()
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range pings {
		if job.Description == description {
			t.Errorf("ping job %s was left behind", job.Id)
		}
	}
	for _, job := range captures {
		if job.Description == description {
			t.Errorf("capture job %s was left behind", job.Id)
		}
	}
}

func TestCliPing(t *testing.T) {
	var description = runPrefix + "-cli-ping"
	var result = mustOpn(t, "/tool", "ping", "127.0.0.1", "count=3", "description="+description)
	var lines = strings.Split(strings.TrimSpace(result.stdout), "\n")
	if len(lines) < 3 || !strings.Contains(lines[0], "SENT") || !strings.HasPrefix(lines[len(lines)-1], "sent=3 received=3 packet-loss=0% min-rtt=") {
		t.Errorf("want the progress lines and a summary of 3 packets:\n%s", result)
	}
	requireNoJobs(t, description)

	result = mustOpn(t, "/tool", "ping", "192.168.1.1", "count=1", "json", "description="+description)
	requireContains(t, result, result.stdout, `"hostname":"192.168.1.1"`, `"send":1`)
	requireNoJobs(t, description)

	// Ctrl-C ends the ping with a summary and removes the job
	var ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var command = opnCommand(t, ctx, "", "/tool", "ping", "10.0.2.2", "description="+description)
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	var deadline = time.Now().Add(20 * time.Second)
	for !strings.Contains(stdout.String(), "     2 ") && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	_ = command.Process.Signal(syscall.SIGINT)
	var err = command.Wait()
	if err != nil || !strings.Contains(stdout.String(), "sent=") {
		t.Errorf("Ctrl-C: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	requireNoJobs(t, description)

	mustFailOpn(t, "/tool", "ping", "10.0.0.1", "interval=0.5")
}

func TestCliTraceroutePortProbeDnsLookup(t *testing.T) {
	var result = mustOpn(t, "/tool", "traceroute", "127.0.0.1")
	requireContains(t, result, result.stdout, "HOP", "ADDRESS", "127.0.0.1", "localhost")
	requireContains(t, result, result.stderr, "traceroute to 127.0.0.1")

	result = mustOpn(t, "/tool", "port-probe", "127.0.0.1", "port=443")
	requireContains(t, result, result.stdout, "succeeded")
	result = mustFailOpn(t, "/tool", "port-probe", "127.0.0.1", "port=9")
	requireContains(t, result, result.stderr, "Connection refused")

	result = mustOpn(t, "/tool", "dns-lookup", "localhost", "server=127.0.0.1")
	requireContains(t, result, result.stdout, "TYPE", "A ", "localhost.", "127.0.0.1")
	result = mustOpn(t, "/tool", "dns-lookup", "127.0.0.1", "server=127.0.0.1")
	requireContains(t, result, result.stdout, "PTR", "1.0.0.127.in-addr.arpa.", "localhost.")
	result = mustFailOpn(t, "/tool", "dns-lookup", "localhost", "server=127.0.0.2")
	requireContains(t, result, result.stderr, "dns-lookup localhost:")
}

func TestCliSniffer(t *testing.T) {
	var description = runPrefix + "-cli-sniffer"
	defer requireNoJobs(t, description)
	var started = mustOpn(t, "/tool/sniffer", "start", "interface=Loopback", "protocol=tcp", "host=127.0.0.1", "port=443", "count=50",
		"description="+description)
	var id = uuidPattern.FindString(started.stdout)
	if id == "" {
		t.Fatalf("no job id:\n%s", started)
	}
	defer func() { _ = diagApi(t).PacketCaptureRemove(id) }()

	var printed = mustOpn(t, "/tool/sniffer", "print")
	requireContains(t, printed, printed.stdout, description, "lo0", "tcp", "127.0.0.1", "443", "50", "running")

	var view opnResult
	var deadline = time.Now().Add(20 * time.Second)
	for {
		time.Sleep(time.Second)
		mustOpn(t, "/tool", "port-probe", "127.0.0.1", "port=443")
		view = mustOpn(t, "/tool/sniffer", "view", description)
		if strings.Contains(view.stdout, "127.0.0.1.443") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no packets after 20s:\n%s", view)
		}
	}
	if !strings.Contains(strings.Split(view.stdout, "\n")[0], " lo0 ") {
		t.Errorf("want time, device and packet:\n%s", view)
	}

	mustOpn(t, "/tool/sniffer", "stop", id)
	printed = mustOpn(t, "/tool/sniffer", "print", "detail")
	requireContains(t, printed, printed.stdout, id, "stopped")

	var dir = t.TempDir()
	var saved = runOpnIn(t, dir, "/tool/sniffer", "download", id)
	if saved.exitCode != 0 {
		t.Fatalf("download:\n%s", saved)
	}
	if info, err := os.Stat(filepath.Join(dir, id+".zip")); err != nil || info.Size() < 100 {
		t.Errorf("zip file: %v", err)
	}
	if again := runOpnIn(t, dir, "/tool/sniffer", "download", id); again.exitCode != 1 || !strings.Contains(again.stderr, "overwrite") {
		t.Errorf("want a refusal without overwrite:\n%s", again)
	}
	if again := runOpnIn(t, dir, "/tool/sniffer", "download", id, "overwrite"); again.exitCode != 0 {
		t.Errorf("overwrite:\n%s", again)
	}

	mustOpn(t, "/tool/sniffer", "remove", description)
	mustFailOpn(t, "/tool/sniffer", "view", id)

	// duration: the capture is stopped by the command
	var timed = mustOpn(t, "/tool/sniffer", "start", "interface=lo0", "count=5", "duration=2s", "description="+description)
	var timedId = uuidPattern.FindString(timed.stdout)
	requireContains(t, timed, timed.stderr, "stopped")
	if job, err := diagApi(t).PacketCaptureJob(timedId); err != nil || job.Running() {
		t.Errorf("the timed capture must be stopped: %+v, %v", job, err)
	}
	mustOpn(t, "/tool/sniffer", "remove", timedId)

	var unknown = mustFailOpn(t, "/tool/sniffer", "start", "interface=a7nonexist0")
	requireContains(t, unknown, unknown.stderr, "unknown interface")
}

func TestCliInterfaceDiagnostics(t *testing.T) {
	var arp = mustOpn(t, "/interface/arp", "print")
	requireContains(t, arp, arp.stdout, "ADDRESS", "MAC-ADDRESS", "192.168.1.1", "permanent")
	arp = mustOpn(t, "/interface/arp", "print", "search=192.168.1.1", "detail")
	requireContains(t, arp, arp.stdout, "device:", "type:")
	mustOpn(t, "/interface/ndp", "print")
	// never run live: only the refusal without confirmation, decided before anything is sent
	var refused = mustFailOpn(t, "/interface/arp", "flush")
	requireContains(t, refused, refused.stderr, "confirm=yes")

	for _, command := range [][]string{
		{"interfaces"}, {"sockets", "listening"}, {"sockets", "unix"}, {"protocols", "protocol=tcp"}, {"bpf"}, {"memory"}, {"netisr"},
	} {
		var result = mustOpn(t, append([]string{"/interface/netstat"}, command...)...)
		if strings.TrimSpace(result.stdout) == "" {
			t.Errorf("no output:\n%s", result)
		}
	}
	var sockets = mustOpn(t, "/interface/netstat", "sockets", "protocol=tcp4", "listening")
	requireContains(t, sockets, sockets.stdout, "*:443", "lighttpd")

	mustOpn(t, "/interface/vip-status", "print")
	var status = mustOpn(t, "/interface/vip-status", "status")
	requireContains(t, status, status.stdout, "carp:", "maintenance-mode:", "demotion:")
	var nodes = mustOpn(t, "/interface/vip-status", "pfsync-nodes")
	requireContains(t, nodes, nodes.stdout, "CREATOR-ID", "yes")
	for _, command := range []string{"enable", "disable"} {
		refused = mustFailOpn(t, "/interface/vip-status", command)
		requireContains(t, refused, refused.stderr, "confirm=yes")
	}
	refused = mustFailOpn(t, "/interface/vip-status", "maintenance", "enter")
	requireContains(t, refused, refused.stderr, "confirm=yes")
}
