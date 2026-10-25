//go:build integration

package integrationsystem

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

// runOpnIn runs the CLI in dir (an empty temp dir when "") with the current environment
func runOpnIn(t *testing.T, dir string, args ...string) opnResult {
	t.Helper()
	return runOpnStdin(t, dir, "", args...)
}

// runOpnStdin runs the CLI in dir (an empty temp dir when "") with stdin, which is never a terminal: without a
// command opn runs it as a script
func runOpnStdin(t *testing.T, dir string, stdin string, args ...string) opnResult {
	t.Helper()
	requireLive(t)
	if opnBuildErr != nil {
		t.Fatalf("the opn binary could not be built: %v", opnBuildErr)
	}
	if dir == "" {
		dir = t.TempDir() // so a .env file in the checkout can not interfere
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var command = exec.CommandContext(ctx, opnBinary, args...)
	command.Dir = dir
	command.Env = os.Environ()
	command.Stdin = strings.NewReader(stdin)

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

// mustOpn runs the CLI and fails the test unless it exits with 0
func mustOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	var result = runOpnIn(t, "", args...)
	if result.exitCode != 0 {
		t.Fatalf("want exit code 0, got:\n%s", result)
	}
	return result
}

// mustFailOpn runs the CLI and fails the test unless it exits with 1 and an error message
func mustFailOpn(t *testing.T, args ...string) opnResult {
	t.Helper()
	var result = runOpnIn(t, "", args...)
	if result.exitCode != 1 || !strings.HasPrefix(result.stderr, "error: ") {
		t.Errorf("want exit code 1 and an \"error: \" message, got:\n%s", result)
	}
	return result
}

// requireNoStdout fails unless a mutation printed nothing on stdout (messages and hints go to stderr)
func requireNoStdout(t *testing.T, result opnResult) {
	t.Helper()
	if result.stdout != "" {
		t.Errorf("want no output on stdout:\n%s", result)
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
