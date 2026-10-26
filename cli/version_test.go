package cli

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var f = newFakeOPN(t)

	// the test binary is built without a version: dev, with the git revision when go build recorded it
	var r = f.run("/version")
	wantExit(t, r, 0)
	if !regexp.MustCompile(`^dev(-[0-9a-f]+(-dirty)?)?\n$`).MatchString(r.stdout) {
		t.Errorf("want only the dev version, got:\n%s", r)
	}

	var option = f.run("--version")
	wantExit(t, option, 0)
	if option.stdout != r.stdout {
		t.Errorf("--version differs from /version:\n%s", option)
	}

	r = f.run("version", "detail")
	wantExit(t, r, 0)
	wantContains(t, "detail", r.stdout, "version:", "go:", "go1.", "platform:")

	// needs no configuration and sends nothing
	wantExit(t, runOpn(t, nil, "version"), 0)
	if calls := f.calls(); len(calls) != 0 {
		t.Errorf("sent %d requests, want none", len(calls))
	}
}

// the release builds set the version like this (Makefile, .github/workflows/release.yml)
func TestVersionLdflags(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	var binary = filepath.Join(t.TempDir(), "opn")
	var build = exec.Command("go", "build", "-trimpath", "-ldflags", "-X opnsense-cli/cli.Version=v1.2.3-test", "-o", binary, ".")
	build.Dir = ".." // module root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	var out, err = exec.Command(binary, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != "v1.2.3-test" {
		t.Errorf("version = %q, want v1.2.3-test", got)
	}
}
