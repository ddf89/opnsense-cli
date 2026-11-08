package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Tests of install.sh: it runs piped into bash like the documented one-liner, against a fake release server, with
// uname and sysctl replaced to simulate the platforms. The fake "binaries" are shell scripts printing their name

// installTestAssets are the release assets of the fake server
var installTestAssets = []string{"opn-linux-amd64", "opn-linux-arm64", "opn-macos-amd64", "opn-macos-arm64"}

// installTestServer serves a fake GitHub release layout: /latest/download/<file> and /download/<tag>/<file> (only
// tag 1.2.3). damaged makes one asset differ from its SHA256SUMS line
func installTestServer(t *testing.T, damaged string) *httptest.Server {
	t.Helper()
	var files = map[string]string{}
	var sums strings.Builder
	for _, asset := range installTestAssets {
		files[asset] = "#!/bin/sh\necho " + asset + "\n"
		fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256([]byte(files[asset])), asset)
	}
	files["SHA256SUMS"] = sums.String()
	if damaged != "" {
		files[damaged] += "# tampered\n"
	}
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var name string
		switch {
		case strings.HasPrefix(r.URL.Path, "/latest/download/"):
			name = strings.TrimPrefix(r.URL.Path, "/latest/download/")
		case strings.HasPrefix(r.URL.Path, "/download/1.2.3/"):
			name = strings.TrimPrefix(r.URL.Path, "/download/1.2.3/")
		}
		var content, found = files[name]
		if !found {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(content))
	}))
	t.Cleanup(server.Close)
	return server
}

type installRun struct {
	os, arch, translated string // what uname -s / uname -m / sysctl -n sysctl.proc_translated report
	args                 []string
	env                  []string
	path                 string // extra PATH entry (before the fakes)
	home                 string // HOME, a new temporary directory when empty
}

type installResult struct {
	home   string
	output string
	err    error
}

// runInstall pipes install.sh into bash with a fresh HOME and fake uname/sysctl
func runInstall(t *testing.T, server *httptest.Server, run installRun) installResult {
	t.Helper()
	var bash, err = exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl")
	}
	var script, readErr = os.ReadFile("install.sh")
	if readErr != nil {
		t.Fatal(readErr)
	}
	var home = run.home
	if home == "" {
		home = t.TempDir()
	}
	var fakes = filepath.Join(t.TempDir(), "fakes")
	if err := os.MkdirAll(fakes, 0o755); err != nil {
		t.Fatal(err)
	}
	var uname = fmt.Sprintf("#!/bin/sh\ncase \"$1\" in -s) echo %q ;; -m) echo %q ;; *) echo %q ;; esac\n", run.os, run.arch, run.os)
	var sysctl = fmt.Sprintf("#!/bin/sh\necho %q\n", run.translated)
	for name, content := range map[string]string{"uname": uname, "sysctl": sysctl} {
		if err := os.WriteFile(filepath.Join(fakes, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var path = fakes + ":" + os.Getenv("PATH")
	if run.path != "" {
		path = run.path + ":" + path
	}
	var command = exec.Command(bash, append([]string{"-s", "--"}, run.args...)...)
	command.Stdin = strings.NewReader(string(script))
	command.Env = append([]string{"HOME=" + home, "PATH=" + path, "TMPDIR=" + t.TempDir(), "SHELL=/bin/bash",
		"OPN_RELEASE_URL=" + server.URL}, run.env...)
	var output, runErr = command.CombinedOutput()
	return installResult{home: home, output: string(output), err: runErr}
}

// installed returns what the installed opn prints (the asset name of the fake), "" when there is none
func installed(t *testing.T, path string) string {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	var output, err = exec.Command(path).Output()
	if err != nil {
		t.Fatalf("running %s: %v", path, err)
	}
	return strings.TrimSpace(string(output))
}

func TestInstallPlatforms(t *testing.T) {
	var server = installTestServer(t, "")
	for _, tc := range []struct {
		os, arch, translated string
		want                 string
	}{
		{"Linux", "x86_64", "", "opn-linux-amd64"},
		{"Linux", "aarch64", "", "opn-linux-arm64"},
		{"Linux", "arm64", "", "opn-linux-arm64"},
		{"Darwin", "arm64", "0", "opn-macos-arm64"},
		{"Darwin", "x86_64", "0", "opn-macos-amd64"},
		// a shell under Rosetta 2 on Apple Silicon reports x86_64
		{"Darwin", "x86_64", "1", "opn-macos-arm64"},
	} {
		var result = runInstall(t, server, installRun{os: tc.os, arch: tc.arch, translated: tc.translated})
		if result.err != nil {
			t.Errorf("%s %s: %v\n%s", tc.os, tc.arch, result.err, result.output)
			continue
		}
		var bin = filepath.Join(result.home, ".local", "bin", "opn")
		if got := installed(t, bin); got != tc.want {
			t.Errorf("%s %s (translated %q): installed %q, want %q\n%s", tc.os, tc.arch, tc.translated, got, tc.want, result.output)
		}
		if info, err := os.Stat(bin); err != nil || info.Mode().Perm() != 0o755 {
			t.Errorf("%s %s: mode %v %v", tc.os, tc.arch, info.Mode(), err)
		}
		for _, want := range []string{"downloading " + tc.want + " (latest release)", "installed opn " + tc.want + " to " + bin,
			"is not in your PATH yet", "opn completion bash"} {
			if !strings.Contains(result.output, want) {
				t.Errorf("%s %s: output lacks %q:\n%s", tc.os, tc.arch, want, result.output)
			}
		}
	}
}

func TestInstallRefusals(t *testing.T) {
	var server = installTestServer(t, "opn-linux-amd64")
	for _, tc := range []struct {
		name string
		run  installRun
		want string
	}{
		{"Git Bash on Windows", installRun{os: "MINGW64_NT-10.0-19045", arch: "x86_64"}, "run this in WSL"},
		{"Cygwin", installRun{os: "CYGWIN_NT-10.0", arch: "x86_64"}, "run this in WSL"},
		{"FreeBSD", installRun{os: "FreeBSD", arch: "amd64"}, "unsupported operating system FreeBSD"},
		{"32 bit ARM", installRun{os: "Linux", arch: "armv7l"}, "unsupported architecture armv7l"},
		{"damaged download", installRun{os: "Linux", arch: "x86_64"}, "checksum mismatch for opn-linux-amd64"},
		{"unknown release", installRun{os: "Linux", arch: "aarch64", args: []string{"--version", "9.9.9"}}, "could not download"},
		{"unknown option", installRun{os: "Linux", arch: "aarch64", args: []string{"--force"}}, "unknown option --force"},
	} {
		var result = runInstall(t, server, tc.run)
		if result.err == nil || !strings.Contains(result.output, "error: ") || !strings.Contains(result.output, tc.want) {
			t.Errorf("%s: want a failure with %q, got %v:\n%s", tc.name, tc.want, result.err, result.output)
		}
		if got := installed(t, filepath.Join(result.home, ".local", "bin", "opn")); got != "" {
			t.Errorf("%s: nothing may be installed, got %q", tc.name, got)
		}
	}
}

func TestInstallOptions(t *testing.T) {
	var server = installTestServer(t, "")

	// WSL is Linux, said so
	var result = runInstall(t, server, installRun{os: "Linux", arch: "x86_64", env: []string{"WSL_DISTRO_NAME=Ubuntu"}})
	if result.err != nil || !strings.Contains(result.output, "WSL (Windows Subsystem for Linux) detected") ||
		installed(t, filepath.Join(result.home, ".local", "bin", "opn")) != "opn-linux-amd64" {
		t.Errorf("WSL: %v\n%s", result.err, result.output)
	}

	// a pinned release and another directory, as options and as environment variables
	var readOnly = filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(readOnly, 0o555); err != nil {
		t.Fatal(err)
	}
	result = runInstall(t, server, installRun{os: "Linux", arch: "aarch64", args: []string{"--dir", readOnly}})
	if os.Geteuid() != 0 && (result.err == nil || !strings.Contains(result.output, "can not write to "+readOnly)) {
		t.Errorf("an unwritable directory must fail: %v\n%s", result.err, result.output)
	}
	var dir = filepath.Join(t.TempDir(), "tools")
	result = runInstall(t, server, installRun{os: "Linux", arch: "aarch64", args: []string{"--version", "1.2.3", "--dir", dir}})
	if result.err != nil || !strings.Contains(result.output, "(1.2.3 release)") || installed(t, filepath.Join(dir, "opn")) != "opn-linux-arm64" {
		t.Errorf("--version --dir: %v\n%s", result.err, result.output)
	}
	var envDir = filepath.Join(t.TempDir(), "envbin")
	result = runInstall(t, server, installRun{os: "Darwin", arch: "arm64", env: []string{"OPN_VERSION=1.2.3", "OPN_INSTALL_DIR=" + envDir}})
	if result.err != nil || installed(t, filepath.Join(envDir, "opn")) != "opn-macos-arm64" {
		t.Errorf("OPN_VERSION/OPN_INSTALL_DIR: %v\n%s", result.err, result.output)
	}

	// ~/bin is used when it is in PATH and ~/.local/bin is not; no PATH hint then. A second run replaces opn
	var home = t.TempDir()
	var inBin = installRun{os: "Linux", arch: "x86_64", path: filepath.Join(home, "bin"), home: home}
	result = runInstall(t, server, inBin)
	if result.err != nil || installed(t, filepath.Join(home, "bin", "opn")) != "opn-linux-amd64" || strings.Contains(result.output, "not in your PATH") {
		t.Errorf("~/bin in PATH: %v\n%s", result.err, result.output)
	}
	result = runInstall(t, server, inBin)
	if result.err != nil || installed(t, filepath.Join(home, "bin", "opn")) != "opn-linux-amd64" {
		t.Errorf("reinstall: %v\n%s", result.err, result.output)
	}

	// --help prints the usage, piped too
	result = runInstall(t, server, installRun{os: "Linux", arch: "x86_64", args: []string{"--help"}})
	if result.err != nil || !strings.Contains(result.output, "usage: install.sh [--version <tag>] [--dir <dir>]") {
		t.Errorf("--help: %v\n%s", result.err, result.output)
	}
}
