package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCompletionScript(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var r = f.run("completion")
	wantExit(t, r, 0)
	wantContains(t, "script", r.stdout, "_opn_completion()", `"$program" __complete "${COMP_LINE:0:COMP_POINT}" "$cur"`,
		"complete -o default -F _opn_completion opn\n")
	r = f.run("/completion", "bash", "name=opn,opn-linux-amd64")
	wantExit(t, r, 0)
	wantContains(t, "script", r.stdout, "complete -o default -F _opn_completion opn opn-linux-amd64\n")
	r = f.run("completion", "zsh", "name=opn,opn-linux-amd64")
	wantExit(t, r, 0)
	wantContains(t, "zsh script", r.stdout, "#compdef opn opn-linux-amd64\n", "_opn() {",
		`"$program" __complete "$line" "$PREFIX"`, "compdef _opn opn opn-linux-amd64\n")
	wantFailure(t, f.run("completion", "fish"), "fish")
	wantFailure(t, f.run("completion", "name=opn;rm"), "not a usable program name")
	wantNoCalls(t, f)

	if bash, err := exec.LookPath("bash"); err == nil {
		var script = filepath.Join(t.TempDir(), "opn.bash")
		if err := os.WriteFile(script, []byte(completionBashScript([]string{"opn"})), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bash, "-n", script).CombinedOutput(); err != nil {
			t.Errorf("bash -n: %v\n%s", err, out)
		}
	}
}

func TestCompleteTrim(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		candidates       []string
		partial, current string
		want             []string
	}{
		{[]string{"print"}, "pr", "pr", []string{"print"}},
		// bash splits at = and :, it only replaces what follows
		{[]string{"sort=ip"}, "sort=i", "i", []string{"ip"}},
		{[]string{"sort=ip"}, "sort=", "=", []string{"=ip"}},
		{[]string{"hwaddr=aa:bb:cc"}, "hwaddr=aa:b", "b", []string{"bb:cc"}},
		// a shell that doesn't split (or no current word given) gets the full candidates
		{[]string{"sort=ip"}, "sort=i", "sort=i", []string{"sort=ip"}},
		{[]string{"x"}, "abc", "zz", []string{"x"}},
	} {
		if got := completeTrim(tc.candidates, tc.partial, tc.current); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("completeTrim(%q, %q, %q) = %q, want %q", tc.candidates, tc.partial, tc.current, got, tc.want)
		}
	}
}

// completeLines runs "opn __complete line current" and returns the candidates
func completeLines(t *testing.T, f *fakeOPN, line string, current string) []string {
	t.Helper()
	var r = f.run(completeCommand, line, current)
	wantExit(t, r, 0)
	if r.stderr != "" {
		t.Errorf("__complete must not print messages: %q", r.stderr)
	}
	var out = strings.TrimRight(r.stdout, "\n")
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

func TestCompleteCommandLine(t *testing.T) {
	t.Parallel()
	var f = newDnsmasqHostFake(t,
		dnsmasqHostRow(map[string]any{"uuid": "u-web", "host": "web", "domain": "example.lan"}),
		dnsmasqHostRow(map[string]any{"uuid": "u-db", "host": "db", "domain": "example.lan"}),
	)
	for _, tc := range []struct {
		line, current string
		want          []string
	}{
		{"opn", "opn", nil},
		{"opn dns", "dns", []string{"dnsmasq"}},
		{"opn /dnsmasq/ho", "/dnsmasq/ho", []string{"/dnsmasq/host"}},
		{"opn dnsmasq host pr", "pr", []string{"print"}},
		{"opn -v dnsmasq host print so", "so", []string{"sort="}},
		{"opn --verbose dnsmasq host print sort=i", "i", []string{"ip"}},
		{"opn dnsmasq host print sort=d", "sort=d", []string{"sort=description", "sort=domain"}},
		{"opn --ve", "--ve", []string{"--verbose", "--version"}},
		{"opn completion ", "", []string{"bash", "name=", "shell=", "zsh"}},
		// item names come from the API (the fake), the positional argument completes without its name
		{"opn /dnsmasq/host remove ", "", []string{"db.example.lan", "item=", "web.example.lan"}},
		{"opn /dnsmasq/host remove w", "w", []string{"web.example.lan"}},
		{"opn /nosuch/menu ", "", nil},
	} {
		var got = completeLines(t, f, tc.line, tc.current)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("complete %q (current %q) = %q, want %q", tc.line, tc.current, got, tc.want)
		}
	}
	wantNoMutations(t, f)
}

// an unreachable firewall: the values from the API are given up, the rest still completes, quickly
func TestCompleteTimeout(t *testing.T) {
	t.Parallel()
	var start = time.Now()
	// 192.0.2.1 (TEST-NET-1) doesn't answer, the connection hangs until the completion timeout
	var r = runOpn(t, []string{"OPN_URL=https://192.0.2.1", "OPN_APIKEY=k", "OPN_APISECRET=s", "OPN_COMPLETE_TIMEOUT=300ms"},
		completeCommand, "opn /dnsmasq/host remove ", "")
	wantExit(t, r, 0)
	if r.stdout != "item=\n" || r.stderr != "" {
		t.Errorf("want only the offline candidates, got %q / %q", r.stdout, r.stderr)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("completion took %s", elapsed)
	}
}

// the generated function in a real bash, like a TAB press after "opn dnsmasq host print sort="
func TestCompletionInBash(t *testing.T) {
	t.Parallel()
	var bash, err = exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	var f = newFakeOPN(t)
	var script = completionBashScript([]string{"opn"}) + `
COMP_LINE="opn dnsmasq host print sort="; COMP_POINT=${#COMP_LINE}
COMP_WORDS=("$OPN_BINARY" dnsmasq host print sort "="); COMP_CWORD=5
_opn_completion; printf '%s\n' "${COMPREPLY[@]}"
COMP_LINE="opn dnsmasq ho"; COMP_POINT=${#COMP_LINE}
COMP_WORDS=("$OPN_BINARY" dnsmasq ho); COMP_CWORD=2
_opn_completion; printf '%s\n' "${COMPREPLY[@]}"
`
	var command = exec.Command(bash, "-c", script)
	command.Env = append(f.env(), "OPN_BINARY="+opnBinary, "PATH="+os.Getenv("PATH"))
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	var want = "=config\n=description\n=domain\n=host\n=hwaddr\n=ip\nhost\n"
	if string(out) != want {
		t.Errorf("bash completion:\n got  %q\n want %q", out, want)
	}
}

// the generated zsh function, with compadd/_files/compdef stubbed: what it adds for a line being completed
func TestCompletionInZsh(t *testing.T) {
	t.Parallel()
	var zsh, err = exec.LookPath("zsh")
	if err != nil {
		t.Skip("no zsh")
	}
	var dir = t.TempDir()
	var script = filepath.Join(dir, "_opn")
	if err := os.WriteFile(script, []byte(completionZshScript([]string{"opn"})), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(zsh, "-n", script).CombinedOutput(); err != nil {
		t.Fatalf("zsh -n: %v\n%s", err, out)
	}

	var f = newDnsmasqHostFake(t, dnsmasqHostRow(map[string]any{"uuid": "u-web", "host": "web", "domain": "example.lan"}))
	var driver = `
compdef() { print -r -- "compdef $*" }
compadd() { print -r -- "compadd ${(j:|:)@}" }
_files() { print -r -- "_files" }
source "$SCRIPT"
complete() { words=("$OPN_BINARY" "${@[1,-2]}" "${@[-1]}"); CURRENT=$#words; PREFIX=${@[-1]}; print -r -- "== ${(j: :)@}"; _opn }
complete dnsmasq ho
complete dnsmasq host print so
complete dnsmasq host print sort=i
complete /dnsmasq/host remove w
complete /dnsmasq/host export hosts
`
	var command = exec.Command(zsh, "-f", "-c", driver)
	command.Env = append(f.env(), "OPN_BINARY="+opnBinary, "SCRIPT="+script, "PATH="+os.Getenv("PATH"))
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("zsh: %v\n%s", err, out)
	}
	var want = "compdef _opn opn\n" +
		"== dnsmasq ho\ncompadd -U|-Q|--|host\n" +
		"== dnsmasq host print so\ncompadd -U|-Q|-S||--|sort=\n" +
		"== dnsmasq host print sort=i\ncompadd -U|-Q|--|sort=ip\n" +
		"== /dnsmasq/host remove w\ncompadd -U|-Q|--|web.example.lan\n" +
		// nothing matches: file names (the file of export)
		"== /dnsmasq/host export hosts\n_files\n"
	if string(out) != want {
		t.Errorf("zsh completion:\n got  %q\n want %q", out, want)
	}
}
