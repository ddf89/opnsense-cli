package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMainModes(t *testing.T) {
	var f = newFakeOPN(t)

	var help = f.run("-h")
	wantExit(t, help, 0)
	wantContains(t, "stdout", help.stdout, "usage: opn", "import")

	var menuHelp = f.run("/")
	wantExit(t, menuHelp, 0)
	wantContains(t, "stdout", menuHelp.stdout, "commands:", "import")

	var unknown = f.run("/nope", "print")
	wantFailure(t, unknown, `error: no such menu or command in /: "nope"`)
	if unknown.stdout != "" {
		t.Errorf("errors must not go to stdout: %q", unknown.stdout)
	}

	// exit as a one-shot command does nothing and succeeds, like in a script
	for _, args := range [][]string{{"exit"}, {"/system", "quit"}} {
		var exit = f.run(args...)
		wantExit(t, exit, 0)
		if exit.stdout != "" || exit.stderr != "" {
			t.Errorf("%q must be silent: %s", args, exit)
		}
	}

	var option = f.run("--nope")
	if option.code != 2 {
		t.Errorf("unknown option: want exit 2, got %s", option)
	}

	// a single argument with spaces is split like a shell line
	var quoted = f.run("/import ?")
	wantExit(t, quoted, 0)
	wantContains(t, "stdout", quoted.stdout, "/import: run the commands")

	// script mode: stdin lines, stops at the first error with its line number
	var script = f.runScript("# comment\n/\nimport ?\n/nope\nimport ?\n")
	wantFailure(t, script, "stdin:4:")
	wantContains(t, "stdout", script.stdout, "/import: run the commands")
	wantNoCalls(t, f)
}

func TestImportCommand(t *testing.T) {
	var f = newFakeOPN(t)
	var dir = t.TempDir()
	var path = filepath.Join(dir, "setup.rsc")
	if err := os.WriteFile(path, []byte("/import ?\n/missing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var r = f.run("/import", path)
	wantFailure(t, r, "setup.rsc:2:", "missing")
	wantContains(t, "stdout", r.stdout, "/import: run the commands")

	var missing = f.run("/import", "file="+filepath.Join(dir, "nope.rsc"))
	wantFailure(t, missing, "nope.rsc")
}
