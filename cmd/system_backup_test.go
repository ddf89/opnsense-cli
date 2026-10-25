package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sysBackupFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", sysBackupProvidersPath, 200, sysBackupProviders)
	f.on("GET", sysBackupListPath, 200, sysBackupList)
	f.on("GET", "/api/core/backup/backups/nope", 200, `{"items":[]}`) // OPNsense answers unknown providers with an empty list
	return f
}

func TestSysBackupProviders(t *testing.T) {
	t.Parallel()
	var f = sysBackupFake(t)
	var r = f.run("system", "backup", "providers")
	wantExit(t, r, 0)
	var rows = sysWantTable(t, r.stdout, []string{"NAME", "DESCRIPTION", "DIRECTORY"}, "this")
	if len(rows) == 2 && strings.Join(rows[1], "|") != "this|This Firewall|/conf/backup" {
		t.Errorf("row: %q", rows[1])
	}
	wantNoMutations(t, f)
}

func TestSysBackupList(t *testing.T) {
	t.Parallel()
	var f = sysBackupFake(t)
	var r = f.run("system", "backup", "list")
	wantExit(t, r, 0)
	var rows = sysWantTable(t, r.stdout, []string{"ID", "TIME", "USER", "SIZE", "DESCRIPTION"}, sysBackupNewest, sysBackupMiddle, sysBackupOldest)
	if len(rows) > 1 {
		// TZ=UTC in the test environment
		if rows[1][1] != "2026-10-24 23:54:04" || rows[1][2] != "root@192.168.1.2" || rows[1][3] != "39130" {
			t.Errorf("row 1: %q", rows[1])
		}
	}
	wantNoMutations(t, f)

	t.Run("alias backups and --provider", func(t *testing.T) {
		t.Parallel()
		var f = sysBackupFake(t)
		wantExit(t, f.run("system", "backups", "list", "--provider", "this"), 0)
		sysWantCalled(t, f, "GET", sysBackupListPath)
	})
	t.Run("unknown provider", func(t *testing.T) {
		t.Parallel()
		var f = sysBackupFake(t)
		wantFailure(t, f.run("system", "backup", "list", "-p", "nope"), "not found", "nope")
	})
}

func TestSysBackupDownload(t *testing.T) {
	t.Parallel()
	const suggested = "config-OPNsense.internal-1792886044.3812.xml"

	var setup = func(t *testing.T) (*fakeOPN, string) {
		var f = sysBackupFake(t)
		sysOnDownload(f, sysBackupDownloadPath, suggested, sysConfigXml)
		sysOnDownload(f, sysBackupDownloadPath+"/"+sysBackupMiddle, "config-OPNsense.internal-1792886029.2372.xml", "<?xml?><opnsense>middle</opnsense>")
		f.on("GET", sysBackupDownloadPath+"/config-1.xml", 200, "") // unknown ids are answered with an empty 200
		return f, t.TempDir()
	}

	var wantFile = func(t *testing.T, path string, content string) {
		t.Helper()
		var data, err = os.ReadFile(path)
		if err != nil {
			t.Fatalf("file not written: %v", err)
		}
		if string(data) != content {
			t.Errorf("%s has %q, want %q", path, data, content)
		}
		var info, _ = os.Stat(path)
		if info != nil && info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v, want 0600 (it contains secrets)", path, info.Mode().Perm())
		}
	}

	t.Run("current config to the suggested file name", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		var r = runOpnIn(t, dir, f.env(), "system", "backup", "download")
		wantExit(t, r, 0)
		wantFile(t, filepath.Join(dir, suggested), sysConfigXml)
		wantNotContains(t, "stdout", r.stdout, "<opnsense>")
		sysWantCalled(t, f, "GET", sysBackupDownloadPath)
		wantNoMutations(t, f)
	})
	t.Run("specific id to --output", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		var r = runOpnIn(t, dir, f.env(), "system", "backup", "download", "--id", sysBackupMiddle, "-o", "out.xml")
		wantExit(t, r, 0)
		wantFile(t, filepath.Join(dir, "out.xml"), "<?xml?><opnsense>middle</opnsense>")
	})
	t.Run("--output - writes to stdout only", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		var r = runOpnIn(t, dir, f.env(), "system", "backup", "download", "--output", "-")
		wantExit(t, r, 0)
		if r.stdout != sysConfigXml {
			t.Errorf("stdout %q, want the config", r.stdout)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("files written: %v", entries)
		}
	})
	t.Run("existing file is not overwritten without --force", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		var path = filepath.Join(dir, "out.xml")
		if err := os.WriteFile(path, []byte("keep me"), 0o644); err != nil {
			t.Fatal(err)
		}
		var r = runOpnIn(t, dir, f.env(), "system", "backup", "download", "-o", "out.xml")
		wantFailure(t, r, "out.xml", "--force")
		if data, _ := os.ReadFile(path); string(data) != "keep me" {
			t.Errorf("file was overwritten: %q", data)
		}

		r = runOpnIn(t, dir, f.env(), "system", "backup", "download", "-o", "out.xml", "--force")
		wantExit(t, r, 0)
		if data, _ := os.ReadFile(path); string(data) != sysConfigXml {
			t.Errorf("file not overwritten with --force: %q", data)
		}
	})
	for _, tc := range []struct{ header, want string }{
		{`"../../evil.xml"`, "evil.xml"}, // parsable: only the base name is used
		{`../../evil.xml`, "config.xml"}, // not a valid header value: the default name is used
		{`"/etc/evil.xml"`, "evil.xml"},
		{`"..\\..\\evil.xml"`, "evil.xml"},
	} {
		t.Run("a path in the suggested file name "+tc.header+" is ignored", func(t *testing.T) {
			t.Parallel()
			var f = sysBackupFake(t)
			sysOnDownload(f, sysBackupDownloadPath, tc.header, sysConfigXml)
			var parent = t.TempDir()
			var dir = filepath.Join(parent, "a", "b")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			wantExit(t, runOpnIn(t, dir, f.env(), "system", "backup", "download"), 0)
			wantFile(t, filepath.Join(dir, tc.want), sysConfigXml)
			var written []string
			_ = filepath.Walk(parent, func(path string, info os.FileInfo, _ error) error {
				if info != nil && !info.IsDir() {
					written = append(written, path)
				}
				return nil
			})
			if len(written) != 1 {
				t.Errorf("want exactly %s, files written: %v", tc.want, written)
			}
		})
	}
	t.Run("unknown id writes no file", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		var r = runOpnIn(t, dir, f.env(), "system", "backup", "download", "--id", "config-1.xml")
		wantFailure(t, r, "not found", "config-1.xml")
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("files written: %v", entries)
		}
	})
	t.Run("HTTP error writes no file", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		f.on("GET", sysBackupDownloadPath, 403, `{"status":403,"message":"Forbidden"}`)
		var r = runOpnIn(t, dir, f.env(), "system", "backup", "download")
		wantFailure(t, r, "403", "Forbidden")
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("files written: %v", entries)
		}
	})
}

func TestSysBackupDiff(t *testing.T) {
	t.Parallel()
	const diff = `{"items":["--- /conf/backup/config-1792885909.1543.xml\t2026-10-24 23:51:49","+++ /conf/backup/config-1792886044.3812.xml\t2026-10-24 23:54:04",` +
		`"@@ -10,3 +10,3 @@","   &lt;system&gt;","-    &lt;hostname&gt;old&lt;/hostname&gt;","+    &lt;hostname&gt;new &amp; shiny&lt;/hostname&gt;"]}`

	t.Run("lines are printed unescaped, target first in the endpoint", func(t *testing.T) {
		t.Parallel()
		var f = sysBackupFake(t)
		// OPNsense runs diff -u <b2> <b1> for diff/<provider>/<b1>/<b2>
		f.on("GET", sysBackupDiffPath+sysBackupNewest+"/"+sysBackupOldest, 200, diff)
		var r = f.run("system", "backup", "diff", "--from", sysBackupOldest)
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "--- /conf/backup/"+sysBackupOldest, "+++ /conf/backup/"+sysBackupNewest,
			"-    <hostname>old</hostname>", "+    <hostname>new & shiny</hostname>")
		wantNotContains(t, "stdout", r.stdout, "&lt;", "&amp;")
		wantNoMutations(t, f)
	})
	t.Run("explicit --to", func(t *testing.T) {
		t.Parallel()
		var f = sysBackupFake(t)
		f.on("GET", sysBackupDiffPath+sysBackupMiddle+"/"+sysBackupOldest, 200, diff)
		wantExit(t, f.run("system", "backup", "diff", "--from", sysBackupOldest, "--to", sysBackupMiddle), 0)
		sysWantCalled(t, f, "GET", sysBackupDiffPath+sysBackupMiddle+"/"+sysBackupOldest)
	})
	t.Run("identical backups", func(t *testing.T) {
		t.Parallel()
		var f = sysBackupFake(t)
		var r = f.run("system", "backup", "diff", "--from", sysBackupNewest)
		wantExit(t, r, 0)
		wantContains(t, "output", r.stdout+r.stderr, "No differences")
	})
	t.Run("--from is required, no API call", func(t *testing.T) {
		t.Parallel()
		var f = sysBackupFake(t)
		wantFailure(t, f.run("system", "backup", "diff"), "from")
		wantNoCalls(t, f)
	})
	t.Run("unknown id is an error, not an empty diff", func(t *testing.T) {
		t.Parallel()
		var f = sysBackupFake(t)
		var r = f.run("system", "backup", "diff", "--from", "config-1.xml")
		wantFailure(t, r, "not found", "config-1.xml")
		sysWantNoCallTo(t, f, sysBackupDiffPath)
	})
}

// revert and rm must never reach the API without --yes
func TestSysBackupRevertRmGuards(t *testing.T) {
	t.Parallel()
	for _, command := range []string{"revert", "rm"} {
		for _, args := range [][]string{
			{"--id", sysBackupMiddle},
			{"--id", sysBackupMiddle, "--yes=false"},
			{"--id", sysBackupMiddle, "yes"},
			{"--yes"},
			{},
		} {
			t.Run(command+"_"+sysName(args), func(t *testing.T) {
				t.Parallel()
				var f = sysBackupFake(t)
				var r = f.run(append([]string{"system", "backup", command}, args...)...)
				wantFailure(t, r)
				wantNoCalls(t, f)
			})
		}
	}
}

func TestSysBackupRevertRm(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		command string
		path    string
		answer  string
	}{
		{"revert", sysBackupRevertPath, `{"status":"reverted"}`},
		{"rm", sysBackupDeletePath, `{"status":"deleted"}`},
	} {
		t.Run(tc.command+" with --yes is a POST of exactly that id", func(t *testing.T) {
			t.Parallel()
			var f = sysBackupFake(t)
			f.on("POST", tc.path+sysBackupMiddle, 200, tc.answer)
			var r = f.run("system", "backup", tc.command, "--id", sysBackupMiddle, "--yes")
			wantExit(t, r, 0)
			wantContains(t, "output", r.stdout+r.stderr, sysBackupMiddle)
			var call = wantOneMutation(t, f, "POST", tc.path+sysBackupMiddle)
			if call.Body != "" {
				t.Errorf("unexpected body %q", call.Body)
			}
		})
		t.Run(tc.command+" of an unknown id", func(t *testing.T) {
			t.Parallel()
			var f = sysBackupFake(t)
			f.on("POST", tc.path+"config-1.xml", 200, `{"status":"not_found"}`)
			wantFailure(t, f.run("system", "backup", tc.command, "--id", "config-1.xml", "--yes"), "not found")
		})
		t.Run(tc.command+" of current is refused", func(t *testing.T) {
			t.Parallel()
			var f = sysBackupFake(t)
			wantFailure(t, f.run("system", "backup", tc.command, "--id", "current", "--yes"), "id")
			wantNoMutations(t, f)
		})
	}
}
