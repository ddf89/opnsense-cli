package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Fixtures are trimmed copies of what OPNsense 26.7 returns

const (
	systemBackupProvidersPath = "/api/core/backup/providers"
	systemBackupListPath      = "/api/core/backup/backups/this"
	systemBackupDownloadPath  = "/api/core/backup/download/this"
	systemBackupDiffPath      = "/api/core/backup/diff/this/"
	systemBackupRevertPath    = "/api/core/backup/revert_backup/"
	systemBackupDeletePath    = "/api/core/backup/delete_backup/"

	systemBackupProvidersAnswer = `{"items":{"this":{"description":"This Firewall","dirname":"/conf/backup"}}}`

	systemBackupNewest = "config-1792886044.3812.xml"
	systemBackupMiddle = "config-1792886029.2372.xml"
	systemBackupOldest = "config-1792885909.1543.xml"

	// systemBackupListAnswer is the history in the (2 decimal time) order OPNsense sends it
	systemBackupListAnswer = `{"items":[` +
		`{"time":"1792886044.38","time_iso":"2026-10-24T23:54:04+00:00","description":"/api/cron/settings/set_job/807ac3e3 made changes","username":"root@192.168.1.2","filesize":39130,"id":"` + systemBackupNewest + `"},` +
		`{"time":"1792886029.24","time_iso":"2026-10-24T23:53:49+00:00","description":"/api/cron/settings/add_job made changes","username":"root@192.168.1.2","filesize":39101,"id":"` + systemBackupMiddle + `"},` +
		`{"time":"1792885909.15","time_iso":"2026-10-24T23:51:49+00:00","description":"/api/dnsmasq/settings/set_host/5f2e09fc made changes","username":"admin@192.168.1.3","filesize":39010,"id":"` + systemBackupOldest + `"}]}`

	// systemBackupConfigXml stands in for a downloaded config.xml
	systemBackupConfigXml = "<?xml version=\"1.0\"?>\n<opnsense>\n  <trigger_initial_wizard/>\n  <system><hostname>OPNsense</hostname></system>\n</opnsense>\n"

	systemBackupStatusOk = `{"status":"ok"}`
)

func systemBackupFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", systemBackupProvidersPath, 200, systemBackupProvidersAnswer)
	f.on("GET", systemBackupListPath, 200, systemBackupListAnswer)
	f.on("GET", "/api/core/backup/backups/nope", 200, `{"items":[]}`) // OPNsense answers unknown providers with an empty list
	return f
}

// systemBackupOnDownload answers a download like OPNsense: octet-stream with a suggested file name
func systemBackupOnDownload(f *fakeOPN, path string, filename string, content string) {
	f.onFunc("GET", path, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		_, _ = io.WriteString(w, content)
	})
}

// --- helpers shared by the system backup / defaults / wizard / power tests

var systemBackupColumnSeparator = regexp.MustCompile(`\s{2,}`)

// systemBackupTable splits table output into cells (columns are separated by at least two spaces)
func systemBackupTable(output string) [][]string {
	var rows [][]string
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		rows = append(rows, systemBackupColumnSeparator.Split(strings.TrimSpace(line), -1))
	}
	return rows
}

// systemBackupWantTable asserts the header and the cells of column col of the data rows, in this order
func systemBackupWantTable(t *testing.T, output string, header []string, col int, wantCol ...string) [][]string {
	t.Helper()
	var rows = systemBackupTable(output)
	if len(rows) == 0 {
		t.Fatalf("no table in output:\n%s", output)
	}
	if strings.Join(rows[0], "|") != strings.Join(header, "|") {
		t.Errorf("table header %q, want %q", rows[0], header)
	}
	var got []string
	for _, row := range rows[1:] {
		if len(row) != len(header) {
			t.Errorf("row has %d cells, header %d: %q", len(row), len(header), row)
			continue
		}
		got = append(got, row[col])
	}
	if strings.Join(got, "|") != strings.Join(wantCol, "|") {
		t.Errorf("table column %d %q, want %q\n%s", col, got, wantCol, output)
	}
	return rows
}

// systemBackupWantCalled asserts that method path was called at least once
func systemBackupWantCalled(t *testing.T, f *fakeOPN, method string, path string) {
	t.Helper()
	for _, call := range f.calls() {
		if call.Method == method && call.Path == path {
			return
		}
	}
	t.Errorf("%s %s was not called, calls: %v", method, path, f.calls())
}

// systemBackupWantNoCallTo asserts that no path with this prefix was requested with any method
func systemBackupWantNoCallTo(t *testing.T, f *fakeOPN, pathPrefix string) {
	t.Helper()
	for _, call := range f.calls() {
		if strings.HasPrefix(call.Path, pathPrefix) {
			t.Errorf("unexpected call %s", call)
		}
	}
}

func systemBackupName(args []string) string {
	return strings.Join(args, "_")
}

// --- tests

func TestSystemBackupProviders(t *testing.T) {
	t.Parallel()
	var f = systemBackupFake(t)
	var r = f.run("/system/backup", "providers")
	wantExit(t, r, 0)
	var rows = systemBackupWantTable(t, r.stdout, []string{"NAME", "DESCRIPTION", "DIRECTORY"}, 0, "this")
	if len(rows) == 2 && strings.Join(rows[1], "|") != "this|This Firewall|/conf/backup" {
		t.Errorf("row: %q", rows[1])
	}
	wantNoMutations(t, f)

	r = f.run("/system/backup", "providers", "json")
	wantExit(t, r, 0)
	var provider map[string]string
	if err := json.Unmarshal([]byte(r.stdout), &provider); err != nil || provider["name"] != "this" || provider["dirname"] != "/conf/backup" {
		t.Errorf("json: %v %q", err, r.stdout)
	}
}

func TestSystemBackupPrint(t *testing.T) {
	t.Parallel()
	var f = systemBackupFake(t)
	var r = f.run("/system", "backup", "print")
	wantExit(t, r, 0)
	var rows = systemBackupWantTable(t, r.stdout, []string{"#", "ID", "TIME", "USER", "SIZE", "DESCRIPTION"}, 1,
		systemBackupNewest, systemBackupMiddle, systemBackupOldest)
	if len(rows) > 1 {
		// TZ=UTC in the test environment
		if rows[1][0] != "0" || rows[1][2] != "2026-10-24 23:54:04" || rows[1][3] != "root@192.168.1.2" || rows[1][4] != "39130" {
			t.Errorf("row 1: %q", rows[1])
		}
	}
	wantNoMutations(t, f)

	t.Run("provider", func(t *testing.T) {
		t.Parallel()
		var f = systemBackupFake(t)
		wantExit(t, f.run("/system/backup", "print", "provider=this"), 0)
		systemBackupWantCalled(t, f, "GET", systemBackupListPath)
	})
	t.Run("unknown provider", func(t *testing.T) {
		t.Parallel()
		var f = systemBackupFake(t)
		wantFailure(t, f.run("/system/backup", "print", "provider=nope"), "not found", "nope")
	})
	t.Run("search", func(t *testing.T) {
		t.Parallel()
		var f = systemBackupFake(t)
		var r = f.run("/system/backup", "print", "search=ADMIN@")
		wantExit(t, r, 0)
		systemBackupWantTable(t, r.stdout, []string{"#", "ID", "TIME", "USER", "SIZE", "DESCRIPTION"}, 1, systemBackupOldest)
	})
	t.Run("detail", func(t *testing.T) {
		t.Parallel()
		var f = systemBackupFake(t)
		var r = f.run("/system/backup", "print", "detail")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "0\n  id:", "id:           "+systemBackupNewest, "description:  /api/dnsmasq/settings/set_host/5f2e09fc made changes", "\n2\n")
	})
	t.Run("json", func(t *testing.T) {
		t.Parallel()
		var f = systemBackupFake(t)
		var r = f.run("/system/backup", "print", "json")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != 3 {
			t.Fatalf("want 3 lines, got %q", r.stdout)
		}
		var backup map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &backup); err != nil || backup["id"] != systemBackupNewest || backup["filesize"] != float64(39130) {
			t.Errorf("json: %v %q", err, lines[0])
		}
	})
}

func TestSystemBackupDownload(t *testing.T) {
	t.Parallel()
	const suggested = "config-OPNsense.internal-1792886044.3812.xml"

	var setup = func(t *testing.T) (*fakeOPN, string) {
		var f = systemBackupFake(t)
		systemBackupOnDownload(f, systemBackupDownloadPath, suggested, systemBackupConfigXml)
		systemBackupOnDownload(f, systemBackupDownloadPath+"/"+systemBackupMiddle, "config-OPNsense.internal-1792886029.2372.xml", "<?xml?><opnsense>middle</opnsense>")
		f.on("GET", systemBackupDownloadPath+"/config-1.xml", 200, "") // unknown ids are answered with an empty 200
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
	var wantNoFiles = func(t *testing.T, dir string) {
		t.Helper()
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("files written: %v", entries)
		}
	}

	t.Run("current config to the suggested file name", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		var r = runOpnIn(t, dir, f.env(), "/system/backup", "download")
		wantExit(t, r, 0)
		wantFile(t, filepath.Join(dir, suggested), systemBackupConfigXml)
		wantNotContains(t, "stdout", r.stdout, "<opnsense>")
		wantContains(t, "stderr", r.stderr, suggested)
		// current needs no lookup in the history
		if calls := f.calls(); len(calls) != 1 || calls[0].Path != systemBackupDownloadPath {
			t.Errorf("want only the download, got %v", calls)
		}
	})
	t.Run("current by name", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		wantExit(t, runOpnIn(t, dir, f.env(), "/system/backup", "download", "current"), 0)
		wantFile(t, filepath.Join(dir, suggested), systemBackupConfigXml)
	})
	t.Run("specific id to file=", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		var r = runOpnIn(t, dir, f.env(), "/system/backup", "download", systemBackupMiddle, "file=out.xml")
		wantExit(t, r, 0)
		wantFile(t, filepath.Join(dir, "out.xml"), "<?xml?><opnsense>middle</opnsense>")
		wantNoMutations(t, f)
	})
	t.Run("# of the list", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		var r = runOpnIn(t, dir, f.env(), "/system/backup", "download", "item=1", "file=out.xml")
		wantExit(t, r, 0)
		wantFile(t, filepath.Join(dir, "out.xml"), "<?xml?><opnsense>middle</opnsense>")
	})
	t.Run("# of the last print in a script", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		var r = runOpnWithStdin(t, dir, f.env(), "/system/backup\nprint search=add_job\ndownload 0 file=-\n")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "<opnsense>middle</opnsense>")
	})
	t.Run("file=- writes to stdout only", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		var r = runOpnIn(t, dir, f.env(), "/system/backup", "download", "file=-")
		wantExit(t, r, 0)
		if r.stdout != systemBackupConfigXml {
			t.Errorf("stdout %q, want the config", r.stdout)
		}
		wantNoFiles(t, dir)
	})
	t.Run("existing file is not overwritten without force", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		var path = filepath.Join(dir, "out.xml")
		if err := os.WriteFile(path, []byte("keep me"), 0o644); err != nil {
			t.Fatal(err)
		}
		var r = runOpnIn(t, dir, f.env(), "/system/backup", "download", "file=out.xml")
		wantFailure(t, r, "out.xml", "force")
		if data, _ := os.ReadFile(path); string(data) != "keep me" {
			t.Errorf("file was overwritten: %q", data)
		}

		r = runOpnIn(t, dir, f.env(), "/system/backup", "download", "file=out.xml", "force")
		wantExit(t, r, 0)
		if data, _ := os.ReadFile(path); string(data) != systemBackupConfigXml {
			t.Errorf("file not overwritten with force: %q", data)
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
			var f = systemBackupFake(t)
			systemBackupOnDownload(f, systemBackupDownloadPath, tc.header, systemBackupConfigXml)
			var parent = t.TempDir()
			var dir = filepath.Join(parent, "a", "b")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			wantExit(t, runOpnIn(t, dir, f.env(), "/system/backup", "download"), 0)
			wantFile(t, filepath.Join(dir, tc.want), systemBackupConfigXml)
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
	t.Run("force with file=- is refused", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		wantFailure(t, runOpnIn(t, dir, f.env(), "/system/backup", "download", "file=-", "force"), "download: force has no effect")
		wantNoCalls(t, f)
	})
	t.Run("unknown id writes no file and does not download", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		var r = runOpnIn(t, dir, f.env(), "/system/backup", "download", "config-1.xml")
		wantFailure(t, r, "not found", "config-1.xml")
		wantNoFiles(t, dir)
		systemBackupWantNoCallTo(t, f, systemBackupDownloadPath)
	})
	t.Run("unknown #", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		wantFailure(t, runOpnIn(t, dir, f.env(), "/system/backup", "download", "7"), "not found", "#7")
		wantNoFiles(t, dir)
	})
	t.Run("empty download is not found", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		f.on("GET", systemBackupDownloadPath+"/"+systemBackupOldest, 200, "")
		wantFailure(t, runOpnIn(t, dir, f.env(), "/system/backup", "download", systemBackupOldest), "not found", systemBackupOldest)
		wantNoFiles(t, dir)
	})
	t.Run("HTTP error writes no file", func(t *testing.T) {
		t.Parallel()
		var f, dir = setup(t)
		f.on("GET", systemBackupDownloadPath, 403, `{"status":403,"message":"Forbidden"}`)
		var r = runOpnIn(t, dir, f.env(), "/system/backup", "download")
		wantFailure(t, r, "403", "Forbidden")
		wantNoFiles(t, dir)
	})
}

func TestSystemBackupDiff(t *testing.T) {
	t.Parallel()
	const diff = `{"items":["--- /conf/backup/config-1792885909.1543.xml\t2026-10-24 23:51:49","+++ /conf/backup/config-1792886044.3812.xml\t2026-10-24 23:54:04",` +
		`"@@ -10,3 +10,3 @@","   &lt;system&gt;","-    &lt;hostname&gt;old&lt;/hostname&gt;","+    &lt;hostname&gt;new &amp; shiny&lt;/hostname&gt;"]}`

	t.Run("lines are printed unescaped, target first in the endpoint", func(t *testing.T) {
		t.Parallel()
		var f = systemBackupFake(t)
		// OPNsense runs diff -u <b2> <b1> for diff/<provider>/<b1>/<b2>
		f.on("GET", systemBackupDiffPath+systemBackupNewest+"/"+systemBackupOldest, 200, diff)
		var r = f.run("/system/backup", "diff", systemBackupOldest)
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "--- /conf/backup/"+systemBackupOldest, "+++ /conf/backup/"+systemBackupNewest,
			"-    <hostname>old</hostname>", "+    <hostname>new & shiny</hostname>")
		wantNotContains(t, "stdout", r.stdout, "&lt;", "&amp;")
		wantNoMutations(t, f)
	})
	t.Run("explicit to", func(t *testing.T) {
		t.Parallel()
		var f = systemBackupFake(t)
		f.on("GET", systemBackupDiffPath+systemBackupMiddle+"/"+systemBackupOldest, 200, diff)
		wantExit(t, f.run("/system/backup", "diff", "from="+systemBackupOldest, "to="+systemBackupMiddle), 0)
		systemBackupWantCalled(t, f, "GET", systemBackupDiffPath+systemBackupMiddle+"/"+systemBackupOldest)
	})
	t.Run("# of the list", func(t *testing.T) {
		t.Parallel()
		var f = systemBackupFake(t)
		f.on("GET", systemBackupDiffPath+systemBackupMiddle+"/"+systemBackupOldest, 200, diff)
		var r = f.run("/system/backup", "diff", "2", "to=1")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "+    <hostname>new & shiny</hostname>")
		systemBackupWantCalled(t, f, "GET", systemBackupDiffPath+systemBackupMiddle+"/"+systemBackupOldest)
	})
	t.Run("identical backups", func(t *testing.T) {
		t.Parallel()
		var f = systemBackupFake(t)
		var r = f.run("/system/backup", "diff", systemBackupNewest)
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "no differences")
		if r.stdout != "" {
			t.Errorf("stdout %q", r.stdout)
		}
		systemBackupWantNoCallTo(t, f, systemBackupDiffPath)
	})
	t.Run("from is required, no API call", func(t *testing.T) {
		t.Parallel()
		var f = systemBackupFake(t)
		wantFailure(t, f.run("/system/backup", "diff"), "from")
		wantNoCalls(t, f)
	})
	t.Run("unknown id is an error, not an empty diff", func(t *testing.T) {
		t.Parallel()
		var f = systemBackupFake(t)
		wantFailure(t, f.run("/system/backup", "diff", "config-1.xml"), "not found", "config-1.xml")
		wantFailure(t, f.run("/system/backup", "diff", "0", "to=config-1.xml"), "not found", "config-1.xml")
		systemBackupWantNoCallTo(t, f, systemBackupDiffPath)
	})
}

// revert and remove must never reach the API without confirmation
func TestSystemBackupRevertRemoveGuards(t *testing.T) {
	t.Parallel()
	for _, command := range []string{"revert", "remove"} {
		for _, args := range [][]string{
			{systemBackupMiddle},
			{systemBackupMiddle, "confirm=no"},
			{"item=" + systemBackupMiddle, "yes"},
			{"confirm"},
			{"0"},
			{},
		} {
			t.Run(command+"_"+systemBackupName(args), func(t *testing.T) {
				t.Parallel()
				var f = systemBackupFake(t)
				var r = f.run(append([]string{"/system/backup", command}, args...)...)
				wantFailure(t, r)
				wantNoCalls(t, f)
			})
		}
	}
	t.Run("the warning is shown", func(t *testing.T) {
		t.Parallel()
		var f = systemBackupFake(t)
		var r = f.run("/system/backup", "revert", "0")
		wantFailure(t, r, "WHOLE running configuration", "confirm=yes")
		wantNoCalls(t, f)
	})
	t.Run("a script answers no to the question", func(t *testing.T) {
		t.Parallel()
		var f = systemBackupFake(t)
		wantFailure(t, f.runScript("/system/backup remove 0\n"), "confirm=yes")
		wantNoCalls(t, f)
	})
}

func TestSystemBackupRevertRemove(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		command string
		path    string
		answer  string
	}{
		{"revert", systemBackupRevertPath, `{"status":"reverted"}`},
		{"remove", systemBackupDeletePath, `{"status":"deleted"}`},
	} {
		t.Run(tc.command+" with confirm is a POST of exactly that id", func(t *testing.T) {
			t.Parallel()
			var f = systemBackupFake(t)
			f.on("POST", tc.path+systemBackupMiddle, 200, tc.answer)
			var r = f.run("/system/backup", tc.command, systemBackupMiddle, "confirm")
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("stdout %q, want silent success", r.stdout)
			}
			var call = wantOneMutation(t, f, "POST", tc.path+systemBackupMiddle)
			if call.Body != "" {
				t.Errorf("unexpected body %q", call.Body)
			}
		})
		t.Run(tc.command+" by # of the last print", func(t *testing.T) {
			t.Parallel()
			var f = systemBackupFake(t)
			f.on("POST", tc.path+systemBackupOldest, 200, tc.answer)
			var r = f.runScript("/system/backup\nprint search=dnsmasq\n" + tc.command + " 0 confirm=yes\n")
			wantExit(t, r, 0)
			wantOneMutation(t, f, "POST", tc.path+systemBackupOldest)
		})
		t.Run(tc.command+" by # of the list (one-shot)", func(t *testing.T) {
			t.Parallel()
			var f = systemBackupFake(t)
			f.on("POST", tc.path+systemBackupOldest, 200, tc.answer)
			wantExit(t, f.run("/system/backup", tc.command, "2", "confirm=yes"), 0)
			wantOneMutation(t, f, "POST", tc.path+systemBackupOldest)
		})
		t.Run(tc.command+" of an unknown id", func(t *testing.T) {
			t.Parallel()
			var f = systemBackupFake(t)
			wantFailure(t, f.run("/system/backup", tc.command, "config-1.xml", "confirm"), "not found", "config-1.xml")
			wantNoMutations(t, f)
		})
		t.Run(tc.command+" answered not_found", func(t *testing.T) {
			t.Parallel()
			var f = systemBackupFake(t)
			f.on("POST", tc.path+systemBackupMiddle, 200, `{"status":"not_found"}`)
			wantFailure(t, f.run("/system/backup", tc.command, systemBackupMiddle, "confirm"), "not found")
		})
		t.Run(tc.command+" of current is refused", func(t *testing.T) {
			t.Parallel()
			var f = systemBackupFake(t)
			wantFailure(t, f.run("/system/backup", tc.command, "current", "confirm"), tc.command+": item must be a backup", "not current")
			// refused before the confirmation question
			var r = f.run("/system/backup", tc.command, "current")
			wantFailure(t, r, "not current")
			wantNotContains(t, "output", r.stderr, "confirm=yes")
			wantFailure(t, f.runScript("/system/backup "+tc.command+" current\n"), "stdin:1: "+tc.command+": item must be a backup")
			wantNoCalls(t, f)
		})
	}
	t.Run("revert hints at reconfiguring", func(t *testing.T) {
		t.Parallel()
		var f = systemBackupFake(t)
		f.on("POST", systemBackupRevertPath+systemBackupMiddle, 200, `{"status":"reverted"}`)
		var r = f.run("/system/backup", "revert", systemBackupMiddle, "confirm")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, systemBackupMiddle, "reconfigure")
	})
}

func TestSystemBackupHelp(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args  []string
		wants []string
	}{
		{[]string{"/system", "?"}, []string{"backup", "defaults", "wizard", "reboot", "shutdown"}},
		{[]string{"/system/backup", "?"}, []string{"print", "providers", "download", "diff", "revert", "remove"}},
		{[]string{"/system/backup", "revert", "?"}, []string{"confirm", "item=", "WHOLE"}},
		{[]string{"/system/backup", "remove", "?"}, []string{"confirm", "item="}},
		{[]string{"/system/backup", "download", "?"}, []string{"file=", "force", "0600"}},
		{[]string{"/system/backup", "diff", "?"}, []string{"from=", "to=", "default current"}},
	} {
		t.Run(systemBackupName(tc.args), func(t *testing.T) {
			t.Parallel()
			var r = runOpn(t, nil, tc.args...)
			wantExit(t, r, 0)
			wantContains(t, "help", r.stdout, tc.wants...)
		})
	}
}

// --- cross-cutting checks for every command of this area that talks to the API

// systemBackupApiCommands are the commands of /system/backup, defaults, wizard and power with minimal valid
// arguments. Destructive ones are included: they only ever reach the fake server
var systemBackupApiCommands = [][]string{
	{"/system/backup", "providers"},
	{"/system/backup", "print"},
	{"/system/backup", "download", "file=-"},
	{"/system/backup", "diff", "config-1.xml"},
	{"/system/backup", "revert", "config-1.xml", "confirm"},
	{"/system/backup", "remove", "config-1.xml", "confirm"},
	{"/system/defaults", "print"},
	{"/system/defaults", "reset", "confirm"},
	{"/system/wizard", "print"},
	{"/system", "reboot", "confirm"},
	{"/system", "shutdown", "confirm"},
}

func TestSystemBackupMissingEnvironment(t *testing.T) {
	t.Parallel()
	var full = map[string]string{"OPN_URL": "https://127.0.0.1:1", "OPN_APIKEY": "k", "OPN_APISECRET": "s"}
	for _, missing := range []string{"OPN_URL", "OPN_APIKEY", "OPN_APISECRET"} {
		var env []string
		for name, value := range full {
			if name != missing {
				env = append(env, name+"="+value)
			}
		}
		for _, args := range systemBackupApiCommands {
			t.Run(missing+"/"+systemBackupName(args), func(t *testing.T) {
				t.Parallel()
				wantFailure(t, runOpn(t, env, args...), missing)
			})
		}
	}
}

// every command authenticates with the api key / secret and stops at the first 401
func TestSystemBackupUnauthorized(t *testing.T) {
	t.Parallel()
	for _, args := range systemBackupApiCommands {
		t.Run(systemBackupName(args), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			var env = []string{"OPN_URL=" + f.srv.URL, "OPN_APIKEY=" + testApiKey, "OPN_APISECRET=wrong", "OPN_NOSSLVERIFY=1"}
			var r = runOpn(t, env, args...)
			wantFailure(t, r, "401", "Authentication Failed")
			var calls = f.calls()
			if len(calls) != 1 {
				t.Errorf("want a single (rejected) API call, got %v", calls)
			}
			for _, call := range calls {
				if !call.HasAuth || call.User != testApiKey || call.Pass != "wrong" {
					t.Errorf("%s: basic auth not sent as given: %q/%q", call, call.User, call.Pass)
				}
			}
		})
	}
}

// OPNsense answers unknown endpoints (e.g. a version without the API) with an empty 200, that is never a success
func TestSystemBackupEmptyResponseIsAnError(t *testing.T) {
	t.Parallel()
	for _, args := range systemBackupApiCommands {
		t.Run(systemBackupName(args), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			var r = f.run(args...)
			wantExit(t, r, 1)
			wantNotContains(t, "output", r.stdout+r.stderr, "success", "saved", "reverted", "scheduled", "initiated")
			if r.stdout != "" {
				t.Errorf("a failed command printed to stdout: %q", r.stdout)
			}
		})
	}
}

// actions must be POSTed: OPNsense silently ignores a GET
func TestSystemBackupActionsArePosts(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args []string
		path string
		body string
	}{
		{[]string{"/system/backup", "remove", systemBackupOldest, "confirm"}, systemBackupDeletePath + systemBackupOldest, `{"status":"deleted"}`},
		{[]string{"/system/backup", "revert", systemBackupOldest, "confirm"}, systemBackupRevertPath + systemBackupOldest, `{"status":"reverted"}`},
		{[]string{"/system/defaults", "reset", "confirm"}, systemDefaultsResetPath, systemBackupStatusOk},
		{[]string{"/system", "reboot", "confirm"}, systemPowerRebootPath, systemBackupStatusOk},
		{[]string{"/system", "shutdown", "confirm"}, systemPowerHaltPath, systemBackupStatusOk},
	} {
		t.Run(systemBackupName(tc.args), func(t *testing.T) {
			t.Parallel()
			var f = systemBackupFake(t)
			f.on("GET", systemDefaultsGetPath, 200, systemDefaultsAnswer)
			// answer the action for any method, so a wrong method would succeed and be caught here
			for _, method := range []string{"GET", "POST", "PUT"} {
				f.on(method, tc.path, 200, tc.body)
			}
			wantExit(t, f.run(tc.args...), 0)
			for _, call := range f.calls() {
				if call.Path == tc.path && call.Method != "POST" {
					t.Errorf("%s sent as %s", tc.path, call.Method)
				}
			}
			wantOneMutation(t, f, "POST", tc.path)
		})
	}
}
