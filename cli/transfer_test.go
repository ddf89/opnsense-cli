package cli

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

// transferTestRoot is a menu tree with a CsvTransfer against /api/zz/csv/{download,upload}
func transferTestRoot() *Menu {
	var transfer = CsvTransfer{What: "things", Key: "name",
		Export: func(c *Context) ([]byte, error) {
			var opn, err = c.Api()
			if err != nil {
				return nil, err
			}
			return opn.DownloadCsv(opn.EndpointForPluginControllerMethod("zz", "csv", "download"))
		},
		Import: func(c *Context, content []byte, filename string) (coreapi.CsvImportResult, error) {
			var opn, err = c.Api()
			if err != nil {
				return coreapi.CsvImportResult{}, err
			}
			return opn.UploadCsv(opn.EndpointForPluginControllerMethod("zz", "csv", "upload"), content, filename)
		},
		Columns: func(c *Context) ([]string, error) { return []string{"name", "ip"}, nil },
	}
	var root = &Menu{}
	root.Menu("things").Add(transfer.ExportCommand(), transfer.ImportCommand())
	return root
}

// transferRun runs one command line in-process (non-interactive) against the fake
func transferRun(t *testing.T, f *fakeOPN, args ...string) runResult {
	t.Helper()
	var out, errOut bytes.Buffer
	var session = NewSession(&out, &errOut)
	var root = transferTestRoot()
	session.root, session.cwd = root, root
	var base, err = url.Parse(f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	session.Configure = func() (*coreapi.OPNsense, error) {
		return &coreapi.OPNsense{BaseUrl: *base, ApiKey: testApiKey, ApiSecret: testApiSecret, NoSslVerify: true}, nil
	}
	var r = runResult{}
	if err := session.Execute(append([]string{"/things"}, args...)); err != nil {
		r.code = 1
		errOut.WriteString("error: " + err.Error() + "\n")
	}
	r.stdout, r.stderr = out.String(), errOut.String()
	return r
}

func transferTestFake(t *testing.T, export string) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.onFunc("GET", "/api/zz/csv/download", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		_, _ = io.WriteString(w, export)
	})
	return f
}

func TestCsvTransferExport(t *testing.T) {
	t.Parallel()
	var dir = t.TempDir()
	var file = filepath.Join(dir, "things.csv")
	var f = transferTestFake(t, "name;ip\na;192.0.2.1\nb;192.0.2.2\n")

	var r = transferRun(t, f, "export", file)
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "saved 2 things to "+file)
	if content, err := os.ReadFile(file); err != nil || string(content) != "name;ip\na;192.0.2.1\nb;192.0.2.2\n" {
		t.Errorf("file: %q, %v", content, err)
	}
	if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("mode: %v, %v", info.Mode(), err)
	}
	wantFailure(t, transferRun(t, f, "export", file), "already exists, add overwrite")
	wantExit(t, transferRun(t, f, "export", file, "overwrite"), 0)
	r = transferRun(t, f, "export", "-")
	wantExit(t, r, 0)
	if r.stdout != "name;ip\na;192.0.2.1\nb;192.0.2.2\n" {
		t.Errorf("stdout: %q", r.stdout)
	}
	wantFailure(t, transferRun(t, f, "export", "-", "overwrite"), "overwrite has no effect")
	wantNoMutations(t, f)

	var empty = transferTestFake(t, "")
	r = transferRun(t, empty, "export", filepath.Join(dir, "none.csv"))
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "there are no things, nothing exported")
	if _, err := os.Stat(filepath.Join(dir, "none.csv")); !os.IsNotExist(err) {
		t.Errorf("an empty export must not write a file: %v", err)
	}
}

func TestCsvTransferImport(t *testing.T) {
	t.Parallel()
	var dir = t.TempDir()
	var write = func(name string, content string) string {
		var path = filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	var good = write("good.csv", "name;ip\na;192.0.2.1\n")

	t.Run("refused without confirm, checked first", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		wantFailure(t, transferRun(t, f, "import", good), "This adds things and overwrites those matching by name", "confirm=yes")
		wantFailure(t, transferRun(t, f, "import", write("empty.csv", ""), "confirm=yes"), "the file is empty")
		wantFailure(t, transferRun(t, f, "import", write("header.csv", "name;ip\n"), "confirm=yes"), "header but no things")
		wantFailure(t, transferRun(t, f, "import", filepath.Join(dir, "missing.csv"), "confirm=yes"), "no such file")
		wantFailure(t, transferRun(t, f, "import", "-", "confirm=yes"), "stdin is not supported")
		wantFailure(t, transferRun(t, f, "import", write("unknown.csv", "name;mac\na;x\n"), "confirm=yes"),
			"unknown columns mac, valid are: name, ip")
		wantNoMutations(t, f)
	})
	t.Run("import", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("POST", "/api/zz/csv/upload", 200, `{"inserted":1,"updated":0,"uuids":{"u1":0},"validations":[]}`)
		var r = transferRun(t, f, "import", good, "confirm=yes")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "imported "+good+": 1 things added, 0 updated")
		wantJSON(t, wantOneMutation(t, f, "POST", "/api/zz/csv/upload"), map[string]any{"payload": "name;ip\na;192.0.2.1\n", "filename": "good.csv"})
	})
	t.Run("rejected rows", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("POST", "/api/zz/csv/upload", 200, `{"inserted":0,"updated":0,"validations":[{"sequence":0,"field":"ip","message":"bad"},{"message":"general"}]}`)
		var r = transferRun(t, f, "import", good, "confirm=yes")
		wantFailure(t, r, "OPNsense rejected rows of "+good, "line 2: ip: bad", "file: general", "check the things")
		if strings.Contains(r.stdout, "imported") {
			t.Errorf("no success message on rejected rows: %q", r.stdout)
		}
	})
}
