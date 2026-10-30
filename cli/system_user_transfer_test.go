package cli

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	systemUserDownloadPath = "/api/auth/user/download"
	systemUserUploadPath   = "/api/auth/user/upload"
	// systemUserExportCsv is an export of OPNsense 26.7.7 (apikeys is always empty)
	systemUserExportCsv = "name;disabled;expires;shell;pwd_changed_at;landing_page;comment;email;apikeys;priv;language;group_memberships;descr\n" +
		"root;0;;;;;;;;;;1999;\"System Administrator\"\n" +
		"automation;0;;;;;;;;;;1999;\n" +
		"alice;1;12/31/2099;;1792942806.4744;;;alice@example.com;;page-status-ntp;;2000;\"Alice A\"\n"
)

// systemUserTransferFake is systemUserFake with a download answering export and an upload answering upload
func systemUserTransferFake(t *testing.T, export string, upload string) *fakeOPN {
	t.Helper()
	var f = systemUserFake(t)
	f.onFunc("GET", systemUserDownloadPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/csv;charset=UTF-8")
		_, _ = io.WriteString(w, export)
	})
	f.on("POST", systemUserUploadPath, 200, upload)
	return f
}

// systemUserTransferFile writes content to a new file in a temp dir and returns its path
func systemUserTransferFile(t *testing.T, content string) string {
	t.Helper()
	var path = filepath.Join(t.TempDir(), "users.csv")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSystemUserExport(t *testing.T) {
	t.Parallel()
	var f = systemUserTransferFake(t, systemUserExportCsv, "")
	var file = filepath.Join(t.TempDir(), "users.csv")

	var r = f.run("/system/user", "export", file)
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "saved 3 users to "+file)
	wantNotContains(t, "stderr", r.stderr, "warning")
	if content, err := os.ReadFile(file); err != nil || string(content) != systemUserExportCsv {
		t.Errorf("file: %q, %v", content, err)
	}
	if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("mode: %v, %v", info.Mode(), err)
	}
	wantFailure(t, f.run("/system/user", "export", file), "already exists, add overwrite")

	r = f.run("/system/user", "export", "-")
	wantExit(t, r, 0)
	if r.stdout != systemUserExportCsv {
		t.Errorf("stdout: %q", r.stdout)
	}
	if r.stderr != "" {
		t.Errorf("an export without secrets warns about nothing: %q", r.stderr)
	}
	wantNoMutations(t, f)
}

func TestSystemUserExportWarnsAboutSecrets(t *testing.T) {
	t.Parallel()
	var f = systemUserTransferFake(t, "name;apikeys;priv\nalice;c2VjcmV0a2V5|$6$cryptedsecret;\nbob;;\n", "")
	var r = f.run("/system/user", "export", "-")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "alice;c2VjcmV0a2V5|$6$cryptedsecret;")
	wantContains(t, "stderr", r.stderr, "warning: this export holds secrets (columns apikeys), keep the output private")
	wantNotContains(t, "stderr", r.stderr, "c2VjcmV0a2V5", "cryptedsecret")

	// a file is private (0600), no warning
	r = f.run("/system/user", "export", filepath.Join(t.TempDir(), "users.csv"))
	wantExit(t, r, 0)
	wantNotContains(t, "stderr", r.stderr, "warning", "c2VjcmV0a2V5")
}

func TestSystemUserImport(t *testing.T) {
	t.Parallel()
	var content = "name;disabled;email;priv;group_memberships;descr;apikeys\n" +
		"alice;0;alice@example.com;page-status-ntp;2000;\"Alice A\";\n" +
		"bob;0;;;;Bob;\n"
	var file = systemUserTransferFile(t, content)

	t.Run("asks", func(t *testing.T) {
		t.Parallel()
		var f = systemUserTransferFake(t, systemUserExportCsv, "")
		wantFailure(t, f.run("/system/user", "import", file), "This adds users and overwrites those matching by name", "confirm=yes")
		wantNoMutations(t, f)
	})
	t.Run("imports", func(t *testing.T) {
		t.Parallel()
		var f = systemUserTransferFake(t, systemUserExportCsv,
			`{"validations":[],"inserted":1,"updated":1,"uuids":{"u-alice":0,"u-bob":1},"fieldnames":["name"]}`)
		var r = f.run("/system/user", "import", file, "confirm=yes")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "imported "+file+": 1 users added, 1 updated")
		wantJSON(t, wantOneMutation(t, f, "POST", systemUserUploadPath), map[string]any{"payload": content, "filename": "users.csv"})
	})
	t.Run("rejected rows", func(t *testing.T) {
		t.Parallel()
		var f = systemUserTransferFake(t, systemUserExportCsv,
			`{"validations":[{"sequence":1,"message":"Option [9] not in list.","field":"group_memberships"}],"inserted":1,"updated":1,"uuids":{"u-alice":0,"u-x":1}}`)
		wantFailure(t, f.run("/system/user", "import", file, "confirm=yes"),
			"OPNsense rejected rows of "+file, "line 3: group_memberships: Option [9] not in list.", "check the users")
	})
}

func TestSystemUserImportRefusesBeforeSending(t *testing.T) {
	t.Parallel()
	var cases = []struct {
		name    string
		content string
		wants   []string
	}{
		{"root", "name;comment\nbob;x\nroot;x\n", []string{"line 3 (root): root is protected by opn"}},
		{"root other case", "name;comment\nRoot;x\n", []string{"line 2 (Root): root is protected by opn"}},
		{"api key user", "name;disabled\nautomation;1\n", []string{"line 2 (automation): the user of the API key opn uses is protected by opn"}},
		{"page-all", "name;priv\nbob;\"page-status-ntp,page-all\"\n", []string{"line 2 (bob): priv grants page-all (All pages)"}},
		{"admins by gid", "name,group_memberships\nbob,\"2000,1999\"\n",
			[]string{"line 2 (bob): group_memberships adds group admins (gid 1999), it grants page-all (All pages)"}},
		{"admins by name", "name;group_memberships\nbob;admins\n", []string{"line 2 (bob): group_memberships adds group admins (gid 1999)"}},
		{"api keys", "name;apikeys\nbob;c2VjcmV0a2V5|$6$cryptedsecret\n",
			[]string{"line 2 (bob): apikeys is not empty: it would replace the API keys of the user, manage them with api-key"}},
		{"all listed", "name;priv;group_memberships\nroot;page-all;1999\nbob;;\n", []string{
			"refusing to import, nothing was sent:", "line 2 (root): root is protected", "line 2 (root): priv grants page-all",
			"line 2 (root): group_memberships adds group admins"}},
		{"no name column", "descr\nBob\n", []string{"the file has no name column: the import matches users by name"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = systemUserTransferFake(t, systemUserExportCsv, `{"inserted":1}`)
			var file = systemUserTransferFile(t, tc.content)
			// refused before the question, and also with confirm=yes
			for _, args := range [][]string{{"import", file}, {"import", file, "confirm=yes"}} {
				var r = f.run(append([]string{"/system/user"}, args...)...)
				wantFailure(t, r, tc.wants...)
				wantNotContains(t, "stderr", r.stderr, "This adds users", "c2VjcmV0a2V5", "cryptedsecret")
			}
			wantNoMutations(t, f)
		})
	}
}

func TestSystemUserImportRefusesCustomAdminGroups(t *testing.T) {
	t.Parallel()
	var f = systemUserTransferFake(t, systemUserExportCsv, `{"inserted":1}`)
	f.search(systemGroupSearchPath, append(systemGroupRows(),
		map[string]any{"uuid": "g-super", "gid": "2005", "name": "super", "scope": "user", "description": "",
			"priv": "page-status-ntp,page-all", "%priv": "", "member": "", "%member": "", "source_networks": ""})...)
	var file = systemUserTransferFile(t, "name;group_memberships\nbob;2000\ncarol;2005\n")
	wantFailure(t, f.run("/system/user", "import", file, "confirm=yes"),
		"line 3 (carol): group_memberships adds group super (gid 2005), it grants page-all")
	wantNoMutations(t, f)
}

func TestSystemUserImportColumns(t *testing.T) {
	t.Parallel()
	var f = systemUserTransferFake(t, systemUserExportCsv, `{"inserted":1}`)
	var r = f.run("/system/user", "import", systemUserTransferFile(t, "name;password;otp_seed\nbob;secret;JBSWY3DP\n"), "confirm=yes")
	wantFailure(t, r, "unknown columns password, otp_seed, valid are: name, disabled, expires")
	wantNotContains(t, "stderr", r.stderr, "JBSWY3DP", ";secret")
	wantNoMutations(t, f)

	// without users to export (impossible, root always exists) the columns of 26.7 apply
	var empty = systemUserTransferFake(t, "", `{"inserted":1,"updated":0,"uuids":{"u":0}}`)
	wantFailure(t, empty.run("/system/user", "import", systemUserTransferFile(t, "name;bogus\nbob;x\n"), "confirm=yes"),
		"unknown columns bogus, valid are: name, disabled")
	wantExit(t, empty.run("/system/user", "import", systemUserTransferFile(t, "name;descr\nbob;Bob\n"), "confirm=yes"), 0)
}

func TestSystemUserImportWithoutKeyOwner(t *testing.T) {
	t.Parallel()
	// the API key in use is not listed (e.g. not allowed to list keys): only root is protected by name
	var f = systemUserTransferFake(t, systemUserExportCsv, `{"inserted":0,"updated":1,"uuids":{"u-api":0}}`)
	f.search(systemUserKeysPath)
	var r = f.run("/system/user", "import", systemUserTransferFile(t, "name;comment\nautomation;x\n"), "confirm=yes")
	wantExit(t, r, 0)
	if !strings.Contains(r.stderr, "0 users added, 1 updated") {
		t.Errorf("stderr: %q", r.stderr)
	}
}
