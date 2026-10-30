//go:build integration

package integrationauth

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/auth"
)

// TestCliUserTransfer drives /system/user export and import. Only users of this run are imported (disabled, without
// privileges, in a group of this run without privileges); the refusals of rows for root, the API key's user and
// "All pages" are tested with fakes only, so nothing about real users is ever sent
func TestCliUserTransfer(t *testing.T) {
	var opn = authApi(t)
	var group = createGroup(t, "csv-ops", auth.GroupFields{})
	var first, second = testName("csv-alice"), testName("csv-bob")
	t.Cleanup(func() {
		for _, name := range []string{first, second} {
			if user, err := opn.UserGetByName(name); err == nil {
				removeUser(t, user.Uuid)
			} else if !api.IsNotFound(err) {
				t.Errorf("cleanup: looking up %s: %v", name, err)
			}
		}
	})
	var dir = t.TempDir()
	var write = func(name string, content string) string {
		var path = filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	var file = write("add.csv", "name;disabled;email;comment;group_memberships;descr\n"+
		first+";1;csv@example.com;imported;"+group.Gid+";\"CSV Alice\"\n"+
		second+";1;;imported;;CSV Bob\n")
	mustFailOpn(t, "/system/user", "import", file) // no confirm
	if _, err := opn.UserGetByName(first); !api.IsNotFound(err) {
		t.Fatalf("import without confirm created %s: %v", first, err)
	}

	t.Run("add", func(t *testing.T) {
		var imported = mustOpn(t, "/system/user", "import", file, "confirm=yes")
		requireContains(t, imported, imported.stderr, "2 users added, 0 updated")
		var alice, err = opn.UserGetByName(first)
		if err != nil {
			t.Fatal(err)
		}
		if !alice.Disabled || alice.Email != "csv@example.com" || alice.Descr != "CSV Alice" || alice.Comment != "imported" ||
			!slices.Equal(alice.Groups, []string{group.Gid}) || len(alice.Privileges) != 0 || alice.IsAdmin || alice.Shell != "" {
			t.Errorf("imported %+v", alice)
		}
		if alice.PasswordChangedAt == "" {
			t.Errorf("an imported user gets a random password: %+v", alice)
		}
		if got, _ := opn.GroupGet(group.Uuid); !slices.Equal(got.Members, []string{alice.Uid}) {
			t.Errorf("group members %v, want [%s]", got.Members, alice.Uid)
		}
	})

	t.Run("update", func(t *testing.T) {
		var imported = mustOpn(t, "/system/user", "import", write("update.csv", "name,comment\n"+first+",updated\n"), "confirm=yes")
		requireContains(t, imported, imported.stderr, "0 users added, 1 updated")
		if alice, _ := opn.UserGetByName(first); alice.Comment != "updated" || alice.Descr != "CSV Alice" ||
			!slices.Equal(alice.Groups, []string{group.Gid}) || !alice.Disabled {
			t.Errorf("after the update (only comment changes) %+v", alice)
		}
	})

	t.Run("rejected", func(t *testing.T) {
		var rejected = mustFailOpn(t, "/system/user", "import", write("bad.csv", "name;disabled\n"+second+";7\n"), "confirm=yes")
		requireContains(t, rejected, rejected.stderr, "line 2: disabled: ")
		var unknown = mustFailOpn(t, "/system/user", "import", write("password.csv", "name;password\n"+second+";x\n"), "confirm=yes")
		requireContains(t, unknown, unknown.stderr, "unknown columns password")
		if bob, _ := opn.UserGetByName(second); !bob.Disabled {
			t.Errorf("a rejected row changed %+v", bob)
		}
	})

	t.Run("export", func(t *testing.T) {
		var out = filepath.Join(dir, "export.csv")
		var exported = mustOpn(t, "/system/user", "export", out)
		requireContains(t, exported, exported.stderr, "users to "+out)
		var content, err = os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if info, _ := os.Stat(out); info.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", info.Mode())
		}
		var parsed, parseErr = api.ParseCsv(content, "users")
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if secrets := auth.UserCsvSecrets(parsed); len(secrets) != 0 {
			t.Errorf("the export holds secrets in %v", secrets) // values are not printed
		}
		for _, column := range []string{"name", "disabled", "group_memberships", "priv", "descr"} {
			if !slices.Contains(parsed.Header, column) {
				t.Errorf("the export lacks the column %s: %v", column, parsed.Header)
			}
		}
		var names, _ = parsed.Column("name")
		var comments, _ = parsed.Column("comment")
		if index := slices.Index(names, first); index < 0 || comments[index] != "updated" {
			t.Errorf("the export lacks %s (or its comment): %v", first, names)
		}
		var stdout = mustOpn(t, "/system/user", "export", "-")
		if !strings.Contains(stdout.stdout, second) || strings.Contains(stdout.stderr, "warning") {
			t.Errorf("export -: stderr %q", stdout.stderr)
		}

		// the export can be imported again once the rows of other users are left out: it updates the users of this run
		var buffer strings.Builder
		var writer = csv.NewWriter(&buffer)
		writer.Comma = ';'
		_ = writer.Write(parsed.Header)
		for i, row := range parsed.Rows {
			if ownedByRun(names[i]) {
				_ = writer.Write(row)
			}
		}
		writer.Flush()
		var again = mustOpn(t, "/system/user", "import", write("again.csv", buffer.String()), "confirm=yes")
		requireContains(t, again, again.stderr, "0 users added, 2 updated")
	})
}
