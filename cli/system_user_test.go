package cli

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const (
	systemUserSearchPath  = "/api/auth/user/search"
	systemUserAddPath     = "/api/auth/user/add"
	systemUserSetPath     = "/api/auth/user/set/"
	systemUserDelPath     = "/api/auth/user/del/"
	systemUserKeysPath    = "/api/auth/user/search_api_key"
	systemGroupSearchPath = "/api/auth/group/search"
	systemPrivSearchPath  = "/api/auth/priv/search"
)

// systemUserRow is a user search row of OPNsense 26.7, with the secret fields it really contains
func systemUserRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "uid": "", "name": "", "disabled": "0", "scope": "user", "expires": "", "authorizedkeys": "",
		"otp_seed": "", "shell": "", "password": "$argon2id$v=19$m=65536,t=4,p=1$secrethash", "%password": "",
		"scrambled_password": "0", "pwd_changed_at": "", "landing_page": "", "comment": "", "email": "",
		"apikeys": "somekey|$6$cryptedsecret", "%apikeys": "", "priv": "", "language": "", "group_memberships": "",
		"%group_memberships": "", "descr": "", "dashboard": "", "is_admin": "0", "shell_warning": "0",
	}, overrides)
}

func systemUserRows() []map[string]any {
	return []map[string]any{
		systemUserRow(map[string]any{"uuid": "u-root", "uid": "0", "name": "root", "scope": "system", "group_memberships": "1999",
			"%group_memberships": "admins", "descr": "System Administrator", "is_admin": "1"}),
		systemUserRow(map[string]any{"uuid": "u-api", "uid": "2000", "name": "automation", "group_memberships": "1999",
			"%group_memberships": "admins", "is_admin": "1"}),
		systemUserRow(map[string]any{"uuid": "u-alice", "uid": "2001", "name": "alice", "disabled": "1", "descr": "Alice A",
			"group_memberships": "2000", "%group_memberships": "ops", "priv": "page-status-ntp", "expires": "12/31/2099",
			"otp_seed": "JBSWY3DPEHPK3PXP", "authorizedkeys": "ssh-ed25519 AAAA a@x", "pwd_changed_at": "1792942806.4744"}),
	}
}

func systemGroupRows() []map[string]any {
	return []map[string]any{
		{"uuid": "g-admins", "gid": "1999", "name": "admins", "scope": "system", "description": "System Administrators",
			"priv": "page-all", "%priv": "All pages", "member": "0,2000", "%member": "root, automation", "source_networks": ""},
		{"uuid": "g-ops", "gid": "2000", "name": "ops", "scope": "user", "description": "operators",
			"priv": "page-status-ntp", "%priv": "Status: NTP", "member": "2001", "%member": "alice", "source_networks": ""},
	}
}

// systemUserKeyRows: the key of the test connection (testApiKey) belongs to automation, not to root
func systemUserKeyRows() []map[string]any {
	return []map[string]any{
		{"username": "root", "key": "cm9vdGtleQ==", "id": "Y205dmRHdGxlUT09"},
		{"username": "automation", "key": testApiKey, "id": "dGVzdC1rZXk="},
		{"username": "alice", "key": "YWxpY2VrZXk=", "id": "WVd4cFkyVnJaWGs9"},
	}
}

func systemPrivRows() []map[string]any {
	return []map[string]any{
		{"id": "page-all", "name": "All pages", "match": "*", "users": []any{}, "groups": []any{"admins"}},
		{"id": "page-diagnostics-ping", "name": "Diagnostics: Ping", "match": "ui/diagnostics/ping*\napi/diagnostics/ping/*",
			"users": []any{}, "groups": []any{}},
		{"id": "page-status-ntp", "name": "Status: NTP", "match": "ui/ntpd/status*", "users": []any{"alice"}, "groups": []any{"ops"}},
	}
}

// systemUserFake answers the searches of users, groups, API keys and privileges
func systemUserFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(systemUserSearchPath, systemUserRows()...)
	f.search(systemGroupSearchPath, systemGroupRows()...)
	f.search(systemUserKeysPath, systemUserKeyRows()...)
	f.search(systemPrivSearchPath, systemPrivRows()...)
	return f
}

func TestSystemUserPrint(t *testing.T) {
	t.Parallel()
	var f = systemUserFake(t)
	var r = f.run("/system/user", "print")
	wantExit(t, r, 0)
	var want = []string{
		"#|NAME|UID|DISABLED|ADMIN|GROUPS|FULL-NAME|EXPIRES",
		"0|root|0|no|yes|admins|System Administrator|-",
		"1|automation|2000|no|yes|admins|-|-",
		"2|alice|2001|yes|no|ops|Alice A|12/31/2099",
	}
	if got := firewallGroupLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}

	var asJSON = f.run("/system/user", "print", "json")
	wantExit(t, asJSON, 0)
	var lines = strings.Split(strings.TrimSpace(asJSON.stdout), "\n")
	var alice map[string]any
	if len(lines) != 3 || json.Unmarshal([]byte(lines[2]), &alice) != nil || alice["name"] != "alice" || alice["priv"] != "page-status-ntp" {
		t.Errorf("want the rows, got %q", asJSON.stdout)
	}
	for _, secret := range []string{"password", "apikeys", "otp_seed"} {
		if _, found := alice[secret]; found {
			t.Errorf("json contains %s", secret)
		}
	}
	wantNotContains(t, "json", asJSON.stdout, "secrethash", "cryptedsecret", "JBSWY3DPEHPK3PXP")

	var detail = f.run("/system/user", "print", "detail")
	wantExit(t, detail, 0)
	wantContains(t, "detail", detail.stdout, "u-alice", "otp:", "password-changed:  2026-10-25 15:40:06 UTC", "api-keys:          1")
	wantNotContains(t, "detail", detail.stdout, "secrethash", "cryptedsecret", "JBSWY3DPEHPK3PXP")

	var searched = f.run("/system/user", "print", "search=alic")
	wantExit(t, searched, 0)
	if got := firewallGroupLines(searched.stdout); len(got) != 2 || !strings.HasPrefix(got[1], "0|alice|") {
		t.Errorf("search: %q", got)
	}
	wantNoMutations(t, f)
}

func TestSystemUserShow(t *testing.T) {
	t.Parallel()
	var f = systemUserFake(t)
	for _, selector := range []string{"2", "u-alice", "alice", "ALICE"} {
		var r = f.run("/system/user", "show", selector)
		wantExit(t, r, 0)
		wantContains(t, "show "+selector, r.stdout, "name:              alice\n", "groups:            ops\n",
			"privileges:        page-status-ntp\n", "otp:               yes\n", "authorized-keys:   1\n", "api-keys:          1\n")
	}
	wantFailure(t, f.run("/system/user", "show", "bob"), "not found")
	wantNoMutations(t, f)
}

func TestSystemUserAdd(t *testing.T) {
	t.Parallel()
	var f = systemUserFake(t)
	f.on("POST", systemUserAddPath, 200, answerAdded("u-new"))
	var r = f.run("/system/user", "add", "name=bob", "full-name=Bob B", "groups=OPS,1999", "privileges=PAGE-STATUS-NTP",
		"expires=2030-12-31", "disabled")
	wantExit(t, r, 0)
	if r.stdout != "u-new\n" {
		t.Errorf("want the uuid on stdout, got %q", r.stdout)
	}
	wantContains(t, "stderr", r.stderr, "random password", "/system/user password bob")
	wantJSON(t, wantOneMutation(t, f, "POST", systemUserAddPath), map[string]any{"user": map[string]any{
		"name": "bob", "descr": "Bob B", "email": "", "comment": "", "shell": "", "language": "", "landing_page": "",
		"expires": "2030-12-31", "disabled": "1", "group_memberships": "2000,1999", "priv": "page-status-ntp",
		"scrambled_password": "1",
	}})

	t.Run("with password", func(t *testing.T) {
		t.Parallel()
		var f = systemUserFake(t)
		f.on("POST", systemUserAddPath, 200, answerAdded("u-new"))
		var r = f.run("/system/user", "add", "name=bob", "password=Secret-123")
		wantExit(t, r, 0)
		wantNotContains(t, "stderr", r.stderr, "random")
		var body = wantOneMutation(t, f, "POST", systemUserAddPath).json(t)["user"].(map[string]any)
		if body["password"] != "Secret-123" || body["scrambled_password"] != nil {
			t.Errorf("body %v", body)
		}
	})

	t.Run("refused before any change", func(t *testing.T) {
		t.Parallel()
		for _, args := range [][]string{{}, {"name="}, {"name=a b"}, {"name=bob", "expires=tomorrow"},
			{"name=bob", "landing-page=https://x"}, {"name=bob", "groups=nosuch"}, {"name=bob", "privileges=page-nosuch"}} {
			var f = systemUserFake(t)
			wantFailure(t, f.run(append([]string{"/system/user", "add"}, args...)...))
			wantNoMutations(t, f)
		}
	})

	t.Run("exists", func(t *testing.T) {
		t.Parallel()
		var f = systemUserFake(t)
		wantFailure(t, f.run("/system/user", "add", "name=alice"), "exists already", "u-alice", "replace")
		wantNoMutations(t, f)
	})

	t.Run("replace", func(t *testing.T) {
		t.Parallel()
		var f = systemUserFake(t)
		f.on("POST", systemUserSetPath+"u-alice", 200, answerSaved)
		var r = f.run("/system/user", "add", "name=alice", "email=a@example.com", "replace")
		wantExit(t, r, 0)
		if r.stdout != "u-alice\n" {
			t.Errorf("stdout %q", r.stdout)
		}
		var body = wantOneMutation(t, f, "POST", systemUserSetPath+"u-alice").json(t)["user"].(map[string]any)
		if body["email"] != "a@example.com" || body["group_memberships"] != "" || body["descr"] != "" || body["password"] != nil {
			t.Errorf("replace must clear the other fields and keep the password: %v", body)
		}
	})

	t.Run("replace refused for protected users", func(t *testing.T) {
		t.Parallel()
		var f = systemUserFake(t)
		wantFailure(t, f.run("/system/user", "add", "name=root", "replace"), "refusing", "root")
		wantFailure(t, f.run("/system/user", "add", "name=automation", "replace"), "refusing", "API key")
		wantNoMutations(t, f)
	})
}

func TestSystemUserSet(t *testing.T) {
	t.Parallel()
	var f = systemUserFake(t)
	f.on("POST", systemUserSetPath+"u-alice", 200, answerSaved)
	wantExit(t, f.run("/system/user", "set", "alice", "shell=/bin/sh", "groups=", "privileges="), 0)
	// the name is always sent, OPNsense syncs the shell account only then
	wantJSON(t, wantOneMutation(t, f, "POST", systemUserSetPath+"u-alice"), map[string]any{"user": map[string]any{
		"name": "alice", "shell": "/bin/sh", "group_memberships": "", "priv": ""}})

	t.Run("nothing to change", func(t *testing.T) {
		t.Parallel()
		var f = systemUserFake(t)
		wantFailure(t, f.run("/system/user", "set", "alice"), "nothing to change")
		wantNoCalls(t, f)
	})

	t.Run("protected users", func(t *testing.T) {
		t.Parallel()
		for _, args := range [][]string{
			{"root", "disabled"}, {"root", "groups="}, {"root", "name=admin"}, {"root", "expires=12/31/2030"},
			{"automation", "disabled=yes"}, {"automation", "groups=ops"}, {"automation", "expires=2030-01-01"},
		} {
			var f = systemUserFake(t)
			wantFailure(t, f.run(append([]string{"/system/user", "set"}, args...)...), "refusing", "protected")
			wantNoMutations(t, f)
		}
		// harmless changes are fine
		var f = systemUserFake(t)
		f.on("POST", systemUserSetPath+"u-root", 200, answerSaved)
		wantExit(t, f.run("/system/user", "set", "root", "email=root@example.com", "groups=admins,ops", "disabled=no"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemUserSetPath+"u-root"), map[string]any{"user": map[string]any{
			"name": "root", "email": "root@example.com", "group_memberships": "1999,2000", "disabled": "0"}})
	})
}

func TestSystemUserEnableDisable(t *testing.T) {
	t.Parallel()
	var f = systemUserFake(t)
	f.on("POST", systemUserSetPath+"u-alice", 200, answerSaved)
	wantExit(t, f.run("/system/user", "enable", "alice"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", systemUserSetPath+"u-alice"), map[string]any{"user": map[string]any{
		"name": "alice", "disabled": "0"}})

	var already = f.run("/system/user", "disable", "alice")
	wantExit(t, already, 0)
	wantContains(t, "stderr", already.stderr, "already disabled")
	wantFailure(t, f.run("/system/user", "disable", "root"), "refusing", "root")
	wantFailure(t, f.run("/system/user", "disable", "automation"), "refusing", "API key")
	if len(f.mutations()) != 1 {
		t.Errorf("unexpected mutations %v", f.mutations())
	}
}

func TestSystemUserRemove(t *testing.T) {
	t.Parallel()
	var f = systemUserFake(t)
	wantFailure(t, f.run("/system/user", "remove", "alice"), "confirm=yes")
	wantNoCalls(t, f)

	f.on("POST", systemUserSetPath+"u-alice", 200, answerSaved)
	f.on("POST", systemUserDelPath+"u-alice", 200, answerDeleted)
	wantExit(t, f.run("/system/user", "remove", "alice", "confirm=yes"), 0)
	var calls = f.mutations()
	if len(calls) != 2 || calls[0].Path != systemUserSetPath+"u-alice" || calls[1].Path != systemUserDelPath+"u-alice" {
		t.Fatalf("want the user taken out of its groups and removed, got %v", calls)
	}
	wantJSON(t, calls[0], map[string]any{"user": map[string]any{"name": "alice", "group_memberships": ""}})

	t.Run("protected", func(t *testing.T) {
		t.Parallel()
		for _, selector := range []string{"root", "0", "u-root", "automation"} {
			var f = systemUserFake(t)
			wantFailure(t, f.run("/system/user", "remove", selector, "confirm=yes"), "refusing", "protected")
			wantNoMutations(t, f)
		}
	})

	t.Run("help", func(t *testing.T) {
		t.Parallel()
		var r = runOpn(t, nil, "/system/user", "remove", "?")
		wantExit(t, r, 0)
		wantContains(t, "help", strings.Join(strings.Fields(r.stdout), " "), "refuses to remove root (uid 0)", "API key")
	})
}

func TestSystemUserPassword(t *testing.T) {
	t.Parallel()
	var f = systemUserFake(t)
	wantFailure(t, f.run("/system/user", "password", "alice"), "terminal", "password=")
	wantNoMutations(t, f)
}

func TestSystemUserReadSecret(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		input, want string
		err         error
	}{
		{"secret\r", "secret", nil},
		{"secret\n", "secret", nil},
		{"sec\x7fcret\r", "secret", nil},
		{"xy\x15secret\r", "secret", nil},
		{"se\x1b[Acret\r", "secret", nil},
		{"pä\x7fss\r", "pss", nil},
		{"\x03", "", ErrCancelled},
		{"abc\x03", "", ErrCancelled},
		{"\x04", "", ErrCancelled},
		{"", "", ErrCancelled},
	} {
		var got, err = systemUserReadSecret(strings.NewReader(tc.input))
		if got != tc.want || !errors.Is(err, tc.err) {
			t.Errorf("%q: got %q / %v, want %q / %v", tc.input, got, err, tc.want, tc.err)
		}
	}
}
