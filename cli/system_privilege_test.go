package cli

import (
	"reflect"
	"strings"
	"testing"
)

const (
	systemPrivGetPath = "/api/auth/priv/get_item/"
	systemPrivSetPath = "/api/auth/priv/set_item/"
)

// systemPrivFake also answers get_item/page-status-ntp: granted to alice and ops
func systemPrivFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = systemUserFake(t)
	f.on("GET", systemPrivGetPath+"page-status-ntp", 200, `{"priv":{"users":{"u-root":{"value":"root","selected":0},`+
		`"u-api":{"value":"automation","selected":0},"u-alice":{"value":"alice","selected":1}},`+
		`"groups":{"g-admins":{"value":"admins","selected":0},"g-ops":{"value":"ops","selected":1}},"id":"page-status-ntp"}}`)
	f.on("POST", systemPrivSetPath+"page-status-ntp", 200, answerSaved)
	return f
}

func TestSystemPrivilegePrint(t *testing.T) {
	t.Parallel()
	var f = systemPrivFake(t)
	var r = f.run("/system/privilege", "print")
	wantExit(t, r, 0)
	var want = []string{"#|ID|NAME|USERS|GROUPS", "0|page-all|All pages|-|admins", "1|page-diagnostics-ping|Diagnostics: Ping|-|-",
		"2|page-status-ntp|Status: NTP|alice|ops"}
	if got := firewallGroupLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	for _, tc := range []struct {
		args []string
		ids  []string
	}{
		{[]string{"granted"}, []string{"page-all", "page-status-ntp"}},
		{[]string{"search=API/DIAG"}, []string{"page-diagnostics-ping"}},
		{[]string{"user=Alice"}, []string{"page-status-ntp"}},
		{[]string{"group=admins"}, []string{"page-all"}},
	} {
		var r = f.run(append([]string{"/system/privilege", "print"}, tc.args...)...)
		wantExit(t, r, 0)
		var lines = firewallGroupLines(r.stdout)
		var ids []string
		for _, line := range lines[1:] {
			ids = append(ids, strings.Split(line, "|")[1])
		}
		if !reflect.DeepEqual(ids, tc.ids) {
			t.Errorf("print %v: got %q, want %q", tc.args, lines, tc.ids)
		}
	}
	var show = f.run("/system/privilege", "show", "diagnostics: ping")
	wantExit(t, show, 0)
	wantContains(t, "show", show.stdout, "id:      page-diagnostics-ping\n", "match:   ui/diagnostics/ping*\n", "match:   api/diagnostics/ping/*\n")
	wantNoMutations(t, f)
}

func TestSystemPrivilegeGrantRevoke(t *testing.T) {
	t.Parallel()
	var f = systemPrivFake(t)
	wantExit(t, f.run("/system/privilege", "grant", "page-status-ntp", "user=root,automation", "group=admins"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", systemPrivSetPath+"page-status-ntp"), map[string]any{"priv": map[string]any{
		"users": "u-root,u-api,u-alice", "groups": "g-admins,g-ops"}})

	t.Run("revoke", func(t *testing.T) {
		t.Parallel()
		var f = systemPrivFake(t)
		wantExit(t, f.run("/system/privilege", "revoke", "2", "user=alice"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemPrivSetPath+"page-status-ntp"), map[string]any{"priv": map[string]any{
			"users": "", "groups": "g-ops"}})
	})

	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		for _, args := range [][]string{
			{"revoke", "page-status-ntp", "user=root"}, {"revoke", "page-status-ntp", "user=automation"},
			{"revoke", "page-status-ntp", "group=admins"}, {"grant", "page-status-ntp"}, {"grant", "page-nosuch", "user=alice"},
			{"grant", "page-status-ntp", "user=ghost"}, {"grant", "page-status-ntp", "group=ghosts"},
		} {
			var f = systemPrivFake(t)
			wantFailure(t, f.run(append([]string{"/system/privilege"}, args...)...))
			wantNoMutations(t, f)
		}
	})
}
