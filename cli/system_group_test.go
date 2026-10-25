package cli

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const (
	systemGroupAddPath = "/api/auth/group/add"
	systemGroupSetPath = "/api/auth/group/set/"
	systemGroupDelPath = "/api/auth/group/del/"
)

func TestSystemGroupPrint(t *testing.T) {
	t.Parallel()
	var f = systemUserFake(t)
	var r = f.run("/system/group", "print")
	wantExit(t, r, 0)
	var want = []string{
		"#|NAME|GID|MEMBERS|PRIVILEGES|DESCRIPTION",
		"0|admins|1999|root,automation|page-all|System Administrators",
		"1|ops|2000|alice|page-status-ntp|operators",
	}
	if got := firewallGroupLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	var asJSON = f.run("/system/group", "print", "json", "search=oper")
	wantExit(t, asJSON, 0)
	var row map[string]any
	if json.Unmarshal([]byte(asJSON.stdout), &row) != nil || row["uuid"] != "g-ops" || row["%member"] != "alice" {
		t.Errorf("json: %q", asJSON.stdout)
	}
	var show = f.run("/system/group", "show", "OPS")
	wantExit(t, show, 0)
	wantContains(t, "show", show.stdout, "gid:              2000\n", "members:          alice\n", "scope:            user\n")
	wantNoMutations(t, f)
}

func TestSystemGroupAdd(t *testing.T) {
	t.Parallel()
	var f = systemUserFake(t)
	f.on("POST", systemGroupAddPath, 200, answerAdded("g-new"))
	var r = f.run("/system/group", "add", "name=dev", "members=alice,2000", "privileges=page-diagnostics-ping",
		"source-networks=10.0.0.0/8")
	wantExit(t, r, 0)
	if r.stdout != "g-new\n" {
		t.Errorf("stdout %q", r.stdout)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", systemGroupAddPath), map[string]any{"group": map[string]any{
		"name": "dev", "description": "", "member": "2001,2000", "priv": "page-diagnostics-ping", "source_networks": "10.0.0.0/8"}})

	t.Run("refused before any change", func(t *testing.T) {
		t.Parallel()
		for _, args := range [][]string{{}, {"name=bad name"}, {"name=dev", "members=ghost"}, {"name=dev", "privileges=nosuch"},
			{"name=ops"}} {
			var f = systemUserFake(t)
			wantFailure(t, f.run(append([]string{"/system/group", "add"}, args...)...))
			wantNoMutations(t, f)
		}
	})

	t.Run("replace admins refused", func(t *testing.T) {
		t.Parallel()
		var f = systemUserFake(t)
		wantFailure(t, f.run("/system/group", "add", "name=admins", "replace"), "refusing", "admins")
		wantNoMutations(t, f)
	})
}

func TestSystemGroupSet(t *testing.T) {
	t.Parallel()
	var f = systemUserFake(t)
	f.on("POST", systemGroupSetPath+"g-ops", 200, answerSaved)
	wantExit(t, f.run("/system/group", "set", "ops", "members=", "description=new"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", systemGroupSetPath+"g-ops"), map[string]any{"group": map[string]any{
		"name": "ops", "member": "", "description": "new"}})

	t.Run("admins is protected", func(t *testing.T) {
		t.Parallel()
		for _, args := range [][]string{{"admins", "name=adm"}, {"admins", "privileges="}, {"admins", "members=root"},
			{"admins", "members=automation"}, {"g-admins", "members="}} {
			var f = systemUserFake(t)
			wantFailure(t, f.run(append([]string{"/system/group", "set"}, args...)...), "refusing", "admins")
			wantNoMutations(t, f)
		}
		var f = systemUserFake(t)
		f.on("POST", systemGroupSetPath+"g-admins", 200, answerSaved)
		wantExit(t, f.run("/system/group", "set", "admins", "members=root,automation,alice", "description=admins!"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemGroupSetPath+"g-admins"), map[string]any{"group": map[string]any{
			"name": "admins", "member": "0,2000,2001", "description": "admins!"}})
	})
}

func TestSystemGroupRemove(t *testing.T) {
	t.Parallel()
	var f = systemUserFake(t)
	wantFailure(t, f.run("/system/group", "remove", "ops"), "confirm=yes")
	wantNoCalls(t, f)
	f.on("POST", systemGroupDelPath+"g-ops", 200, answerDeleted)
	wantExit(t, f.run("/system/group", "remove", "ops", "confirm=yes"), 0)
	wantOneMutation(t, f, "POST", systemGroupDelPath+"g-ops")
	for _, selector := range []string{"admins", "g-admins", "0"} {
		wantFailure(t, f.run("/system/group", "remove", selector, "confirm=yes"), "refusing", "admins")
	}
	if len(f.mutations()) != 1 {
		t.Errorf("unexpected mutations %v", f.mutations())
	}
	var help = runOpn(t, nil, "/system/group", "remove", "?")
	wantContains(t, "help", strings.Join(strings.Fields(help.stdout), " "), "refuses to remove the admins group (gid 1999)")
}
