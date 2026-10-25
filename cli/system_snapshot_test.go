package cli

import (
	"strings"
	"testing"
)

const (
	systemSnapshotDefault = "0d5d1a8e-3a3c-3f0a-9a3e-6f0f8d1f7c11"
	systemSnapshotOld     = "8c0b7f8e-9f0e-3b7e-8f4c-0e3c9d2e1a22"
)

func systemSnapshotFake(t *testing.T, supported bool) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", "/api/core/snapshots/is_supported", 200, map[bool]string{true: `{"supported":true}`, false: `{"supported":false}`}[supported])
	f.search("/api/core/snapshots/search",
		map[string]any{"uuid": systemSnapshotDefault, "name": "default", "active": "NR", "mountpoint": "/", "size": "2.1G", "created_str": "2026-07-13 15:01"},
		map[string]any{"uuid": systemSnapshotOld, "name": "before-update", "active": "-", "mountpoint": "-", "size": "8K", "created_str": "2026-10-20 10:00"})
	f.on("GET", "/api/core/snapshots/get/"+systemSnapshotOld, 200, `{"uuid":"`+systemSnapshotOld+`","name":"before-update","note":"pre update"}`)
	f.on("GET", "/api/core/snapshots/get", 200, `{"name":"20261025153949","uuid":""}`)
	for _, path := range []string{"add", "set/" + systemSnapshotOld, "del/" + systemSnapshotOld, "activate/" + systemSnapshotOld} {
		f.on("POST", "/api/core/snapshots/"+path, 200, `{"status":"ok","result":"done"}`)
	}
	return f
}

func TestSystemSnapshotUnsupported(t *testing.T) {
	t.Parallel()
	var f = systemSnapshotFake(t, false)
	var r = f.run("/system/snapshot", "print")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "does not run on ZFS")
	for _, args := range [][]string{{"add"}, {"remove", "1"}, {"set", "1", "note=x"}, {"activate", "1", "confirm=yes"}, {"show", "0"}} {
		wantFailure(t, f.run(append([]string{"/system/snapshot"}, args...)...), "does not run on ZFS")
	}
	wantNoMutations(t, f)
}

func TestSystemSnapshotPrintShow(t *testing.T) {
	t.Parallel()
	var f = systemSnapshotFake(t, true)
	var r = f.run("/system/snapshot", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "0  default        now,reboot  /", "1  before-update  -           -")
	r = f.run("/system/snapshot", "show", "before-update")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "uuid:        "+systemSnapshotOld, "note:        pre update")
	wantNoMutations(t, f)
}

func TestSystemSnapshotMutations(t *testing.T) {
	t.Parallel()
	var f = systemSnapshotFake(t, true)
	wantFailure(t, f.run("/system/snapshot", "add", "name=default"), "exists already")
	wantFailure(t, f.run("/system/snapshot", "add", "name=a b"), "invalid snapshot name")
	wantFailure(t, f.run("/system/snapshot", "remove", "default"), "is active")
	wantFailure(t, f.run("/system/snapshot", "set", "1"), "nothing to change")
	wantFailure(t, f.run("/system/snapshot", "activate", "1"), "next reboot", "confirm=yes")
	wantNoMutations(t, f)

	// the created one is not in the canned list: add reports it missing
	wantFailure(t, f.run("/system/snapshot", "add", "from=before-update", "note=n"), `"20261025153949" is missing after the add`)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/core/snapshots/add"),
		map[string]any{"name": "20261025153949", "note": "n", "uuid": systemSnapshotOld})

	var g = systemSnapshotFake(t, true)
	wantExit(t, g.run("/system/snapshot", "set", "1", "name=renamed"), 0)
	wantJSON(t, wantOneMutation(t, g, "POST", "/api/core/snapshots/set/"+systemSnapshotOld),
		map[string]any{"name": "renamed", "note": "pre update"})

	for _, args := range []string{"remove before-update", "activate 1 confirm=yes"} {
		var h = systemSnapshotFake(t, true)
		wantExit(t, h.run(append([]string{"/system/snapshot"}, strings.Fields(args)...)...), 0)
		var path = map[string]string{"remove": "del", "activate": "activate"}[strings.Fields(args)[0]]
		wantOneMutation(t, h, "POST", "/api/core/snapshots/"+path+"/"+systemSnapshotOld)
	}
}
