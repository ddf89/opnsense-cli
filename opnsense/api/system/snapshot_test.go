package system

import (
	"encoding/json"
	"reflect"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

const (
	snapshotTestUuid    = "0d5d1a8e-3a3c-3f0a-9a3e-6f0f8d1f7c11"
	snapshotTestOldUuid = "8c0b7f8e-9f0e-3b7e-8f4c-0e3c9d2e1a22"
	// snapshotTestSearch is a core/snapshots/search answer on a ZFS install (bectl list)
	snapshotTestSearch = `{"total":2,"rowCount":2,"current":1,"rows":[` +
		`{"uuid":"` + snapshotTestUuid + `","name":"default","active":"NR","mountpoint":"\/","size":"2.1G",` +
		`"created_str":"2026-07-13 15:01","created":1783954860},` +
		`{"uuid":"` + snapshotTestOldUuid + `","name":"before-update","active":"-","mountpoint":"-","size":"8K",` +
		`"created_str":"2026-10-20 10:00","created":1792490400}]}`
)

func TestSnapshotListAndGet(t *testing.T) {
	var api, server = newCoreTestApi(t, map[string]string{
		"GET /api/core/snapshots/is_supported":                  `{"supported":true}`,
		"GET /api/core/snapshots/search":                        snapshotTestSearch,
		"GET /api/core/snapshots/get/" + snapshotTestOldUuid:    `{"note":"pre 26.7.7","uuid":"` + snapshotTestOldUuid + `","name":"before-update","active":"-"}`,
		"GET /api/core/snapshots/get/00000000-0000-3000-8000-0": `{"name":"20261025153949","uuid":"","note":""}`,
		"GET /api/core/snapshots/get":                           `{"name":"20261025153949","uuid":""}`,
	})
	if supported, err := api.SnapshotSupported(); err != nil || !supported {
		t.Errorf("supported %v %v", supported, err)
	}
	var snapshots, err = api.SnapshotList()
	if err != nil {
		t.Fatal(err)
	}
	var want = []Snapshot{
		{Uuid: snapshotTestUuid, Name: "default", Active: "NR", Mountpoint: "/", Size: "2.1G", Created: "2026-07-13 15:01"},
		{Uuid: snapshotTestOldUuid, Name: "before-update", Active: "-", Mountpoint: "-", Size: "8K", Created: "2026-10-20 10:00"},
	}
	if !reflect.DeepEqual(snapshots, want) {
		t.Errorf("got  %+v\nwant %+v", snapshots, want)
	}
	if !snapshots[0].ActiveNow() || !snapshots[0].ActiveOnReboot() || snapshots[1].ActiveNow() || snapshots[1].ActiveOnReboot() {
		t.Error("unexpected active flags")
	}
	if snapshot, err := api.SnapshotGet(snapshotTestOldUuid); err != nil || snapshot.Note != "pre 26.7.7" {
		t.Errorf("get %+v %v", snapshot, err)
	}
	if _, err := api.SnapshotGet("00000000-0000-3000-8000-0"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError for the default record, got %v", err)
	}
	if name, err := api.SnapshotDefaultName(); err != nil || name != "20261025153949" {
		t.Errorf("default name %q %v", name, err)
	}
	if len(server.posts()) != 0 {
		t.Errorf("reads must not post: %v", server.posts())
	}

	server.set("GET /api/core/snapshots/is_supported", `{"supported":false}`)
	if supported, err := api.SnapshotSupported(); err != nil || supported {
		t.Errorf("unsupported %v %v", supported, err)
	}
	server.set("GET /api/core/snapshots/is_supported", `[]`)
	if _, err := api.SnapshotSupported(); err == nil {
		t.Error("want an error without supported flag")
	}
}

func TestSnapshotMutations(t *testing.T) {
	var api, server = newCoreTestApi(t, map[string]string{
		"POST /api/core/snapshots/add":                             `"{\"status\": \"ok\", \"result\": \"bootenvironment executed create successfully\"}"`,
		"POST /api/core/snapshots/set/" + snapshotTestOldUuid:      `{"status":"ok","result":"bootenvironment executed rename successfully"}`,
		"GET /api/core/snapshots/get/" + snapshotTestOldUuid:       `{"note":"keep me","uuid":"` + snapshotTestOldUuid + `","name":"before-update"}`,
		"POST /api/core/snapshots/del/" + snapshotTestOldUuid:      `{"status":"ok","result":"bootenvironment executed destroy successfully"}`,
		"POST /api/core/snapshots/activate/" + snapshotTestOldUuid: `{"status":"failed","result":"Unsupported root filesystem"}`,
		"POST /api/core/snapshots/del/unknown":                     `500 {"errorMessage":"Snapshot not found","errorTitle":"Snapshots"}`,
	})
	coreTestWantError(t, api.SnapshotCreate("a9-snap", "a note", ""), "")
	coreTestWantError(t, api.SnapshotCreate("a9-clone", "", snapshotTestOldUuid), "")
	coreTestWantError(t, api.SnapshotUpdate(snapshotTestOldUuid, "renamed", nil), "")
	var note = ""
	coreTestWantError(t, api.SnapshotUpdate(snapshotTestOldUuid, "renamed", &note), "")
	coreTestWantError(t, api.SnapshotRemove(snapshotTestOldUuid), "")
	coreTestWantError(t, api.SnapshotActivate(snapshotTestOldUuid), "Unsupported root filesystem")
	if err := api.SnapshotRemove("unknown"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}

	var posts = server.posts()
	if len(posts) != 7 {
		t.Fatalf("want 7 posts, got %+v", posts)
	}
	var wantBodies = []map[string]string{
		{"name": "a9-snap", "note": "a note"},
		{"name": "a9-clone", "note": "", "uuid": snapshotTestOldUuid},
		{"name": "renamed", "note": "keep me"},
		{"name": "renamed", "note": ""},
	}
	for i, want := range wantBodies {
		var got map[string]string
		if err := json.Unmarshal([]byte(posts[i].Body), &got); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("post %d %s: body %s, want %v", i, posts[i].Path, posts[i].Body, want)
		}
	}
	for _, post := range posts[4:] {
		if post.Body != "" {
			t.Errorf("want no body for %s, got %q", post.Path, post.Body)
		}
	}

	server.set("POST /api/core/snapshots/add", `{"status":"failed","validations":{"name":"A snapshot already exists by this name"}}`)
	coreTestWantError(t, api.SnapshotCreate("dup", "", ""), "already exists")
	var sent = len(server.posts())
	for _, bad := range []string{"", ".", "..", "a b", "x/y", "ü"} {
		if err := api.SnapshotCreate(bad, "", ""); err == nil {
			t.Errorf("name %q: want an error", bad)
		}
		if err := api.SnapshotUpdate(snapshotTestOldUuid, bad, &note); err == nil {
			t.Errorf("rename to %q: want an error", bad)
		}
	}
	coreTestWantError(t, api.SnapshotRemove(""), "without uuid")
	coreTestWantError(t, api.SnapshotActivate(""), "without uuid")
	if len(server.posts()) != sent {
		t.Errorf("invalid input must not be sent: %v", server.posts()[sent:])
	}
}
