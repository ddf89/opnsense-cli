package auth

import (
	"reflect"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

const (
	groupTestUuid = "d9b007b9-4f71-4c42-88a2-aaea9021d5e1"
	groupTestPath = "/api/auth/group/"
)

const groupTestSearch = `{"rows":[` +
	`{"uuid":"99b6c4f5-9d07-4ba9-985a-b9035fe1e245","gid":"1999","name":"admins","scope":"system",` +
	`"description":"System Administrators","priv":"page-all","%priv":"All pages","member":"0","%member":"root","source_networks":""},` +
	`{"uuid":"d9b007b9-4f71-4c42-88a2-aaea9021d5e1","gid":"2000","name":"ops","scope":"user","description":"operators",` +
	`"priv":"page-status-ntp,page-diagnostics-ping","%priv":"Status: NTP, Diagnostics: Ping","member":"2000,2001",` +
	`"%member":"alice, bob","source_networks":"10.0.0.0/8,192.168.1.0/24"}` +
	`],"rowCount":2,"total":2,"current":1}`

func groupTestHandler(mutation *string) func(r testRequest) (int, string) {
	return func(r testRequest) (int, string) {
		if strings.HasSuffix(r.Path, "/search") {
			return 200, groupTestSearch
		}
		return 200, *mutation
	}
}

func TestGroupSearchAndGet(t *testing.T) {
	var api, _ = newTestApi(t, groupTestHandler(new(string)))
	var groups, err = api.GroupList()
	if err != nil {
		t.Fatal(err)
	}
	var ops = groups[1]
	ops.Raw = nil
	var want = Group{Uuid: groupTestUuid, Gid: "2000", Name: "ops", Scope: "user", Description: "operators",
		Members: []string{"2000", "2001"}, Privileges: []string{"page-status-ntp", "page-diagnostics-ping"},
		SourceNetworks: []string{"10.0.0.0/8", "192.168.1.0/24"}}
	if !reflect.DeepEqual(ops, want) {
		t.Errorf("got  %+v\nwant %+v", ops, want)
	}
	if groups[0].Raw["%member"] != "root" {
		t.Errorf("Raw: %v", groups[0].Raw)
	}
	if group, err := api.GroupGetByName("admins"); err != nil || group.Gid != AdminsGid {
		t.Errorf("GroupGetByName: %+v / %v", group, err)
	}
	if _, err := api.GroupGet("00000000-0000-4000-8000-000000000000"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
}

func TestGroupCreateUpdateRemove(t *testing.T) {
	var mutation = `{"result":"saved","uuid":"new-group"}`
	var api, requests = newTestApi(t, groupTestHandler(&mutation))
	var name = "dev"
	var members = []string{"2000"}
	var uuid, err = api.GroupCreate(GroupFields{Name: &name, Members: &members})
	if err != nil || uuid != "new-group" {
		t.Fatalf("GroupCreate: %q / %v", uuid, err)
	}
	wantBody(t, posts(*requests)[0], map[string]any{"group": map[string]any{"name": "dev", "member": "2000"}})

	var bad = "bad name!"
	if _, err := api.GroupCreate(GroupFields{Name: &bad}); err == nil {
		t.Error("want an error for an invalid name")
	}

	mutation = `{"result":"saved"}`
	var description = "new"
	if err := api.GroupUpdate(groupTestUuid, GroupFields{Description: &description}); err != nil {
		t.Fatal(err)
	}
	var update = posts(*requests)[1]
	if update.Path != groupTestPath+"set/"+groupTestUuid {
		t.Errorf("unexpected request %+v", update)
	}
	wantBody(t, update, map[string]any{"group": map[string]any{"name": "ops", "description": "new"}})
	if err := api.GroupUpdate("00000000-0000-4000-8000-000000000000", GroupFields{Description: &description}); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}

	mutation = `{"result":"deleted"}`
	if err := api.GroupRemove(groupTestUuid); err != nil {
		t.Fatal(err)
	}
	if got := posts(*requests)[2].Path; got != groupTestPath+"del/"+groupTestUuid {
		t.Errorf("unexpected request %s", got)
	}
	if err := api.GroupRemove("99b6c4f5-9d07-4ba9-985a-b9035fe1e245"); err == nil || !strings.Contains(err.Error(), "admins") {
		t.Errorf("want a refusal for admins, got %v", err)
	}
	if len(posts(*requests)) != 3 {
		t.Errorf("unexpected mutations %+v", posts(*requests))
	}
}
