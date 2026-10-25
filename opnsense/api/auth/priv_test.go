package auth

import (
	"reflect"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

const privTestSearch = `{"total":3,"rowCount":3,"current":1,"rows":[` +
	`{"id":"page-all","name":"All pages","match":"*","users":[],"groups":["admins"]},` +
	`{"id":"page-diagnostics-arptable","name":"Diagnostics: ARP Table","match":"ui/diagnostics/interface/arp/*\napi/diagnostics/interface/get_arp*",` +
	`"users":["alice"],"groups":[]},` +
	`{"id":"page-status-ntp","name":"Status: NTP","match":"ui/ntpd/status*","users":[],"groups":[]}]}`

// privTestGetItem is get_item/page-diagnostics-arptable: alice holds it, bob, root and the groups not
const privTestGetItem = `{"priv":{"users":{"u-alice":{"value":"alice","selected":1},"u-bob":{"value":"bob","selected":0},` +
	`"u-root":{"value":"root","selected":0}},"groups":{"g-admins":{"value":"admins","selected":0},"g-ops":{"value":"ops","selected":1}},` +
	`"id":"page-diagnostics-arptable"}}`

func privTestHandler(r testRequest) (int, string) {
	switch {
	case strings.HasSuffix(r.Path, "/priv/search"):
		return 200, privTestSearch
	case strings.Contains(r.Path, "/priv/get_item/"):
		return 200, privTestGetItem
	}
	return 200, `{"result":"saved"}`
}

func TestPrivilegeList(t *testing.T) {
	var api, _ = newTestApi(t, privTestHandler)
	var privileges, err = api.PrivilegeList()
	if err != nil {
		t.Fatal(err)
	}
	if len(privileges) != 3 {
		t.Fatalf("want 3 privileges, got %+v", privileges)
	}
	var arp = privileges[1]
	if arp.Id != "page-diagnostics-arptable" || !reflect.DeepEqual(arp.Match, []string{"ui/diagnostics/interface/arp/*", "api/diagnostics/interface/get_arp*"}) ||
		!reflect.DeepEqual(arp.Users, []string{"alice"}) || len(arp.Groups) != 0 || !strings.Contains(string(arp.Raw), `"match"`) {
		t.Errorf("unexpected %+v", arp)
	}
	if _, err := api.PrivilegeGet("page-nonexistent"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
}

func TestPrivilegeGrantRevoke(t *testing.T) {
	var api, requests = newTestApi(t, privTestHandler)
	if err := api.PrivilegeGrant("page-diagnostics-arptable", []string{"u-bob"}, []string{"g-admins"}); err != nil {
		t.Fatal(err)
	}
	var calls = posts(*requests)
	if len(calls) != 1 || calls[0].Path != "/api/auth/priv/set_item/page-diagnostics-arptable" {
		t.Fatalf("unexpected requests %+v", *requests)
	}
	// the existing holders (alice, ops) are kept
	wantBody(t, calls[0], map[string]any{"priv": map[string]any{"users": "u-alice,u-bob", "groups": "g-admins,g-ops"}})

	if err := api.PrivilegeRevoke("page-diagnostics-arptable", []string{"u-alice"}, nil); err != nil {
		t.Fatal(err)
	}
	wantBody(t, posts(*requests)[1], map[string]any{"priv": map[string]any{"users": "", "groups": "g-ops"}})

	// unknown privileges would be written unvalidated, unknown holders are refused before
	if err := api.PrivilegeGrant("page-nonexistent", []string{"u-bob"}, nil); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if err := api.PrivilegeGrant("page-diagnostics-arptable", []string{"u-ghost"}, nil); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if err := api.PrivilegeGrant("page-diagnostics-arptable", nil, nil); err == nil {
		t.Error("want an error without holders")
	}
	if len(posts(*requests)) != 2 {
		t.Errorf("unexpected mutations %+v", posts(*requests))
	}
}
