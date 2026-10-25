package auth

import (
	"reflect"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

const (
	userTestUuid = "55642ee7-6d54-4296-ba41-d5eb4e4290b7"
	userTestPath = "/api/auth/user/"
)

// userTestSearch is a search answer of OPNsense 26.7 (with the secret fields it really contains)
const userTestSearch = `{"rows":[` +
	`{"uuid":"cab4a1b9-9d1b-4e12-a5ef-86e586af1ce4","uid":"0","name":"root","disabled":"0","scope":"system","expires":"",` +
	`"authorizedkeys":"","otp_seed":"","shell":"","password":"$2y$10$hashhashhash","%password":"","scrambled_password":"0",` +
	`"pwd_changed_at":"","landing_page":"","comment":"","email":"","apikeys":"key1|$6$cryptedsecret","%apikeys":"","priv":"",` +
	`"language":"","group_memberships":"1999","%group_memberships":"admins","descr":"System Administrator","dashboard":"",` +
	`"is_admin":"1","shell_warning":"0"},` +
	`{"uuid":"55642ee7-6d54-4296-ba41-d5eb4e4290b7","uid":"2000","name":"alice","disabled":"1","scope":"user",` +
	`"expires":"12/31/2099","authorizedkeys":"ssh-ed25519 AAAA alice@x\nssh-rsa BBBB alice@y","otp_seed":"JBSWY3DPEHPK3PXP",` +
	`"shell":"/bin/sh","password":"$argon2id$v=19$hash","%password":"","scrambled_password":"0","pwd_changed_at":"1792942806.4744",` +
	`"landing_page":"/ui/core/dashboard","comment":"note","email":"alice@example.com","apikeys":"","%apikeys":"",` +
	`"priv":"page-status-ntp,page-diagnostics-ping","language":"de_DE","group_memberships":"2000,2001",` +
	`"%group_memberships":"ops, dev","descr":"Alice","dashboard":"","is_admin":"0","shell_warning":"1"}` +
	`],"rowCount":2,"total":2,"current":1}`

func userTestHandler(mutation *string) func(r testRequest) (int, string) {
	return func(r testRequest) (int, string) {
		switch {
		case strings.HasSuffix(r.Path, "/search"):
			return 200, userTestSearch
		case r.Path == userTestPath+"get":
			return 200, `{"user":{"name":"","shell":{"":{"value":"Default","selected":1},"/bin/sh":{"value":"/bin/sh","selected":0}},` +
				`"group_memberships":{"1999":{"value":"admins","selected":0}},"priv":{"page-all":{"value":"All pages","selected":0}},` +
				`"language":{"":{"value":"Default","selected":1}},"otp_seed":""}}`
		}
		return 200, *mutation
	}
}

func TestUserSearchKeepsNoSecrets(t *testing.T) {
	var api, requests = newTestApi(t, userTestHandler(new(string)))
	var users, err = api.UserSearch("ali")
	if err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Path != userTestPath+"search" || got.Query.Get("searchPhrase") != "ali" {
		t.Errorf("unexpected request %+v", got)
	}
	if len(users) != 2 {
		t.Fatalf("want 2 users, got %d", len(users))
	}
	var alice = users[1]
	var raw = alice.Raw
	alice.Raw = nil
	var want = User{Uuid: userTestUuid, Uid: "2000", Name: "alice", Scope: "user", Disabled: true, Descr: "Alice",
		Email: "alice@example.com", Comment: "note", LandingPage: "/ui/core/dashboard", Language: "de_DE", Shell: "/bin/sh",
		Expires: "12/31/2099", Groups: []string{"2000", "2001"}, Privileges: []string{"page-status-ntp", "page-diagnostics-ping"},
		PasswordChangedAt: "1792942806.4744", HasOtpSeed: true, AuthorizedKeys: "ssh-ed25519 AAAA alice@x\nssh-rsa BBBB alice@y"}
	if !reflect.DeepEqual(alice, want) {
		t.Errorf("got  %+v\nwant %+v", alice, want)
	}
	if !users[0].IsAdmin || users[0].Uid != "0" || users[0].Scope != "system" || len(users[0].Privileges) != 0 {
		t.Errorf("root: %+v", users[0])
	}
	for _, user := range users {
		for _, secret := range UserSecretFields {
			if _, kept := user.Raw[secret]; kept {
				t.Errorf("%s: Raw keeps the secret field %s", user.Name, secret)
			}
		}
	}
	if raw["name"] != "alice" || raw["shell_warning"] != "1" {
		t.Errorf("Raw lost fields: %v", raw)
	}
}

func TestUserGet(t *testing.T) {
	var api, _ = newTestApi(t, userTestHandler(new(string)))
	if user, err := api.UserGet(userTestUuid); err != nil || user.Name != "alice" {
		t.Errorf("UserGet: %+v / %v", user, err)
	}
	if _, err := api.UserGet("00000000-0000-4000-8000-000000000000"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if user, err := api.UserGetByName("root"); err != nil || user.Uid != "0" {
		t.Errorf("UserGetByName: %+v / %v", user, err)
	}
	if _, err := api.UserGetByName("Alice"); !coreapi.IsNotFound(err) {
		t.Errorf("names are case-sensitive, want NotFoundError, got %v", err)
	}
	if _, err := api.UserGet(""); err == nil {
		t.Error("want an error for an empty uuid")
	}
}

func TestUserOptions(t *testing.T) {
	var api, _ = newTestApi(t, userTestHandler(new(string)))
	var options, err = api.UserOptions()
	if err != nil {
		t.Fatal(err)
	}
	if got := options["shell"]; len(got) != 2 || got[1].Key != "/bin/sh" || !got[0].Selected {
		t.Errorf("shell: %+v", got)
	}
	if got := options["group_memberships"]; len(got) != 1 || got[0].Value != "admins" {
		t.Errorf("groups: %+v", got)
	}
}

func TestUserValidate(t *testing.T) {
	for _, name := range []string{"", "a b", "a,b", "ä", strings.Repeat("a", 321)} {
		if err := UserValidateName(name); err == nil {
			t.Errorf("name %q: want an error", name)
		}
	}
	for _, name := range []string{"alice", "a.b-c_d", "alice@example.com", "A1"} {
		if err := UserValidateName(name); err != nil {
			t.Errorf("name %q: %v", name, err)
		}
	}
	for _, expires := range []string{"tomorrow", "31.12.2030", "12/31/30"} {
		if err := UserValidateExpires(expires); err == nil {
			t.Errorf("expires %q: want an error", expires)
		}
	}
	for _, expires := range []string{"", "12/31/2030", "2030-12-31"} {
		if err := UserValidateExpires(expires); err != nil {
			t.Errorf("expires %q: %v", expires, err)
		}
	}
	if err := UserValidateLandingPage("https://evil"); err == nil {
		t.Error("landing page: want an error for an URL")
	}
}

func TestUserCreate(t *testing.T) {
	var mutation = `{"result":"saved","uuid":"new-uuid"}`
	var api, requests = newTestApi(t, userTestHandler(&mutation))
	var name, descr = "bob", "Bob"
	var disabled = true
	var groups = []string{"2000", "2001"}
	var uuid, err = api.UserCreate(UserFields{Name: &name, Descr: &descr, Disabled: &disabled, Groups: &groups, RandomPassword: true})
	if err != nil || uuid != "new-uuid" {
		t.Fatalf("UserCreate: %q / %v", uuid, err)
	}
	var calls = posts(*requests)
	if len(calls) != 1 || calls[0].Path != userTestPath+"add" {
		t.Fatalf("unexpected requests %+v", *requests)
	}
	wantBody(t, calls[0], map[string]any{"user": map[string]any{"name": "bob", "descr": "Bob", "disabled": "1",
		"group_memberships": "2000,2001", "scrambled_password": "1"}})

	if _, err := api.UserCreate(UserFields{Name: &name}); err == nil {
		t.Error("want an error without password")
	}
	var empty = ""
	if _, err := api.UserCreate(UserFields{Name: &name, Password: &empty}); err == nil {
		t.Error("want an error for an empty password")
	}
	var bad = "a b"
	if _, err := api.UserCreate(UserFields{Name: &bad, RandomPassword: true}); err == nil {
		t.Error("want an error for an invalid name")
	}
	if len(posts(*requests)) != 1 {
		t.Errorf("invalid users were sent: %+v", posts(*requests))
	}

	mutation = `{"result":"failed","validations":{"user.name":"This username already exist."}}`
	if _, err := api.UserCreate(UserFields{Name: &name, RandomPassword: true}); err == nil || !strings.Contains(err.Error(), "already exist") {
		t.Errorf("want the validation, got %v", err)
	}
}

func TestUserUpdate(t *testing.T) {
	var mutation = `{"result":"saved"}`
	var api, requests = newTestApi(t, userTestHandler(&mutation))
	var password = "s3cret"
	var none = []string{}
	if err := api.UserUpdate(userTestUuid, UserFields{Password: &password, Privileges: &none}); err != nil {
		t.Fatal(err)
	}
	var calls = posts(*requests)
	if len(calls) != 1 || calls[0].Path != userTestPath+"set/"+userTestUuid {
		t.Fatalf("unexpected requests %+v", *requests)
	}
	// the name is always sent, OPNsense syncs the system account only then
	wantBody(t, calls[0], map[string]any{"user": map[string]any{"name": "alice", "password": "s3cret", "priv": ""}})

	if err := api.UserUpdate("00000000-0000-4000-8000-000000000000", UserFields{Password: &password}); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if len(posts(*requests)) != 1 {
		t.Errorf("an unknown uuid was set: %+v", posts(*requests))
	}
}

func TestUserRemove(t *testing.T) {
	var mutation = `{"result":"deleted"}`
	var api, requests = newTestApi(t, func(r testRequest) (int, string) {
		if r.Path == userTestPath+"set/"+userTestUuid {
			return 200, `{"result":"saved"}`
		}
		return userTestHandler(&mutation)(r)
	})
	if err := api.UserRemove(userTestUuid); err != nil {
		t.Fatal(err)
	}
	// alice is in two groups: taken out first, then removed
	var calls = posts(*requests)
	if len(calls) != 2 || calls[0].Path != userTestPath+"set/"+userTestUuid || calls[1].Path != userTestPath+"del/"+userTestUuid {
		t.Fatalf("unexpected requests %+v", calls)
	}
	wantBody(t, calls[0], map[string]any{"user": map[string]any{"name": "alice", "group_memberships": ""}})

	if err := api.UserRemove("cab4a1b9-9d1b-4e12-a5ef-86e586af1ce4"); err == nil || !strings.Contains(err.Error(), "system user") {
		t.Errorf("want a refusal for root, got %v", err)
	}
	if err := api.UserRemove("00000000-0000-4000-8000-000000000000"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if err := api.UserRemove("a,b"); err == nil {
		t.Error("want an error for a uuid list")
	}
	if len(posts(*requests)) != 2 {
		t.Errorf("unexpected mutations %+v", posts(*requests))
	}
}
