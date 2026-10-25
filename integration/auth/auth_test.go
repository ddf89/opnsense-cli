//go:build integration

package integrationauth

import (
	"errors"
	"net/http"
	"slices"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/auth"
	"opnsense-cli/opnsense/api/hostdiscovery"
	"opnsense-cli/opnsense/api/ntpd"
)

// TestUserLifecycle creates, changes and removes a disabled test user
func TestUserLifecycle(t *testing.T) {
	var opn = authApi(t)
	var descr = "integration test"
	var user = createUser(t, "life", auth.UserFields{Descr: &descr})
	if !user.Disabled || user.Scope != "user" || user.Descr != descr || user.Uid == "" || user.Uid == "0" {
		t.Errorf("created %+v", user)
	}
	for _, secret := range auth.UserSecretFields {
		if _, kept := user.Raw[secret]; kept {
			t.Errorf("Raw keeps %s", secret)
		}
	}
	if byName, err := opn.UserGetByName(user.Name); err != nil || byName.Uuid != user.Uuid {
		t.Errorf("UserGetByName: %+v / %v", byName, err)
	}

	// an ISO date is converted by OPNsense
	var email, expires, password = "life@example.com", "2099-12-31", "Integration-Test-Pw-1"
	if err := opn.UserUpdate(user.Uuid, auth.UserFields{Email: &email, Expires: &expires, Password: &password}); err != nil {
		t.Fatal(err)
	}
	var changed, _ = opn.UserGet(user.Uuid)
	if changed.Email != email || changed.Expires != "12/31/2099" || changed.Descr != descr || changed.PasswordChangedAt == "" {
		t.Errorf("after update %+v", changed)
	}

	var bad = "notadate"
	if err := opn.UserUpdate(user.Uuid, auth.UserFields{Expires: &bad}); err == nil {
		t.Error("want a client side refusal of an invalid date")
	}
	if err := opn.UserUpdate("00000000-0000-4000-8000-0000000000a4", auth.UserFields{Email: &email}); !api.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	var duplicate = user.Name
	if _, err := opn.UserCreate(auth.UserFields{Name: &duplicate, RandomPassword: true}); err == nil {
		t.Error("want a validation error for a duplicate name")
	}
}

// TestUserGroupsAndRemove checks memberships both ways and that removing a user leaves no stale uid in its groups
func TestUserGroupsAndRemove(t *testing.T) {
	var opn = authApi(t)
	var group = createGroup(t, "members", auth.GroupFields{})
	var groups = []string{group.Gid}
	var user = createUser(t, "member", auth.UserFields{Groups: &groups})

	var withMember, _ = opn.GroupGet(group.Uuid)
	if !slices.Contains(withMember.Members, user.Uid) {
		t.Errorf("the group lacks the member %s: %+v", user.Uid, withMember)
	}
	if err := opn.UserRemove(user.Uuid); err != nil {
		t.Fatal(err)
	}
	if _, err := opn.UserGet(user.Uuid); !api.IsNotFound(err) {
		t.Errorf("the user still exists: %v", err)
	}
	var after, _ = opn.GroupGet(group.Uuid)
	if slices.Contains(after.Members, user.Uid) {
		t.Errorf("the removed user's uid stayed in the group: %+v", after)
	}
}

// TestGroupLifecycle creates, changes and removes a group
func TestGroupLifecycle(t *testing.T) {
	var opn = authApi(t)
	var description = "integration test"
	var privileges = []string{"page-status-ntp"}
	var group = createGroup(t, "life", auth.GroupFields{Description: &description, Privileges: &privileges})
	if group.Scope != "user" || group.Description != description || !slices.Equal(group.Privileges, privileges) {
		t.Errorf("created %+v", group)
	}
	var user = createUser(t, "grouped", auth.UserFields{})
	var members = []string{user.Uid}
	var networks = []string{"192.0.2.0/24"}
	if err := opn.GroupUpdate(group.Uuid, auth.GroupFields{Members: &members, SourceNetworks: &networks}); err != nil {
		t.Fatal(err)
	}
	var changed, _ = opn.GroupGet(group.Uuid)
	if !slices.Equal(changed.Members, members) || !slices.Equal(changed.SourceNetworks, networks) || changed.Description != description {
		t.Errorf("after update %+v", changed)
	}
	var memberUser, _ = opn.UserGet(user.Uuid)
	if !slices.Contains(memberUser.Groups, group.Gid) {
		t.Errorf("the user does not list the group: %+v", memberUser)
	}
	var unknown = []string{"64999"}
	if err := opn.GroupUpdate(group.Uuid, auth.GroupFields{Members: &unknown}); err == nil {
		t.Error("want a validation error for an unknown uid")
	}
	if err := opn.GroupRemove(group.Uuid); err != nil {
		t.Fatal(err)
	}
	if _, err := opn.GroupGet(group.Uuid); !api.IsNotFound(err) {
		t.Errorf("the group still exists: %v", err)
	}
}

// TestPrivilegeGrantRevoke grants and revokes a privilege to a test user and group, keeping the other holders
func TestPrivilegeGrantRevoke(t *testing.T) {
	var opn = authApi(t)
	const id = "page-diagnostics-ping"
	var user = createUser(t, "priv", auth.UserFields{})
	var group = createGroup(t, "priv", auth.GroupFields{})
	var before, err = opn.PrivilegeGet(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := opn.PrivilegeGrant(id, []string{user.Uuid}, []string{group.Uuid}); err != nil {
		t.Fatal(err)
	}
	var granted, _ = opn.PrivilegeGet(id)
	if !slices.Contains(granted.Users, user.Name) || !slices.Contains(granted.Groups, group.Name) ||
		len(granted.Users) != len(before.Users)+1 || len(granted.Groups) != len(before.Groups)+1 {
		t.Errorf("after grant %+v (before %+v)", granted, before)
	}
	var withPriv, _ = opn.UserGet(user.Uuid)
	if !slices.Contains(withPriv.Privileges, id) {
		t.Errorf("the user lacks the privilege: %+v", withPriv)
	}
	if err := opn.PrivilegeRevoke(id, []string{user.Uuid}, []string{group.Uuid}); err != nil {
		t.Fatal(err)
	}
	var revoked, _ = opn.PrivilegeGet(id)
	if !slices.Equal(revoked.Users, before.Users) || !slices.Equal(revoked.Groups, before.Groups) {
		t.Errorf("after revoke %+v, want the holders of before %+v", revoked, before)
	}
	if err := opn.PrivilegeGrant("page-a4au-nosuch", []string{user.Uuid}, nil); !api.IsNotFound(err) {
		t.Errorf("want NotFoundError for an unknown privilege, got %v", err)
	}
}

// TestApiKeyLifecycle creates an API key for an enabled test user that may only read the NTP status, checks the
// key works with exactly that privilege, and removes it again
func TestApiKeyLifecycle(t *testing.T) {
	var opn = authApi(t)
	var enabled = false
	var privileges = []string{"page-status-ntp"}
	var user = createUser(t, "keys", auth.UserFields{Disabled: &enabled, Privileges: &privileges})

	var created, err = opn.ApiKeyCreate(user.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(created.Key) < 40 || len(created.Secret) < 40 || created.Hostname == "" {
		t.Errorf("unexpected key lengths %d/%d, hostname %q", len(created.Key), len(created.Secret), created.Hostname)
	}
	var keys, _ = opn.ApiKeyList()
	var index = slices.IndexFunc(keys, func(key auth.ApiKey) bool { return key.Key == created.Key })
	if index < 0 || keys[index].Username != user.Name || keys[index].Id != auth.ApiKeyId(created.Key) {
		t.Fatalf("the new key is not listed correctly")
	}

	var withKey = *opn.OPNsense
	withKey.ApiKey, withKey.ApiSecret = created.Key, created.Secret
	if _, err := (&ntpd.NtpdApi{OPNsense: &withKey}).Status(); err != nil {
		t.Errorf("the new key can not read the NTP status: %v", err)
	}
	var forbidden = (&auth.AuthApi{OPNsense: &withKey}).UserList
	if _, err := forbidden(); err == nil {
		t.Error("the new key may list users without the privilege")
	}

	if err := opn.ApiKeyRemove(keys[index].Id); err != nil {
		t.Fatal(err)
	}
	if err := opn.ApiKeyRemove(keys[index].Id); !api.IsNotFound(err) {
		t.Errorf("second remove: want NotFoundError, got %v", err)
	}
	var httpErr *api.HttpError
	if _, err := (&ntpd.NtpdApi{OPNsense: &withKey}).Status(); err == nil {
		t.Error("the removed key still works")
	} else if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusUnauthorized {
		t.Logf("removed key answered %v", err)
	}
	if _, err := opn.ApiKeyCreate(testName("ghost")); !api.IsNotFound(err) {
		t.Errorf("want NotFoundError for an unknown user, got %v", err)
	}
}

// TestHostDiscoveryAndNtp reads the host discovery and NTP status and changes and restores a host discovery setting
// (never reconfigured: hostwatch would start sniffing)
func TestHostDiscoveryAndNtp(t *testing.T) {
	var core = coreApi(t)
	var discovery = &hostdiscovery.HostDiscoveryApi{OPNsense: core}
	var before, err = discovery.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	if before.Enabled == "" || len(before.InterfaceOptions) == 0 {
		t.Errorf("settings %+v", before)
	}
	t.Cleanup(func() {
		var restore = hostdiscovery.SettingsFields{Enabled: &before.Enabled, Promisc: &before.Promisc, Verbose: &before.Verbose,
			SkipNets: &before.SkipNets, Expire4Interval: &before.Expire4Interval, Expire6Interval: &before.Expire6Interval,
			Interfaces: &before.Interfaces}
		if err := discovery.SettingsSet(restore); err != nil {
			t.Errorf("restoring the host discovery settings: %v", err)
		}
		if after, _ := discovery.SettingsGet(); mustJSON(t, after) != mustJSON(t, before) {
			t.Errorf("host discovery settings not restored:\n%+v\n%+v", after, before)
		}
	})
	var expire, skip = "7200", "198.51.100.0/24"
	if err := discovery.SettingsSet(hostdiscovery.SettingsFields{Expire4Interval: &expire, SkipNets: &skip}); err != nil {
		t.Fatal(err)
	}
	if changed, _ := discovery.SettingsGet(); changed.Expire4Interval != expire || changed.SkipNets != skip || changed.Enabled != before.Enabled {
		t.Errorf("after set %+v", changed)
	}
	var tooShort = "100"
	if err := discovery.SettingsSet(hostdiscovery.SettingsFields{Expire4Interval: &tooShort}); err == nil {
		t.Error("want a validation error for an interval below 3600")
	}
	if _, err := discovery.HostList(); err != nil {
		t.Error(err)
	}
	if status, err := discovery.ServiceStatus(); err != nil || status == "" {
		t.Errorf("status %q / %v", status, err)
	}

	var peers, ntpErr = (&ntpd.NtpdApi{OPNsense: core}).Status()
	if ntpErr != nil {
		t.Fatal(ntpErr)
	}
	for _, peer := range peers {
		if peer.Server == "" || peer.Stratum == "" {
			t.Errorf("incomplete peer %+v", peer)
		}
	}
	if _, err := (&ntpd.NtpdApi{OPNsense: core}).Gps(); err != nil {
		t.Error(err)
	}
	_ = rawJSON(t, "ntpd/service/meta")
}
