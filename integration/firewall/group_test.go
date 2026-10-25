//go:build integration

package integrationfirewall

import (
	"errors"
	"reflect"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/firewall"
)

// Interface groups are only created with names starting with namePrefix() (a8fw_<8 hex>, 13 characters: a group name
// has at most 15 and must not end with a digit, so tests add "_" and a letter) and are never applied

func groupFirewallApi(t *testing.T) *firewall.FirewallApi {
	t.Helper()
	return &firewall.FirewallApi{OPNsense: coreApi(t)}
}

// groupTestName returns a group name for this run ending with suffix, a single letter
func groupTestName(suffix string) string {
	return namePrefix() + "_" + suffix
}

// groupCleanup removes the group uuid when the test ends
func groupCleanup(t *testing.T, fw *firewall.FirewallApi, uuid string) {
	t.Helper()
	t.Cleanup(func() {
		if err := fw.GroupRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of group %s failed: %v", uuid, err)
		}
	})
}

// groupRawNames returns the names of this run's groups, read with the raw API
func groupRawNames(t *testing.T) []string {
	t.Helper()
	var core = coreApi(t)
	var rows, err = rawSearch(core, "firewall/group/search_item", "")
	if err != nil {
		t.Fatalf("raw search: %v", err)
	}
	var names []string
	for _, row := range rows {
		if ownedByRun(row.Ifname) || ownedByRun(row.Descr) {
			names = append(names, row.Ifname)
		}
	}
	return names
}

func TestGroupLibraryLifecycle(t *testing.T) {
	var fw = groupFirewallApi(t)
	var name = groupTestName("g")
	var description = testDescription("group-lib")

	var interfaces, err = fw.GroupInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	var offered = map[string]bool{}
	for _, iface := range interfaces {
		offered[iface.Name] = true
	}
	if !offered["lan"] || !offered["wan"] {
		t.Fatalf("lan and wan are not offered as members: %+v", interfaces)
	}

	var groups, listErr = fw.GroupList()
	if listErr != nil {
		t.Fatal(listErr)
	}
	for _, group := range groups {
		if (group.Name == "openvpn" || group.Name == "enc0" || group.Name == "wireguard") != group.IsBuiltin() {
			t.Errorf("built-in detection: %+v", group)
		}
	}

	uuid, err := fw.GroupCreate(firewall.Group{Name: name, Members: []string{"lan"}, Sequence: 42, Description: description})
	if err != nil {
		t.Fatalf("GroupCreate: %v", err)
	}
	groupCleanup(t, fw, uuid)

	t.Run("get", func(t *testing.T) {
		var group, err = fw.GroupGet(uuid)
		var want = firewall.Group{Uuid: uuid, Name: name, Members: []string{"lan"}, MembersText: "LAN", Sequence: 42, Description: description}
		if err != nil || !reflect.DeepEqual(group, want) {
			t.Errorf("GroupGet: %+v / %v", group, err)
		}
		if byName, err := fw.GroupGetByName(name); err != nil || byName.Uuid != uuid {
			t.Errorf("GroupGetByName: %+v / %v", byName, err)
		}
	})

	t.Run("update", func(t *testing.T) {
		var members = []string{"lan", "wan"}
		var noGroup = true
		if err := fw.GroupUpdate(uuid, firewall.GroupPatch{Members: &members, NoGroup: &noGroup}); err != nil {
			t.Fatalf("GroupUpdate: %v", err)
		}
		var group, _ = fw.GroupGet(uuid)
		if group.Name != name || !reflect.DeepEqual(group.Members, members) || !group.NoGroup || group.Sequence != 42 || group.Description != description {
			t.Errorf("unexpected group after the partial update %+v", group)
		}

		var renamed = groupTestName("h")
		if err := fw.GroupUpdate(uuid, firewall.GroupPatch{Name: &renamed}); err != nil {
			t.Fatalf("rename: %v", err)
		}
		if group, err := fw.GroupGetByName(renamed); err != nil || group.Uuid != uuid || !reflect.DeepEqual(group.Members, members) {
			t.Errorf("after the rename: %+v / %v", group, err)
		}
		if _, err := fw.GroupGetByName(name); !api.IsNotFound(err) {
			t.Errorf("the old name must be gone: %v", err)
		}
	})

	t.Run("refused", func(t *testing.T) {
		// Only unit tested, never live: an interface name as group name (OPNsense accepts it, but such a group can not
		// be removed while rules use the interface, and renaming a group to it rewrites those rules) and changes of
		// the built-in groups
		var members = []string{"lan"}
		if err := fw.GroupUpdate("00000000-0000-4000-8000-0000000a8f00", firewall.GroupPatch{Members: &members}); !api.IsNotFound(err) {
			t.Errorf("unknown uuid: want NotFoundError, got %v", err)
		}
		var validationErr *api.ValidationError
		if _, err := fw.GroupCreate(firewall.Group{Name: groupTestName("h"), Members: []string{"wan"}, Description: description}); !errors.As(err, &validationErr) {
			t.Errorf("duplicate name: want a validation error, got %v", err)
		}
		if got := groupRawNames(t); !reflect.DeepEqual(got, []string{groupTestName("h")}) {
			t.Errorf("only the test group must exist, got %v", got)
		}
	})

	t.Run("remove", func(t *testing.T) {
		if err := fw.GroupRemove(uuid); err != nil {
			t.Fatalf("GroupRemove: %v", err)
		}
		if err := fw.GroupRemove(uuid); !api.IsNotFound(err) {
			t.Errorf("second remove: want NotFoundError, got %v", err)
		}
		if got := groupRawNames(t); len(got) != 0 {
			t.Errorf("no test group must be left, got %v", got)
		}
	})
}
