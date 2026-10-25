//go:build integration

package integrationsystem

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
)

// Gateway group tests create their own member gateways: LAN gateways (192.168.1.250-254) which are never the default,
// are not monitored and are never applied, like the groups (reconfigure is never called live)

// gatewayGroupRandomName returns a name like a8gg_1a2b3c4d (gateway and group names allow a-z, 0-9, _ and -)
func gatewayGroupRandomName(t *testing.T) string {
	t.Helper()
	var random = make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	return "a8gg_" + hex.EncodeToString(random)
}

// gatewayGroupMembers creates one test gateway per address with the raw API (not the library under test), removes
// them when the test ends (after the groups, whose cleanups are registered later) and waits until OPNsense offers
// them as group members (the option list is cached for about 30 seconds). Returns their names
func gatewayGroupMembers(t *testing.T, label string, addresses ...string) []string {
	t.Helper()
	var core = coreApi(t)
	var names []string
	for _, address := range addresses {
		var name = gatewayGroupRandomName(t)
		var uuid, err = core.Mutate(core.EndpointForModule("routing/settings/add_gateway"), map[string]map[string]string{
			"gateway_item": {
				"name": name, "interface": "lan", "ipprotocol": "inet", "gateway": address, "defaultgw": "0",
				"monitor_disable": "1", "descr": testDescription(label),
			},
		})
		if err != nil {
			t.Fatalf("creating the test gateway %s (%s): %v", name, address, err)
		}
		t.Cleanup(func() {
			if _, err := core.Mutate(core.EndpointForModule("routing/settings/del_gateway/"+uuid), nil); err != nil {
				t.Errorf("cleanup of test gateway %s (%s) failed: %v", name, uuid, err)
			}
		})
		names = append(names, name)
	}

	var sys = &system.SystemApi{OPNsense: core}
	var deadline = time.Now().Add(2 * time.Minute)
	for {
		var candidates, err = sys.GatewayGroupCandidates()
		if err != nil {
			t.Fatalf("GatewayGroupCandidates: %v", err)
		}
		var offered = map[string]bool{}
		for _, candidate := range candidates {
			offered[candidate.Name] = true
		}
		var missing = 0
		for _, name := range names {
			if !offered[name] {
				missing++
			}
		}
		if missing == 0 {
			return names
		}
		if time.Now().After(deadline) {
			t.Fatalf("the test gateways %v are not offered as group members after 2 minutes: %+v", names, candidates)
		}
		time.Sleep(3 * time.Second)
	}
}

// gatewayGroupCleanup removes the group uuid when the test ends (before the member gateways)
func gatewayGroupCleanup(t *testing.T, sys *system.SystemApi, uuid string) {
	t.Helper()
	t.Cleanup(func() {
		if err := sys.GatewayGroupRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of gateway group %s failed: %v", uuid, err)
		}
	})
}

// gatewayGroupRawNames returns the names of the groups carrying this run's prefix, read with the raw API
func gatewayGroupRawNames(t *testing.T) []string {
	t.Helper()
	var core = coreApi(t)
	var rows, err = api.Search[struct {
		Name  string `json:"name"`
		Descr string `json:"descr"`
	}](core, core.EndpointForModule("routing/group_settings/search"), runPrefix)
	if err != nil {
		t.Fatalf("raw search: %v", err)
	}
	var names []string
	for _, row := range rows {
		if ownedByRun(row.Descr) {
			names = append(names, row.Name)
		}
	}
	return names
}

func TestGatewayGroupLibraryLifecycle(t *testing.T) {
	var sys = systemApi(t)
	var members = gatewayGroupMembers(t, "gateway-group-lib member", "192.168.1.250", "192.168.1.251")
	var gwA, gwB = members[0], members[1]
	var name = gatewayGroupRandomName(t)
	var description = testDescription("gateway-group-lib")

	var candidates, err = sys.GatewayGroupCandidates()
	if err != nil {
		t.Fatal(err)
	}
	var candidateNames []string
	for _, candidate := range candidates {
		candidateNames = append(candidateNames, candidate.Name)
		if candidate.Name == gwA && candidate.Description != gwA+" - 192.168.1.250" {
			t.Errorf("unexpected candidate %+v", candidate)
		}
	}
	if !strings.Contains(strings.Join(candidateNames, ","), "WAN_DHCP") {
		t.Errorf("the WAN gateway is not a candidate: %v", candidateNames)
	}

	uuid, err := sys.GatewayGroupCreate(system.GatewayGroup{
		Name: name, Tiers: [system.GatewayGroupTierCount][]string{{gwA}, {gwB, gwA}},
		Trigger: system.GatewayGroupTriggerLoss, PoolOptions: system.GatewayGroupPoolRoundRobin, Description: description,
	})
	if err != nil {
		t.Fatalf("GatewayGroupCreate: %v", err)
	}
	gatewayGroupCleanup(t, sys, uuid)

	t.Run("get", func(t *testing.T) {
		var group, err = sys.GatewayGroupGet(uuid)
		if err != nil {
			t.Fatal(err)
		}
		var wantTiers = [system.GatewayGroupTierCount][]string{{gwA}, {gwB, gwA}}
		if group.Name != name || !reflect.DeepEqual(group.Tiers, wantTiers) || group.Trigger != system.GatewayGroupTriggerLoss ||
			group.PoolOptions != system.GatewayGroupPoolRoundRobin || group.Description != description {
			t.Errorf("unexpected group %+v", group)
		}
		if len(group.Status[0]) != 1 || group.Status[0][0].Name != gwA || len(group.Status[1]) != 2 || group.Status[0][0].StatusText == "" {
			t.Errorf("unexpected member status %+v", group.Status)
		}
		byName, err := sys.GatewayGroupGetByName(name)
		if err != nil || byName.Uuid != uuid {
			t.Errorf("GatewayGroupGetByName: %+v / %v", byName, err)
		}
		if _, err := sys.GatewayGroupGetByName(name[:len(name)-1]); !api.IsNotFound(err) {
			t.Errorf("a name prefix must not match: %v", err)
		}
	})

	t.Run("validations", func(t *testing.T) {
		var validationErr *api.ValidationError
		if _, err := sys.GatewayGroupCreate(system.GatewayGroup{Name: name, Tiers: [system.GatewayGroupTierCount][]string{{gwB}},
			Description: description}); !errors.As(err, &validationErr) || !strings.Contains(err.Error(), "already exists") {
			t.Errorf("duplicate name: want a validation error, got %v", err)
		}
		if _, err := sys.GatewayGroupCreate(system.GatewayGroup{Name: gwA, Tiers: [system.GatewayGroupTierCount][]string{{gwB}},
			Description: description}); !errors.As(err, &validationErr) || !strings.Contains(err.Error(), "same name") {
			t.Errorf("name of a gateway: want a validation error, got %v", err)
		}
		if _, err := sys.GatewayGroupCreate(system.GatewayGroup{Name: gatewayGroupRandomName(t),
			Tiers: [system.GatewayGroupTierCount][]string{nil, {"a8gg_nonexistent"}}, Description: description}); !errors.As(err, &validationErr) ||
			!strings.Contains(err.Error(), "not in list") {
			t.Errorf("unknown gateway: want a validation error, got %v", err)
		}
		if got := gatewayGroupRawNames(t); !reflect.DeepEqual(got, []string{name}) {
			t.Errorf("only the test group must exist, got %v", got)
		}
	})

	t.Run("update", func(t *testing.T) {
		var tier3 = []string{gwA, gwB}
		var empty []string
		var newDescription = description + " changed"
		if err := sys.GatewayGroupUpdate(uuid, system.GatewayGroupPatch{
			Tiers: [system.GatewayGroupTierCount]*[]string{nil, &empty, &tier3}, Description: &newDescription,
		}); err != nil {
			t.Fatalf("GatewayGroupUpdate: %v", err)
		}
		var group, err = sys.GatewayGroupGet(uuid)
		if err != nil {
			t.Fatal(err)
		}
		var wantTiers = [system.GatewayGroupTierCount][]string{{gwA}, nil, {gwA, gwB}}
		if !reflect.DeepEqual(group.Tiers, wantTiers) || group.Description != newDescription ||
			group.Trigger != system.GatewayGroupTriggerLoss || group.PoolOptions != system.GatewayGroupPoolRoundRobin {
			t.Errorf("unexpected group after the partial update %+v", group)
		}

		// OPNsense would silently keep tier 1, the library refuses
		if err := sys.GatewayGroupUpdate(uuid, system.GatewayGroupPatch{Tiers: [system.GatewayGroupTierCount]*[]string{&empty}}); err == nil ||
			!strings.Contains(err.Error(), "tier 1") {
			t.Errorf("clearing tier 1: want a refusal, got %v", err)
		}
		// set/<uuid> with complete fields would create a group, the library checks first
		var unknown = "00000000-0000-4000-8000-0000000a8a8a"
		if err := sys.GatewayGroupUpdate(unknown, system.GatewayGroupPatch{Description: &newDescription}); !api.IsNotFound(err) {
			t.Errorf("unknown uuid: want NotFoundError, got %v", err)
		}
		if got := gatewayGroupRawNames(t); !reflect.DeepEqual(got, []string{name}) {
			t.Errorf("only the test group must exist, got %v", got)
		}
	})

	t.Run("a member gateway can not be removed", func(t *testing.T) {
		var core = coreApi(t)
		// search_gateway ignores searchPhrase, it always returns all gateways
		var gateways, err = api.Search[struct {
			Uuid string `json:"uuid"`
			Name string `json:"name"`
		}](core, core.EndpointForModule("routing/settings/search_gateway"), "")
		if err != nil {
			t.Fatal(err)
		}
		var gatewayUuid string
		for _, gateway := range gateways {
			if gateway.Name == gwB {
				gatewayUuid = gateway.Uuid
			}
		}
		if gatewayUuid == "" {
			t.Fatalf("the test gateway %s is not listed: %+v", gwB, gateways)
		}
		_, err = core.Mutate(core.EndpointForModule("routing/settings/del_gateway/"+gatewayUuid), nil)
		var httpErr *api.HttpError
		if !errors.As(err, &httpErr) || httpErr.StatusCode != 500 || !strings.Contains(httpErr.Message, name) {
			t.Errorf("want HTTP 500 naming the group, got %v", err)
		}
	})

	t.Run("remove", func(t *testing.T) {
		if err := sys.GatewayGroupRemove(uuid); err != nil {
			t.Fatalf("GatewayGroupRemove: %v", err)
		}
		if err := sys.GatewayGroupRemove(uuid); !api.IsNotFound(err) {
			t.Errorf("second remove: want NotFoundError, got %v", err)
		}
		if _, err := sys.GatewayGroupGet(uuid); !api.IsNotFound(err) {
			t.Errorf("get after remove: want NotFoundError, got %v", err)
		}
		if got := gatewayGroupRawNames(t); len(got) != 0 {
			t.Errorf("no test group must be left, got %v", got)
		}
	})
}
