//go:build integration

package integrationsystem

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
)

// Gateway tests create LAN gateways (192.168.1.240-249, monitoring disabled, never upstream / default) and never
// apply them; the generated WAN_DHCP / WAN_DHCP6 gateways are only read, their override path is tested with fakes

// gatewayTestName returns a name like a8gw_1a2b3c4d
func gatewayTestName(t *testing.T) string {
	t.Helper()
	var random = make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	return "a8gw_" + hex.EncodeToString(random)
}

// createTestGateway creates a LAN gateway owned by this run and registers its removal
func createTestGateway(t *testing.T, sys *system.SystemApi, label string, address string) (string, system.GatewayFields) {
	t.Helper()
	var fields = system.GatewayFields{
		"name": gatewayTestName(t), "interface": "lan", "ipprotocol": "inet", "gateway": address,
		"descr": testDescription(label), "defaultgw": "0", "monitor_disable": "1",
	}
	var uuid, err = sys.GatewayCreate(fields)
	if err != nil {
		t.Fatalf("GatewayCreate(%v): %v", fields, err)
	}
	if !system.GatewayIsUuid(uuid) {
		t.Fatalf("GatewayCreate returned %q, not a uuid", uuid)
	}
	cleanupGateway(t, sys, uuid)
	return uuid, fields
}

func cleanupGateway(t *testing.T, sys *system.SystemApi, uuid string) {
	t.Helper()
	t.Cleanup(func() {
		if err := sys.GatewayRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of gateway %s failed: %v", uuid, err)
		}
		if gateways, err := sys.GatewayList(); err == nil {
			for _, gateway := range gateways {
				if gateway.Uuid == uuid {
					t.Errorf("gateway %s (%s) is still there after the cleanup", gateway.Name, uuid)
				}
			}
		}
	})
}

func TestGatewayLifecycle(t *testing.T) {
	var sys = systemApi(t)
	var uuid, created = createTestGateway(t, sys, "gateway-lifecycle", "192.168.1.240")
	var name = created["name"]

	t.Run("listed as configured with the given and default fields", func(t *testing.T) {
		var gateway, err = sys.GatewayGet(name)
		if err != nil {
			t.Fatal(err)
		}
		if gateway.Uuid != uuid || !gateway.IsConfigured() || gateway.Interface != "lan" || gateway.IpProtocol != "inet" ||
			gateway.Address != "192.168.1.240" || gateway.Description != created["descr"] || gateway.Disabled ||
			gateway.Upstream || gateway.Default || gateway.Dynamic || !gateway.MonitorDisable || gateway.Priority != "255" ||
			gateway.Weight != "1" || gateway.Current["latencyhigh"] != "500" || gateway.Status == "" {
			t.Errorf("unexpected gateway %+v", gateway)
		}
		if byUuid, err := sys.GatewayGet(uuid); err != nil || byUuid.Name != name {
			t.Errorf("GatewayGet(uuid): %+v / %v", byUuid, err)
		}
	})

	t.Run("record", func(t *testing.T) {
		var record, err = sys.GatewayRecord(uuid)
		if err != nil {
			t.Fatal(err)
		}
		if record["name"] != name || record["interface"] != "lan" || record["ipprotocol"] != "inet" || record["gateway"] != "192.168.1.240" {
			t.Errorf("unexpected record %v", record)
		}
	})

	t.Run("update changes only the given fields", func(t *testing.T) {
		var description = testDescription("gateway-lifecycle changed")
		var updated, err = sys.GatewayUpdate(uuid, system.GatewayFields{"priority": "100", "descr": description, "latencyhigh": "800"})
		if err != nil || updated != uuid {
			t.Fatalf("GatewayUpdate: %q / %v", updated, err)
		}
		var gateway, getErr = sys.GatewayGet(uuid)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if gateway.Priority != "100" || gateway.Description != description || gateway.LatencyHigh != "800" ||
			gateway.Address != "192.168.1.240" || gateway.Interface != "lan" || !gateway.MonitorDisable {
			t.Errorf("unexpected gateway after update %+v", gateway)
		}
	})

	t.Run("OPNsense validations are returned", func(t *testing.T) {
		var _, err = sys.GatewayUpdate(uuid, system.GatewayFields{"latencylow": "900"}) // above latencyhigh 800
		var validationErr *api.ValidationError
		if !errors.As(err, &validationErr) || !strings.Contains(err.Error(), "latency") {
			t.Errorf("want a latency ValidationError, got %v", err)
		}
	})

	t.Run("rename is refused", func(t *testing.T) {
		if _, err := sys.GatewayUpdate(uuid, system.GatewayFields{"name": name + "x"}); err == nil || !strings.Contains(err.Error(), "renamed") {
			t.Errorf("want rename refusal, got %v", err)
		}
	})

	t.Run("duplicate address is refused", func(t *testing.T) {
		var fields = system.GatewayFields{"name": gatewayTestName(t), "interface": "lan", "gateway": "192.168.1.240",
			"descr": testDescription("gateway-duplicate"), "monitor_disable": "1"}
		var duplicate, err = sys.GatewayCreate(fields)
		if err == nil {
			cleanupGateway(t, sys, duplicate)
			t.Fatalf("a second gateway with the same address was created: %s", duplicate)
		}
		if !strings.Contains(err.Error(), "already exists") {
			t.Errorf("want the duplicate address message, got %v", err)
		}
	})

	t.Run("disable and enable", func(t *testing.T) {
		for _, step := range []struct {
			enabled, changed bool
		}{{false, true}, {false, false}, {true, true}, {true, false}} {
			var changed, err = sys.GatewaySetEnabled(name, step.enabled)
			if err != nil || changed != step.changed {
				t.Fatalf("GatewaySetEnabled(%v): changed %v / %v, want changed %v", step.enabled, changed, err, step.changed)
			}
			var gateway, _ = sys.GatewayGet(uuid)
			if gateway.Disabled == step.enabled {
				t.Errorf("after GatewaySetEnabled(%v) disabled is %v", step.enabled, gateway.Disabled)
			}
		}
	})

	t.Run("remove", func(t *testing.T) {
		if err := sys.GatewayRemove(uuid); err != nil {
			t.Fatal(err)
		}
		if _, err := sys.GatewayGet(uuid); !api.IsNotFound(err) {
			t.Errorf("want NotFoundError after remove, got %v", err)
		}
		if err := sys.GatewayRemove(uuid); !api.IsNotFound(err) {
			t.Errorf("want NotFoundError for a second remove, got %v", err)
		}
		if _, err := sys.GatewayUpdate(uuid, system.GatewayFields{"priority": "1"}); !api.IsNotFound(err) {
			t.Errorf("want NotFoundError for an update, got %v", err)
		}
		if _, err := sys.GatewaySetEnabled(uuid, true); !api.IsNotFound(err) {
			t.Errorf("want NotFoundError for enable, got %v", err)
		}
	})
}

// a gateway in use by a group can not be removed, OPNsense's message is returned
func TestGatewayRemoveInUse(t *testing.T) {
	var sys = systemApi(t)
	var core = sys.OPNsense
	var uuid, created = createTestGateway(t, sys, "gateway-in-use", "192.168.1.241")

	var group = map[string]map[string]string{"gateway_group": {
		"name": gatewayTestName(t), "item2": created["name"], "trigger": "down", "descr": testDescription("gateway-in-use group"),
	}}
	// the member options of groups are cached by OPNsense for about 30 seconds, a new gateway is "not in list" until then
	var groupUuid string
	var err error
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(3 * time.Second) {
		groupUuid, err = core.Mutate(core.EndpointForModule("routing/group_settings/add"), group)
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "not in list") || time.Now().After(deadline) {
			t.Fatalf("creating the group: %v", err)
		}
	}
	var groupRemoved = false
	var removeGroup = func() {
		if groupRemoved {
			return
		}
		groupRemoved = true
		if _, err := core.Mutate(core.EndpointForModule("routing/group_settings/del/"+groupUuid), nil); err != nil {
			t.Errorf("removing the group %s: %v", groupUuid, err)
		}
	}
	t.Cleanup(removeGroup) // runs before the cleanup of the gateway (last in first out)

	err = sys.GatewayRemove(uuid)
	if err == nil || !strings.Contains(err.Error(), "cannot be deleted because it is in use on Gateway Group") ||
		strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("want the in use message, got %v", err)
	}
	if _, getErr := sys.GatewayGet(uuid); getErr != nil {
		t.Errorf("the gateway must still exist: %v", getErr)
	}

	removeGroup()
	if err := sys.GatewayRemove(uuid); err != nil {
		t.Errorf("remove after the group is gone: %v", err)
	}
}

// read-only checks of the generated gateways, interfaces and status
func TestGatewayReadOnly(t *testing.T) {
	var sys = systemApi(t)

	var interfaces, err = sys.GatewayInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, iface := range interfaces {
		keys = append(keys, iface.Key)
	}
	if !strings.Contains(","+strings.Join(keys, ",")+",", ",lan,") || !strings.Contains(","+strings.Join(keys, ",")+",", ",wan,") {
		t.Errorf("want lan and wan among the interfaces, got %v", keys)
	}

	var gateways, listErr = sys.GatewayList()
	if listErr != nil {
		t.Fatal(listErr)
	}
	var names = map[string]bool{}
	for _, gateway := range gateways {
		names[gateway.Name] = true
		if gateway.Name == "" || gateway.Uuid == "" || gateway.Priority == "" {
			t.Errorf("incomplete gateway %+v", gateway)
		}
		if gateway.Name == "WAN_DHCP" && !gateway.IsConfigured() && (gateway.Uuid != "WAN_DHCP" || !gateway.Dynamic) {
			t.Errorf("unexpected generated gateway %+v", gateway)
		}
	}

	var statuses, statusErr = sys.GatewayStatuses()
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	for _, status := range statuses {
		if status.Name == "" || status.Status == "" || status.Loss == "" || len(status.Raw) == 0 {
			t.Errorf("incomplete status %+v", status)
		}
	}
	if len(gateways) > 0 && len(statuses) == 0 {
		t.Errorf("no status for %d gateways", len(gateways))
	}

	// refused client-side, nothing is sent
	if names["WAN_DHCP"] {
		if err := sys.GatewayRemove("WAN_DHCP"); err == nil || !strings.Contains(err.Error(), "not configured") {
			t.Errorf("want refusal for removing WAN_DHCP, got %v", err)
		}
	}
	if _, err := sys.GatewayCreate(system.GatewayFields{"name": "bad name", "interface": "lan"}); err == nil {
		t.Errorf("want a validation error for a bad name")
	}
}
