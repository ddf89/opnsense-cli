//go:build integration

package integrationvpn

import (
	"errors"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/openvpn"
)

// csoCreateServerInstance creates a DISABLED OpenVPN server instance through the raw API (not the library under
// test) for overrides to refer to, it is removed when the test ends. vpnid "" makes OPNsense pick a free id
// (leaving it out fails with "instance.vpnid: A value is required.")
func csoCreateServerInstance(t *testing.T, core *api.OPNsense, label string) string {
	t.Helper()
	var description = testDescription(label)
	var uuid, err = core.Mutate(core.EndpointForModule("openvpn/instances/add"), map[string]any{"instance": map[string]string{
		"vpnid": "", "enabled": "0", "role": "server", "dev_type": "tun", "proto": "udp", "server": "10.213.0.0/24",
		"verify_client_cert": "none", "authmode": "Local Database", "description": description,
	}})
	if err != nil {
		t.Fatalf("creating the disabled test instance %q: %v", description, err)
	}
	t.Cleanup(func() {
		if _, err := core.Mutate(core.EndpointForModule("openvpn/instances/del/"+uuid), nil); err != nil {
			t.Errorf("removing the test instance %s: %v", uuid, err)
		}
	})
	return uuid
}

// csoRawFind returns the raw search rows of client_overwrites with this uuid (0 or 1)
func csoRawFind(t *testing.T, core *api.OPNsense, uuid string) []map[string]any {
	t.Helper()
	var rows, err = api.Search[map[string]any](core, core.EndpointForModule("openvpn/client_overwrites/search"), "")
	if err != nil {
		t.Fatalf("raw search: %v", err)
	}
	return api.Filter(rows, func(row map[string]any) bool { return row["uuid"] == uuid })
}

// csoCleanup removes the override when the test ends (when it still exists) and checks it is gone
func csoCleanup(t *testing.T, core *api.OPNsense, uuid string) {
	t.Cleanup(func() {
		if len(csoRawFind(t, core, uuid)) > 0 {
			if _, err := core.Mutate(core.EndpointForModule("openvpn/client_overwrites/del/"+uuid), nil); err != nil {
				t.Errorf("removing client specific override %s: %v", uuid, err)
			}
		}
		if len(csoRawFind(t, core, uuid)) > 0 {
			t.Errorf("client specific override %s still exists", uuid)
		}
	})
}

func TestClientOverrideLifecycle(t *testing.T) {
	var core = coreApi(t)
	var vpn = &openvpn.OpenVPNApi{OPNsense: core}
	var server = csoCreateServerInstance(t, core, "cso-lib-server")

	// the servers option list offers the new instance, labelled "description (port / PROTO)"
	var servers, err = vpn.ClientOverrideServers()
	if err != nil {
		t.Fatalf("ClientOverrideServers: %v", err)
	}
	var found bool
	for _, s := range servers {
		if s.Id == server {
			found = true
			if s.Description() != testDescription("cso-lib-server") || !strings.HasSuffix(s.Label, " / UDP)") {
				t.Errorf("unexpected server option %+v (description %q)", s, s.Description())
			}
		}
	}
	if !found {
		t.Fatalf("the test instance %s is not in the servers options %+v", server, servers)
	}

	var commonName = runPrefix + " lib"
	uuid, err := vpn.ClientOverrideCreate(openvpn.ClientOverride{
		Enabled: "0", Servers: server, CommonName: commonName, TunnelNetwork: "10.213.0.8/30",
		TunnelNetworkV6: "fd00:213::8/64", LocalNetworks: "192.168.213.0/24,fd00:214::/64", RedirectGateway: "def1,bypass-dhcp",
		DnsServers: "10.213.0.53", DnsDomain: "example.lan", Description: testDescription("cso-lib"),
	})
	if err != nil {
		t.Fatalf("ClientOverrideCreate: %v", err)
	}
	csoCleanup(t, core, uuid)

	got, err := vpn.ClientOverrideGet(uuid)
	if err != nil {
		t.Fatalf("ClientOverrideGet: %v", err)
	}
	if got.Enabled != "0" || got.Servers != server || got.CommonName != commonName || got.TunnelNetworkV6 != "fd00:213::8/64" ||
		got.LocalNetworks != "192.168.213.0/24,fd00:214::/64" || got.RedirectGateway != "def1,bypass-dhcp" ||
		!strings.HasPrefix(got.ServersLabel, testDescription("cso-lib-server")) || got.Block != "0" {
		t.Errorf("unexpected override %+v", got)
	}

	// natural key: common name (case-sensitive) and the same servers
	if byKey, err := vpn.ClientOverrideFindByKey(commonName, server); err != nil || len(byKey) != 1 || byKey[0].Uuid != uuid {
		t.Errorf("FindByKey: %+v / %v", byKey, err)
	}
	if byKey, err := vpn.ClientOverrideFindByKey(strings.ToUpper(commonName), server); err != nil || len(byKey) != 0 {
		t.Errorf("FindByKey must be case-sensitive: %+v / %v", byKey, err)
	}
	if byKey, err := vpn.ClientOverrideFindByKey(commonName, ""); err != nil || len(byKey) != 0 {
		t.Errorf("FindByKey for all servers must not match: %+v / %v", byKey, err)
	}

	// partial update keeps the other fields
	if err := vpn.ClientOverrideUpdate(uuid, openvpn.ClientOverrideFields{"block": "1", "description": testDescription("cso-lib changed")}); err != nil {
		t.Fatalf("ClientOverrideUpdate: %v", err)
	}
	if got, _ = vpn.ClientOverrideGet(uuid); got.Block != "1" || got.TunnelNetwork != "10.213.0.8/30" || got.Enabled != "0" ||
		got.Description != testDescription("cso-lib changed") {
		t.Errorf("after update: %+v", got)
	}

	// OPNsense's own validation (the library does not check networks)
	err = vpn.ClientOverrideUpdate(uuid, openvpn.ClientOverrideFields{"tunnel_network": "10.213.0.8"})
	var validation *api.ValidationError
	if !errors.As(err, &validation) || validation.Validations["cso.tunnel_network"] == "" {
		t.Errorf("want a validation error for cso.tunnel_network, got %v", err)
	}

	// set/<unknown uuid> would create an override, the library refuses
	const ghost = "0f0f0f0f-1111-4222-8333-a8a8a8a8a8a8"
	if err := vpn.ClientOverrideUpdate(ghost, openvpn.ClientOverrideFields{
		"common_name": runPrefix + " ghost", "enabled": "0", "description": testDescription("cso-ghost")}); !api.IsNotFound(err) {
		t.Errorf("update of an unknown uuid: want NotFoundError, got %v", err)
	}
	if rows := csoRawFind(t, core, ghost); len(rows) != 0 {
		t.Errorf("the update of an unknown uuid created %v", rows)
	}

	// replace by natural key overwrites completely, keeping it disabled
	replaced, wasReplaced, err := vpn.ClientOverrideCreateOrUpdate(openvpn.ClientOverride{
		Enabled: "0", Servers: server, CommonName: commonName, RemoteNetworks: "192.168.215.0/24", Description: testDescription("cso-lib replaced"),
	})
	if err != nil || replaced != uuid || !wasReplaced {
		t.Fatalf("CreateOrUpdate: %q %v %v", replaced, wasReplaced, err)
	}
	if got, _ = vpn.ClientOverrideGet(uuid); got.TunnelNetwork != "" || got.Block != "0" || got.RemoteNetworks != "192.168.215.0/24" || got.Enabled != "0" {
		t.Errorf("after replace: %+v", got)
	}

	// toggle to the state it has: answers unchanged (enabling is never done live)
	if changed, err := vpn.ClientOverrideSetEnabled(uuid, false); err != nil || changed {
		t.Errorf("SetEnabled(false) on a disabled override: %v %v", changed, err)
	}
	if _, err := vpn.ClientOverrideSetEnabled(ghost, false); !api.IsNotFound(err) {
		t.Errorf("toggle of an unknown uuid: want NotFoundError, got %v", err)
	}

	if err := vpn.ClientOverrideRemove(uuid); err != nil {
		t.Fatalf("ClientOverrideRemove: %v", err)
	}
	if rows := csoRawFind(t, core, uuid); len(rows) != 0 {
		t.Errorf("still there after remove: %v", rows)
	}
	if err := vpn.ClientOverrideRemove(uuid); !api.IsNotFound(err) {
		t.Errorf("second remove: want NotFoundError, got %v", err)
	}
}
