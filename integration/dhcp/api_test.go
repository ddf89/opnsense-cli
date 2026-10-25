//go:build integration

package integrationdhcp

import (
	"errors"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dhcp"
)

// The library against the live box: Kea subnets, reservations, options, peers, settings and leases, relays and
// radvd entries. All records use documentation networks and the run prefix, relays and radvd entries are disabled

const unknownUuid = "0a5d0000-0000-4000-8000-0000000000a5"

func TestKeaSubnetReservationLifecycle(t *testing.T) {
	var dhcpApi = dhcpApi(t)
	var options = dhcpApi.KeaOptions4()
	var optionUuid, err = options.Create(dhcp.Fields{"description": testLabel("api-option"), "code": "224", "data": "0a0b0c"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = options.Remove(optionUuid) })

	var subnets = dhcpApi.KeaSubnets4()
	var subnetUuid, createErr = subnets.Create(dhcp.Fields{
		"subnet": "198.51.100.0/24", "description": testLabel("api-subnet"), "pools": "198.51.100.10-198.51.100.20\n198.51.100.32/28",
		"option_data_autocollect": "0", "option_data.routers": "198.51.100.1", "option": optionUuid,
	})
	if createErr != nil {
		t.Fatal(createErr)
	}
	t.Cleanup(func() { _ = subnets.Remove(subnetUuid) })

	var subnet, getErr = subnets.Get(subnetUuid)
	if getErr != nil || subnet.Routers != "198.51.100.1" || subnet.Pools != "198.51.100.10-198.51.100.20\n198.51.100.32/28" || subnet.Option != optionUuid {
		t.Errorf("Get: %+v / %v", subnet, getErr)
	}

	// set is a partial merge
	if err := subnets.Update(subnetUuid, dhcp.Fields{"option_data.domain_name": "a5.example"}); err != nil {
		t.Fatal(err)
	}
	if subnet, err := subnets.Get(subnetUuid); err != nil || subnet.DomainName != "a5.example" || subnet.Routers != "198.51.100.1" {
		t.Errorf("after update: %+v / %v", subnet, err)
	}
	// an unknown uuid is refused before set_subnet could create it
	if err := subnets.Update(unknownUuid, dhcp.Fields{"description": testLabel("ghost")}); !api.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}

	var reservations = dhcpApi.KeaReservations4()
	var _, invalidErr = reservations.Create(dhcp.Fields{"subnet": subnetUuid, "ip_address": "10.0.0.5", "hw_address": "02:00:5e:10:00:01", "client_id": "01:02"})
	var validation *api.ValidationError
	if !errors.As(invalidErr, &validation) || !strings.Contains(validation.Validations["reservation.ip_address"], "not in specified subnet") {
		t.Errorf("want the validation error, got %v", invalidErr)
	}
	var reservationUuid, resErr = reservations.Create(dhcp.Fields{"subnet": subnetUuid, "ip_address": "198.51.100.50",
		"hw_address": "02:00:5e:10:00:01", "hostname": testHostname("printer"), "option_data.routers": "198.51.100.1"})
	if resErr != nil {
		t.Fatal(resErr)
	}
	t.Cleanup(func() { _ = reservations.Remove(reservationUuid) })
	if reservation, err := reservations.Get(reservationUuid); err != nil || reservation.SubnetDisplay != "198.51.100.0/24" || reservation.Routers != "198.51.100.1" {
		t.Errorf("reservation %+v / %v", reservation, err)
	}

	// the subnet is in use by the reservation
	if err := subnets.Remove(subnetUuid); err == nil || !strings.Contains(err.Error(), "in use by") || !strings.Contains(err.Error(), reservationUuid) {
		t.Errorf("want the in use error, got %v", err)
	}
	if err := reservations.Remove(reservationUuid); err != nil {
		t.Fatal(err)
	}
	if err := reservations.Remove(reservationUuid); !api.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if err := subnets.Remove(subnetUuid); err != nil {
		t.Fatal(err)
	}
	if err := options.Remove(optionUuid); err != nil {
		t.Fatal(err)
	}
}

func TestKeaDhcp6Records(t *testing.T) {
	var dhcpApi = dhcpApi(t)
	var subnets = dhcpApi.KeaSubnets6()
	// a DHCPv6 subnet needs its interface in the DHCPv6 interfaces
	requireKeaDisabled(t, dhcpApi)
	var _, refused = subnets.Create(dhcp.Fields{"subnet": "2001:db8:a5::/64", "interface": "wan", "description": testLabel("api-v6-refused")})
	if refused == nil || !strings.Contains(refused.Error(), "not selected in the general settings") {
		t.Errorf("want the interface refusal, got %v", refused)
	}
	keaDhcp6WithInterface(t, dhcpApi, "lan")

	var subnetUuid, err = subnets.Create(dhcp.Fields{"subnet": "2001:db8:a5::/64", "interface": "lan", "description": testLabel("api-v6"),
		"pools": "2001:db8:a5::100-2001:db8:a5::1ff", "option_data.dns_servers": "2001:db8:a5::53"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = subnets.Remove(subnetUuid) })

	var reservations = dhcpApi.KeaReservations6()
	var reservationUuid, resErr = reservations.Create(dhcp.Fields{"subnet": subnetUuid, "ip_address": "2001:db8:a5::50",
		"duid": "00:01:00:01:aa:bb:cc:dd", "hostname": testHostname("nas")})
	if resErr != nil {
		t.Fatal(resErr)
	}
	t.Cleanup(func() { _ = reservations.Remove(reservationUuid) })

	var pools = dhcpApi.KeaPdPools()
	var poolUuid, poolErr = pools.Create(dhcp.Fields{"subnet": subnetUuid, "prefix": "2001:db8:a500::", "prefix_len": "48",
		"delegated_len": "56", "description": testLabel("api-pd")})
	if poolErr != nil {
		t.Fatal(poolErr)
	}
	t.Cleanup(func() { _ = pools.Remove(poolUuid) })
	if pool, err := pools.Get(poolUuid); err != nil || pool.PrefixLen != "48" || pool.DelegatedLen != "56" || pool.Subnet != subnetUuid {
		t.Errorf("pd pool %+v / %v", pool, err)
	}

	for _, remove := range []func() error{
		func() error { return pools.Remove(poolUuid) },
		func() error { return reservations.Remove(reservationUuid) },
		func() error { return subnets.Remove(subnetUuid) },
	} {
		if err := remove(); err != nil {
			t.Error(err)
		}
	}
}

func TestKeaPeersAndSettings(t *testing.T) {
	var dhcpApi = dhcpApi(t)
	var peers = dhcpApi.KeaPeers6()
	var uuid, err = peers.Create(dhcp.Fields{"name": testHostname("peer"), "url": "http://198.51.100.9:8000/"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peers.Remove(uuid) })
	if peer, err := peers.Get(uuid); err != nil || peer.Role != "primary" {
		t.Errorf("peer %+v / %v", peer, err)
	}
	if err := peers.Remove(uuid); err != nil {
		t.Fatal(err)
	}

	// a setting changed and restored while Kea is disabled
	requireKeaDisabled(t, dhcpApi)
	var form, getErr = dhcpApi.SettingsGet(dhcp.KeaDhcp4Settings)
	if getErr != nil {
		t.Fatal(getErr)
	}
	var lifetime = form.Value("general.valid_lifetime")
	t.Cleanup(func() {
		_ = dhcpApi.SettingsSet(dhcp.KeaDhcp4Settings, dhcp.Fields{"general.valid_lifetime": lifetime})
	})
	if err := dhcpApi.SettingsSet(dhcp.KeaDhcp4Settings, dhcp.Fields{"general.valid_lifetime": "3601"}); err != nil {
		t.Fatal(err)
	}
	if after, err := dhcpApi.SettingsGet(dhcp.KeaDhcp4Settings); err != nil || after.Value("general.valid_lifetime") != "3601" ||
		after.Value("general.enabled") != form.Value("general.enabled") {
		t.Errorf("after set: %v / %v", after, err)
	}
	var invalid = dhcpApi.SettingsSet(dhcp.KeaDhcp4Settings, dhcp.Fields{"general.valid_lifetime": "abc"})
	var validation *api.ValidationError
	if !errors.As(invalid, &validation) || validation.Validations["dhcpv4.general.valid_lifetime"] == "" {
		t.Errorf("want the validation error, got %v", invalid)
	}
	if err := dhcpApi.SettingsSet(dhcp.KeaDhcp4Settings, dhcp.Fields{"general.valid_lifetime": lifetime}); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []dhcp.SettingsSpec{dhcp.KeaCtrlAgentSettings, dhcp.KeaDdnsSettings, dhcp.KeaDhcp6Settings} {
		if form, err := dhcpApi.SettingsGet(spec); err != nil || form.Value("general.enabled") == "" {
			t.Errorf("%s: %v / %v", spec.What(), form, err)
		}
	}
}

func TestKeaLeasesAndService(t *testing.T) {
	var dhcpApi = dhcpApi(t)
	var status, err = dhcpApi.ServiceStatus(dhcp.KeaService)
	if err != nil || status == "" {
		t.Fatalf("status %q / %v", status, err)
	}
	for _, version := range []int{4, 6} {
		if _, _, err := dhcpApi.KeaLeases(version, ""); err != nil {
			t.Errorf("leases%d: %v", version, err)
		}
	}
	if status != "running" {
		// without a running Kea the delete fails in the backend: the error of OPNsense is passed through
		var removeErr = dhcpApi.KeaLeaseRemove(4, "198.51.100.99")
		if removeErr == nil || !strings.Contains(removeErr.Error(), "198.51.100.99") {
			t.Errorf("want the backend error, got %v", removeErr)
		}
	}
}

func TestRelayAndRadvdRecords(t *testing.T) {
	var dhcpApi = dhcpApi(t)
	var destinations = dhcpApi.RelayDestinations()
	var destUuid, err = destinations.Create(dhcp.Fields{"name": testHostname("dest"), "server": "198.51.100.67,198.51.100.68"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = destinations.Remove(destUuid) })

	var relays = dhcpApi.Relays()
	var relayUuid, relayErr = relays.Create(dhcp.Fields{"enabled": "0", "interface": "lan", "destination": destUuid, "agent_info": "1"})
	if relayErr != nil {
		t.Fatal(relayErr)
	}
	t.Cleanup(func() { _ = relays.Remove(relayUuid) })
	if relay, err := relays.Get(relayUuid); err != nil || relay.Enabled != "0" || relay.DestinationName != testHostname("dest") || relay.Status != "grey" {
		t.Errorf("relay %+v / %v", relay, err)
	}
	if changed, err := relays.SetEnabled(relayUuid, false); err != nil || changed {
		t.Errorf("disable a disabled relay: %v / %v", changed, err)
	}
	if _, err := relays.SetEnabled(unknownUuid, false); !api.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if err := destinations.Remove(destUuid); err == nil || !strings.Contains(err.Error(), "in use by") {
		t.Errorf("want the in use error, got %v", err)
	}
	if err := relays.Remove(relayUuid); err != nil {
		t.Fatal(err)
	}
	if err := destinations.Remove(destUuid); err != nil {
		t.Fatal(err)
	}

	var entries = dhcpApi.RadvdEntries()
	if existing, err := entries.List(""); err != nil {
		t.Fatal(err)
	} else {
		for _, entry := range existing {
			if entry.Interface == "lan" {
				t.Skip("lan has a radvd entry already, the interface is unique")
			}
		}
	}
	var defaults, defaultsErr = entries.Defaults()
	if defaultsErr != nil || defaults["enabled"] != "1" || defaults["mode"] != "stateless" {
		t.Errorf("defaults %v / %v", defaults, defaultsErr)
	}
	var entryUuid, entryErr = entries.Create(dhcp.Fields{"enabled": "0", "interface": "lan", "mode": "managed",
		"RDNSS": "2001:db8::53", "DNSSL": runPrefix + ".example"})
	if entryErr != nil {
		t.Fatal(entryErr)
	}
	t.Cleanup(func() { _ = entries.Remove(entryUuid) })
	var _, duplicate = entries.Create(dhcp.Fields{"enabled": "0", "interface": "lan", "DNSSL": runPrefix + ".example"})
	if duplicate == nil || !strings.Contains(duplicate.Error(), "already exists") {
		t.Errorf("want the unique interface error, got %v", duplicate)
	}
	if err := entries.Update(entryUuid, dhcp.Fields{"MinRtrAdvInterval": "500", "MaxRtrAdvInterval": "600"}); err == nil {
		t.Error("want the min interval validation")
	}
	if err := entries.Remove(entryUuid); err != nil {
		t.Fatal(err)
	}
	if status, err := dhcpApi.ServiceStatus(dhcp.RadvdService); err != nil || status == "" {
		t.Errorf("radvd status %q / %v", status, err)
	}
}
