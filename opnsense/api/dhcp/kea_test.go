package dhcp

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

const (
	testSubnetUuid      = "7bbdb6e0-fa69-42b5-91ad-21af3c1ffd54"
	testReservationUuid = "fd7ffa2d-3cea-4080-9486-4e4cd680df1a"
	testUnknownUuid     = "00000000-0000-4000-8000-000000000000"
)

// testSubnetSearch is a search_subnet answer of 26.7 (shortened)
const testSubnetSearch = `{"rows":[{"uuid":"` + testSubnetUuid + `","subnet":"198.51.100.0\/24","valid_lifetime":"",` +
	`"option_data_autocollect":"0","option_data.domain_name_servers":"198.51.100.2,198.51.100.3","option_data.routers":"198.51.100.1",` +
	`"option":"","match-client-id":"1","allocator":"random","%allocator":"Random","pools":"198.51.100.10-198.51.100.20\n198.51.100.32\/28",` +
	`"ddns_domain_key_secret":"c2VjcmV0","description":"office"}],"rowCount":1,"total":1,"current":1}`

const testReservationSearch = `{"rows":[{"uuid":"` + testReservationUuid + `","subnet":"` + testSubnetUuid + `","%subnet":"198.51.100.0\/24",` +
	`"ip_address":"198.51.100.50","hw_address":"02:00:5e:10:00:01","client_id":"","hostname":"printer","description":"",` +
	`"option_data.routers":"198.51.100.1","option":""}],"rowCount":1,"total":1,"current":1}`

func TestCollectionList(t *testing.T) {
	var api, server = newTestApi(t, map[string]string{
		"GET /api/kea/dhcpv4/search_subnet":      testSubnetSearch,
		"GET /api/kea/dhcpv4/search_reservation": testReservationSearch,
	})
	var subnets, err = api.KeaSubnets4().List("office")
	if err != nil {
		t.Fatal(err)
	}
	if got := server.recorded()[0]; got.Path != "/api/kea/dhcpv4/search_subnet" || got.Query.Get("searchPhrase") != "office" {
		t.Errorf("unexpected request %+v", got)
	}
	var subnet = subnets[0]
	if len(subnets) != 1 || subnet.Uuid != testSubnetUuid || subnet.Subnet != "198.51.100.0/24" || subnet.Routers != "198.51.100.1" ||
		subnet.DomainNameServers != "198.51.100.2,198.51.100.3" || subnet.Pools != "198.51.100.10-198.51.100.20\n198.51.100.32/28" ||
		subnet.Allocator != "random" || subnet.MatchClientId != "1" {
		t.Errorf("got %+v", subnets)
	}

	var rows, raws, rowsErr = api.KeaSubnets4().Rows("")
	if rowsErr != nil || len(rows) != 1 || len(raws) != 1 || rows[0].Uuid() != testSubnetUuid || rows[0]["option_data.routers"] != "198.51.100.1" ||
		rows[0].Display("allocator") != "Random" || rows[0].Display("subnet") != "198.51.100.0/24" {
		t.Errorf("rows %+v / %v", rows, rowsErr)
	}

	var reservation, getErr = api.KeaReservations4().Get(strings.ToUpper(testReservationUuid))
	if getErr != nil || reservation.Hostname != "printer" || reservation.Subnet != testSubnetUuid || reservation.SubnetDisplay != "198.51.100.0/24" {
		t.Errorf("Get: %+v / %v", reservation, getErr)
	}
	if _, err := api.KeaReservations4().Get(testUnknownUuid); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if _, err := api.KeaReservations4().Get(""); err == nil {
		t.Error("want an error for an empty uuid")
	}
}

func TestCollectionCreate(t *testing.T) {
	var api, server = newTestApi(t, map[string]string{
		"POST /api/kea/dhcpv4/add_subnet":      `{"result":"saved","uuid":"` + testSubnetUuid + `"}`,
		"POST /api/kea/dhcpv4/add_reservation": `{"result":"failed","validations":{"reservation.ip_address":"Address not in specified subnet","reservation.hw_address":["Either a client ID or a MAC address should be specified, but not both"]}}`,
	})
	var uuid, err = api.KeaSubnets4().Create(Fields{"subnet": "198.51.100.0/24", "option_data.routers": "198.51.100.1", "pools": "a\nb"})
	if err != nil || uuid != testSubnetUuid {
		t.Fatalf("got %q / %v", uuid, err)
	}
	wantBody(t, server.mutations()[0], `{"subnet4":{"subnet":"198.51.100.0/24","option_data":{"routers":"198.51.100.1"},"pools":"a\nb"}}`)

	var _, createErr = api.KeaReservations4().Create(Fields{"ip_address": "10.0.0.5"})
	var validation *coreapi.ValidationError
	if !errors.As(createErr, &validation) || validation.Validations["reservation.ip_address"] != "Address not in specified subnet" ||
		!strings.Contains(createErr.Error(), "but not both") {
		t.Errorf("want the validation error, got %v", createErr)
	}

	server.reset()
	if _, err := api.KeaSubnets4().Create(nil); err == nil || len(server.recorded()) != 0 {
		t.Errorf("an empty create must not be sent: %v", err)
	}
}

func TestCollectionUpdate(t *testing.T) {
	var api, server = newTestApi(t, map[string]string{
		"GET /api/kea/dhcpv4/search_subnet":                 testSubnetSearch,
		"POST /api/kea/dhcpv4/set_subnet/" + testSubnetUuid: `{"result":"saved"}`,
	})
	if err := api.KeaSubnets4().Update(testSubnetUuid, Fields{"description": "", "option_data.domain_name": "lan"}); err != nil {
		t.Fatal(err)
	}
	var mutations = server.mutations()
	if len(mutations) != 1 || mutations[0].Path != "/api/kea/dhcpv4/set_subnet/"+testSubnetUuid {
		t.Fatalf("mutations %+v", mutations)
	}
	wantBody(t, mutations[0], `{"subnet4":{"description":"","option_data":{"domain_name":"lan"}}}`)

	// set_* would create an unknown uuid, so it is checked first and nothing is sent
	server.reset()
	if err := api.KeaSubnets4().Update(testUnknownUuid, Fields{"description": "x"}); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if err := api.KeaSubnets4().Update("", Fields{"description": "x"}); err == nil {
		t.Error("want an error for an empty uuid")
	}
	if err := api.KeaSubnets4().Update(testSubnetUuid, nil); err == nil {
		t.Error("want an error for nothing to change")
	}
	if got := server.mutations(); len(got) != 0 {
		t.Errorf("want no mutation, got %+v", got)
	}
}

func TestCollectionRemove(t *testing.T) {
	var api, server = newTestApi(t, map[string]string{
		"POST /api/kea/dhcpv4/del_reservation/" + testReservationUuid: `{"result":"deleted"}`,
		"POST /api/kea/dhcpv4/del_reservation/" + testUnknownUuid:     `{"result":"not found"}`,
		"POST /api/kea/dhcpv4/del_subnet/" + testSubnetUuid: `500 {"errorMessage":"dhcp4 - r1 {dhcp4.reservations.reservation.` + testReservationUuid + `}\n",` +
			`"errorTitle":"Item subnets.subnet4 {office} in use by:"}`,
	})
	if err := api.KeaReservations4().Remove(testReservationUuid); err != nil {
		t.Fatal(err)
	}
	if got := server.mutations()[0]; got.Method != "POST" || got.Raw != "" {
		t.Errorf("unexpected request %+v", got)
	}
	if err := api.KeaReservations4().Remove(testUnknownUuid); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	var err = api.KeaSubnets4().Remove(testSubnetUuid)
	if err == nil || err.Error() != "cannot remove kea dhcpv4 subnet "+testSubnetUuid+", it is in use by: dhcp4 - r1 {dhcp4.reservations.reservation."+testReservationUuid+"}" {
		t.Errorf("want the in use message, got %v", err)
	}
	server.reset()
	for _, uuid := range []string{"", "a,b", "a/b"} {
		if err := api.KeaSubnets4().Remove(uuid); err == nil {
			t.Errorf("%q: want an error", uuid)
		}
	}
	if len(server.recorded()) != 0 {
		t.Errorf("want no requests, got %+v", server.recorded())
	}
}

func TestCollectionSetEnabled(t *testing.T) {
	const relayUuid = "1a288696-da01-4942-ac1f-874b2c237d6f"
	var api, server = newTestApi(t, map[string]string{
		"POST /api/dhcrelay/settings/toggle_relay/" + relayUuid + "/1":       `{"result":"Enabled","changed":true}`,
		"POST /api/dhcrelay/settings/toggle_relay/" + relayUuid + "/0":       `{"result":"Disabled","changed":false}`,
		"POST /api/dhcrelay/settings/toggle_relay/" + testUnknownUuid + "/0": `{"result":"failed"}`,
	})
	if changed, err := api.Relays().SetEnabled(relayUuid, true); err != nil || !changed {
		t.Errorf("enable: %v / %v", changed, err)
	}
	if changed, err := api.Relays().SetEnabled(relayUuid, false); err != nil || changed {
		t.Errorf("disable: %v / %v", changed, err)
	}
	if _, err := api.Relays().SetEnabled(testUnknownUuid, false); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	server.reset()
	if _, err := api.KeaSubnets4().SetEnabled(testSubnetUuid, true); err == nil || len(server.recorded()) != 0 {
		t.Errorf("kea subnets have no enabled flag: %v", err)
	}
	if !api.Relays().CanToggle() || !api.RadvdEntries().CanToggle() || api.RelayDestinations().CanToggle() {
		t.Error("CanToggle")
	}
}

func TestCollectionDefaults(t *testing.T) {
	var api, _ = newTestApi(t, map[string]string{
		"GET /api/radvd/settings/get_entry": `{"entries":{"enabled":"1","interface":{"lan":{"value":"LAN","selected":0}},` +
			`"mode":{"router":{"value":"Router Only","selected":0},"stateless":{"value":"Stateless","selected":1}},"MinRtrAdvInterval":"200"}}`,
		"GET /api/radvd/settings/get_entry/" + testUnknownUuid: `[]`,
	})
	var defaults, err = api.RadvdEntries().Defaults()
	if err != nil || !reflect.DeepEqual(defaults, Fields{"enabled": "1", "interface": "", "mode": "stateless", "MinRtrAdvInterval": "200"}) {
		t.Errorf("defaults %v / %v", defaults, err)
	}
	if _, err := api.RadvdEntries().Form(testUnknownUuid); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
}

func TestKeaLeases(t *testing.T) {
	var api, server = newTestApi(t, map[string]string{
		"GET /api/kea/leases4/search": `{"total":2,"rowCount":2,"current":1,"rows":[` +
			`{"address":"192.168.1.100","prefix_len":128,"type":"","hwaddr":"02:00:5e:10:00:01","duid":"","client_id":"01:02","iaid":"",` +
			`"valid_lifetime":4000,"expire":1761400000,"hostname":"laptop","state":0,"if":"vtnet0","if_descr":"LAN","if_name":"lan",` +
			`"mac_info":"","lease_type":"dynamic","is_reserved":[]},` +
			`{"address":"192.168.1.101","prefix_len":128,"hwaddr":"","valid_lifetime":4000,"expire":0,"state":2,"if":null,"lease_type":"static","is_reserved":["hwaddr"]}],` +
			`"stats":{"active":1,"inactive":1,"total":2},"interfaces":{"lan":"LAN"}}`,
		"POST /api/kea/leases4/del_lease/192.168.1.100":       `{"status":"ok"}`,
		"POST /api/kea/leases6/del_lease/2001:db8::5":         `500 {"errorMessage":"Failed to delete lease(s): 2001:db8::5: kea-dhcp6 control socket path does not exist","errorTitle":""}`,
		"POST /api/kea/leases4/del_lease/192.168.1.1":         `{"status":"error","message":"Missing lease IP parameter"}`,
		"POST /api/kea/leases4/del_lease/192.0.2.1,192.0.2.2": `{"status":"ok"}`,
	})
	var leases, raws, err = api.KeaLeases(4, "")
	if err != nil || len(leases) != 2 || len(raws) != 2 {
		t.Fatalf("%+v / %v", leases, err)
	}
	if lease := leases[0]; lease.Hostname != "laptop" || lease.InterfaceName != "lan" || lease.StateText() != "active" || lease.ValidLifetime != "4000" {
		t.Errorf("lease %+v", lease)
	}
	if expire, ok := leases[0].ExpireTime(); !ok || expire.Unix() != 1761400000 {
		t.Errorf("expire %v %v", expire, ok)
	}
	if _, ok := leases[1].ExpireTime(); ok || leases[1].StateText() != "expired" || leases[1].Interface != "" {
		t.Errorf("lease %+v", leases[1])
	}

	if err := api.KeaLeaseRemove(4, "192.168.1.100"); err != nil {
		t.Fatal(err)
	}
	if got := server.mutations()[0]; got.Raw != "{}\n" {
		t.Errorf("del_lease must be POSTed with {}: %+v", got)
	}
	if err := api.KeaLeaseRemove(4, "192.0.2.1", "192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	if err := api.KeaLeaseRemove(6, "2001:db8::5"); err == nil || !strings.Contains(err.Error(), "control socket") {
		t.Errorf("want the OPNsense message, got %v", err)
	}
	if err := api.KeaLeaseRemove(4, "192.168.1.1"); err == nil || !strings.Contains(err.Error(), "Missing lease IP") {
		t.Errorf("want the OPNsense message, got %v", err)
	}
	server.reset()
	for _, call := range []struct {
		version int
		ips     []string
	}{{4, nil}, {4, []string{"2001:db8::1"}}, {6, []string{"192.0.2.1"}}, {4, []string{"x"}}, {5, []string{"192.0.2.1"}}} {
		if err := api.KeaLeaseRemove(call.version, call.ips...); err == nil {
			t.Errorf("%+v: want an error", call)
		}
	}
	if _, _, err := api.KeaLeases(5, ""); err == nil {
		t.Error("want an error for IP version 5")
	}
	if len(server.recorded()) != 0 {
		t.Errorf("want no requests, got %+v", server.recorded())
	}
}

func TestServices(t *testing.T) {
	var api, server = newTestApi(t, map[string]string{
		"GET /api/kea/service/status":            `{"status":"disabled","widget":{}}`,
		"POST /api/kea/service/start":            `{"response":"OK\n"}`,
		"POST /api/kea/service/stop":             `{"response":"Execute error"}`,
		"POST /api/kea/service/reconfigure":      `{"status":"ok"}`,
		"POST /api/radvd/service/reconfigure":    `{"status":"failed","status_msg":"Service \"radvd\" failed to start."}`,
		"POST /api/radvd/service/restart":        `{"response":[]}`,
		"POST /api/dhcrelay/service/reconfigure": `{"status":"ok"}`,
		"GET /api/radvd/service/status":          `{}`,
	})
	if status, err := api.ServiceStatus(KeaService); err != nil || status != "disabled" {
		t.Errorf("status %q / %v", status, err)
	}
	if _, err := api.ServiceStatus(RadvdService); err == nil {
		t.Error("want an error without status")
	}
	if err := api.ServiceStart(KeaService); err != nil {
		t.Error(err)
	}
	if err := api.ServiceStop(KeaService); err == nil || !strings.Contains(err.Error(), "Execute error") {
		t.Errorf("want the configd answer, got %v", err)
	}
	if err := api.ServiceRestart(RadvdService); err == nil {
		t.Error("want an error for an empty response")
	}
	if err := api.ServiceReconfigure(KeaService); err != nil {
		t.Error(err)
	}
	if err := api.ServiceReconfigure(RadvdService); err == nil || !strings.Contains(err.Error(), "failed to start") {
		t.Errorf("want the status message, got %v", err)
	}
	if err := api.RelayReconfigure(); err != nil {
		t.Error(err)
	}
	for _, request := range server.mutations() {
		if request.Method != "POST" {
			t.Errorf("actions must be POSTed: %+v", request)
		}
	}
}

func TestRelayAndRadvdRecords(t *testing.T) {
	var api, _ = newTestApi(t, map[string]string{
		"GET /api/dhcrelay/settings/search_relay": `{"rows":[{"uuid":"r1","enabled":"0","interface":"lan","%interface":"LAN",` +
			`"destination":"d1","%destination":"servers","agent_info":"1","carp_depend_on":"","status":"grey"}]}`,
		"GET /api/dhcrelay/settings/search_dest": `{"rows":[{"uuid":"d1","name":"servers","server":"198.51.100.67,198.51.100.68"}]}`,
		"GET /api/radvd/settings/search_entry": `{"rows":[{"uuid":"e1","enabled":"0","interface":"lan","mode":"managed","%mode":"Managed",` +
			`"RDNSS":"2001:db8::53","MinRtrAdvInterval":"200","AdvDefaultPreference":"medium"}]}`,
	})
	if relays, err := api.Relays().List(""); err != nil || len(relays) != 1 || relays[0].DestinationName != "servers" || relays[0].Status != "grey" {
		t.Errorf("relays %+v / %v", relays, err)
	}
	if destinations, err := api.RelayDestinations().List(""); err != nil || destinations[0].Server != "198.51.100.67,198.51.100.68" {
		t.Errorf("destinations %+v / %v", destinations, err)
	}
	if entries, err := api.RadvdEntries().List(""); err != nil || entries[0].Mode != "managed" || entries[0].RDNSS != "2001:db8::53" {
		t.Errorf("entries %+v / %v", entries, err)
	}
	if api.RadvdEntries().Container() != "entries" || api.RelayDestinations().Container() != "destination" || api.KeaPdPools().What() != "kea dhcpv6 pd pool" {
		t.Error("container names")
	}
}
