package dnsmasq

import (
	"testing"
	"time"
)

// leaseTestSearchAnswer is shaped like the 26.x leases/search answer (rows enriched by LeasesController)
const leaseTestSearchAnswer = `{"total":2,"rowCount":2,"current":1,"rows":[
{"expire":1761350400,"hwaddr":"aa:bb:cc:dd:ee:ff","iaid":"","address":"192.168.1.10","hostname":"laptop","client_id":"01:aa:bb:cc:dd:ee:ff","if":"igc1","if_descr":"LAN","if_name":"lan","mac_info":"Vendor","is_reserved":["hwaddr"],"lease_type":"static","sort_address":"04.192.168.001.010"},
{"expire":0,"hwaddr":"","iaid":"12345","address":"fd00::10","hostname":"*","client_id":"*","is_reserved":[],"lease_type":"dynamic"}
],"interfaces":{"lan":"LAN"}}`

func TestLeaseList(t *testing.T) {
	var api, method = serviceTestApi(t, "/api/dnsmasq/leases/search", 200, leaseTestSearchAnswer)

	var leases, err = api.LeaseList("")
	if err != nil {
		t.Fatal(err)
	}
	if *method != "GET" {
		t.Errorf("method = %s, want GET", *method)
	}
	if len(leases) != 2 {
		t.Fatalf("got %d leases, want 2", len(leases))
	}

	var first = leases[0]
	if first.Address != "192.168.1.10" || first.Hwaddr != "aa:bb:cc:dd:ee:ff" || first.Hostname != "laptop" ||
		first.Interface != "igc1" || first.InterfaceDescr != "LAN" || first.InterfaceName != "lan" || first.LeaseType != "static" {
		t.Errorf("unexpected first lease %+v", first)
	}
	var expire, ok = first.ExpireTime()
	if !ok || !expire.Equal(time.Unix(1761350400, 0)) {
		t.Errorf("ExpireTime() = %v, %v", expire, ok)
	}

	if _, ok := leases[1].ExpireTime(); ok {
		t.Errorf("lease with expire 0 should have no expiry")
	}
	if leases[1].Iaid != "12345" {
		t.Errorf("iaid = %q", leases[1].Iaid)
	}
}

func TestLeaseListEmpty(t *testing.T) {
	var api, _ = serviceTestApi(t, "/api/dnsmasq/leases/search", 200, `{"total":0,"rowCount":0,"current":1,"rows":[],"interfaces":[]}`)

	var leases, err = api.LeaseList("")
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 0 {
		t.Errorf("got %d leases, want 0", len(leases))
	}
}

func TestLeaseExpireAsString(t *testing.T) {
	var api, _ = serviceTestApi(t, "/api/dnsmasq/leases/search", 200, `{"rows":[{"address":"10.0.0.1","expire":"1761350400"}]}`)

	var leases, err = api.LeaseList("")
	if err != nil {
		t.Fatal(err)
	}
	if expire, ok := leases[0].ExpireTime(); !ok || expire.Unix() != 1761350400 {
		t.Errorf("ExpireTime() = %v, %v", expire, ok)
	}
}
