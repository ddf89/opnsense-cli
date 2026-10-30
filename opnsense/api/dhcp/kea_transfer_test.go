package dhcp

import (
	"slices"
	"testing"
)

func TestKeaReservationsCsv(t *testing.T) {
	const export = "ip_address;prefix;duid;hw_address;hostname;domain_search;option;description\n" +
		"2001:db8:a5::10;;00:01:00:01:aa:bb:cc:01;;host-a;;;\"a\"\n"
	var api, server = newTestApi(t, map[string]string{
		"GET /api/kea/dhcpv6/download_reservations": "csv:" + export,
		"GET /api/kea/dhcpv4/download_reservations": `{"status":"failed"}`,
		"POST /api/kea/dhcpv4/upload_reservations": `{"validations":[{"sequence":1,"message":"A value is required.","field":"subnet"}],` +
			`"inserted":2,"updated":1,"uuids":{"u1":0,"u2":1,"u3":2},"fieldnames":["ip_address","hw_address"]}`,
	})

	var content, err = api.KeaReservationsDownload(6)
	if err != nil || string(content) != export {
		t.Errorf("download: %q, %v", content, err)
	}
	if _, err := api.KeaReservationsDownload(4); err == nil {
		t.Error("a JSON answer to a download must fail")
	}
	if _, err := api.KeaReservationsDownload(5); err == nil {
		t.Error("version 5 must fail")
	}

	server.reset()
	var result, uploadErr = api.KeaReservationsUpload(4, []byte("ip_address;hw_address\n198.51.100.5;02:00:5e:10:00:01\n"), "r.csv")
	if uploadErr != nil || result.Inserted != 2 || result.Updated != 1 || len(result.Uuids) != 3 || len(result.Validations) != 1 ||
		result.Validations[0].Row != 1 || result.Validations[0].Field != "subnet" {
		t.Errorf("upload: %+v, %v", result, uploadErr)
	}
	var mutations = server.mutations()
	if len(mutations) != 1 || mutations[0].Path != "/api/kea/dhcpv4/upload_reservations" {
		t.Fatalf("mutations %+v", mutations)
	}
	wantBody(t, mutations[0], `{"payload":"ip_address;hw_address\n198.51.100.5;02:00:5e:10:00:01\n","filename":"r.csv"}`)
	if _, err := api.KeaReservationsUpload(0, nil, ""); err == nil {
		t.Error("version 0 must fail")
	}

	for version, column := range map[int]string{4: "client_id", 6: "duid"} {
		if columns := KeaReservationCsvColumns(version); !slices.Contains(columns, column) || !slices.Contains(columns, "subnet") {
			t.Errorf("columns of v%d: %v", version, columns)
		}
	}
}
