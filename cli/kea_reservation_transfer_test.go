package cli

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// keaTransferExport4 is a download_reservations answer of 26.7
const keaTransferExport4 = "ip_address;hw_address;client_id;hostname;description;next_server;option_data;option\n" +
	"198.51.100.50;02:00:5e:10:00:01;;printer;\"office printer\";;;\n"

// keaTransferFake is keaFake with a DHCPv4 export
func keaTransferFake(t *testing.T, export string) *fakeOPN {
	t.Helper()
	var f = keaFake(t)
	f.onFunc("GET", "/api/kea/dhcpv4/download_reservations", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/csv;charset=UTF-8")
		_, _ = io.WriteString(w, export)
	})
	return f
}

// keaTransferFile writes content to a file in dir and returns its path
func keaTransferFile(t *testing.T, dir string, name string, content string) string {
	t.Helper()
	var path = filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestKeaReservationExport(t *testing.T) {
	t.Parallel()
	var dir = t.TempDir()
	var file = filepath.Join(dir, "reservations.csv")
	var f = keaTransferFake(t, keaTransferExport4)

	var r = f.run("/kea/dhcp4/reservation", "export", file)
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "saved 1 reservations to "+file)
	if content, err := os.ReadFile(file); err != nil || string(content) != keaTransferExport4 {
		t.Errorf("file: %q, %v", content, err)
	}
	r = f.run("/kea/dhcp4/reservation", "export", "-")
	wantExit(t, r, 0)
	if r.stdout != keaTransferExport4 {
		t.Errorf("stdout: %q", r.stdout)
	}
	wantNoMutations(t, f)

	var empty = newFakeOPN(t)
	empty.onFunc("GET", "/api/kea/dhcpv6/download_reservations", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/csv;charset=UTF-8")
	})
	r = empty.run("/kea/dhcp6/reservation", "export", filepath.Join(dir, "none.csv"))
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "there are no reservations, nothing exported")

	var help = f.run("/kea/dhcp4/reservation", "export", "?")
	wantContains(t, "help", help.stdout, "every field but the subnet (no secrets)", "option_data.<option> columns")
}

func TestKeaReservationImport(t *testing.T) {
	t.Parallel()
	var dir = t.TempDir()
	var good = keaTransferFile(t, dir, "good.csv", "ip_address;hw_address;hostname;description\n"+
		"198.51.100.50;02:00:5e:10:00:01;printer;changed\n203.0.113.7;02:00:5e:10:00:02;lab-pc;\n")

	t.Run("confirmation and checks before sending", func(t *testing.T) {
		t.Parallel()
		var f = keaFake(t)
		wantFailure(t, f.run("/kea/dhcp4/reservation", "import", good),
			"This adds reservations and overwrites those matching by subnet and MAC address", "confirm=yes")
		wantFailure(t, f.run("/kea/dhcp4/reservation", "import", keaTransferFile(t, dir, "unknown.csv", "ip_address;mac\n198.51.100.9;x\n"), "confirm=yes"),
			"unknown columns mac, valid are: ip_address, hw_address, client_id, hostname, description, next_server, option_data, "+
				"option_data.domain_name_servers, option_data.domain_search, option_data.routers, option_data.static_routes, "+
				"option_data.classless_static_route, option_data.domain_name, option_data.ntp_servers, option_data.time_servers, "+
				"option_data.tftp_server_name, option_data.boot_file_name, option, subnet")
		wantFailure(t, f.run("/kea/dhcp6/reservation", "import", keaTransferFile(t, dir, "unknown6.csv", "ip_address;client_id\n2001:db8::9;01:02\n"), "confirm=yes"),
			"unknown columns client_id, valid are: ip_address, prefix, duid, hw_address, hostname, domain_search, option, description, subnet")
		var r = f.run("/kea/dhcp4/reservation", "import", keaTransferFile(t, dir, "subnets.csv", "ip_address;hw_address\n"+
			"198.51.100.9;02:00:5e:10:00:09\n192.0.2.5;02:00:5e:10:00:0a\n;02:00:5e:10:00:0b\n2001:db8::1;02:00:5e:10:00:0c\nnot-an-ip;02:00:5e:10:00:0d\n"), "confirm=yes")
		wantFailure(t, r, "subnets.csv: the subnet of these rows is not found, nothing was imported",
			"line 3: no DHCPv4 subnet contains 192.0.2.5",
			"line 4: there is no ip_address to find the subnet by, add a subnet column",
			`line 5: ip_address "2001:db8::1" is not an IPv4 address`,
			`line 6: ip_address "not-an-ip" is not an IPv4 address`)
		if strings.Contains(r.stderr, "line 2") {
			t.Errorf("line 2 is in a subnet: %s", r.stderr)
		}
		r = f.run("/kea/dhcp4/reservation", "import", keaTransferFile(t, dir, "named.csv", "subnet;ip_address;hw_address\n"+
			"nowhere;198.51.100.9;02:00:5e:10:00:09\nlab;198.51.100.10;02:00:5e:10:00:0a\n;;02:00:5e:10:00:0b\n"), "confirm=yes")
		wantFailure(t, r, `line 2: not found: subnet "nowhere", valid are: "198.51.100.0/24", "203.0.113.0/24"`,
			"line 3: 198.51.100.10 is not in the subnet lab", "line 4: there is no ip_address to find the subnet by, give its subnet")
		wantNoMutations(t, f)
	})
	t.Run("import", func(t *testing.T) {
		t.Parallel()
		var f = keaFake(t)
		f.on("POST", "/api/kea/dhcpv4/upload_reservations", 200,
			`{"validations":[],"inserted":1,"updated":1,"uuids":{"u1":0,"u2":1},"fieldnames":["ip_address","hw_address","hostname","description"]}`)
		var r = f.run("/kea/dhcp4/reservation", "import", good, "confirm=yes")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "imported "+good+": 1 reservations added, 1 updated")
		var content, _ = os.ReadFile(good)
		wantJSON(t, wantOneMutation(t, f, "POST", "/api/kea/dhcpv4/upload_reservations"), map[string]any{"payload": string(content), "filename": "good.csv"})
	})
	t.Run("subnet column sent as uuids", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.search("/api/kea/dhcpv6/search_subnet", map[string]any{"uuid": keaSubnetUuid, "subnet": "2001:db8:a5::/64", "interface": "lan", "description": "office"},
			map[string]any{"uuid": keaSubnet2Uuid, "subnet": "2001:db8:a6::/64", "interface": "lan", "description": "lab"})
		f.on("POST", "/api/kea/dhcpv6/upload_reservations", 200, `{"validations":[],"inserted":2,"updated":0,"uuids":{"u1":0,"u2":1}}`)
		var file = keaTransferFile(t, dir, "prefix.csv", "subnet,prefix,hw_address,description\n"+
			"2001:db8:a5::/64,2001:db8:a5:0:100::/80,02:00:5e:10:00:01,\"pd, office\"\nLAB,2001:db8:a6:0:100::/80,02:00:5e:10:00:02,lab\n")
		wantExit(t, f.run("/kea/dhcp6/reservation", "import", file, "confirm=yes"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", "/api/kea/dhcpv6/upload_reservations"), map[string]any{"filename": "prefix.csv",
			"payload": "subnet,prefix,hw_address,description\n" + keaSubnetUuid + ",2001:db8:a5:0:100::/80,02:00:5e:10:00:01,\"pd, office\"\n" +
				keaSubnet2Uuid + ",2001:db8:a6:0:100::/80,02:00:5e:10:00:02,lab\n"})
	})
	t.Run("rejected rows", func(t *testing.T) {
		t.Parallel()
		var f = keaFake(t)
		f.on("POST", "/api/kea/dhcpv4/upload_reservations", 200, `{"validations":[{"sequence":1,"message":"Duplicate entry exists.","field":"ip_address"}],`+
			`"inserted":1,"updated":1,"uuids":{"u1":0,"u2":1}}`)
		wantFailure(t, f.run("/kea/dhcp4/reservation", "import", good, "confirm=yes"),
			"OPNsense rejected rows of "+good, "line 3: ip_address: Duplicate entry exists.", "check the reservations")
	})
}
