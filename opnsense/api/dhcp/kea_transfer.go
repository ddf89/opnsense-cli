package dhcp

import (
	"fmt"

	coreapi "opnsense-cli/opnsense/api"
)

// The Kea reservations as CSV (Services > Kea DHCP > Kea DHCPv4/v6 > Reservations, "Export as csv" / "Import csv",
// kea/dhcpv4|dhcpv6 download_reservations / upload_reservations).
//
// The export has every reservation field but the subnet, see KeaReservationCsvColumns. option holds the uuids of
// custom options. The per-reservation DHCPv4 options (routers, DNS servers, ...) are one option_data.<option>
// column each from 26.7.2 on, exported and imported (nested ArrayField records); 26.7 and 26.7.1 have a single,
// always empty option_data column instead and ignore option_data.* columns.
//
// The import puts a row with an ip_address into the subnet containing that address (the last one when several
// do). A row without an address keeps the value of a subnet column (the subnet's uuid), else it has no subnet and
// is rejected ("subnet: A value is required.", for v4 also "ip_address: Address not in specified subnet"), so v6
// reservations of only a prefix need the subnet column. Rows are matched to existing reservations by subnet and
// hw_address (v4) / duid (v6); a row with an empty MAC address / DUID updates the reservation of its subnet without
// one if there is exactly one, else it adds a reservation (which fails as a duplicate when its client id, MAC or
// address is taken)

// KeaReservationCsvColumns returns the columns the reservation import of the DHCPv4 (4) or DHCPv6 (6) server
// understands: those of the export (26.7 and 26.7.2+) and subnet
func KeaReservationCsvColumns(version int) []string {
	if version == 6 {
		return []string{"ip_address", "prefix", "duid", "hw_address", "hostname", "domain_search", "option", "description", "subnet"}
	}
	var columns = []string{"ip_address", "hw_address", "client_id", "hostname", "description", "next_server", "option_data"}
	for _, option := range KeaReservationOptionColumns {
		columns = append(columns, "option_data."+option)
	}
	return append(columns, "option", "subnet")
}

// KeaReservationOptionColumns are the per-reservation DHCPv4 options of the export from 26.7.2 on (option_data.<name>)
var KeaReservationOptionColumns = []string{"domain_name_servers", "domain_search", "routers", "static_routes",
	"classless_static_route", "domain_name", "ntp_servers", "time_servers", "tftp_server_name", "boot_file_name"}

func keaReservationController(version int) (string, error) {
	switch version {
	case 4:
		return "dhcpv4", nil
	case 6:
		return "dhcpv6", nil
	}
	return "", fmt.Errorf("kea reservations: unknown IP version %d", version)
}

// KeaReservationsDownload returns the reservations of the DHCPv4 (4) or DHCPv6 (6) server as CSV (';' separated,
// with a header row), empty when there are none
func (opn *DhcpApi) KeaReservationsDownload(version int) ([]byte, error) {
	var controller, err = keaReservationController(version)
	if err != nil {
		return nil, err
	}
	return opn.DownloadCsv(opn.EndpointForPluginControllerMethod("kea", controller, "download_reservations"))
}

// KeaReservationsUpload imports reservations of the DHCPv4 (4) or DHCPv6 (6) server from CSV (see above). They
// are only saved, the reconfigure of KeaService applies them. filename is informative
func (opn *DhcpApi) KeaReservationsUpload(version int, content []byte, filename string) (coreapi.CsvImportResult, error) {
	var controller, err = keaReservationController(version)
	if err != nil {
		return coreapi.CsvImportResult{}, err
	}
	return opn.UploadCsv(opn.EndpointForPluginControllerMethod("kea", controller, "upload_reservations"), content, filename)
}
