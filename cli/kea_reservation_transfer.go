package cli

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/netip"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dhcp"
)

// export / import of /kea/dhcp4/reservation and /kea/dhcp6/reservation: the CSV of the GUI (kea/dhcpv4|dhcpv6
// download_reservations / upload_reservations). OPNsense leaves the subnet out of the export and finds it by the
// address on import, so the import checks first that every row has a subnet: the one containing its ip_address or
// one named in a subnet column (network, description or uuid, sent as the uuid OPNsense expects)

// keaReservationTransfer returns the CSV transfer of the DHCPv4 (4) or DHCPv6 (6) reservations; subnets are the
// subnets of that server
func keaReservationTransfer(version int, subnets *keaRefSpec) CsvTransfer {
	var key, keyless = "subnet and MAC address", "A row without MAC address (a reservation by client id)"
	var export = `The export has every field but the subnet (no secrets); option holds the uuids of custom options. The
reservation's own DHCP options (routers, dns-servers, ... of set) are neither exported nor imported, the
option_data column stays empty.`
	if version == 6 {
		key, keyless = "subnet and DUID", "A row without DUID (a reservation by MAC address)"
		export = `The export has every field but the subnet (no secrets); option holds the uuids of custom options.`
	}
	return CsvTransfer{
		What: "reservations",
		Key:  key,
		Note: export + `
The import puts a reservation into the subnet containing its ip_address, rows without one need a subnet
column (the subnet's network, description or uuid). A row whose subnet is not found refuses the whole file
before anything is sent. ` + keyless + ` updates the only such
reservation of its subnet; when the subnet has several, it is added and rejected as a duplicate.
` + keaApplyHint,
		Export: func(c *Context) ([]byte, error) {
			var dhcpApi, err = keaApi(c)
			if err != nil {
				return nil, err
			}
			return dhcpApi.KeaReservationsDownload(version)
		},
		Import: func(c *Context, content []byte, filename string) (coreapi.CsvImportResult, error) {
			var rows, err = subnets.rows(c)
			if err != nil {
				return coreapi.CsvImportResult{}, err
			}
			content, err = keaReservationSubnets(content, version, rows, subnets)
			if err != nil {
				return coreapi.CsvImportResult{}, fmt.Errorf("%s: %w", filename, err)
			}
			dhcpApi, err := keaApi(c)
			if err != nil {
				return coreapi.CsvImportResult{}, err
			}
			return dhcpApi.KeaReservationsUpload(version, content, filename)
		},
		Columns: func(*Context) ([]string, error) { return dhcp.KeaReservationCsvColumns(version), nil },
	}
}

// keaReservationSubnets checks that every row of an import has a subnet (see above) and returns the content to
// send: unchanged, or with the subnet column given as uuids
func keaReservationSubnets(content []byte, version int, rows []dhcp.Row, subnets *keaRefSpec) ([]byte, error) {
	var parsed, err = coreapi.ParseCsv(content, "reservations")
	if err != nil {
		return nil, err
	}
	var addresses, _ = parsed.Column("ip_address")
	var named, hasSubnet = parsed.Column("subnet")
	var subnetIndex = -1
	for i, name := range parsed.Header {
		if name == "subnet" {
			subnetIndex = i
		}
	}
	var problems []string
	var rewrite = false
	for i := range parsed.Rows {
		var line = fmt.Sprintf("line %d: ", i+2)
		var address = strings.TrimSpace(addresses[i])
		var uuid = ""
		if strings.TrimSpace(named[i]) != "" {
			var resolveErr error
			if uuid, resolveErr = keaResolveRef(rows, subnets, "subnet", named[i]); resolveErr != nil {
				problems = append(problems, line+resolveErr.Error())
				continue
			}
			if uuid != named[i] {
				parsed.Rows[i][subnetIndex] = uuid
				rewrite = true
			}
		}
		switch {
		case address != "":
			var addr, parseErr = netip.ParseAddr(address)
			if parseErr != nil || addr.Is4() != (version == 4) {
				problems = append(problems, fmt.Sprintf("%sip_address %q is not an IPv%d address", line, address, version))
				continue
			}
			var containing = ""
			for _, row := range rows {
				if keaNetworkContains(row["subnet"], address) {
					containing = row.Uuid()
				}
			}
			if containing == "" {
				problems = append(problems, fmt.Sprintf("%sno DHCPv%d subnet contains %s", line, version, address))
			} else if uuid != "" && uuid != containing {
				problems = append(problems, fmt.Sprintf("%s%s is not in the subnet %s", line, address, named[i]))
			}
		case uuid == "":
			var hint = "add a subnet column (the subnet's network, description or uuid)"
			if hasSubnet {
				hint = "give its subnet"
			}
			problems = append(problems, fmt.Sprintf("%sthere is no ip_address to find the subnet by, %s", line, hint))
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("the subnet of these rows is not found, nothing was imported:\n  %s", strings.Join(problems, "\n  "))
	}
	if !rewrite {
		return content, nil
	}
	var buffer bytes.Buffer
	var writer = csv.NewWriter(&buffer)
	writer.Comma = parsed.Separator
	if err := writer.WriteAll(append([][]string{parsed.Header}, parsed.Rows...)); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
