package dnsmasq

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	coreapi "opnsense-cli/opnsense/api"
)

// CSV export / import of the hosts (api/dnsmasq/settings/download_hosts, upload_hosts), the format of the GUI's
// "Export as csv" / "Import csv" of Dnsmasq > Hosts; see coreapi.DownloadCsv and UploadCsv.
//
// The export lists the hosts in the configured order with all fields except comments; four columns carry the
// names of Kea / ISC DHCP exports: hostname (host), ip_address (ip), hw_address (hwaddr) and description (descr).
// The import accepts both names (the export name wins when a row has both) and matches existing hosts by host,
// domain and ip, compared as exact strings (case and the order of the addresses count). List fields (ip, cnames,
// hwaddr, aliases) are comma separated, set_tag holds the uuid of the tag

// HostCsvRenames maps the CSV column names of the export to the host fields they stand for
var HostCsvRenames = map[string]string{
	"hostname":    "host",
	"ip_address":  "ip",
	"hw_address":  "hwaddr",
	"description": "descr",
}

// HostExportCsv returns the hosts as CSV (download_hosts), empty when there are none
func (opn *DnsmasqApi) HostExportCsv() ([]byte, error) {
	return opn.DownloadCsv(opn.settingsEndpoint("download_hosts"))
}

// HostImportCsv uploads a CSV of hosts (upload_hosts): rows matching a host by host, domain and ip update it,
// the others add hosts. The content is checked with HostCheckCsv first, nothing is sent when that fails
func (opn *DnsmasqApi) HostImportCsv(content []byte, filename string) (coreapi.CsvImportResult, error) {
	var parsed, err = coreapi.ParseCsv(content, "hosts")
	if err != nil {
		return coreapi.CsvImportResult{}, err
	}
	if err := HostCheckCsv(parsed); err != nil {
		return coreapi.CsvImportResult{}, err
	}
	return opn.UploadCsv(opn.settingsEndpoint("upload_hosts"), content, filename)
}

// HostCheckCsv refuses a file giving a field under both names (e.g. ip and ip_address): OPNsense would silently
// take the export name
func HostCheckCsv(parsed coreapi.Csv) error {
	var names = map[string]bool{}
	for _, name := range parsed.Header {
		names[name] = true
	}
	var exportNames = make([]string, 0, len(HostCsvRenames))
	for exportName := range HostCsvRenames {
		exportNames = append(exportNames, exportName)
	}
	sort.Strings(exportNames)
	for _, exportName := range exportNames {
		if field := HostCsvRenames[exportName]; names[exportName] && names[field] {
			return fmt.Errorf("line 1: the columns %s and %s are the same field, keep one of them", exportName, field)
		}
	}
	return nil
}

// HostCsvColumns returns the columns the import understands, sorted: the host fields (from get_host, comments
// included), the renamed ones under both names (host and hostname, ip and ip_address, ...)
func (opn *DnsmasqApi) HostCsvColumns() ([]string, error) {
	var answer struct {
		Host map[string]json.RawMessage `json:"host"`
	}
	if err := opn.DoJSON("GET", opn.settingsEndpoint("get_host"), nil, &answer); err != nil {
		return nil, err
	}
	if len(answer.Host) == 0 {
		return nil, errors.New("get_host returned no host fields")
	}
	var exportNames = map[string]string{}
	for exportName, field := range HostCsvRenames {
		exportNames[field] = exportName
	}
	var columns = make([]string, 0, len(answer.Host)+len(HostCsvRenames))
	for field := range answer.Host {
		columns = append(columns, field)
		if exportName, renamed := exportNames[field]; renamed {
			columns = append(columns, exportName)
		}
	}
	sort.Strings(columns)
	return columns, nil
}
