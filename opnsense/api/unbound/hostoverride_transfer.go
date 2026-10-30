package unbound

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"

	coreapi "opnsense-cli/opnsense/api"
)

// CSV export / import of the host overrides (api/unbound/settings/download_host_overrides,
// upload_host_overrides), the format of the GUI's "Export as csv" / "Import csv" of Unbound > Overrides; see
// coreapi.DownloadCsv and UploadCsv. OPNsense added them to stable/26.7 after 26.7.7 (2026-10-26, commit 9f1249b),
// releases up to 26.7.7 answer both with an empty 200 like any unknown method.
//
// The export has "@uuid" first, then every field of the model (enabled, hostname, domain, rr, mxprio, mx, ttl,
// server, txtdata, addptr, aliases, description) in the configured order. aliases lists the FQDNs of the host's
// aliases (comma separated); importing the column makes them the host's aliases, adding and removing alias
// records. The import matches existing entries by @uuid only: rows with an empty @uuid add entries, an @uuid that
// does not exist adds the entry with that uuid

// HostOverrideCsvUuidColumn is the key column of the host override CSV
const HostOverrideCsvUuidColumn = "@uuid"

// ErrHostOverrideCsvUnsupported is returned when OPNsense has no host override CSV endpoints
var ErrHostOverrideCsvUnsupported = errors.New("this OPNsense version has no CSV export/import of Unbound host overrides (added after 26.7.7)")

// hostOverrideCsvUuid is the uuid format the import accepts (importRecordSet of OPNsense)
var hostOverrideCsvUuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// HostOverrideExportCsv returns the host overrides as CSV, empty when there are none.
// Returns ErrHostOverrideCsvUnsupported when OPNsense answers empty although there are host overrides
func (opn *UnboundApi) HostOverrideExportCsv() ([]byte, error) {
	var content, err = opn.DownloadCsv(opn.settingsEndpoint("download_host_overrides"))
	if err != nil || len(content) > 0 {
		return content, err
	}
	unsupported, err := opn.hostOverrideCsvUnsupported()
	if err != nil {
		return nil, err
	}
	if unsupported {
		return nil, ErrHostOverrideCsvUnsupported
	}
	return nil, nil
}

// hostOverrideCsvUnsupported tells whether an empty export comes from an OPNsense without the endpoint (an unknown
// method answers empty too): it does when there are host overrides. Without any it can't tell and answers false
func (opn *UnboundApi) hostOverrideCsvUnsupported() (bool, error) {
	var overrides, err = opn.HostOverrideList()
	if err != nil {
		return false, err
	}
	return len(overrides) > 0, nil
}

// HostOverrideImportCsv uploads a CSV of host overrides: rows with the @uuid of an entry update it, the others add
// entries. The content is checked with HostOverrideCheckCsv first, nothing is sent when that fails. When the upload
// fails on an OPNsense without the endpoint, the error is ErrHostOverrideCsvUnsupported
func (opn *UnboundApi) HostOverrideImportCsv(content []byte, filename string) (coreapi.CsvImportResult, error) {
	var parsed, err = coreapi.ParseCsv(content, "host overrides")
	if err != nil {
		return coreapi.CsvImportResult{}, err
	}
	if err := HostOverrideCheckCsv(parsed); err != nil {
		return coreapi.CsvImportResult{}, err
	}
	result, err := opn.UploadCsv(opn.settingsEndpoint("upload_host_overrides"), content, filename)
	if err != nil {
		// the endpoint is missing when the export is empty although there are host overrides
		var export, exportErr = opn.DownloadCsv(opn.settingsEndpoint("download_host_overrides"))
		if exportErr == nil && len(export) == 0 {
			if unsupported, _ := opn.hostOverrideCsvUnsupported(); unsupported {
				return result, ErrHostOverrideCsvUnsupported
			}
		}
	}
	return result, err
}

// HostOverrideCheckCsv checks the @uuid column like OPNsense (empty or a lower case v4 uuid) and that no @uuid is
// given twice. Errors name the line
func HostOverrideCheckCsv(parsed coreapi.Csv) error {
	var uuids, _ = parsed.Column(HostOverrideCsvUuidColumn)
	var seen = map[string]int{}
	for i, uuid := range uuids {
		if uuid == "" {
			continue
		}
		if !hostOverrideCsvUuid.MatchString(uuid) {
			return fmt.Errorf("line %d: invalid @uuid %q, must be a lower case v4 uuid or empty to add an entry", i+2, uuid)
		}
		if first, twice := seen[uuid]; twice {
			return fmt.Errorf("line %d: the @uuid %s is on line %d already", i+2, uuid, first+2)
		}
		seen[uuid] = i
	}
	return nil
}

// HostOverrideCsvColumns returns the columns the import understands, sorted: @uuid and the host override fields
// (from get_host_override)
func (opn *UnboundApi) HostOverrideCsvColumns() ([]string, error) {
	var answer struct {
		Host map[string]json.RawMessage `json:"host"`
	}
	if err := opn.DoJSON("GET", opn.settingsEndpoint("get_host_override"), nil, &answer); err != nil {
		return nil, err
	}
	if len(answer.Host) == 0 {
		return nil, errors.New("get_host_override returned no host override fields")
	}
	var columns = []string{HostOverrideCsvUuidColumn}
	for field := range answer.Host {
		columns = append(columns, field)
	}
	sort.Strings(columns)
	return columns, nil
}
