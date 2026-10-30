package firewall

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// CSV export / import of shaper pipes and queues (api/trafficshaper/settings/download_pipes, upload_pipes,
// download_queues, upload_queues), the format of the GUI's "Export as csv" / "Import csv" buttons. There is no CSV
// endpoint for shaper rules.
//
// The export has all fields, "@uuid" first; a queue names its pipe by uuid. The import is an upsert keyed by
// "@uuid": a row whose @uuid is an existing record overwrites the fields given in the file, every other row is
// added (with the given @uuid when it is a valid v4 uuid, so a pipe keeps its uuid on another firewall and the
// queues referring to it can be imported after it). The import does not number new records like add_pipe and
// add_queue do: without a number OPNsense rejects the row, and it accepts a number used by another pipe (queue),
// which breaks the shaper when applied. ShaperPipeImport and ShaperQueueImport therefore number new rows without
// a number (the lowest free number from 10000 on, like the GUI), keep the number of existing records when the cell
// is empty and refuse numbers used twice, before anything is sent. ShaperQueueImport also accepts the description
// of a pipe instead of its uuid and refuses unknown pipes.

// ShaperPipeCsvColumns are the columns of the pipe export, the ones the import understands
var ShaperPipeCsvColumns = []string{
	"@uuid", "number", "enabled", "bandwidth", "bandwidthMetric", "queue", "mask", "buckets", "scheduler", "codel_enable",
	"codel_target", "codel_interval", "codel_ecn_enable", "pie_enable", "fqcodel_quantum", "fqcodel_limit",
	"fqcodel_flows", "origin", "delay", "description",
}

// ShaperQueueCsvColumns are the columns of the queue export, the ones the import understands
var ShaperQueueCsvColumns = []string{
	"@uuid", "number", "enabled", "pipe", "weight", "mask", "buckets", "codel_enable", "codel_target", "codel_interval",
	"codel_ecn_enable", "pie_enable", "description", "origin",
}

// shaperFirstNumber is the first number OPNsense gives pipes and queues, the ones below are for internal use
const shaperFirstNumber = 10000

// ShaperPipeExport returns the pipes as CSV, empty when there are no pipes
func (opn *FirewallApi) ShaperPipeExport() ([]byte, error) {
	return opn.DownloadCsv(opn.shaperSettingsEndpoint("download_pipes"))
}

// ShaperQueueExport returns the queues as CSV, empty when there are no queues
func (opn *FirewallApi) ShaperQueueExport() ([]byte, error) {
	return opn.DownloadCsv(opn.shaperSettingsEndpoint("download_queues"))
}

// ShaperPipeImport imports pipes from a CSV file (see above for the numbering). Errors found before sending
// name the line of the file; filename is only informative
func (opn *FirewallApi) ShaperPipeImport(content []byte, filename string) (coreapi.CsvImportResult, error) {
	var parsed, err = coreapi.ParseCsv(content, "pipes")
	if err != nil {
		return coreapi.CsvImportResult{}, err
	}
	pipes, err := opn.ShaperPipeList("")
	if err != nil {
		return coreapi.CsvImportResult{}, err
	}
	var existing = make([]shaperNumbered, len(pipes))
	for i, pipe := range pipes {
		existing[i] = shaperNumbered{uuid: pipe.Uuid, number: pipe.Number, description: pipe.Description}
	}
	changed, err := shaperPrepareImport(&parsed, "pipe", existing)
	if err != nil {
		return coreapi.CsvImportResult{}, err
	}
	if changed {
		if content, err = shaperEncodeCsv(parsed); err != nil {
			return coreapi.CsvImportResult{}, err
		}
	}
	return opn.UploadCsv(opn.shaperSettingsEndpoint("upload_pipes"), content, filename)
}

// ShaperQueueImport imports queues from a CSV file (see above for the numbering). The pipe column takes the uuid
// or the description of an existing pipe (sent as its uuid). Errors found before sending name the line of the
// file; filename is only informative
func (opn *FirewallApi) ShaperQueueImport(content []byte, filename string) (coreapi.CsvImportResult, error) {
	var parsed, err = coreapi.ParseCsv(content, "queues")
	if err != nil {
		return coreapi.CsvImportResult{}, err
	}
	queues, err := opn.ShaperQueueList("")
	if err != nil {
		return coreapi.CsvImportResult{}, err
	}
	var existing = make([]shaperNumbered, len(queues))
	for i, queue := range queues {
		existing[i] = shaperNumbered{uuid: queue.Uuid, number: queue.Number, description: queue.Description}
	}
	changed, err := shaperPrepareImport(&parsed, "queue", existing)
	if err != nil {
		return coreapi.CsvImportResult{}, err
	}
	if column := shaperColumn(parsed, "pipe"); column >= 0 {
		pipes, err := opn.ShaperPipeList("")
		if err != nil {
			return coreapi.CsvImportResult{}, err
		}
		resolved, err := shaperResolvePipes(&parsed, column, pipes)
		if err != nil {
			return coreapi.CsvImportResult{}, err
		}
		changed = changed || resolved
	}
	if changed {
		if content, err = shaperEncodeCsv(parsed); err != nil {
			return coreapi.CsvImportResult{}, err
		}
	}
	return opn.UploadCsv(opn.shaperSettingsEndpoint("upload_queues"), content, filename)
}

// shaperNumbered is an existing pipe or queue
type shaperNumbered struct {
	uuid        string
	number      string
	description string
}

func shaperColumn(parsed coreapi.Csv, name string) int {
	for i, column := range parsed.Header {
		if column == name {
			return i
		}
	}
	return -1
}

// shaperNumberKey normalizes a number for comparisons ("010000" is 10000), other text stays as it is
func shaperNumberKey(number string) string {
	number = strings.TrimSpace(number)
	if value, err := strconv.Atoi(number); err == nil {
		return strconv.Itoa(value)
	}
	return number
}

// shaperPrepareImport checks the @uuid column and the numbers of an import of pipes or queues (what) and fills in
// missing numbers: the current one for rows updating an existing record, the lowest free one from 10000 on for new
// rows. It adds a number column when new rows need one. Returns whether parsed was changed
func shaperPrepareImport(parsed *coreapi.Csv, what string, existing []shaperNumbered) (bool, error) {
	var byUuid = map[string]shaperNumbered{}
	for _, record := range existing {
		byUuid[record.uuid] = record
	}

	// the existing record every row updates (by @uuid, like OPNsense: exact match)
	var targets = make([]*shaperNumbered, len(parsed.Rows))
	var rowOfUuid = map[string]int{}
	if uuidColumn := shaperColumn(*parsed, "@uuid"); uuidColumn >= 0 {
		for i, row := range parsed.Rows {
			var uuid = row[uuidColumn]
			if uuid == "" {
				continue
			}
			if !filterRulesUuidPattern.MatchString(uuid) {
				return false, fmt.Errorf("line %d: invalid @uuid %q (a lower case version 4 uuid, or empty for a new %s)", i+2, uuid, what)
			}
			if first, seen := rowOfUuid[uuid]; seen {
				return false, fmt.Errorf("line %d: the @uuid %s is given twice (line %d)", i+2, uuid, first+2)
			}
			rowOfUuid[uuid] = i
			if record, found := byUuid[uuid]; found {
				targets[i] = &record
			}
		}
	}

	var changed = false
	var numberColumn = shaperColumn(*parsed, "number")
	var needsNumber = false
	for i := range parsed.Rows {
		if targets[i] == nil && (numberColumn < 0 || strings.TrimSpace(parsed.Rows[i][numberColumn]) == "") {
			needsNumber = true
		}
	}
	if numberColumn < 0 && needsNumber {
		parsed.Header = append(parsed.Header, "number")
		numberColumn = len(parsed.Header) - 1
		for i := range parsed.Rows {
			parsed.Rows[i] = append(parsed.Rows[i], "")
		}
		changed = true
	}

	// the numbers after the import: the given or kept ones of the rows and those of the records not in the file
	type owner struct {
		row         int // -1 for an existing record not in the file
		description string
	}
	var owners = map[string]owner{}
	var claim = func(number string, claimant owner) error {
		var key = shaperNumberKey(number)
		var other, taken = owners[key]
		if !taken {
			owners[key] = claimant
			return nil
		}
		// claims come in file order, after the existing records
		if claimant.row < 0 { // two existing records, not ours to judge
			return nil
		}
		if other.row < 0 {
			return fmt.Errorf("line %d: the number %s is used by the %s %q, leave number empty to get a free one", claimant.row+2,
				strings.TrimSpace(number), what, other.description)
		}
		return fmt.Errorf("line %d: the number %s is given on line %d too, leave number empty to get a free one", claimant.row+2,
			strings.TrimSpace(number), other.row+2)
	}
	for _, record := range existing {
		if _, inFile := rowOfUuid[record.uuid]; !inFile {
			if err := claim(record.number, owner{row: -1, description: record.description}); err != nil {
				return false, err
			}
		}
	}
	for i, row := range parsed.Rows {
		var number = ""
		if numberColumn >= 0 {
			number = strings.TrimSpace(row[numberColumn])
		}
		if number == "" && targets[i] != nil {
			number = targets[i].number
			if numberColumn >= 0 && row[numberColumn] != number {
				row[numberColumn] = number
				changed = true
			}
		}
		if number != "" {
			if err := claim(number, owner{row: i}); err != nil {
				return false, err
			}
		}
	}

	// number the new rows
	if numberColumn < 0 {
		return changed, nil
	}
	var next = shaperFirstNumber
	for i, row := range parsed.Rows {
		if targets[i] != nil || strings.TrimSpace(row[numberColumn]) != "" {
			continue
		}
		for {
			if _, taken := owners[strconv.Itoa(next)]; !taken {
				break
			}
			next++
		}
		if next > 65535 {
			return false, fmt.Errorf("line %d: no free %s number left (%d-65535)", i+2, what, shaperFirstNumber)
		}
		row[numberColumn] = strconv.Itoa(next)
		owners[strconv.Itoa(next)] = owner{row: i}
		changed = true
	}
	return changed, nil
}

// shaperResolvePipes replaces pipe descriptions in the pipe column of a queue import by the pipe's uuid and
// refuses unknown or ambiguous pipes. Returns whether parsed was changed
func shaperResolvePipes(parsed *coreapi.Csv, column int, pipes []ShaperPipe) (bool, error) {
	var changed = false
	for i, row := range parsed.Rows {
		var value = strings.TrimSpace(row[column])
		if value == "" {
			continue // OPNsense requires it, its message names the row
		}
		var matches []ShaperPipe
		for _, pipe := range pipes {
			if pipe.Uuid == value {
				matches = []ShaperPipe{pipe}
				break
			}
			if strings.EqualFold(strings.TrimSpace(pipe.Description), value) {
				matches = append(matches, pipe)
			}
		}
		switch len(matches) {
		case 0:
			return false, fmt.Errorf("line %d: there is no pipe %q (give the uuid or description of an existing pipe, import the pipes first)", i+2, value)
		case 1:
			if row[column] != matches[0].Uuid {
				row[column] = matches[0].Uuid
				changed = true
			}
		default:
			var uuids = make([]string, len(matches))
			for j, pipe := range matches {
				uuids[j] = pipe.Uuid
			}
			return false, fmt.Errorf("line %d: %d pipes are described %q, give the uuid (%s)", i+2, len(matches), value, strings.Join(uuids, ", "))
		}
	}
	return changed, nil
}

// shaperEncodeCsv writes a parsed CSV back with its separator
func shaperEncodeCsv(parsed coreapi.Csv) ([]byte, error) {
	var buffer bytes.Buffer
	var writer = csv.NewWriter(&buffer)
	writer.Comma = parsed.Separator
	if err := writer.Write(parsed.Header); err != nil {
		return nil, err
	}
	if err := writer.WriteAll(parsed.Rows); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
