package firewall

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// CSV export / import of the NAT rules (download_rules / upload_rules of the four NAT controllers), the format of
// the GUI's "Export as csv" / "Import csv". It is the format of the filter rules (see filter_transfer.go): ';'
// separated, a header row with "@uuid" first, and the import is an upsert keyed by @uuid that never removes rules.
//
// OPNsense 26.7 exports the nested source / destination of d_nat as two empty columns "source" and "destination"
// (verified live), so a plain export loses the addresses and ports. Export replaces them with the columns
// source.network, source.port, source.not, destination.network, destination.port, destination.not from
// search_rule; the import understands these dotted columns (ArrayField::importRecordSet walks the dots)

// natExpandedColumns are the d_nat container columns Export replaces by their fields
var natExpandedColumns = map[string][]string{
	"source":      {"source.network", "source.port", "source.not"},
	"destination": {"destination.network", "destination.port", "destination.not"},
}

// Export returns the rules as CSV, empty when there are no (configured) rules
func (rules *NatRules) Export() ([]byte, error) {
	var content, err = rules.opn.filterRulesDownloadCsv(rules.endpoint("download_rules"))
	if err != nil || len(bytes.TrimSpace(content)) == 0 || !rules.kind.disabledFlag {
		return content, err
	}
	return rules.expandExport(content)
}

// expandExport replaces the empty d_nat source / destination columns by their fields from search_rule
func (rules *NatRules) expandExport(content []byte) ([]byte, error) {
	var reader = csv.NewReader(bytes.NewReader(content))
	reader.Comma = ';'
	reader.LazyQuotes = true
	var records, err = reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("unexpected export from %s: %w", rules.endpoint("download_rules"), err)
	}
	var parsed = FilterRulesCsv{Separator: ';', Header: records[0], Rows: records[1:]}
	var list, listErr = rules.List()
	if listErr != nil {
		return nil, listErr
	}
	var byUuid = map[string]NatRule{}
	for _, rule := range list {
		byUuid[rule.Uuid] = rule
	}

	var header []string
	for _, name := range parsed.Header {
		if expanded, ok := natExpandedColumns[name]; ok {
			header = append(header, expanded...)
		} else {
			header = append(header, name)
		}
	}
	var uuids = parsed.Uuids()
	var buffer bytes.Buffer
	var writer = csv.NewWriter(&buffer)
	writer.Comma = ';'
	_ = writer.Write(header)
	for i, row := range parsed.Rows {
		var rule, found = byUuid[uuids[i]]
		if !found {
			return nil, fmt.Errorf("the exported %s %s is not listed by search_rule", rules.kind.name, uuids[i])
		}
		var record []string
		for j, name := range parsed.Header {
			if expanded, ok := natExpandedColumns[name]; ok {
				for _, field := range expanded {
					record = append(record, rule.Fields[field])
				}
			} else {
				record = append(record, row[j])
			}
		}
		_ = writer.Write(record)
	}
	writer.Flush()
	return buffer.Bytes(), writer.Error()
}

// Columns returns the columns the import understands: @uuid, the rule fields of get_rule and the dotted fields of
// nested containers (source.network), sorted
func (rules *NatRules) Columns() ([]string, error) {
	var answer struct {
		Rule map[string]json.RawMessage `json:"rule"`
	}
	if err := rules.opn.DoJSON("GET", rules.endpoint("get_rule"), nil, &answer); err != nil {
		return nil, err
	}
	if len(answer.Rule) == 0 {
		return nil, errors.New("get_rule returned no rule fields")
	}
	var columns = []string{FilterRulesUuidColumn, "sort_order", "prio_group"}
	for name, raw := range answer.Rule {
		columns = append(columns, name)
		// a container (d_nat source) is an object of plain values, an option list an object of objects
		var container map[string]any
		if json.Unmarshal(raw, &container) != nil {
			continue
		}
		for child, value := range container {
			if _, isOption := value.(map[string]any); isOption {
				break
			}
			columns = append(columns, name+"."+child)
		}
	}
	sort.Strings(columns)
	return columns, nil
}

// Import uploads a rule CSV (an upsert keyed by @uuid, see filter_transfer.go). filename is only informative. The
// rules are saved, they take effect with Apply
func (rules *NatRules) Import(content []byte, filename string) (FilterRulesImportResult, error) {
	var answer struct {
		Status      string          `json:"status"`
		Inserted    int             `json:"inserted"`
		Updated     int             `json:"updated"`
		Uuids       json.RawMessage `json:"uuids"`
		Fieldnames  []string        `json:"fieldnames"`
		Validations []struct {
			Sequence *int   `json:"sequence"`
			Field    string `json:"field"`
			Message  string `json:"message"`
		} `json:"validations"`
	}
	var body = map[string]string{"payload": string(content), "filename": filename}
	if err := rules.opn.DoJSON("POST", rules.endpoint("upload_rules"), body, &answer); err != nil {
		return FilterRulesImportResult{}, err
	}
	if answer.Status != "" { // {"status":"failed"}: not a POST or no payload
		return FilterRulesImportResult{}, fmt.Errorf("the import was refused: status %q", answer.Status)
	}

	var result = FilterRulesImportResult{Inserted: answer.Inserted, Updated: answer.Updated, Fieldnames: answer.Fieldnames, Uuids: map[string]int{}}
	if trimmed := bytes.TrimSpace(answer.Uuids); len(trimmed) > 0 && trimmed[0] == '{' { // [] when empty (PHP)
		if err := json.Unmarshal(trimmed, &result.Uuids); err != nil {
			return result, fmt.Errorf("unexpected uuids in the import answer: %w", err)
		}
	}
	for _, validation := range answer.Validations {
		var row = -1
		if validation.Sequence != nil {
			row = *validation.Sequence
		}
		result.Validations = append(result.Validations, FilterRulesImportValidation{Row: row, Field: validation.Field, Message: validation.Message})
	}
	return result, nil
}
