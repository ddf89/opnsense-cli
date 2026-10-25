package firewall

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"sort"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// CSV export / import of the MVC filter rules (Firewall > Rules: api/firewall/filter/download_rules and
// upload_rules), the format the GUI's "Export as csv" / "Import csv" buttons use.
//
// The export is ';' separated with a header row, "@uuid" first, followed by the rule fields (without sort_order,
// prio_group and audit). Categories are exported by name and overload by alias name. Without rules the export is
// empty (no header either).
//
// The import is an upsert keyed by "@uuid": a row whose @uuid is an existing rule overwrites the fields present
// in the file, every other row is added (with the given @uuid when it is a valid v4 uuid). Nothing is removed and
// the rule order columns are ignored. OPNsense detects the separator (the first ',' or ';' in the file), maps
// category and alias names back to their uuids (unknown categories are dropped) and silently ignores unknown
// columns. When rows fail validation OPNsense retries without them and saves the rest if that second pass is
// clean; the answer only describes the first pass

// FilterRulesUuidColumn is the key column of the rule CSV
const FilterRulesUuidColumn = "@uuid"

// filterRulesIgnoredColumns are rule fields left out of the export and dropped by the import
var filterRulesIgnoredColumns = []string{"sort_order", "prio_group", "audit"}

// filterRulesUuidPattern is the uuid check of the import (ArrayField::importRecordSet)
var filterRulesUuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// FilterRulesExport returns the filter rules as CSV, empty when there are no rules
func (opn *FirewallApi) FilterRulesExport() ([]byte, error) {
	return opn.filterRulesDownloadCsv(opn.endpoint("firewall", "filter", "download_rules"))
}

// filterRulesDownloadCsv GETs a CSV download (exportCsv of OPNsense), a JSON answer is an error
func (opn *FirewallApi) filterRulesDownloadCsv(endpoint string) ([]byte, error) {
	var request, err = http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "text/csv, application/json")
	response, err := opn.Send(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var mediaType, _, _ = mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaType == "application/json" {
		var container struct {
			Message      string `json:"message"`
			ErrorMessage string `json:"errorMessage"`
		}
		var message = strings.TrimSpace(string(content))
		if json.Unmarshal(content, &container) == nil {
			if container.Message != "" {
				message = container.Message
			} else if container.ErrorMessage != "" {
				message = container.ErrorMessage
			}
		}
		if response.StatusCode != http.StatusOK {
			return nil, &coreapi.HttpError{StatusCode: response.StatusCode, Message: message}
		}
		return nil, fmt.Errorf("expected CSV from %s, got: %s", endpoint, message)
	}
	return content, nil
}

// FilterRulesCsv is a parsed rule CSV
type FilterRulesCsv struct {
	Separator rune
	Header    []string
	Rows      [][]string
}

// Uuids returns the @uuid of every row ("" for rows without one), nil when there is no @uuid column
func (f FilterRulesCsv) Uuids() []string {
	var column = -1
	for i, name := range f.Header {
		if name == FilterRulesUuidColumn {
			column = i
		}
	}
	if column < 0 {
		return nil
	}
	var uuids = make([]string, len(f.Rows))
	for i, row := range f.Rows {
		uuids[i] = row[column]
	}
	return uuids
}

// FilterRulesParseCsv parses and checks a rule CSV like the import does (separator detection, header row,
// @uuid format) and stricter: every row must have as many columns as the header, header names must be unique
// and non-empty, and there must be at least one row. Errors name the line
func FilterRulesParseCsv(content []byte) (FilterRulesCsv, error) {
	var result FilterRulesCsv
	content = bytes.TrimPrefix(content, []byte("\xef\xbb\xbf")) // UTF-8 BOM of spreadsheet exports
	if len(bytes.TrimSpace(content)) == 0 {
		return result, errors.New("the file is empty")
	}
	// like OPNsense: the first ',' or ';' of the content decides
	result.Separator = ';'
	if comma, semicolon := bytes.IndexByte(content, ','), bytes.IndexByte(content, ';'); comma >= 0 && (semicolon < 0 || comma < semicolon) {
		result.Separator = ','
	}

	var reader = csv.NewReader(bytes.NewReader(content))
	reader.Comma = result.Separator
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil {
		return result, fmt.Errorf("not a valid CSV file: %w", err)
	}
	result.Header = records[0]
	var seen = map[string]bool{}
	for i, name := range result.Header {
		if strings.TrimSpace(name) == "" {
			return result, fmt.Errorf("line 1: column %d has no name", i+1)
		}
		if seen[name] {
			return result, fmt.Errorf("line 1: the column %q is given twice", name)
		}
		seen[name] = true
	}
	result.Rows = records[1:]
	if len(result.Rows) == 0 {
		return result, errors.New("the file has a header but no rules")
	}
	for i, uuid := range result.Uuids() {
		if uuid != "" && !filterRulesUuidPattern.MatchString(uuid) {
			return result, fmt.Errorf("line %d: invalid @uuid %q, must be a lower case v4 uuid or empty to add a rule", i+2, uuid)
		}
	}
	return result, nil
}

// FilterRulesColumns returns the columns the import understands: @uuid and the rule fields (from get_rule),
// without the ignored order fields, sorted
func (opn *FirewallApi) FilterRulesColumns() ([]string, error) {
	var answer struct {
		Rule map[string]json.RawMessage `json:"rule"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("firewall", "filter", "get_rule"), nil, &answer); err != nil {
		return nil, err
	}
	if len(answer.Rule) == 0 {
		return nil, errors.New("get_rule returned no rule fields")
	}
	var columns = []string{FilterRulesUuidColumn}
	for name := range answer.Rule {
		var ignored = false
		for _, ignore := range filterRulesIgnoredColumns {
			ignored = ignored || name == ignore
		}
		if !ignored {
			columns = append(columns, name)
		}
	}
	sort.Strings(columns)
	return columns, nil
}

// FilterRulesImportValidation is a rejected row of an import
type FilterRulesImportValidation struct {
	// Row is the 0 based data row (the header excluded, line Row+2 of the file), -1 when OPNsense names none
	Row     int    `json:"row"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

// FilterRulesImportResult is the answer of an import, describing OPNsense's first pass (see the package
// comment): when Validations is not empty, the other rows may have been saved by the second pass
type FilterRulesImportResult struct {
	Inserted    int
	Updated     int
	Validations []FilterRulesImportValidation
	// Uuids maps the uuid of every imported rule to its 0 based data row
	Uuids map[string]int
	// Fieldnames is the header OPNsense parsed
	Fieldnames []string
}

// FilterRulesImport uploads a rule CSV (see the package comment for the upsert semantics). filename is only
// informative. The changes take effect when the filter rules are applied
func (opn *FirewallApi) FilterRulesImport(content []byte, filename string) (FilterRulesImportResult, error) {
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
	if err := opn.DoJSON("POST", opn.endpoint("firewall", "filter", "upload_rules"), body, &answer); err != nil {
		return FilterRulesImportResult{}, err
	}
	if answer.Status != "" { // {"status":"failed"}: not a POST or no payload
		return FilterRulesImportResult{}, fmt.Errorf("the import was refused: status %q", answer.Status)
	}

	var result = FilterRulesImportResult{Inserted: answer.Inserted, Updated: answer.Updated, Fieldnames: answer.Fieldnames, Uuids: map[string]int{}}
	// uuids is {"<uuid>":row,...}, or [] when empty (PHP)
	if trimmed := bytes.TrimSpace(answer.Uuids); len(trimmed) > 0 && trimmed[0] == '{' {
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
