package api

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

// CSV export / import of OPNsense's MVC grids (download_* / upload_* endpoints, ApiMutableModelControllerBase
// exportCsv and importCsv), the format of the GUI's "Export as csv" / "Import csv" buttons.
//
// The export is ';' separated with a header row; without records it is empty (no header either). The import
// detects the separator (the first ',' or ';' in the file) and is an upsert keyed by the key fields of the
// endpoint (e.g. host+domain+ip for dnsmasq hosts, "@uuid" where the endpoint offers it): matching records are
// updated with the columns of the file, other rows are added, nothing is removed. Unknown columns are silently
// ignored. When rows fail validation OPNsense retries without them and saves the rest if that second pass is
// clean; the answer only describes the first pass

// DownloadCsv GETs a CSV download (exportCsv of OPNsense), a JSON answer is an error. The content is empty when
// there is nothing to export
func (opn *OPNsense) DownloadCsv(endpoint string) ([]byte, error) {
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
			return nil, &HttpError{StatusCode: response.StatusCode, Message: message}
		}
		return nil, fmt.Errorf("expected CSV from %s, got: %s", endpoint, message)
	}
	return content, nil
}

// Csv is a parsed CSV export or import file
type Csv struct {
	Separator rune
	Header    []string
	Rows      [][]string
}

// Column returns the values of the named column ("" for every row when there is no such column) and whether the
// column exists
func (c Csv) Column(name string) ([]string, bool) {
	var index = -1
	for i, column := range c.Header {
		if column == name {
			index = i
		}
	}
	var values = make([]string, len(c.Rows))
	if index < 0 {
		return values, false
	}
	for i, row := range c.Rows {
		values[i] = row[index]
	}
	return values, true
}

// ParseCsv parses and checks an import file like OPNsense does (separator detection, header row) and stricter:
// every row must have as many columns as the header, header names must be unique and non-empty, and there must be
// at least one row. what names the rows in errors ("hosts"). Errors name the line
func ParseCsv(content []byte, what string) (Csv, error) {
	var result Csv
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
		return result, fmt.Errorf("the file has a header but no %s", what)
	}
	return result, nil
}

// CsvImportValidation is a rejected row of an import
type CsvImportValidation struct {
	// Row is the 0 based data row (the header excluded, line Row+2 of the file), -1 when OPNsense names none
	Row     int    `json:"row"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

// CsvImportResult is the answer of an import, describing OPNsense's first pass (see above): when Validations is
// not empty, the other rows may have been saved by the second pass
type CsvImportResult struct {
	Inserted    int
	Updated     int
	Validations []CsvImportValidation
	// Uuids maps the uuid of every imported record to its 0 based data row
	Uuids map[string]int
	// Fieldnames is the header OPNsense parsed
	Fieldnames []string
}

// UploadCsv POSTs an import file to an upload_* endpoint ({"payload": content}). filename is only informative
func (opn *OPNsense) UploadCsv(endpoint string, content []byte, filename string) (CsvImportResult, error) {
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
	if err := opn.DoJSON("POST", endpoint, body, &answer); err != nil {
		return CsvImportResult{}, err
	}
	if answer.Status != "" { // {"status":"failed"}: not a POST or no payload
		return CsvImportResult{}, fmt.Errorf("the import was refused: status %q", answer.Status)
	}

	var result = CsvImportResult{Inserted: answer.Inserted, Updated: answer.Updated, Fieldnames: answer.Fieldnames, Uuids: map[string]int{}}
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
		result.Validations = append(result.Validations, CsvImportValidation{Row: row, Field: validation.Field, Message: validation.Message})
	}
	return result, nil
}
