package firewall

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

type filterTransferTestRequest struct {
	Method      string
	Path        string
	ContentType string
	Body        string
}

type filterTransferTestAnswer struct {
	Status      int
	ContentType string
	Body        string
}

// filterTransferTestApi starts a fake OPNsense answering "METHOD /path" from answers (unknown: empty 200)
func filterTransferTestApi(t *testing.T, answers map[string]filterTransferTestAnswer) (*FirewallApi, func() []filterTransferTestRequest) {
	t.Helper()
	var mu sync.Mutex
	var requests []filterTransferTestRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, filterTransferTestRequest{Method: r.Method, Path: r.URL.Path, ContentType: r.Header.Get("Content-Type"), Body: string(body)})
		mu.Unlock()
		var answer, found = answers[r.Method+" "+r.URL.Path]
		if !found {
			return
		}
		if answer.ContentType != "" {
			w.Header().Set("Content-Type", answer.ContentType)
		}
		if answer.Status != 0 {
			w.WriteHeader(answer.Status)
		}
		_, _ = io.WriteString(w, answer.Body)
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &FirewallApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, func() []filterTransferTestRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]filterTransferTestRequest(nil), requests...)
	}
}

const (
	filterTransferTestCsv = "@uuid;enabled;action;interface;description\n" +
		"d621e174-154f-4ebb-9465-6e2fac4b2bcb;1;pass;lan;\"Default allow LAN to any rule\"\n" +
		";1;block;wan;\"semi;colon\"\n"
	filterTransferTestUploadPath = "/api/firewall/filter/upload_rules"
)

func filterTransferTestCsvAnswer(body string) filterTransferTestAnswer {
	return filterTransferTestAnswer{ContentType: "text/csv;charset=UTF-8", Body: body}
}

func TestFilterRulesExport(t *testing.T) {
	var api, requests = filterTransferTestApi(t, map[string]filterTransferTestAnswer{
		"GET /api/firewall/filter/download_rules": filterTransferTestCsvAnswer(filterTransferTestCsv),
	})
	var content, err = api.FilterRulesExport()
	if err != nil || string(content) != filterTransferTestCsv {
		t.Fatalf("FilterRulesExport: %q %v", content, err)
	}
	if got := requests(); len(got) != 1 || got[0].Method != "GET" {
		t.Errorf("requests: %+v", got)
	}
}

func TestFilterRulesExportEmptyAndErrors(t *testing.T) {
	var api, _ = filterTransferTestApi(t, map[string]filterTransferTestAnswer{
		"GET /api/firewall/filter/download_rules":       filterTransferTestCsvAnswer(""),
		"GET /api/firewall/migration/download_rules":    {Status: 401, ContentType: "application/json", Body: `{"status":401,"message":"Authentication Failed"}`},
		"GET /api/firewall/migration/download_outbound": {ContentType: "application/json", Body: `{"errorMessage":"something broke"}`},
	})
	if content, err := api.FilterRulesExport(); err != nil || len(content) != 0 {
		t.Errorf("no rules: %q %v", content, err)
	}
	var httpErr *coreapi.HttpError
	if _, err := api.MigrationExport(MigrationFilter); !errors.As(err, &httpErr) || httpErr.StatusCode != 401 || httpErr.Message != "Authentication Failed" {
		t.Errorf("401: %v", err)
	}
	if _, err := api.MigrationExport(MigrationOutbound); err == nil || !strings.Contains(err.Error(), "something broke") {
		t.Errorf("JSON instead of CSV must be an error: %v", err)
	}
}

func TestFilterRulesParseCsv(t *testing.T) {
	var parsed, err = FilterRulesParseCsv([]byte(filterTransferTestCsv))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Separator != ';' || !reflect.DeepEqual(parsed.Header, []string{"@uuid", "enabled", "action", "interface", "description"}) ||
		len(parsed.Rows) != 2 || parsed.Rows[1][4] != "semi;colon" {
		t.Errorf("parsed: %+v", parsed)
	}
	if got := parsed.Uuids(); !reflect.DeepEqual(got, []string{"d621e174-154f-4ebb-9465-6e2fac4b2bcb", ""}) {
		t.Errorf("Uuids: %q", got)
	}

	// the first , or ; decides, like OPNsense; a BOM is dropped
	parsed, err = FilterRulesParseCsv([]byte("\xef\xbb\xbfenabled,action,description\r\n1,pass,\"a;b\"\r\n"))
	if err != nil || parsed.Separator != ',' || parsed.Header[0] != "enabled" || parsed.Rows[0][2] != "a;b" || parsed.Uuids() != nil {
		t.Errorf("comma separated: %+v %v", parsed, err)
	}

	for name, content := range map[string]string{
		"empty":           " \n",
		"header only":     "@uuid;enabled\n",
		"short row":       "@uuid;enabled;action\n;1\n",
		"long row":        "@uuid;enabled\n;1;pass\n",
		"bad uuid":        "@uuid;enabled\nnot-a-uuid;1\n",
		"upper case uuid": "@uuid;enabled\nD621E174-154F-4EBB-9465-6E2FAC4B2BCB;1\n",
		"v1 uuid":         "@uuid;enabled\nd621e174-154f-1ebb-9465-6e2fac4b2bcb;1\n",
		"duplicate":       "enabled;enabled\n1;1\n",
		"unnamed":         "enabled;;action\n1;x;pass\n",
	} {
		if _, err := FilterRulesParseCsv([]byte(content)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := FilterRulesParseCsv([]byte("@uuid;enabled\n;1\nnope;1\n")); err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("errors name the line: %v", err)
	}
}

func TestFilterRulesColumns(t *testing.T) {
	var api, _ = filterTransferTestApi(t, map[string]filterTransferTestAnswer{
		"GET /api/firewall/filter/get_rule": {ContentType: "application/json",
			Body: `{"rule":{"enabled":"1","sort_order":"","prio_group":"","action":{"pass":{"value":"Pass","selected":1}},"description":""}}`},
	})
	var columns, err = api.FilterRulesColumns()
	if err != nil || !reflect.DeepEqual(columns, []string{"@uuid", "action", "description", "enabled"}) {
		t.Errorf("columns: %q %v", columns, err)
	}

	var empty, _ = filterTransferTestApi(t, map[string]filterTransferTestAnswer{"GET /api/firewall/filter/get_rule": {Body: `[]`}})
	if _, err := empty.FilterRulesColumns(); err == nil {
		t.Errorf("an empty answer must be an error")
	}
}

func TestFilterRulesImport(t *testing.T) {
	var api, requests = filterTransferTestApi(t, map[string]filterTransferTestAnswer{
		"POST " + filterTransferTestUploadPath: {ContentType: "application/json", Body: `{"validations":[{"sequence":1,"message":"option not in list","field":"interface"},` +
			`{"sequence":null,"message":"Duplicate key entry found"}],"inserted":1,"updated":1,` +
			`"uuids":{"d621e174-154f-4ebb-9465-6e2fac4b2bcb":0,"5b3e2f7a-1c2d-4e5f-8a9b-0c1d2e3f4a5b":1},"fieldnames":["@uuid","enabled"]}`},
	})
	var result, err = api.FilterRulesImport([]byte(filterTransferTestCsv), "rules.csv")
	if err != nil {
		t.Fatal(err)
	}
	var want = FilterRulesImportResult{
		Inserted: 1, Updated: 1, Fieldnames: []string{"@uuid", "enabled"},
		Uuids: map[string]int{"d621e174-154f-4ebb-9465-6e2fac4b2bcb": 0, "5b3e2f7a-1c2d-4e5f-8a9b-0c1d2e3f4a5b": 1},
		Validations: []FilterRulesImportValidation{
			{Row: 1, Field: "interface", Message: "option not in list"},
			{Row: -1, Message: "Duplicate key entry found"},
		},
	}
	if !reflect.DeepEqual(result, want) {
		t.Errorf("result:\n got  %+v\n want %+v", result, want)
	}

	var got = requests()
	if len(got) != 1 || got[0].Method != "POST" || !strings.HasPrefix(got[0].ContentType, "application/json") {
		t.Fatalf("requests: %+v", got)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(got[0].Body), &body); err != nil || body["payload"] != filterTransferTestCsv || body["filename"] != "rules.csv" {
		t.Errorf("body: %v %v", body, err)
	}
}

func TestFilterRulesImportAnswers(t *testing.T) {
	var api, _ = filterTransferTestApi(t, map[string]filterTransferTestAnswer{
		"POST " + filterTransferTestUploadPath: {ContentType: "application/json", Body: `{"validations":[],"inserted":0,"updated":0,"uuids":[],"fieldnames":["@uuid"]}`},
	})
	if result, err := api.FilterRulesImport([]byte("x"), "x.csv"); err != nil || len(result.Uuids) != 0 || len(result.Validations) != 0 {
		t.Errorf("empty uuids list: %+v %v", result, err)
	}

	var refused, _ = filterTransferTestApi(t, map[string]filterTransferTestAnswer{
		"POST " + filterTransferTestUploadPath: {ContentType: "application/json", Body: `{"status":"failed"}`},
	})
	if _, err := refused.FilterRulesImport([]byte("x"), "x.csv"); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("status failed: %v", err)
	}

	var empty, _ = filterTransferTestApi(t, nil)
	if _, err := empty.FilterRulesImport([]byte("x"), "x.csv"); err == nil {
		t.Errorf("an empty answer must be an error")
	}
}
