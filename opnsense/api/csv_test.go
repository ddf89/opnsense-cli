package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newCsvTestOPNsense(t *testing.T, handler http.HandlerFunc) *OPNsense {
	t.Helper()
	var server = httptest.NewServer(handler)
	t.Cleanup(server.Close)
	var baseUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &OPNsense{BaseUrl: *baseUrl, ApiKey: "k", ApiSecret: "s"}
}

func TestDownloadCsv(t *testing.T) {
	var opn = newCsvTestOPNsense(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/csv":
			if r.Header.Get("Accept") != "text/csv, application/json" {
				t.Errorf("accept: %q", r.Header.Get("Accept"))
			}
			w.Header().Set("Content-Type", "text/csv")
			_, _ = io.WriteString(w, "host;ip\nweb;192.0.2.1\n")
		case "/empty":
			w.Header().Set("Content-Type", "text/csv")
		case "/json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"message":"no export"}`)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errorMessage":"Endpoint not found"}`)
		}
	})
	if content, err := opn.DownloadCsv(opn.BaseUrl.String() + "/csv"); err != nil || string(content) != "host;ip\nweb;192.0.2.1\n" {
		t.Errorf("csv: %q, %v", content, err)
	}
	if content, err := opn.DownloadCsv(opn.BaseUrl.String() + "/empty"); err != nil || len(content) != 0 {
		t.Errorf("empty: %q, %v", content, err)
	}
	if _, err := opn.DownloadCsv(opn.BaseUrl.String() + "/json"); err == nil || !strings.Contains(err.Error(), "no export") {
		t.Errorf("json answer: want an error with the message, got %v", err)
	}
	var httpErr *HttpError
	if _, err := opn.DownloadCsv(opn.BaseUrl.String() + "/missing"); err == nil || !asHttpError(err, &httpErr) || httpErr.StatusCode != 404 {
		t.Errorf("404: want HttpError, got %v", err)
	}
}

func asHttpError(err error, target **HttpError) bool {
	var httpErr, ok = err.(*HttpError)
	*target = httpErr
	return ok
}

func TestParseCsv(t *testing.T) {
	var parsed, err = ParseCsv([]byte("\xef\xbb\xbfhost,ip;x\nweb,192.0.2.1;y\n"), "hosts")
	if err != nil || parsed.Separator != ',' || len(parsed.Rows) != 1 || parsed.Header[1] != "ip;x" {
		t.Errorf("comma first: %+v, %v", parsed, err)
	}
	parsed, err = ParseCsv([]byte("host;ip\nweb;192.0.2.1\ndb;192.0.2.2\n"), "hosts")
	if err != nil || parsed.Separator != ';' || len(parsed.Rows) != 2 {
		t.Fatalf("semicolon: %+v, %v", parsed, err)
	}
	if ips, found := parsed.Column("ip"); !found || ips[1] != "192.0.2.2" {
		t.Errorf("column ip: %q %v", ips, found)
	}
	if values, found := parsed.Column("nope"); found || len(values) != 2 || values[0] != "" {
		t.Errorf("missing column: %q %v", values, found)
	}
	for content, want := range map[string]string{
		"":                       "the file is empty",
		"host;ip\n":              "header but no hosts",
		"host;;ip\nweb;x;1\n":    "column 2 has no name",
		"host;host\nweb;db\n":    `"host" is given twice`,
		"host;ip\nweb;1;extra\n": "not a valid CSV file",
	} {
		if _, err := ParseCsv([]byte(content), "hosts"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want %q, got %v", content, want, err)
		}
	}
}

func TestUploadCsv(t *testing.T) {
	var answer = `{"inserted":1,"updated":2,"uuids":{"u1":0},"fieldnames":["host","ip"],` +
		`"validations":[{"sequence":1,"field":"ip","message":"bad ip"},{"sequence":null,"message":"general"}]}`
	var body string
	var opn = newCsvTestOPNsense(t, func(w http.ResponseWriter, r *http.Request) {
		var content, _ = io.ReadAll(r.Body)
		body = string(content)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, answer)
	})
	var result, err = opn.UploadCsv(opn.BaseUrl.String()+"/up", []byte("host;ip\nweb;1\n"), "hosts.csv")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(body) != `{"filename":"hosts.csv","payload":"host;ip\nweb;1\n"}` {
		t.Errorf("body: %s", body)
	}
	if result.Inserted != 1 || result.Updated != 2 || result.Uuids["u1"] != 0 || len(result.Fieldnames) != 2 ||
		len(result.Validations) != 2 || result.Validations[0] != (CsvImportValidation{Row: 1, Field: "ip", Message: "bad ip"}) ||
		result.Validations[1].Row != -1 {
		t.Errorf("result: %+v", result)
	}

	answer = `{"inserted":0,"updated":0,"uuids":[],"validations":[]}`
	if result, err = opn.UploadCsv(opn.BaseUrl.String()+"/up", []byte("x\n1\n"), "f"); err != nil || len(result.Uuids) != 0 {
		t.Errorf("empty uuids list: %+v, %v", result, err)
	}
	answer = `{"status":"failed"}`
	if _, err = opn.UploadCsv(opn.BaseUrl.String()+"/up", []byte("x\n1\n"), "f"); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("failed: want an error, got %v", err)
	}
}
