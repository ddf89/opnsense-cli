package unbound

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

// hostOverrideTransferCsv is an export as stable/26.7 writes it
const hostOverrideTransferCsv = "@uuid;enabled;hostname;domain;rr;mxprio;mx;ttl;server;txtdata;addptr;aliases;description\n" +
	"d26f2774-c005-4187-8a0f-cae22db12285;1;web;example.lan;A;;;;192.0.2.21;;1;www.example.lan;\"web\"\n" +
	"2ce94aac-7b91-4619-9b71-600706ddaaf6;1;mail;example.lan;MX;10;mx.example.lan;;;;1;;\n"

// newHostOverrideTransferApi starts a fake OPNsense with the given handlers ("METHOD /path"); like OPNsense, other
// requests get an empty 200. It records the request paths
func newHostOverrideTransferApi(t *testing.T, handlers map[string]http.HandlerFunc) (*UnboundApi, *[]string) {
	t.Helper()
	var requests []string
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if handler := handlers[r.Method+" "+r.URL.Path]; handler != nil {
			handler(w, r)
		}
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &UnboundApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, &requests
}

func hostOverrideTransferSearch(count int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		var rows = make([]HostOverride, count)
		for i := range rows {
			rows[i] = HostOverride{Uuid: "u", Host: "web", Domain: "example.lan", Rr: "A", Ip: "192.0.2.21"}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": rows, "rowCount": count, "total": count, "current": 1})
	}
}

func hostOverrideTransferDownload(content string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/csv;charset=UTF-8")
		_, _ = io.WriteString(w, content)
	}
}

const (
	hostOverrideTransferDownloadPath = "GET /api/unbound/settings/download_host_overrides"
	hostOverrideTransferUploadPath   = "POST /api/unbound/settings/upload_host_overrides"
	hostOverrideTransferSearchPath   = "GET /api/unbound/settings/search_host_override"
)

func TestHostOverrideExportCsv(t *testing.T) {
	t.Run("export", func(t *testing.T) {
		var api, _ = newHostOverrideTransferApi(t, map[string]http.HandlerFunc{
			hostOverrideTransferDownloadPath: hostOverrideTransferDownload(hostOverrideTransferCsv),
		})
		var content, err = api.HostOverrideExportCsv()
		if err != nil || string(content) != hostOverrideTransferCsv {
			t.Errorf("got %q, %v", content, err)
		}
	})
	t.Run("nothing to export", func(t *testing.T) {
		var api, _ = newHostOverrideTransferApi(t, map[string]http.HandlerFunc{
			hostOverrideTransferDownloadPath: hostOverrideTransferDownload(""),
			hostOverrideTransferSearchPath:   hostOverrideTransferSearch(0),
		})
		var content, err = api.HostOverrideExportCsv()
		if err != nil || len(content) != 0 {
			t.Errorf("got %q, %v", content, err)
		}
	})
	t.Run("no endpoint (26.7 to 26.7.7)", func(t *testing.T) {
		// the download is unknown: an empty 200, although there are host overrides
		var api, _ = newHostOverrideTransferApi(t, map[string]http.HandlerFunc{
			hostOverrideTransferSearchPath: hostOverrideTransferSearch(2),
		})
		var _, err = api.HostOverrideExportCsv()
		if !errors.Is(err, ErrHostOverrideCsvUnsupported) {
			t.Errorf("err %v", err)
		}
	})
}

func TestHostOverrideImportCsv(t *testing.T) {
	t.Run("import", func(t *testing.T) {
		var payload map[string]string
		var api, _ = newHostOverrideTransferApi(t, map[string]http.HandlerFunc{
			hostOverrideTransferUploadPath: func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&payload)
				_, _ = io.WriteString(w, `{"validations":[],"inserted":0,"updated":2,"uuids":{"d26f2774-c005-4187-8a0f-cae22db12285":0,"2ce94aac-7b91-4619-9b71-600706ddaaf6":1},"fieldnames":["@uuid"]}`)
			},
		})
		var result, err = api.HostOverrideImportCsv([]byte(hostOverrideTransferCsv), "overrides.csv")
		if err != nil || result.Updated != 2 || len(result.Uuids) != 2 {
			t.Errorf("got %+v, %v", result, err)
		}
		if payload["payload"] != hostOverrideTransferCsv {
			t.Errorf("payload %v", payload)
		}
	})
	t.Run("no endpoint (26.7 to 26.7.7)", func(t *testing.T) {
		var api, requests = newHostOverrideTransferApi(t, map[string]http.HandlerFunc{
			hostOverrideTransferSearchPath: hostOverrideTransferSearch(1),
		})
		var _, err = api.HostOverrideImportCsv([]byte(hostOverrideTransferCsv), "overrides.csv")
		if !errors.Is(err, ErrHostOverrideCsvUnsupported) {
			t.Errorf("err %v", err)
		}
		if !slices.Equal(*requests, []string{hostOverrideTransferUploadPath, hostOverrideTransferDownloadPath, hostOverrideTransferSearchPath}) {
			t.Errorf("requests %v", *requests)
		}
	})
	t.Run("no endpoint and no entries: the plain error", func(t *testing.T) {
		var api, _ = newHostOverrideTransferApi(t, map[string]http.HandlerFunc{
			hostOverrideTransferSearchPath: hostOverrideTransferSearch(0),
		})
		var _, err = api.HostOverrideImportCsv([]byte("hostname;domain\nweb;example.lan\n"), "overrides.csv")
		if err == nil || errors.Is(err, ErrHostOverrideCsvUnsupported) || !strings.Contains(err.Error(), "empty response") {
			t.Errorf("err %v", err)
		}
	})
	t.Run("checked before sending", func(t *testing.T) {
		var api, requests = newHostOverrideTransferApi(t, nil)
		for content, want := range map[string]string{
			"@uuid;hostname\nD26F2774-C005-4187-8A0F-CAE22DB12285;web\n":                                             `line 2: invalid @uuid "D26F2774`,
			"@uuid;hostname\n;web\nd26f2774-c005-4187-8a0f-cae22db12285;a\nd26f2774-c005-4187-8a0f-cae22db12285;b\n": "line 4: the @uuid d26f2774-c005-4187-8a0f-cae22db12285 is on line 3 already",
			"@uuid;hostname\n": "no host overrides",
		} {
			var _, err = api.HostOverrideImportCsv([]byte(content), "x.csv")
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%q: err %v, want %q", content, err, want)
			}
		}
		if len(*requests) != 0 {
			t.Errorf("requests %v", *requests)
		}
	})
}

func TestHostOverrideCsvColumns(t *testing.T) {
	var api, _ = newHostOverrideTransferApi(t, map[string]http.HandlerFunc{
		"GET /api/unbound/settings/get_host_override": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"host":{"enabled":"1","hostname":"","domain":"","rr":{"A":{"value":"A","selected":1}},"mxprio":"",`+
				`"mx":"","ttl":"","server":"","txtdata":"","addptr":"1","aliases":{"":{"value":"","selected":1}},"description":""}}`)
		},
	})
	var columns, err = api.HostOverrideCsvColumns()
	if err != nil {
		t.Fatal(err)
	}
	var want = []string{"@uuid", "addptr", "aliases", "description", "domain", "enabled", "hostname", "mx", "mxprio", "rr",
		"server", "ttl", "txtdata"}
	if !slices.Equal(columns, want) {
		t.Errorf("columns %v", columns)
	}
}
