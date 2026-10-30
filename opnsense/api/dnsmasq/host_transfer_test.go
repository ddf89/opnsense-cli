package dnsmasq

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

// hostTransferCsv is an export of OPNsense 26.7
const hostTransferCsv = "hostname;domain;local;ip_address;cnames;client_id;hw_address;lease_time;ignore;set_tag;description;aliases\n" +
	"web;example.lan;0;192.0.2.11;www.example.lan;;02:00:00:00:00:11;;0;;\"web server\";w1\n" +
	"db;example.lan;0;192.0.2.12,2001:db8::12;;;;;0;;\"db; \"\"main\"\"\";\n"

// newHostTransferApi starts a fake OPNsense with the given handlers ("METHOD /path"), recording the request paths
func newHostTransferApi(t *testing.T, handlers map[string]http.HandlerFunc) (*DnsmasqApi, *[]string) {
	t.Helper()
	var requests []string
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if handler := handlers[r.Method+" "+r.URL.Path]; handler != nil {
			handler(w, r)
			return
		}
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &DnsmasqApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, &requests
}

func TestHostExportCsv(t *testing.T) {
	var api, _ = newHostTransferApi(t, map[string]http.HandlerFunc{
		"GET /api/dnsmasq/settings/download_hosts": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/csv;charset=UTF-8")
			_, _ = io.WriteString(w, hostTransferCsv)
		},
	})
	var content, err = api.HostExportCsv()
	if err != nil || string(content) != hostTransferCsv {
		t.Errorf("got %q, %v", content, err)
	}
}

func TestHostImportCsv(t *testing.T) {
	var payload map[string]string
	var api, requests = newHostTransferApi(t, map[string]http.HandlerFunc{
		"POST /api/dnsmasq/settings/upload_hosts": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&payload)
			_, _ = io.WriteString(w, `{"validations":[],"inserted":1,"updated":1,"uuids":{"u1":0,"u2":1},"fieldnames":["hostname"]}`)
		},
	})
	var result, err = api.HostImportCsv([]byte(hostTransferCsv), "hosts.csv")
	if err != nil {
		t.Fatal(err)
	}
	if result.Inserted != 1 || result.Updated != 1 || len(result.Uuids) != 2 {
		t.Errorf("result %+v", result)
	}
	if payload["payload"] != hostTransferCsv || payload["filename"] != "hosts.csv" {
		t.Errorf("payload %v", payload)
	}

	// a field under both names is refused before anything is sent
	*requests = nil
	_, err = api.HostImportCsv([]byte("host,ip,ip_address\nweb,192.0.2.1,192.0.2.2\n"), "x.csv")
	if err == nil || !strings.Contains(err.Error(), "the columns ip_address and ip are the same field") {
		t.Errorf("err %v", err)
	}
	_, err = api.HostImportCsv([]byte("host;ip\n"), "x.csv")
	if err == nil || !strings.Contains(err.Error(), "no hosts") {
		t.Errorf("err %v", err)
	}
	if len(*requests) != 0 {
		t.Errorf("requests %v", *requests)
	}
}

func TestHostCheckCsv(t *testing.T) {
	for _, header := range [][]string{{"host", "domain", "ip"}, {"hostname", "domain", "ip_address", "hw_address", "description"}, {"hostname", "ip", "descr"}} {
		if err := HostCheckCsv(coreapi.Csv{Header: header}); err != nil {
			t.Errorf("%v: %v", header, err)
		}
	}
	for _, pair := range [][]string{{"hostname", "host"}, {"hw_address", "hwaddr"}, {"descr", "description"}} {
		if err := HostCheckCsv(coreapi.Csv{Header: pair}); err == nil {
			t.Errorf("%v must be refused", pair)
		}
	}
}

func TestHostCsvColumns(t *testing.T) {
	var api, _ = newHostTransferApi(t, map[string]http.HandlerFunc{
		"GET /api/dnsmasq/settings/get_host": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"host":{"host":"","domain":"","local":"0","ip":{"":{"value":"","selected":1}},"cnames":{},`+
				`"client_id":"","hwaddr":{},"lease_time":"","ignore":"0","set_tag":{},"descr":"","comments":"","aliases":{}}}`)
		},
	})
	var columns, err = api.HostCsvColumns()
	if err != nil {
		t.Fatal(err)
	}
	var want = []string{"aliases", "client_id", "cnames", "comments", "descr", "description", "domain", "host", "hostname",
		"hw_address", "hwaddr", "ignore", "ip", "ip_address", "lease_time", "local", "set_tag"}
	if !slices.Equal(columns, want) {
		t.Errorf("columns %v", columns)
	}
}
