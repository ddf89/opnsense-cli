package cli

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

const (
	dnsmasqHostTransferDownloadPath = "/api/dnsmasq/settings/download_hosts"
	dnsmasqHostTransferUploadPath   = "/api/dnsmasq/settings/upload_hosts"

	// dnsmasqHostTransferCsv is an export of OPNsense 26.7
	dnsmasqHostTransferCsv = "hostname;domain;local;ip_address;cnames;client_id;hw_address;lease_time;ignore;set_tag;description;aliases\n" +
		"web;example.lan;0;192.0.2.11;www.example.lan;;02:00:00:00:00:11;;0;;\"web server\";w1\n" +
		"db;example.lan;0;192.0.2.12,2001:db8::12;;;;;0;;\"db; \"\"main\"\"\";\n"

	// dnsmasqHostTransferGetHost is get_host without uuid (26.7): the field names of a host
	dnsmasqHostTransferGetHost = `{"host":{"host":"","domain":"","local":"0","ip":{"":{"value":"","selected":1}},"cnames":{},` +
		`"client_id":"","hwaddr":{},"lease_time":"","ignore":"0","set_tag":{},"descr":"","comments":"","aliases":{}}}`
)

func dnsmasqHostTransferFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.onFunc("GET", dnsmasqHostTransferDownloadPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/csv;charset=UTF-8")
		_, _ = w.Write([]byte(dnsmasqHostTransferCsv))
	})
	f.on("GET", "/api/dnsmasq/settings/get_host", 200, dnsmasqHostTransferGetHost)
	return f
}

// dnsmasqHostTransferFile writes content to a new file in a temp dir and returns its path
func dnsmasqHostTransferFile(t *testing.T, content string) string {
	t.Helper()
	var path = filepath.Join(t.TempDir(), "hosts.csv")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDnsmasqHostExport(t *testing.T) {
	t.Parallel()
	var f = dnsmasqHostTransferFake(t)
	var r = f.run("/dnsmasq/host", "export", "-")
	wantExit(t, r, 0)
	if r.stdout != dnsmasqHostTransferCsv {
		t.Errorf("stdout:\n%s", r.stdout)
	}

	var path = filepath.Join(t.TempDir(), "hosts.csv")
	r = f.run("/dnsmasq/host", "export", path)
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "saved 2 hosts to "+path)
	if content, err := os.ReadFile(path); err != nil || string(content) != dnsmasqHostTransferCsv {
		t.Errorf("file: %q, %v", content, err)
	}
	wantNoMutations(t, f)

	var help = f.run("/dnsmasq/host", "export", "?")
	wantContains(t, "help", help.stdout, "comments are not exported", "hostname, domain, local, ip_address")
}

func TestDnsmasqHostImport(t *testing.T) {
	t.Parallel()
	t.Run("import", func(t *testing.T) {
		t.Parallel()
		var f = dnsmasqHostTransferFake(t)
		f.on("POST", dnsmasqHostTransferUploadPath, 200,
			`{"validations":[],"inserted":1,"updated":1,"uuids":{"u1":0,"u2":1},"fieldnames":["hostname"]}`)
		var path = dnsmasqHostTransferFile(t, dnsmasqHostTransferCsv)
		var r = f.run("/dnsmasq/host", "import", path, "confirm=yes")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "imported "+path+": 1 hosts added, 1 updated")
		wantJSON(t, wantOneMutation(t, f, "POST", dnsmasqHostTransferUploadPath),
			map[string]any{"payload": dnsmasqHostTransferCsv, "filename": "hosts.csv"})
	})
	t.Run("field names and , separator", func(t *testing.T) {
		t.Parallel()
		var f = dnsmasqHostTransferFake(t)
		f.on("POST", dnsmasqHostTransferUploadPath, 200, `{"validations":[],"inserted":1,"updated":0,"uuids":{"u1":0},"fieldnames":["host"]}`)
		var path = dnsmasqHostTransferFile(t, "host,domain,ip,hwaddr,descr,comments\nweb,example.lan,192.0.2.1,,x,y\n")
		wantExit(t, f.run("/dnsmasq/host", "import", path, "confirm=yes"), 0)
		wantOneMutation(t, f, "POST", dnsmasqHostTransferUploadPath)
	})
	t.Run("needs confirmation", func(t *testing.T) {
		t.Parallel()
		var f = dnsmasqHostTransferFake(t)
		var path = dnsmasqHostTransferFile(t, dnsmasqHostTransferCsv)
		wantFailure(t, f.run("/dnsmasq/host", "import", path),
			"This adds hosts and overwrites those matching by hostname, domain and ip_address", "confirm=yes")
		wantNoCalls(t, f)
	})
	t.Run("a field under both names", func(t *testing.T) {
		t.Parallel()
		var f = dnsmasqHostTransferFake(t)
		var path = dnsmasqHostTransferFile(t, "hostname;ip;ip_address\nweb;192.0.2.1;192.0.2.2\n")
		wantFailure(t, f.run("/dnsmasq/host", "import", path), path, "line 1: the columns ip_address and ip are the same field")
		wantNoCalls(t, f)
	})
	t.Run("unknown columns", func(t *testing.T) {
		t.Parallel()
		var f = dnsmasqHostTransferFake(t)
		var path = dnsmasqHostTransferFile(t, "hostname;domain;mac\nweb;example.lan;x\n")
		wantFailure(t, f.run("/dnsmasq/host", "import", path, "confirm=yes"), "unknown columns mac",
			"valid are: aliases, client_id, cnames, comments, descr, description, domain, host, hostname, hw_address, hwaddr, ignore, ip, ip_address, lease_time, local, set_tag")
		wantNoMutations(t, f)
	})
	t.Run("rejected rows", func(t *testing.T) {
		t.Parallel()
		var f = dnsmasqHostTransferFake(t)
		f.on("POST", dnsmasqHostTransferUploadPath, 200,
			`{"validations":[{"sequence":1,"field":"ip","message":"Entry is not a valid ip address."}],"inserted":1,"updated":0,"uuids":{"u1":0,"u2":1},"fieldnames":["hostname"]}`)
		var path = dnsmasqHostTransferFile(t, dnsmasqHostTransferCsv)
		wantFailure(t, f.run("/dnsmasq/host", "import", path, "confirm=yes"),
			"OPNsense rejected rows of "+path, "line 3: ip: Entry is not a valid ip address.", "check the hosts")
	})
}
