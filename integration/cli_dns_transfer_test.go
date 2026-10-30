//go:build integration

package integration

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dnsmasq"
	"opnsense-cli/opnsense/api/unbound"
)

// Live tests of /dnsmasq/host and /unbound/host-override export and import. The imported files only hold rows of
// the test's own domain, so an import can only update or add records of this run

// dnsTransferRows returns the rows of an export whose domain column is domain, in export order
func dnsTransferRows(t *testing.T, content []byte, what string, domain string) (api.Csv, [][]string) {
	t.Helper()
	var parsed, err = api.ParseCsv(content, what)
	if err != nil {
		t.Fatalf("the export is no CSV: %v\n%s", err, content)
	}
	var domains, _ = parsed.Column("domain")
	var rows [][]string
	for i, row := range parsed.Rows {
		if domains[i] == domain {
			rows = append(rows, row)
		}
	}
	return parsed, rows
}

// dnsTransferWrite writes a ; separated CSV to a new file and returns its path
func dnsTransferWrite(t *testing.T, separator rune, header []string, rows [][]string) string {
	t.Helper()
	var buffer bytes.Buffer
	var writer = csv.NewWriter(&buffer)
	writer.Comma = separator
	_ = writer.Write(header)
	_ = writer.WriteAll(rows)
	var path = filepath.Join(t.TempDir(), "import.csv")
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func dnsTransferIndex(t *testing.T, header []string, column string) int {
	t.Helper()
	var index = slices.Index(header, column)
	if index < 0 {
		t.Fatalf("the export has no column %s: %v", column, header)
	}
	return index
}

func TestCliDnsmasqHostTransfer(t *testing.T) {
	var dnsmasqApi = dnsmasqApi(t)
	var domain = testDomain("csvh")
	var uuids = []string{
		createDnsmasqHost(t, dnsmasqApi, dnsmasq.Host{Host: "web", Domain: domain, Ip: "192.0.2.11", Hwaddr: "02:00:00:00:00:11",
			Description: "web server", Comments: "keep me"}),
		createDnsmasqHost(t, dnsmasqApi, dnsmasq.Host{Host: "db", Domain: domain, Ip: "192.0.2.12,2001:db8::12", Description: `db; "main"`}),
		createDnsmasqHost(t, dnsmasqApi, dnsmasq.Host{Host: "app", Domain: domain, Ip: "192.0.2.13", Cnames: "api." + domain}),
	}

	var path = filepath.Join(t.TempDir(), "hosts.csv")
	var exported = mustOpn(t, "/dnsmasq/host", "export", path)
	requireContains(t, exported, exported.stderr, "saved", "hosts to "+path)
	var content, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode())
	}
	var parsed, rows = dnsTransferRows(t, content, "hosts", domain)
	var header = parsed.Header
	var want = []string{"hostname", "domain", "local", "ip_address", "cnames", "client_id", "hw_address", "lease_time", "ignore", "set_tag", "description", "aliases"}
	if !slices.Equal(header, want) {
		t.Errorf("header %v, want %v", header, want)
	}
	var hostname, ip, description = dnsTransferIndex(t, header, "hostname"), dnsTransferIndex(t, header, "ip_address"), dnsTransferIndex(t, header, "description")
	if len(rows) != 3 || rows[0][hostname] != "web" || rows[1][hostname] != "db" || rows[2][hostname] != "app" {
		t.Fatalf("want the 3 hosts in the configured order: %v", rows)
	}
	if rows[1][ip] != "192.0.2.12,2001:db8::12" || rows[1][description] != `db; "main"` || rows[0][dnsTransferIndex(t, header, "hw_address")] != "02:00:00:00:00:11" {
		t.Errorf("unexpected values: %v", rows)
	}

	// change a description, add a host
	rows[0][description] = "web changed"
	var added = slices.Clone(rows[2])
	added[hostname], added[ip], added[description] = "new", "192.0.2.14", "added by import"
	added[dnsTransferIndex(t, header, "cnames")] = ""
	var importPath = dnsTransferWrite(t, ';', header, append(rows, added))

	var refused = mustFailOpn(t, "/dnsmasq/host", "import", importPath)
	requireContains(t, refused, refused.stderr, "confirm=yes")
	var imported = mustOpn(t, "/dnsmasq/host", "import", importPath, "confirm=yes")
	requireContains(t, imported, imported.stderr, "1 hosts added, 3 updated")
	var newHosts, findErr = dnsmasqApi.HostFindByFQDN("new", domain)
	for _, host := range newHosts {
		cleanupRemove(t, "dnsmasq host", host.Uuid, dnsmasqApi.HostRemove)
	}
	if findErr != nil || len(newHosts) != 1 || newHosts[0].Ip != "192.0.2.14" || newHosts[0].Description != "added by import" {
		t.Errorf("the added host: %+v %v", newHosts, findErr)
	}
	var web, _ = dnsmasqApi.HostGet(uuids[0])
	if web.Description != "web changed" || web.Comments != "keep me" || web.Hwaddr != "02:00:00:00:00:11" {
		t.Errorf("the updated host (comments must be kept): %+v", web)
	}
	if db, _ := dnsmasqApi.HostGet(uuids[1]); db.Ip != "192.0.2.12,2001:db8::12" || db.Description != `db; "main"` {
		t.Errorf("the unchanged host: %+v", db)
	}

	t.Run("field names, comma separated", func(t *testing.T) {
		var path = dnsTransferWrite(t, ',', []string{"host", "domain", "ip", "descr", "comments"},
			[][]string{{"app", domain, "192.0.2.13", "app, by field names", "a comment"}})
		var result = mustOpn(t, "/dnsmasq/host", "import", path, "confirm=yes")
		requireContains(t, result, result.stderr, "0 hosts added, 1 updated")
		if app, _ := dnsmasqApi.HostGet(uuids[2]); app.Description != "app, by field names" || app.Comments != "a comment" || app.Cnames != "api."+domain {
			t.Errorf("the updated host: %+v", app)
		}
	})

	t.Run("checked before sending", func(t *testing.T) {
		var path = dnsTransferWrite(t, ';', []string{"hostname", "domain", "ip", "ip_address"}, [][]string{{"x", domain, "192.0.2.1", "192.0.2.1"}})
		var result = mustFailOpn(t, "/dnsmasq/host", "import", path, "confirm=yes")
		requireContains(t, result, result.stderr, "the columns ip_address and ip are the same field")
		path = dnsTransferWrite(t, ';', []string{"hostname", "domain", "mac"}, [][]string{{"x", domain, "02:00:00:00:00:01"}})
		result = mustFailOpn(t, "/dnsmasq/host", "import", path, "confirm=yes")
		requireContains(t, result, result.stderr, "unknown columns mac", "valid are:", "hostname", "ip_address")
		if hosts, _ := dnsmasqApi.HostFindByFQDN("x", domain); len(hosts) != 0 {
			t.Errorf("a refused import added %v", hosts)
		}
	})

	t.Run("rejected rows", func(t *testing.T) {
		var path = dnsTransferWrite(t, ';', []string{"hostname", "domain", "ip_address"}, [][]string{{"bad", domain, "not-an-ip"}})
		var result = mustFailOpn(t, "/dnsmasq/host", "import", path, "confirm=yes")
		requireContains(t, result, result.stderr, "OPNsense rejected rows", "line 2: ip:")
		var hosts, _ = dnsmasqApi.HostFindByFQDN("bad", domain)
		for _, host := range hosts {
			cleanupRemove(t, "dnsmasq host", host.Uuid, dnsmasqApi.HostRemove)
		}
		if len(hosts) != 0 {
			t.Errorf("a rejected row was saved: %+v", hosts)
		}
	})
}

func TestCliUnboundHostOverrideTransfer(t *testing.T) {
	var unboundApi = unboundApi(t)
	var domain = testDomain("csvu")
	var webUuid = createUnboundOverride(t, unboundApi, unbound.HostOverride{Host: "web", Domain: domain, Rr: "A", Ip: "192.0.2.21", Description: "web"})
	createUnboundOverride(t, unboundApi, unbound.HostOverride{Host: "mail", Domain: domain, Rr: "MX", Mxprio: "10", Mx: "mx." + domain})

	var path = filepath.Join(t.TempDir(), "overrides.csv")
	var exported = runOpn(t, "/unbound/host-override", "export", path)
	if strings.Contains(exported.stderr, unbound.ErrHostOverrideCsvUnsupported.Error()) {
		// 26.7 to 26.7.7: the import fails the same way and adds nothing
		var importPath = dnsTransferWrite(t, ';', []string{"hostname", "domain", "rr", "server"}, [][]string{{"new", domain, "A", "192.0.2.24"}})
		var result = mustFailOpn(t, "/unbound/host-override", "import", importPath, "confirm=yes")
		requireContains(t, result, result.stderr, unbound.ErrHostOverrideCsvUnsupported.Error())
		if overrides, _ := unboundApi.HostOverrideSearch(domain); len(overrides) != 2 {
			t.Errorf("want only the 2 entries of the test: %+v", overrides)
		}
		t.Skip("this OPNsense has no host override CSV endpoints (newer than 26.7.7)")
	}
	if exported.exitCode != 0 {
		t.Fatalf("export failed:\n%s", exported)
	}
	var content, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var parsed, rows = dnsTransferRows(t, content, "host overrides", domain)
	var header = parsed.Header
	if len(header) == 0 || header[0] != "@uuid" {
		t.Errorf("header %v", header)
	}
	var uuid, hostname, description = dnsTransferIndex(t, header, "@uuid"), dnsTransferIndex(t, header, "hostname"), dnsTransferIndex(t, header, "description")
	if len(rows) != 2 || rows[0][uuid] != webUuid || rows[0][hostname] != "web" || rows[1][hostname] != "mail" {
		t.Fatalf("want the 2 entries in the configured order: %v", rows)
	}

	rows[0][description] = "web changed"
	var added = slices.Clone(rows[0])
	added[uuid], added[hostname], added[description] = "", "new", "added by import"
	added[dnsTransferIndex(t, header, "server")] = "192.0.2.24"
	var importPath = dnsTransferWrite(t, ';', header, append(rows, added))
	var imported = mustOpn(t, "/unbound/host-override", "import", importPath, "confirm=yes")
	var overrides, _ = unboundApi.HostOverrideSearch(domain)
	for _, override := range overrides {
		cleanupRemove(t, "unbound host override", override.Uuid, unboundApi.HostEntryRemove)
	}
	requireContains(t, imported, imported.stderr, "1 host overrides added, 2 updated")
	if web := getUnboundOverride(t, unboundApi, webUuid); web.Description != "web changed" || web.Ip != "192.0.2.21" {
		t.Errorf("the updated entry: %+v", web)
	}
	if newEntries, _ := unboundApi.HostOverrideFindByFQDN("new", domain, "A"); len(newEntries) != 1 || newEntries[0].Ip != "192.0.2.24" {
		t.Errorf("the added entry: %+v", newEntries)
	}
}
