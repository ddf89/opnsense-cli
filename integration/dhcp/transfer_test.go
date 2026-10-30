//go:build integration

package integrationdhcp

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
)

// export / import of the Kea reservations through the binary: export, edit a copy (change a description, add a
// reservation), import, check. Only this run's rows are imported (the export holds every reservation of the box)

// transferExport exports the reservations of menu and returns this run's rows
func transferExport(t *testing.T, menu string) api.Csv {
	t.Helper()
	var file = filepath.Join(t.TempDir(), "export.csv")
	var result = mustOpn(t, menu, "export", file)
	requireContains(t, result, result.stderr, "reservations to "+file)
	var info, statErr = os.Stat(file)
	if statErr != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the export must be mode 0600: %v %v", info, statErr)
	}
	var content, err = os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := api.ParseCsv(content, "reservations")
	if err != nil {
		t.Fatalf("export: %v\n%s", err, content)
	}
	if slices.Contains(parsed.Header, "subnet") {
		t.Errorf("the export has a subnet column now: %v", parsed.Header)
	}
	var hostnames, _ = parsed.Column("hostname")
	var own = parsed
	own.Rows = nil
	for i, row := range parsed.Rows {
		if ownedByRun(hostnames[i]) {
			own.Rows = append(own.Rows, row)
		}
	}
	return own
}

// transferSet sets column of the row whose hostname is host
func transferSet(t *testing.T, parsed api.Csv, host string, column string, value string) {
	t.Helper()
	var hostnames, _ = parsed.Column("hostname")
	var index = slices.Index(parsed.Header, column)
	for i := range parsed.Rows {
		if hostnames[i] == host && index >= 0 {
			parsed.Rows[i][index] = value
			return
		}
	}
	t.Fatalf("no row %s with a column %s in %v", host, column, parsed)
}

// transferRow returns a row of the columns of parsed from values (column -> value)
func transferRow(parsed api.Csv, values map[string]string) []string {
	var row = make([]string, len(parsed.Header))
	for i, column := range parsed.Header {
		row[i] = values[column]
	}
	return row
}

// transferWrite writes parsed as a ';' separated file and returns its path
func transferWrite(t *testing.T, parsed api.Csv) string {
	t.Helper()
	var buffer bytes.Buffer
	var writer = csv.NewWriter(&buffer)
	writer.Comma = ';'
	if err := writer.WriteAll(append([][]string{parsed.Header}, parsed.Rows...)); err != nil {
		t.Fatal(err)
	}
	var file = filepath.Join(t.TempDir(), "import.csv")
	if err := os.WriteFile(file, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// transferUuid returns the uuid of the reservation with this host name
func transferUuid(t *testing.T, menu string, host string) string {
	t.Helper()
	var printed = mustOpn(t, menu, "print", "json", "search="+host)
	for _, line := range strings.Split(strings.TrimSpace(printed.stdout), "\n") {
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) == nil && row["hostname"] == host {
			return row["uuid"].(string)
		}
	}
	t.Fatalf("no reservation %s:\n%s", host, printed)
	return ""
}

func TestCliKeaReservationTransfer4(t *testing.T) {
	const menu = "/kea/dhcp4/reservation"
	var subnet = testLabel("csv-v4")
	var subnetUuid = uuidFrom(t, mustOpn(t, "/kea/dhcp4/subnet", "add", "subnet=198.51.100.0/24", "description="+subnet, "auto-options=no"))
	t.Cleanup(func() { runOpn(t, "", "/kea/dhcp4/subnet", "remove", subnetUuid) })
	var hostMac, hostClient, hostNew = testHostname("csv-mac"), testHostname("csv-client"), testHostname("csv-new")
	var macUuid = uuidFrom(t, mustOpn(t, menu, "add", "ip-address=198.51.100.60", "mac-address=02:00:5e:10:00:c1",
		"hostname="+hostMac, "description="+testLabel("csv mac")))
	t.Cleanup(func() { runOpn(t, "", menu, "remove", macUuid) })
	var clientUuid = uuidFrom(t, mustOpn(t, menu, "add", "ip-address=198.51.100.61", "client-id=01:02:03:c2", "hostname="+hostClient))
	t.Cleanup(func() { runOpn(t, "", menu, "remove", clientUuid) })

	var exported = transferExport(t, menu)
	if len(exported.Rows) != 2 || !slices.Equal(exported.Header, []string{"ip_address", "hw_address", "client_id", "hostname", "description", "next_server", "option_data", "option"}) {
		t.Fatalf("export: %+v", exported)
	}
	transferSet(t, exported, hostMac, "description", testLabel("csv changed; by import"))
	exported.Rows = append(exported.Rows, transferRow(exported, map[string]string{"ip_address": "198.51.100.62", "hw_address": "02:00:5e:10:00:c3",
		"hostname": hostNew, "description": testLabel("csv new")}))
	var file = transferWrite(t, exported)

	mustFailOpn(t, menu, "import", file) // no confirmation non-interactively
	var imported = mustOpn(t, menu, "import", file, "confirm=yes")
	requireContains(t, imported, imported.stderr, "1 reservations added, 2 updated")
	var newUuid = transferUuid(t, menu, hostNew)
	t.Cleanup(func() { runOpn(t, "", menu, "remove", newUuid) })
	var show = mustOpn(t, menu, "show", macUuid)
	requireContains(t, show, show.stdout, testLabel("csv changed; by import"), "198.51.100.0/24")
	show = mustOpn(t, menu, "show", newUuid)
	requireContains(t, show, show.stdout, "198.51.100.62", "02:00:5e:10:00:c3", "198.51.100.0/24", testLabel("csv new"))
	show = mustOpn(t, menu, "show", clientUuid)
	requireContains(t, show, show.stdout, "01:02:03:c2", "198.51.100.61")

	// a row outside every subnet refuses the whole file before anything is sent
	exported.Rows = append(exported.Rows, transferRow(exported, map[string]string{"ip_address": "192.0.2.77", "hw_address": "02:00:5e:10:00:c4",
		"hostname": testHostname("csv-outside")}))
	transferSet(t, exported, hostNew, "description", testLabel("csv must not change"))
	var refused = mustFailOpn(t, menu, "import", transferWrite(t, exported), "confirm=yes")
	requireContains(t, refused, refused.stderr, "nothing was imported", "line 5: no DHCPv4 subnet contains 192.0.2.77")
	show = mustOpn(t, menu, "show", newUuid)
	requireContains(t, show, show.stdout, testLabel("csv new"))

	mustOpn(t, menu, "remove", newUuid)
	mustOpn(t, menu, "remove", clientUuid)
	mustOpn(t, menu, "remove", macUuid)
	mustOpn(t, "/kea/dhcp4/subnet", "remove", subnetUuid)
}

func TestCliKeaReservationTransfer6(t *testing.T) {
	const menu = "/kea/dhcp6/reservation"
	var dhcpApi = dhcpApi(t)
	keaDhcp6WithInterface(t, dhcpApi, "lan")
	var subnetUuid = uuidFrom(t, mustOpn(t, "/kea/dhcp6/subnet", "add", "subnet=2001:db8:a7::/64", "interface=lan", "description="+testLabel("csv-v6")))
	t.Cleanup(func() { runOpn(t, "", "/kea/dhcp6/subnet", "remove", subnetUuid) })
	var hostDuid, hostPrefix, hostNew = testHostname("csv6-duid"), testHostname("csv6-prefix"), testHostname("csv6-new")
	var duidUuid = uuidFrom(t, mustOpn(t, menu, "add", "ip-address=2001:db8:a7::60", "duid=00:01:00:01:aa:bb:cc:c1", "hostname="+hostDuid))
	t.Cleanup(func() { runOpn(t, "", menu, "remove", duidUuid) })
	var prefixUuid = uuidFrom(t, mustOpn(t, menu, "add", "subnet=2001:db8:a7::/64", "prefix=2001:db8:a7:0:100::/80",
		"mac-address=02:00:5e:10:00:c2", "hostname="+hostPrefix))
	t.Cleanup(func() { runOpn(t, "", menu, "remove", prefixUuid) })

	var exported = transferExport(t, menu)
	if len(exported.Rows) != 2 || !slices.Equal(exported.Header, []string{"ip_address", "prefix", "duid", "hw_address", "hostname", "domain_search", "option", "description"}) {
		t.Fatalf("export: %+v", exported)
	}
	transferSet(t, exported, hostPrefix, "description", testLabel("csv6 changed"))
	exported.Rows = append(exported.Rows, transferRow(exported, map[string]string{"ip_address": "2001:db8:a7::62", "duid": "00:01:00:01:aa:bb:cc:c3",
		"hostname": hostNew}))

	// the prefix-only reservation has no address to find its subnet by
	var refused = mustFailOpn(t, menu, "import", transferWrite(t, exported), "confirm=yes")
	requireContains(t, refused, refused.stderr, "nothing was imported", "there is no ip_address to find the subnet by, add a subnet column")

	exported.Header = append(exported.Header, "subnet")
	for i := range exported.Rows {
		exported.Rows[i] = append(exported.Rows[i], "2001:db8:a7::/64")
	}
	var imported = mustOpn(t, menu, "import", transferWrite(t, exported), "confirm=yes")
	requireContains(t, imported, imported.stderr, "1 reservations added, 2 updated")
	var newUuid = transferUuid(t, menu, hostNew)
	t.Cleanup(func() { runOpn(t, "", menu, "remove", newUuid) })
	var show = mustOpn(t, menu, "show", prefixUuid)
	requireContains(t, show, show.stdout, testLabel("csv6 changed"), "2001:db8:a7:0:100::/80")
	show = mustOpn(t, menu, "show", newUuid)
	requireContains(t, show, show.stdout, "2001:db8:a7::62", "00:01:00:01:aa:bb:cc:c3", "2001:db8:a7::/64")

	mustOpn(t, menu, "remove", newUuid)
	mustOpn(t, menu, "remove", prefixUuid)
	mustOpn(t, menu, "remove", duidUuid)
	mustOpn(t, "/kea/dhcp6/subnet", "remove", subnetUuid)
}
