//go:build integration

package integrationfirewall

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/firewall"
)

// shaperTransferExport runs export into a temp file and returns it parsed, with the header checked
func shaperTransferExport(t *testing.T, menu string, what string, columns []string) api.Csv {
	t.Helper()
	var file = filepath.Join(t.TempDir(), "export.csv")
	mustOpn(t, menu, "export", file)
	var content, err = os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := api.ParseCsv(content, what)
	if err != nil {
		t.Fatalf("export of %s: %v\n%s", menu, err, content)
	}
	if !reflect.DeepEqual(parsed.Header, columns) {
		t.Errorf("columns of the %s export changed:\ngot  %q\nwant %q", what, parsed.Header, columns)
	}
	return parsed
}

// shaperTransferRows returns the rows of parsed whose column has one of the values, in that order
func shaperTransferRows(t *testing.T, parsed api.Csv, column string, values ...string) [][]string {
	t.Helper()
	var cells, _ = parsed.Column(column)
	var rows [][]string
	for _, value := range values {
		for i, cell := range cells {
			if cell == value {
				rows = append(rows, append([]string(nil), parsed.Rows[i]...))
			}
		}
	}
	if len(rows) != len(values) {
		t.Fatalf("export lacks rows with %s %q:\n%q", column, values, parsed.Rows)
	}
	return rows
}

// shaperTransferWrite writes header and rows as a ';' separated file
func shaperTransferWrite(t *testing.T, header []string, rows ...[]string) string {
	t.Helper()
	var lines = []string{strings.Join(header, ";")}
	for _, row := range rows {
		lines = append(lines, strings.Join(row, ";"))
	}
	var file = filepath.Join(t.TempDir(), "import.csv")
	if err := os.WriteFile(file, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func shaperTransferSet(t *testing.T, header []string, row []string, values map[string]string) []string {
	t.Helper()
	for name, value := range values {
		var found = false
		for i, column := range header {
			if column == name {
				row[i], found = value, true
			}
		}
		if !found {
			t.Fatalf("no column %s in %q", name, header)
		}
	}
	return row
}

// TestCliShaperTransfer exports pipes and queues, imports an edited copy that changes this run's records and adds
// new ones (all disabled), and checks the numbering and the pipe mapping. Nothing is applied
func TestCliShaperTransfer(t *testing.T) {
	var core = coreApi(t)
	var fw = &firewall.FirewallApi{OPNsense: core}
	var pipe1Description, pipe2Description = testDescription("transfer-pipe1"), testDescription("transfer-pipe2")
	var queue1Description, queue2Description = testDescription("transfer-queue1"), testDescription("transfer-queue2")

	var pipe1 = uuidFrom(t, mustOpn(t, "/firewall/shaper/pipe", "add", "bandwidth=64Kbit", "description="+pipe1Description, "disabled"))
	shaperCleanup(t, core, "pipe", pipe1)
	var queue1 = uuidFrom(t, mustOpn(t, "/firewall/shaper/queue", "add", "pipe="+pipe1, "weight=10", "description="+queue1Description, "disabled"))
	shaperCleanup(t, core, "queue", queue1)

	// pipes: change pipe1, add pipe2 without @uuid and number
	var pipes = shaperTransferExport(t, "/firewall/shaper/pipe", "pipes", firewall.ShaperPipeCsvColumns)
	var row = shaperTransferRows(t, pipes, "@uuid", pipe1)[0]
	var pipe1Number = row[1]
	var changed = shaperTransferSet(t, pipes.Header, append([]string(nil), row...), map[string]string{"bandwidth": "48"})
	var added = shaperTransferSet(t, pipes.Header, append([]string(nil), row...), map[string]string{"@uuid": "", "number": "",
		"bandwidth": "32", "origin": "", "description": pipe2Description})

	// a number used by another pipe is refused before anything is sent
	var clash = shaperTransferSet(t, pipes.Header, append([]string(nil), added...), map[string]string{"number": pipe1Number})
	var refused = mustFailOpn(t, "/firewall/shaper/pipe", "import", shaperTransferWrite(t, pipes.Header, clash), "confirm=yes")
	requireContains(t, refused, refused.stderr, "the number "+pipe1Number+" is used by the pipe")

	var imported = mustOpn(t, "/firewall/shaper/pipe", "import", shaperTransferWrite(t, pipes.Header, changed, added), "confirm=yes")
	requireContains(t, imported, imported.stderr, "1 pipes added, 1 updated")
	var found, err = fw.ShaperPipeFindByDescription(pipe2Description)
	if err != nil || len(found) != 1 {
		t.Fatalf("pipe2 after the import: %+v / %v", found, err)
	}
	var pipe2 = found[0].Uuid
	shaperCleanup(t, core, "pipe", pipe2)
	all, err := fw.ShaperPipeList("")
	if err != nil {
		t.Fatal(err)
	}
	for _, pipe := range all {
		switch {
		case pipe.Uuid == pipe1 && (pipe.Bandwidth != "48" || pipe.Number != pipe1Number || pipe.Enabled != "0"):
			t.Errorf("pipe1 after the import: %+v", pipe)
		case pipe.Uuid == pipe2 && (pipe.Bandwidth != "32" || pipe.Number == "" || pipe.Enabled != "0"):
			t.Errorf("pipe2 after the import: %+v", pipe)
		case pipe.Uuid != pipe2 && pipe.Number == found[0].Number:
			t.Errorf("pipe2 got the number %s of %s", pipe.Number, pipe.Uuid)
		}
	}

	// queues: change queue1, add queue2 on pipe2 given by description
	var queues = shaperTransferExport(t, "/firewall/shaper/queue", "queues", firewall.ShaperQueueCsvColumns)
	row = shaperTransferRows(t, queues, "@uuid", queue1)[0]
	if cells, _ := (api.Csv{Header: queues.Header, Rows: [][]string{row}}).Column("pipe"); cells[0] != pipe1 {
		t.Errorf("the export must name the pipe by uuid: %q", row)
	}
	changed = shaperTransferSet(t, queues.Header, append([]string(nil), row...), map[string]string{"weight": "20"})
	added = shaperTransferSet(t, queues.Header, append([]string(nil), row...), map[string]string{"@uuid": "", "number": "",
		"pipe": pipe2Description, "weight": "30", "origin": "", "description": queue2Description})
	refused = mustFailOpn(t, "/firewall/shaper/queue", "import", shaperTransferWrite(t, queues.Header,
		shaperTransferSet(t, queues.Header, append([]string(nil), added...), map[string]string{"pipe": runPrefix + " no such pipe"})), "confirm=yes")
	requireContains(t, refused, refused.stderr, "there is no pipe")

	imported = mustOpn(t, "/firewall/shaper/queue", "import", shaperTransferWrite(t, queues.Header, changed, added), "confirm=yes")
	requireContains(t, imported, imported.stderr, "1 queues added, 1 updated")
	foundQueues, err := fw.ShaperQueueFindByDescription(queue2Description)
	if err != nil || len(foundQueues) != 1 {
		t.Fatalf("queue2 after the import: %+v / %v", foundQueues, err)
	}
	shaperCleanup(t, core, "queue", foundQueues[0].Uuid)
	if queue := foundQueues[0]; queue.Pipe != pipe2 || queue.Weight != "30" || queue.Enabled != "0" || queue.Number == "" {
		t.Errorf("queue2 after the import: %+v", queue)
	}
	if rows := shaperRawRows(t, core, "queue", queue1); len(rows) != 1 || rows[0]["weight"] != "20" || rows[0]["pipe"] != pipe1 {
		t.Errorf("queue1 after the import: %v", rows)
	}
}

// TestCliCategoryTransfer exports the categories and imports an edited copy that changes this run's category and
// adds one
func TestCliCategoryTransfer(t *testing.T) {
	var fw = groupFirewallApi(t)
	var name1, name2 = namePrefix() + " transfer1", namePrefix() + " transfer2"
	const menu = "/firewall/category"

	categoryCleanup(t, fw, uuidFrom(t, mustOpn(t, menu, "add", "name="+name1, "color=ff8800")))
	var categories = shaperTransferExport(t, menu, "categories", firewall.CategoryCsvColumns)
	shaperTransferRows(t, categories, "name", name1)

	var refused = mustFailOpn(t, menu, "import", shaperTransferWrite(t, []string{"name", "color", "auto"}, []string{name2, "", "1"}), "confirm=yes")
	requireContains(t, refused, refused.stderr, "unknown columns auto")

	var imported = mustOpn(t, menu, "import", shaperTransferWrite(t, categories.Header, []string{name1, "00ff00"}, []string{name2, "abcdef"}), "confirm=yes")
	requireContains(t, imported, imported.stderr, "1 categories added, 1 updated")
	var added, err = fw.CategoryGetByName(name2)
	if err != nil {
		t.Fatalf("the imported category: %v", err)
	}
	categoryCleanup(t, fw, added.Uuid)
	if added.Color != "abcdef" || added.Auto {
		t.Errorf("the imported category: %+v", added)
	}
	if changed, err := fw.CategoryGetByName(name1); err != nil || changed.Color != "00ff00" {
		t.Errorf("the updated category: %+v / %v", changed, err)
	}
}
