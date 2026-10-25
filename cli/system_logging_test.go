package cli

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const (
	systemLoggingGetPath         = "/api/syslog/settings/get"
	systemLoggingSetPath         = "/api/syslog/settings/set"
	systemLoggingSearchDestPath  = "/api/syslog/settings/search_destinations"
	systemLoggingGetDestPath     = "/api/syslog/settings/get_destination/"
	systemLoggingAddDestPath     = "/api/syslog/settings/add_destination"
	systemLoggingSetDestPath     = "/api/syslog/settings/set_destination/"
	systemLoggingDelDestPath     = "/api/syslog/settings/del_destination/"
	systemLoggingToggleDestPath  = "/api/syslog/settings/toggle_destination/"
	systemLoggingStatusPath      = "/api/syslog/service/status"
	systemLoggingRestartPath     = "/api/syslog/service/restart"
	systemLoggingReconfigurePath = "/api/syslog/service/reconfigure"
	systemLoggingStatsPath       = "/api/syslog/service/stats"

	systemLoggingDestUuid = "2e9349d9-ee68-47ce-9cfc-f4ba1d5bb47a"
)

// --- fixtures, trimmed copies of OPNsense 26.7 answers

const systemLoggingSettings = `{"syslog":{"general":{"enabled":"1","loglocal":"1","maxpreserve":"31","maxfilesize":""},` +
	`"destinations":{"destination":{}}}}`

func systemLoggingDestinationRow(overrides map[string]any) map[string]any {
	var row = map[string]any{
		"uuid": "", "enabled": "0", "transport": "udp4", "%transport": "UDP(4)", "program": "filterlog,unbound",
		"%program": "filter (filterlog), resolver (unbound)", "level": "info,err", "%level": "info, error",
		"facility": "kern,local0", "%facility": "kernel messages, locally used (0)", "hostname": "192.0.2.10",
		"certificate": "", "port": "1514", "rfc5424": "0", "description": "siem",
	}
	maps.Copy(row, overrides)
	return row
}

// systemLoggingDestinationGet is get_destination/<uuid> with option maps (trimmed)
func systemLoggingDestinationGet(description string) string {
	var quoted, _ = json.Marshal(description)
	return `{"destination":{"enabled":"0",` +
		`"transport":{"udp4":{"value":"UDP(4)","selected":1},"tcp4":{"value":"TCP(4)","selected":0},"udp6":{"value":"UDP(6)","selected":0}},` +
		`"program":{"audit":{"value":"audit (audit)","selected":0},"filterlog":{"value":"filter (filterlog)","selected":1},"unbound":{"value":"resolver (unbound)","selected":1}},` +
		`"level":{"debug":{"value":"debug","selected":0},"info":{"value":"info","selected":1},"err":{"value":"error","selected":1}},` +
		`"facility":{"kern":{"value":"kernel messages","selected":1},"user":{"value":"user-level messages","selected":0},"local0":{"value":"locally used (0)","selected":1}},` +
		`"hostname":"192.0.2.10","certificate":{"":{"value":"None","selected":1},"6add3e24dc0a9":{"value":"Web GUI TLS certificate","selected":0}},` +
		`"port":"1514","rfc5424":"0","description":` + string(quoted) + `}}`
}

const systemLoggingStatsAnswer = `{"total":3,"rowCount":9999,"current":1,"rows":[` +
	`{"#":"1350a2e3","Description":"","SourceName":"dst.program","SourceId":"d_config_changed_event#0","SourceInstance":"/usr/local/sbin/configctl","State":"a","Type":"processed","Number":"228"},` +
	`{"#":"92b5447b","Description":"","SourceName":"global","SourceId":"scratch_buffers_count","SourceInstance":"","State":"a","Type":"queued","Number":"3"},` +
	`{"#":"6e7c40f9","Description":"","SourceName":"destination","SourceId":"d_local_portalauth","SourceInstance":"","State":"a","Type":"dropped","Number":"0"}]}`

// systemLoggingFake serves the general settings, the destination search (target "siem" plus decoys) and get_destination
func systemLoggingFake(t *testing.T, extraRows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", systemLoggingGetPath, 200, systemLoggingSettings)
	var rows = append([]map[string]any{
		systemLoggingDestinationRow(map[string]any{"uuid": systemLoggingDestUuid}),
		systemLoggingDestinationRow(map[string]any{"uuid": "d-siem-backup", "description": "siem backup", "enabled": "1"}),
		systemLoggingDestinationRow(map[string]any{"uuid": "d-old-siem", "description": "old siem"}),
	}, extraRows...)
	f.search(systemLoggingSearchDestPath, rows...)
	f.on("GET", systemLoggingGetDestPath+systemLoggingDestUuid, 200, systemLoggingDestinationGet("siem"))
	f.on("GET", systemLoggingGetDestPath+"d-siem-backup", 200, systemLoggingDestinationGet("siem backup"))
	f.on("GET", systemLoggingGetDestPath+"d-unknown", 200, `[]`) // OPNsense answers unknown uuids with an empty array
	return f
}

// --- helpers

var systemLoggingColumnSeparator = regexp.MustCompile(`\s{2,}`)

// systemLoggingTable splits table output into cells (columns are separated by at least two spaces)
func systemLoggingTable(output string) [][]string {
	var rows [][]string
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			rows = append(rows, systemLoggingColumnSeparator.Split(strings.TrimSpace(line), -1))
		}
	}
	return rows
}

// systemLoggingWantTable asserts the header and that the cells of column of the data rows are want, in this order
func systemLoggingWantTable(t *testing.T, output string, header []string, column int, want ...string) [][]string {
	t.Helper()
	var rows = systemLoggingTable(output)
	if len(rows) == 0 {
		t.Fatalf("no table in output:\n%s", output)
	}
	if strings.Join(rows[0], "|") != strings.Join(header, "|") {
		t.Errorf("table header %q, want %q", rows[0], header)
	}
	var got []string
	for _, row := range rows[1:] {
		if len(row) != len(header) {
			t.Errorf("row has %d cells, header %d: %q", len(row), len(header), row)
			continue
		}
		got = append(got, row[column])
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("table column %d: %q, want %q\n%s", column, got, want, output)
	}
	return rows
}

// systemLoggingFields parses "name: value" lines
func systemLoggingFields(output string) map[string]string {
	var fields = map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if name, value, found := strings.Cut(line, ":"); found {
			fields[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	return fields
}

func systemLoggingName(args []string) string {
	return strings.ReplaceAll(fmt.Sprint(args), " ", "_")
}

func systemLoggingDest(args ...string) []string {
	return append([]string{"/system/logging/destination"}, args...)
}

// --- general settings

func TestSystemLoggingPrint(t *testing.T) {
	t.Parallel()
	var f = systemLoggingFake(t)
	var r = f.run("/system/logging", "print")
	wantExit(t, r, 0)
	var fields = systemLoggingFields(r.stdout)
	for key, want := range map[string]string{"enabled": "yes", "local": "yes", "max-preserve": "31", "max-file-size": ""} {
		if got, ok := fields[key]; !ok || got != want {
			t.Errorf("%s: got %q (present %v), want %q\n%s", key, got, ok, want, r.stdout)
		}
	}
	wantNoMutations(t, f)

	t.Run("json", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t)
		var r = f.run("/system/logging", "print", "json")
		wantExit(t, r, 0)
		if got := strings.TrimSpace(r.stdout); got != `{"enabled":"1","loglocal":"1","maxpreserve":"31","maxfilesize":""}` {
			t.Errorf("json: %s", got)
		}
	})
}

func TestSystemLoggingSet(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args []string
		want map[string]any
	}{
		{[]string{"max-preserve=10"}, map[string]any{"maxpreserve": "10"}},
		{[]string{"local=no"}, map[string]any{"loglocal": "0"}},
		{[]string{"enabled"}, map[string]any{"enabled": "1"}},
		{[]string{"max-file-size="}, map[string]any{"maxfilesize": ""}},
		{[]string{"max-file-size=100", "enabled=no"}, map[string]any{"maxfilesize": "100", "enabled": "0"}},
	} {
		t.Run(systemLoggingName(tc.args), func(t *testing.T) {
			t.Parallel()
			var f = systemLoggingFake(t)
			f.on("POST", systemLoggingSetPath, 200, answerSaved)
			var r = f.run(append([]string{"/system/logging", "set"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("set must be silent, got %q", r.stdout)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", systemLoggingSetPath), map[string]any{"syslog": map[string]any{"general": tc.want}})
		})
	}

	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"nothing to change", nil, []string{"nothing to change"}},
		{"max-preserve not a number", []string{"max-preserve=abc"}, []string{"max-preserve"}},
		{"max-preserve negative", []string{"max-preserve=-1"}, []string{"max-preserve"}},
		{"max-preserve empty", []string{"max-preserve="}, []string{"max-preserve", "empty"}},
		{"max-file-size not a number", []string{"max-file-size=10M"}, []string{"max-file-size"}},
		{"invalid bool", []string{"local=maybe"}, []string{"local"}},
		{"unknown argument", []string{"loglocal=yes"}, []string{"loglocal"}},
	} {
		t.Run(tc.name+", no API call", func(t *testing.T) {
			t.Parallel()
			var f = systemLoggingFake(t)
			wantFailure(t, f.run(append([]string{"/system/logging", "set"}, tc.args...)...), tc.wants...)
			wantNoCalls(t, f)
		})
	}

	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t)
		f.on("POST", systemLoggingSetPath, 200, answerValidation("syslog.general.maxpreserve", "Value out of range."))
		wantFailure(t, f.run("/system/logging", "set", "max-preserve=99999"), "syslog.general.maxpreserve", "Value out of range.")
	})
}

func TestSystemLoggingStats(t *testing.T) {
	t.Parallel()
	var header = []string{"SOURCE", "ID", "INSTANCE", "STATE", "TYPE", "NUMBER"}

	var f = newFakeOPN(t)
	f.on("GET", systemLoggingStatsPath, 200, systemLoggingStatsAnswer)
	var r = f.run("/system/logging", "stats")
	wantExit(t, r, 0)
	// sorted by source
	systemLoggingWantTable(t, r.stdout, header, 0, "destination", "dst.program", "global")
	wantNoMutations(t, f)

	t.Run("search filters case-insensitive", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", systemLoggingStatsPath, 200, systemLoggingStatsAnswer)
		var r = f.run("/system/logging", "stats", "search=PORTALAUTH")
		wantExit(t, r, 0)
		systemLoggingWantTable(t, r.stdout, header, 0, "destination")
	})
	t.Run("json", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", systemLoggingStatsPath, 200, systemLoggingStatsAnswer)
		var r = f.run("/system/logging", "stats", "json", "search=a")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != 3 {
			t.Fatalf("want 3 ndjson lines, got:\n%s", r.stdout)
		}
		var first map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &first); err != nil || first["SourceName"] != "destination" || first["Number"] != "0" {
			t.Errorf("first line %s (%v)", lines[0], err)
		}
	})
}

// --- destinations

func TestSystemLoggingDestinationPrint(t *testing.T) {
	t.Parallel()
	var header = []string{"#", "DISABLED", "TRANSPORT", "HOSTNAME", "PORT", "PROGRAM", "LEVEL", "FACILITY", "DESCRIPTION"}

	var f = systemLoggingFake(t)
	var r = f.run(systemLoggingDest("print")...)
	wantExit(t, r, 0)
	var rows = systemLoggingWantTable(t, r.stdout, header, 0, "0", "1", "2")
	if len(rows) > 1 {
		if got := strings.Join(rows[1][1:], "|"); got != "yes|udp4|192.0.2.10|1514|filterlog,unbound|info,err|kern,local0|siem" {
			t.Errorf("row 0: %s", got)
		}
	}
	wantSearchPhrases(t, f, systemLoggingSearchDestPath, "")
	wantNoMutations(t, f)

	t.Run("search is passed on", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t)
		var r = f.run(systemLoggingDest("print", "search=backup")...)
		wantExit(t, r, 0)
		systemLoggingWantTable(t, r.stdout, header, 8, "siem backup")
		wantSearchPhrases(t, f, systemLoggingSearchDestPath, "backup")
	})
	t.Run("detail", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t)
		var r = f.run(systemLoggingDest("print", "detail")...)
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "uuid:", systemLoggingDestUuid, "disabled:", "d-siem-backup", "d-old-siem", "certificate:", "rfc5424:", "description:  old siem")
	})
	t.Run("json is the raw rows", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t)
		var r = f.run(systemLoggingDest("print", "json")...)
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != 3 {
			t.Fatalf("want 3 lines:\n%s", r.stdout)
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &row); err != nil || row["uuid"] != systemLoggingDestUuid || row["%transport"] != "UDP(4)" {
			t.Errorf("line 0: %s (%v)", lines[0], err)
		}
	})
}

func TestSystemLoggingDestinationShow(t *testing.T) {
	t.Parallel()
	for _, item := range []string{systemLoggingDestUuid, "siem", "SIEM", "0", "item=siem"} {
		t.Run(item, func(t *testing.T) {
			t.Parallel()
			var f = systemLoggingFake(t)
			var r = f.run(systemLoggingDest("show", item)...)
			wantExit(t, r, 0)
			var fields = systemLoggingFields(r.stdout)
			for key, want := range map[string]string{
				"uuid": systemLoggingDestUuid, "disabled": "yes", "transport": "udp4", "hostname": "192.0.2.10", "port": "1514",
				"program": "filterlog,unbound", "level": "info,err", "facility": "kern,local0", "certificate": "",
				"rfc5424": "no", "description": "siem",
			} {
				if got, ok := fields[key]; !ok || got != want {
					t.Errorf("%s: got %q (present %v), want %q\n%s", key, got, ok, want, r.stdout)
				}
			}
			wantNoMutations(t, f)
		})
	}

	t.Run("ambiguous description lists the uuids", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t, systemLoggingDestinationRow(map[string]any{"uuid": "d-dup", "description": "siem"}))
		wantFailure(t, f.run(systemLoggingDest("show", "siem")...), systemLoggingDestUuid, "d-dup")
	})
	for _, item := range []string{"d-unknown", "sie", "3"} {
		t.Run("unknown "+item, func(t *testing.T) {
			t.Parallel()
			var f = systemLoggingFake(t)
			wantFailure(t, f.run(systemLoggingDest("show", item)...), "not found")
		})
	}
	t.Run("no item, no API call", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t)
		wantFailure(t, f.run(systemLoggingDest("show")...), "item")
		wantNoCalls(t, f)
	})
}

func TestSystemLoggingDestinationAdd(t *testing.T) {
	t.Parallel()

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t)
		f.on("POST", systemLoggingAddDestPath, 200, answerAdded("d-new"))
		var r = f.run(systemLoggingDest("add", "hostname=192.0.2.10")...)
		wantExit(t, r, 0)
		if strings.TrimSpace(r.stdout) != "d-new" {
			t.Errorf("stdout: want the uuid, got %q", r.stdout)
		}
		wantJSON(t, wantOneMutation(t, f, "POST", systemLoggingAddDestPath), map[string]any{"destination": map[string]any{
			"enabled": "1", "transport": "udp4", "program": "", "level": "", "facility": "", "hostname": "192.0.2.10",
			"certificate": "", "port": "514", "rfc5424": "0", "description": "",
		}})
	})
	t.Run("all arguments", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t)
		f.on("POST", systemLoggingAddDestPath, 200, answerAdded("d-new"))
		var r = f.run(systemLoggingDest("add", "hostname=2001:db8::10", "transport=TLS6", "port=6514", "program=filterlog",
			"level=err, CRIT", "facility=local0,local7", "certificate=6add3e24dc0a9", "rfc5424", "disabled", "description=remote")...)
		wantExit(t, r, 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemLoggingAddDestPath), map[string]any{"destination": map[string]any{
			"enabled": "0", "transport": "tls6", "program": "filterlog", "level": "err,crit", "facility": "local0,local7",
			"hostname": "2001:db8::10", "certificate": "6add3e24dc0a9", "port": "6514", "rfc5424": "1", "description": "remote",
		}})
	})
	t.Run("existing description fails", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t)
		wantFailure(t, f.run(systemLoggingDest("add", "hostname=192.0.2.11", "description=SIEM")...), "exists", systemLoggingDestUuid, "replace")
		wantNoMutations(t, f)
	})
	t.Run("replace replaces the existing destination completely", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t)
		f.on("POST", systemLoggingSetDestPath+systemLoggingDestUuid, 200, answerSaved)
		var r = f.run(systemLoggingDest("add", "hostname=192.0.2.11", "description=siem", "replace")...)
		wantExit(t, r, 0)
		if strings.TrimSpace(r.stdout) != systemLoggingDestUuid {
			t.Errorf("stdout: want the uuid, got %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, "replaced the existing destination")
		wantJSON(t, wantOneMutation(t, f, "POST", systemLoggingSetDestPath+systemLoggingDestUuid), map[string]any{"destination": map[string]any{
			"enabled": "1", "transport": "udp4", "program": "", "level": "", "facility": "", "hostname": "192.0.2.11",
			"certificate": "", "port": "514", "rfc5424": "0", "description": "siem",
		}})
	})
	t.Run("replace without existing destination adds", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t)
		f.on("POST", systemLoggingAddDestPath, 200, answerAdded("d-new"))
		wantExit(t, f.run(systemLoggingDest("add", "hostname=192.0.2.11", "description=new", "replace")...), 0)
		wantOneMutation(t, f, "POST", systemLoggingAddDestPath)
	})
	t.Run("replace of an ambiguous description", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t, systemLoggingDestinationRow(map[string]any{"uuid": "d-dup", "description": "siem"}))
		wantFailure(t, f.run(systemLoggingDest("add", "hostname=h", "description=siem", "replace")...), systemLoggingDestUuid, "d-dup")
		wantNoMutations(t, f)
	})

	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"hostname is required", nil, []string{"hostname"}},
		{"empty hostname", []string{"hostname= "}, []string{"hostname"}},
		{"unknown transport", []string{"hostname=h", "transport=udp"}, []string{"transport", "udp"}},
		{"two transports", []string{"hostname=h", "transport=udp4,tcp4"}, []string{"transport"}},
		{"empty transport", []string{"hostname=h", "transport="}, []string{"transport"}},
		{"port out of range", []string{"hostname=h", "port=65536"}, []string{"port"}},
		{"port not a number", []string{"hostname=h", "port=syslog"}, []string{"port"}},
		{"empty port", []string{"hostname=h", "port="}, []string{"port"}},
		{"unknown level", []string{"hostname=h", "level=info,verbose"}, []string{"level", "verbose"}},
		{"unknown facility", []string{"hostname=h", "facility=kernel"}, []string{"facility", "kernel"}},
	} {
		t.Run(tc.name+", no API call", func(t *testing.T) {
			t.Parallel()
			var f = systemLoggingFake(t)
			wantFailure(t, f.run(systemLoggingDest(append([]string{"add"}, tc.args...)...)...), tc.wants...)
			wantNoCalls(t, f)
		})
	}

	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t)
		f.on("POST", systemLoggingAddDestPath, 200,
			`{"result":"failed","validations":{"destination.transport":"Transport protocol does not match address in hostname"}}`)
		wantFailure(t, f.run(systemLoggingDest("add", "hostname=192.0.2.10", "transport=udp6")...), "destination.transport", "does not match")
	})
}

func TestSystemLoggingDestinationSet(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		want map[string]any
	}{
		{"by uuid, only the changed field", []string{systemLoggingDestUuid, "port=1515"}, map[string]any{"port": "1515"}},
		{"by description", []string{"siem", "level=err"}, map[string]any{"level": "err"}},
		{"by #", []string{"0", "level=err"}, map[string]any{"level": "err"}},
		{"clear a list", []string{systemLoggingDestUuid, "program="}, map[string]any{"program": ""}},
		{"booleans", []string{systemLoggingDestUuid, "disabled", "rfc5424"}, map[string]any{"enabled": "0", "rfc5424": "1"}},
		{"enable with disabled=no", []string{systemLoggingDestUuid, "disabled=no"}, map[string]any{"enabled": "1"}},
		{"rename", []string{"siem", "description=siem2"}, map[string]any{"description": "siem2"}},
		{"transport and hostname", []string{systemLoggingDestUuid, "transport=tcp6", "hostname=2001:db8::1"},
			map[string]any{"transport": "tcp6", "hostname": "2001:db8::1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = systemLoggingFake(t)
			f.on("POST", systemLoggingSetDestPath+systemLoggingDestUuid, 200, answerSaved)
			var r = f.run(systemLoggingDest(append([]string{"set"}, tc.args...)...)...)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("set must be silent, got %q", r.stdout)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", systemLoggingSetDestPath+systemLoggingDestUuid), map[string]any{"destination": tc.want})
		})
	}

	for _, tc := range []struct {
		name    string
		args    []string
		wants   []string
		noCalls bool
	}{
		{"nothing to change", []string{systemLoggingDestUuid}, []string{"nothing to change"}, true},
		{"empty transport", []string{systemLoggingDestUuid, "transport="}, []string{"transport"}, true},
		{"empty hostname", []string{systemLoggingDestUuid, "hostname="}, []string{"hostname"}, true},
		{"invalid port", []string{systemLoggingDestUuid, "port=0"}, []string{"port"}, true},
		{"invalid level", []string{systemLoggingDestUuid, "level=loud"}, []string{"loud"}, true},
		{"no item", []string{"port=1515"}, []string{"item"}, true},
		{"replace is only for add", []string{systemLoggingDestUuid, "replace=yes"}, []string{"replace"}, true},
		{"unknown uuid", []string{"d-unknown", "port=1515"}, []string{"not found"}, false},
		{"description is a substring only", []string{"sie", "port=1515"}, []string{"not found"}, false},
	} {
		t.Run(tc.name+", no change", func(t *testing.T) {
			t.Parallel()
			var f = systemLoggingFake(t)
			wantFailure(t, f.run(systemLoggingDest(append([]string{"set"}, tc.args...)...)...), tc.wants...)
			if tc.noCalls {
				wantNoCalls(t, f)
			}
			wantNoMutations(t, f)
		})
	}

	t.Run("ambiguous description", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t, systemLoggingDestinationRow(map[string]any{"uuid": "d-dup", "description": "siem"}))
		wantFailure(t, f.run(systemLoggingDest("set", "siem", "port=1")...), systemLoggingDestUuid, "d-dup")
		wantNoMutations(t, f)
	})
	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t)
		f.on("POST", systemLoggingSetDestPath+systemLoggingDestUuid, 200, answerValidation("destination.transport", "Transport protocol does not match"))
		wantFailure(t, f.run(systemLoggingDest("set", systemLoggingDestUuid, "transport=udp6")...), "destination.transport", "does not match")
	})
	t.Run("# refers to the last print of the session", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t)
		f.on("POST", systemLoggingSetDestPath+"d-siem-backup", 200, answerSaved)
		var r = f.runScript("/system/logging/destination\nprint search=backup\nset 0 port=1515\n")
		wantExit(t, r, 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemLoggingSetDestPath+"d-siem-backup"), map[string]any{"destination": map[string]any{"port": "1515"}})
	})
}

func TestSystemLoggingDestinationRemoveEnableDisable(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args   []string
		path   string
		answer string
		stderr string
	}{
		{[]string{"remove", systemLoggingDestUuid}, systemLoggingDelDestPath + systemLoggingDestUuid, answerDeleted, ""},
		{[]string{"remove", "siem"}, systemLoggingDelDestPath + systemLoggingDestUuid, answerDeleted, ""},
		{[]string{"remove", "1"}, systemLoggingDelDestPath + "d-siem-backup", answerDeleted, ""},
		{[]string{"enable", "siem"}, systemLoggingToggleDestPath + systemLoggingDestUuid + "/1", `{"result":"Enabled","changed":true}`, ""},
		{[]string{"disable", systemLoggingDestUuid}, systemLoggingToggleDestPath + systemLoggingDestUuid + "/0", `{"result":"Disabled","changed":false}`, "is already disabled"},
	} {
		t.Run(systemLoggingName(tc.args), func(t *testing.T) {
			t.Parallel()
			var f = systemLoggingFake(t)
			f.on("POST", tc.path, 200, tc.answer)
			var r = f.run(systemLoggingDest(tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("must be silent, got %q", r.stdout)
			}
			wantContains(t, "stderr", r.stderr, tc.stderr)
			wantOneMutation(t, f, "POST", tc.path)
		})
	}

	for _, command := range []string{"remove", "enable", "disable"} {
		t.Run(command+" ambiguous / unknown / no item make no change", func(t *testing.T) {
			t.Parallel()
			var f = systemLoggingFake(t, systemLoggingDestinationRow(map[string]any{"uuid": "d-dup", "description": "siem"}))
			wantFailure(t, f.run(systemLoggingDest(command, "siem")...), systemLoggingDestUuid, "d-dup")
			wantFailure(t, f.run(systemLoggingDest(command, "nope")...), "not found")
			wantFailure(t, f.run(systemLoggingDest(command, "d-unknown")...), "not found")
			wantFailure(t, f.run(systemLoggingDest(command, "4")...), "not found")
			wantFailure(t, f.run(systemLoggingDest(command)...), "item")
			wantNoMutations(t, f)
		})
	}

	t.Run("remove of a destination deleted meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t)
		f.on("POST", systemLoggingDelDestPath+systemLoggingDestUuid, 200, answerNotFound)
		wantFailure(t, f.run(systemLoggingDest("remove", systemLoggingDestUuid)...), "not found")
	})
	t.Run("enable of a destination deleted meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = systemLoggingFake(t)
		f.on("POST", systemLoggingToggleDestPath+systemLoggingDestUuid+"/1", 200, answerFailedBare)
		wantFailure(t, f.run(systemLoggingDest("enable", systemLoggingDestUuid)...), "not found")
	})
}

// --- service

func TestSystemLoggingService(t *testing.T) {
	t.Parallel()

	t.Run("status", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", systemLoggingStatusPath, 200, `{"status":"running","widget":{"caption_restart":"Restart","caption_start":"Start","caption_stop":"Stop"}}`)
		var r = f.run("/system/logging/service", "status")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "status:", "running")
		wantNoMutations(t, f)
	})
	for _, tc := range []struct {
		command string
		path    string
		answer  string
	}{
		{"restart", systemLoggingRestartPath, `{"response":"OK"}`},
		{"reconfigure", systemLoggingReconfigurePath, `{"status":"ok"}`},
	} {
		t.Run(tc.command+" is a POST", func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on("POST", tc.path, 200, tc.answer)
			var r = f.run("/system/logging/service", tc.command)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("must be silent, got %q", r.stdout)
			}
			wantOneMutation(t, f, "POST", tc.path)
			if calls := f.calls(); len(calls) != 1 {
				t.Errorf("want a single call, got %v", calls)
			}
		})
	}
	t.Run("reconfigure failure", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("POST", systemLoggingReconfigurePath, 200, `{"status":"failed","status_msg":"syslog-ng config invalid"}`)
		wantFailure(t, f.run("/system/logging/service", "reconfigure"), "syslog-ng config invalid")
	})
	t.Run("restart failure", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("POST", systemLoggingRestartPath, 200, `{"response":"FAILED"}`)
		wantFailure(t, f.run("/system/logging/service", "restart"), "FAILED")
	})
}

func TestSystemLoggingDestinationComplete(t *testing.T) {
	t.Parallel()
	var f = systemLoggingFake(t)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		// descriptions with spaces are completed quoted, like the cron jobs
		"/system/logging/destination show s":      {`"siem backup"`, "siem"},
		"/system/logging/destination remove \"o":  {`"old siem"`},
		"/system/logging/destination set item=si": {`item="siem backup"`, "item=siem"},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}
