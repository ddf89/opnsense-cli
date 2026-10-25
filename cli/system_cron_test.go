package cli

import (
	"regexp"
	"strings"
	"testing"
)

const (
	systemCronSearchPath   = "/api/cron/settings/search_jobs"
	systemCronGetJobPath   = "/api/cron/settings/get_job"
	systemCronAddPath      = "/api/cron/settings/add_job"
	systemCronSetPath      = "/api/cron/settings/set_job/"
	systemCronDelPath      = "/api/cron/settings/del_job/"
	systemCronTogglePath   = "/api/cron/settings/toggle_job/"
	systemCronReconfigPath = "/api/cron/service/reconfigure"

	systemCronAnswerStatusOk = `{"status":"ok"}`
)

// systemCronRow is a search_jobs row as OPNsense 26.7 returns it
func systemCronRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "origin": "cron", "enabled": "1", "minutes": "0", "hours": "5", "days": "*", "months": "*",
		"weekdays": "*", "who": "root", "command": "firmware changelog cron", "%command": "Firmware changelog update",
		"parameters": "", "description": "nightly changelog",
	}, overrides)
}

// systemCronGetJob is get_job without uuid: the defaults of a new job with the command options (trimmed)
const systemCronGetJob = `{"job":{"origin":"cron","enabled":"1","minutes":"0","hours":"0","days":"*","months":"*","weekdays":"*","who":"root",` +
	`"command":{"firmware poll":{"value":"Firmware update check","selected":0},` +
	`"firmware changelog cron":{"value":"Firmware changelog update","selected":0},` +
	`"system remote backup":{"value":"Remote backup","selected":0},` +
	`"cron restart":{"value":"Restart Cron service","selected":0}},"parameters":"","description":""}}`

// systemCronFake serves search_jobs with rows and get_job with the command options
func systemCronFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(systemCronSearchPath, rows...)
	f.on("GET", systemCronGetJobPath, 200, systemCronGetJob)
	return f
}

// systemCronDecoys are jobs whose descriptions contain "nightly" without being "nightly"
var systemCronDecoys = []map[string]any{
	systemCronRow(map[string]any{"uuid": "c-nightly-backup", "description": "nightly backup"}),
	systemCronRow(map[string]any{"uuid": "c-pre-nightly", "description": "pre nightly"}),
}

// systemCronTarget is the job "nightly", followed by the decoys and two jobs sharing the description "dup"
func systemCronRows() []map[string]any {
	return append([]map[string]any{
		systemCronRow(map[string]any{"uuid": "c-nightly", "description": "nightly", "parameters": "--quiet"}),
		systemCronRow(map[string]any{"uuid": "c-d1", "description": "dup"}),
		systemCronRow(map[string]any{"uuid": "c-d2", "description": "dup"}),
		systemCronRow(map[string]any{"uuid": "c-fw", "origin": "Firmware", "command": "firmware poll", "%command": "Firmware update check",
			"parameters": "--x", "description": "firmware check", "enabled": "0"}),
	}, systemCronDecoys...)
}

var systemCronColumnSeparator = regexp.MustCompile(`\s{2,}`)

// systemCronTable splits table output into cells (columns are separated by at least two spaces)
func systemCronTable(output string) [][]string {
	var rows [][]string
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			rows = append(rows, systemCronColumnSeparator.Split(strings.TrimSpace(line), -1))
		}
	}
	return rows
}

// systemCronWantTable asserts the header and the cells of column col of the data rows, returns all rows
func systemCronWantTable(t *testing.T, output string, header []string, col int, want ...string) [][]string {
	t.Helper()
	var rows = systemCronTable(output)
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
		got = append(got, row[col])
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("column %s: %q, want %q\n%s", header[col], got, want, output)
	}
	return rows
}

// systemCronWantCalled asserts that method path was called at least once
func systemCronWantCalled(t *testing.T, f *fakeOPN, method string, path string) {
	t.Helper()
	for _, call := range f.calls() {
		if call.Method == method && call.Path == path {
			return
		}
	}
	t.Errorf("%s %s was not called, calls: %v", method, path, f.calls())
}

func systemCronName(args []string) string {
	return strings.Join(args, "_")
}

var systemCronHeader = []string{"#", "DISABLED", "SCHEDULE", "WHO", "COMMAND", "PARAMETERS", "DESCRIPTION", "ORIGIN"}

func TestSystemCronPrint(t *testing.T) {
	t.Parallel()
	var f = systemCronFake(t,
		systemCronRow(map[string]any{"uuid": "c1", "minutes": "*/5", "description": "every five"}),
		systemCronRow(map[string]any{"uuid": "c2", "enabled": "0", "origin": "Firmware", "command": "firmware poll", "description": ""}),
	)
	var r = f.run("/system/cron", "print")
	wantExit(t, r, 0)
	var rows = systemCronWantTable(t, r.stdout, systemCronHeader, 0, "0", "1")
	if len(rows) == 3 {
		if got := strings.Join(rows[1], "|"); got != "0|no|*/5 5 * * *|root|firmware changelog cron|-|every five|cron" {
			t.Errorf("row c1: %q", got)
		}
		if got := strings.Join(rows[2], "|"); got != "1|yes|0 5 * * *|root|firmware poll|-|-|Firmware" {
			t.Errorf("row c2: %q", got)
		}
	}
	wantSearchPhrases(t, f, systemCronSearchPath, "")
	wantNoMutations(t, f)

	t.Run("search phrase is passed on", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRow(map[string]any{"uuid": "c1"}))
		wantExit(t, f.run("/system/cron", "print", "search=change log&x"), 0)
		wantSearchPhrases(t, f, systemCronSearchPath, "change log&x")
	})
	t.Run("detail", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		var r = f.run("/system/cron", "print", "detail")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "0\n  uuid:", "c-nightly", "command:      firmware changelog cron (Firmware changelog update)",
			"parameters:   --quiet", "\n5\n", "origin:       Firmware")
	})
	t.Run("json is the raw API rows", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		var r = f.run("/system/cron", "print", "json")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != len(systemCronRows()) || !strings.Contains(lines[0], `"uuid":"c-nightly"`) || !strings.Contains(lines[0], `"%command":"Firmware changelog update"`) {
			t.Errorf("json output:\n%s", r.stdout)
		}
	})
	t.Run("the # of a filtered print selects in a script", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		f.on("POST", systemCronSetPath+"c-pre-nightly", 200, answerSaved)
		var r = f.runScript("/system/cron\nprint search=pre\nset 0 hours=7\n")
		wantExit(t, r, 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemCronSetPath+"c-pre-nightly"), map[string]any{"job": map[string]any{"hours": "7"}})
	})
}

func TestSystemCronShow(t *testing.T) {
	t.Parallel()
	for _, selector := range []string{"c-nightly", "C-NIGHTLY", "nightly", "Nightly", "0"} {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()
			var f = systemCronFake(t, systemCronRows()...)
			var r = f.run("/system/cron", "show", selector)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, "uuid:         c-nightly", "description:  nightly\n", "schedule:     0 5 * * *",
				"command:      firmware changelog cron (Firmware changelog update)", "parameters:   --quiet", "disabled:     no", "origin:       cron")
			wantNotContains(t, "stdout", r.stdout, "c-nightly-backup", "c-pre-nightly")
			wantNoMutations(t, f)
		})
	}

	t.Run("ambiguous description is an error listing the candidates", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		wantFailure(t, f.run("/system/cron", "show", "dup"), "c-d1", "c-d2")
	})
	t.Run("unknown description", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronDecoys...)
		wantFailure(t, f.run("/system/cron", "show", "nightly"), "not found")
	})
	t.Run("unknown uuid", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronDecoys...)
		wantFailure(t, f.run("/system/cron", "show", "item=c-nope"), "not found")
	})
	t.Run("index out of range", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronDecoys...)
		wantFailure(t, f.run("/system/cron", "show", "2"), "not found", "#2")
	})
	t.Run("item required, no API call", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t)
		wantFailure(t, f.run("/system/cron", "show"), "item")
		wantNoCalls(t, f)
	})
}

func TestSystemCronAdd(t *testing.T) {
	t.Parallel()

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		f.on("POST", systemCronAddPath, 200, answerAdded("c-new"))
		var r = f.run("/system/cron", "add", "command=firmware poll", "description=poll")
		wantExit(t, r, 0)
		if r.stdout != "c-new\n" {
			t.Errorf("stdout must be the uuid: %q", r.stdout)
		}
		wantJSON(t, wantOneMutation(t, f, "POST", systemCronAddPath), map[string]any{"job": map[string]any{
			"enabled": "1", "minutes": "0", "hours": "0", "days": "*", "months": "*", "weekdays": "*", "who": "root",
			"command": "firmware poll", "description": "poll",
		}})
	})

	t.Run("all arguments", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t)
		f.on("POST", systemCronAddPath, 200, answerAdded("c-new"))
		var r = f.run("/system/cron", "add", "command=system remote backup", "description=remote",
			"parameters=--now", "minutes=*/15", "hours=1-5", "days=1,15", "months=JAN-MAR/2", "weekdays=0",
			"who=nobody", "disabled")
		wantExit(t, r, 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemCronAddPath), map[string]any{"job": map[string]any{
			"enabled": "0", "minutes": "*/15", "hours": "1-5", "days": "1,15", "months": "JAN-MAR/2", "weekdays": "0", "who": "nobody",
			"command": "system remote backup", "parameters": "--now", "description": "remote",
		}})
	})

	t.Run("existing description fails without replace", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		var r = f.run("/system/cron", "add", "command=firmware poll", "description=NIGHTLY")
		wantFailure(t, r, "exists already", "c-nightly", "replace")
		wantNoMutations(t, f)
	})

	t.Run("replace replaces the job completely", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		f.on("POST", systemCronSetPath+"c-nightly", 200, answerSaved)
		var r = f.run("/system/cron", "add", "command=cron restart", "description=nightly", "hours=3", "replace")
		wantExit(t, r, 0)
		if r.stdout != "c-nightly\n" {
			t.Errorf("stdout must be the uuid: %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, `replaced the existing cron job "nightly"`)
		wantJSON(t, wantOneMutation(t, f, "POST", systemCronSetPath+"c-nightly"), map[string]any{"job": map[string]any{
			"enabled": "1", "minutes": "0", "hours": "3", "days": "*", "months": "*", "weekdays": "*", "who": "root",
			"command": "cron restart", "parameters": "", "description": "nightly",
		}})
	})

	t.Run("replace keeps the protections of jobs of other origins", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		wantFailure(t, f.run("/system/cron", "add", "command=cron restart", "description=firmware check", "replace"), "Firmware", "can not be changed")
		wantNoMutations(t, f)

		var same = systemCronFake(t, systemCronRows()...)
		same.on("POST", systemCronSetPath+"c-fw", 200, answerSaved)
		wantExit(t, same.run("/system/cron", "add", "command=firmware poll", "parameters=--x", "description=firmware check", "replace"), 0)
		wantOneMutation(t, same, "POST", systemCronSetPath+"c-fw")
	})

	t.Run("several jobs with the description", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		wantFailure(t, f.run("/system/cron", "add", "command=firmware poll", "description=dup", "replace"), "c-d1", "c-d2")
		wantNoMutations(t, f)
	})

	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"command is required", []string{"description=x"}, []string{"command"}},
		{"description is required", []string{"command=firmware poll"}, []string{"description"}},
		{"empty description", []string{"command=firmware poll", "description="}, []string{"description must not be empty"}},
		{"positional args are rejected", []string{"command=firmware poll", "description=x", "extra"}, []string{"extra"}},
		{"minutes out of range", []string{"command=firmware poll", "description=x", "minutes=61"}, []string{"minutes must be 0-59", `"61"`}},
		{"empty minutes", []string{"command=firmware poll", "description=x", "minutes="}, []string{"minutes must not be empty"}},
		{"bad step", []string{"command=firmware poll", "description=x", "minutes=*/90"}, []string{"minutes must be"}},
		{"days 0", []string{"command=firmware poll", "description=x", "days=0"}, []string{"days must be 1-31", "L for the last day"}},
		{"L in a list", []string{"command=firmware poll", "description=x", "days=L,15"}, []string{"days must be"}},
		{"lower case month", []string{"command=firmware poll", "description=x", "months=jan"}, []string{"months must be 1-12 or JAN-DEC"}},
		{"weekday name", []string{"command=firmware poll", "description=x", "weekdays=MON"}, []string{"weekdays must be 0-7"}},
		{"spaces in the schedule", []string{"command=firmware poll", "description=x", "hours=1, 2"}, []string{"hours must be"}},
		{"who with a space", []string{"command=firmware poll", "description=x", "who=root /bin/sh"}, []string{"who must be a user name"}},
		{"parameters with a newline", []string{"command=firmware poll", "description=x", "parameters=a\nb"}, []string{"parameters must not contain control characters"}},
		{"disabled is yes or no", []string{"command=firmware poll", "description=x", "disabled=2"}, []string{"disabled must be yes or no"}},
	} {
		t.Run(tc.name+", no API call", func(t *testing.T) {
			t.Parallel()
			var f = systemCronFake(t)
			var r = f.run(append([]string{"/system/cron", "add"}, tc.args...)...)
			wantFailure(t, r, tc.wants...)
			wantNoCalls(t, f)
		})
	}

	for _, schedule := range []string{"days=L", "minutes=1,2-4,*/10", "hours=05", "months=1-12/3", "weekdays=7", "months=*/2,DEC"} {
		t.Run("valid "+schedule, func(t *testing.T) {
			t.Parallel()
			var f = systemCronFake(t)
			f.on("POST", systemCronAddPath, 200, answerAdded("c-new"))
			wantExit(t, f.run("/system/cron", "add", "command=firmware poll", "description=x", schedule), 0)
			wantOneMutation(t, f, "POST", systemCronAddPath)
		})
	}

	t.Run("unknown command is rejected before any change", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t)
		var r = f.run("/system/cron", "add", "command=system halt", "description=x")
		wantFailure(t, r, "system halt", "/system/cron commands")
		wantNoMutations(t, f)
	})

	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t)
		f.on("POST", systemCronAddPath, 200, answerValidation("job.who", "Please specify a valid user."))
		var r = f.run("/system/cron", "add", "command=firmware poll", "description=x", "who=nobody2")
		wantFailure(t, r, "job.who", "Please specify a valid user.")
	})
}

func TestSystemCronSet(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		args []string
		want map[string]any
	}{
		{"by uuid, only the changed field", []string{"c-nightly", "minutes=30"}, map[string]any{"minutes": "30"}},
		{"by description", []string{"nightly", "hours=4", "disabled"}, map[string]any{"hours": "4", "enabled": "0"}},
		{"by index", []string{"0", "disabled=no"}, map[string]any{"enabled": "1"}},
		{"clear parameters", []string{"c-nightly", "parameters="}, map[string]any{"parameters": ""}},
		{"rename", []string{"nightly", "description=renamed"}, map[string]any{"description": "renamed"}},
		{"command is validated and sent", []string{"c-nightly", "command=cron restart"}, map[string]any{"command": "cron restart"}},
		{"all schedule fields", []string{"nightly", "minutes=5", "hours=*/2", "days=L", "months=FEB", "weekdays=1-5", "who=nobody"},
			map[string]any{"minutes": "5", "hours": "*/2", "days": "L", "months": "FEB", "weekdays": "1-5", "who": "nobody"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = systemCronFake(t, systemCronRows()...)
			f.on("POST", systemCronSetPath+"c-nightly", 200, answerSaved)
			var r = f.run(append([]string{"/system/cron", "set"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("set must be silent: %q", r.stdout)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", systemCronSetPath+"c-nightly"), map[string]any{"job": tc.want})
		})
	}

	t.Run("job of another origin keeps its command and parameters", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		f.on("POST", systemCronSetPath+"c-fw", 200, answerSaved)
		wantExit(t, f.run("/system/cron", "set", "firmware check", "hours=3"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemCronSetPath+"c-fw"),
			map[string]any{"job": map[string]any{"hours": "3", "command": "firmware poll", "parameters": "--x"}})

		for _, change := range []string{"command=cron restart", "parameters=--y"} {
			var f2 = systemCronFake(t, systemCronRows()...)
			wantFailure(t, f2.run("/system/cron", "set", "c-fw", change), "Firmware", "can not be changed")
			wantNoMutations(t, f2)
		}
	})

	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"nothing to change", []string{"c-nightly"}, []string{"nothing to change"}},
		{"empty description", []string{"c-nightly", "description="}, []string{"description must not be empty"}},
		{"unknown command", []string{"c-nightly", "command=system reboot"}, []string{"system reboot", "/system/cron commands"}},
		{"ambiguous description", []string{"dup", "hours=1"}, []string{"c-d1", "c-d2"}},
		{"unknown item", []string{"c-nope", "hours=1"}, []string{"not found"}},
		{"no item", []string{"hours=1"}, []string{"item"}},
		{"invalid hours", []string{"c-nightly", "hours=24"}, []string{"hours must be 0-23"}},
	} {
		t.Run(tc.name+", no change", func(t *testing.T) {
			t.Parallel()
			var f = systemCronFake(t, systemCronRows()...)
			var r = f.run(append([]string{"/system/cron", "set"}, tc.args...)...)
			wantFailure(t, r, tc.wants...)
			wantNoMutations(t, f)
		})
	}

	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		f.on("POST", systemCronSetPath+"c-nightly", 200, `{"result":"failed","validations":{"job.minutes":["Please specify a valid minute."]}}`)
		wantFailure(t, f.run("/system/cron", "set", "c-nightly", "minutes=5-1"), "job.minutes", "Please specify a valid minute.")
	})
	t.Run("removed meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		f.on("POST", systemCronSetPath+"c-nightly", 200, answerFailedBare)
		wantFailure(t, f.run("/system/cron", "set", "c-nightly", "minutes=1"), "not found")
	})
}

func TestSystemCronRemove(t *testing.T) {
	t.Parallel()
	for _, selector := range []string{"c-nightly", "nightly", "0"} {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()
			var f = systemCronFake(t, systemCronRows()...)
			f.on("POST", systemCronDelPath+"c-nightly", 200, answerDeleted)
			var r = f.run("/system/cron", "remove", selector)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("remove must be silent: %q", r.stdout)
			}
			wantOneMutation(t, f, "POST", systemCronDelPath+"c-nightly")
		})
	}

	t.Run("jobs of other origins are refused", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		wantFailure(t, f.run("/system/cron", "remove", "c-fw"), "Firmware", "disable it instead")
		wantNoMutations(t, f)
	})
	t.Run("ambiguous description", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		wantFailure(t, f.run("/system/cron", "remove", "dup"), "c-d1", "c-d2")
		wantNoMutations(t, f)
	})
	t.Run("not found", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		wantFailure(t, f.run("/system/cron", "remove", "c-nope"), "not found")
		wantNoMutations(t, f)
	})
	t.Run("removed meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		f.on("POST", systemCronDelPath+"c-nightly", 200, answerNotFound)
		wantFailure(t, f.run("/system/cron", "remove", "c-nightly"), "not found")
	})
	t.Run("no item, no API call", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		wantFailure(t, f.run("/system/cron", "remove"), "item")
		wantNoCalls(t, f)
	})
}

func TestSystemCronEnableDisable(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args     []string
		answer   string
		path     string
		wantInfo string
	}{
		{[]string{"enable", "c-nightly"}, `{"result":"Enabled","changed":true}`, systemCronTogglePath + "c-nightly/1", ""},
		{[]string{"enable", "nightly"}, `{"result":"Enabled","changed":false}`, systemCronTogglePath + "c-nightly/1", `cron job "nightly" is already enabled`},
		{[]string{"disable", "0"}, `{"result":"Disabled","changed":false}`, systemCronTogglePath + "c-nightly/0", "already disabled"},
		{[]string{"disable", "nightly"}, `{"result":"Disabled","changed":true}`, systemCronTogglePath + "c-nightly/0", ""},
		{[]string{"enable", "firmware check"}, `{"result":"Enabled","changed":true}`, systemCronTogglePath + "c-fw/1", ""},
	} {
		t.Run(systemCronName(tc.args), func(t *testing.T) {
			t.Parallel()
			var f = systemCronFake(t, systemCronRows()...)
			f.on("POST", tc.path, 200, tc.answer)
			var r = f.run(append([]string{"/system/cron"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("%s must be silent: %q", tc.args[0], r.stdout)
			}
			if tc.wantInfo != "" {
				wantContains(t, "stderr", r.stderr, tc.wantInfo)
			} else if r.stderr != "" {
				t.Errorf("stderr: %q", r.stderr)
			}
			wantOneMutation(t, f, "POST", tc.path)
		})
	}

	t.Run("unknown item", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		wantFailure(t, f.run("/system/cron", "enable", "c-nope"), "not found")
		wantNoMutations(t, f)
	})
	t.Run("removed meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		f.on("POST", systemCronTogglePath+"c-nightly/1", 200, `{"result":"failed"}`)
		wantFailure(t, f.run("/system/cron", "enable", "c-nightly"), "not found")
	})
	t.Run("ambiguous description", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t, systemCronRows()...)
		wantFailure(t, f.run("/system/cron", "disable", "dup"), "c-d1", "c-d2")
		wantNoMutations(t, f)
	})
	t.Run("no item, no API call", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t)
		wantFailure(t, f.run("/system/cron", "enable"), "item")
		wantNoCalls(t, f)
	})
}

func TestSystemCronCommands(t *testing.T) {
	t.Parallel()
	var f = systemCronFake(t)
	var r = f.run("/system/cron", "commands")
	wantExit(t, r, 0)
	var rows = systemCronWantTable(t, r.stdout, []string{"COMMAND", "DESCRIPTION"}, 0,
		"cron restart", "firmware changelog cron", "firmware poll", "system remote backup")
	if len(rows) > 1 && rows[1][1] != "Restart Cron service" {
		t.Errorf("description of cron restart: %q", rows[1])
	}
	systemCronWantCalled(t, f, "GET", systemCronGetJobPath)

	var asJSON = f.run("/system/cron", "commands", "json")
	wantExit(t, asJSON, 0)
	wantContains(t, "stdout", asJSON.stdout, `{"command":"cron restart","description":"Restart Cron service"}`)
	wantNoMutations(t, f)
}

func TestSystemCronApply(t *testing.T) {
	t.Parallel()
	var f = systemCronFake(t)
	f.on("POST", systemCronReconfigPath, 200, systemCronAnswerStatusOk)
	var r = f.run("/system/cron", "apply")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("apply must be silent: %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", systemCronReconfigPath)

	t.Run("failure status", func(t *testing.T) {
		t.Parallel()
		var f = systemCronFake(t)
		f.on("POST", systemCronReconfigPath, 200, `{"status":"failed"}`)
		wantFailure(t, f.run("/system/cron", "apply"), "failed")
	})
}

func TestSystemCronHelp(t *testing.T) {
	t.Parallel()
	var f = systemCronFake(t)
	var r = f.run("/system/cron", "add", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "description=<string>", "command=<string>", "minutes=<string>", "default 0", "disabled[=yes|no]", "replace", "/system/cron apply")
	wantNoCalls(t, f)
}
