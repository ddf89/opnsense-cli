package cmd

import (
	"strings"
	"testing"
)

// sysCronFake serves search_jobs with rows and get_job with the command options
func sysCronFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(sysCronSearchPath, rows...)
	f.on("GET", sysCronGetJobPath, 200, sysCronGetJob)
	return f
}

// sysCronDecoys are jobs whose descriptions contain "nightly" without being exactly "nightly"
var sysCronDecoys = []map[string]any{
	sysCronRow(map[string]any{"uuid": "c-nightly-backup", "description": "nightly backup"}),
	sysCronRow(map[string]any{"uuid": "c-pre-nightly", "description": "pre nightly"}),
}

func TestSysCronList(t *testing.T) {
	t.Parallel()
	var f = sysCronFake(t,
		sysCronRow(map[string]any{"uuid": "c1", "minutes": "*/5", "description": "every five"}),
		sysCronRow(map[string]any{"uuid": "c2", "enabled": "0", "origin": "Firmware", "command": "firmware poll", "description": ""}),
	)
	var r = f.run("system", "cron", "list")
	wantExit(t, r, 0)
	var rows = sysWantTable(t, r.stdout,
		[]string{"UUID", "ENABLED", "SCHEDULE", "WHO", "COMMAND", "PARAMETERS", "DESCRIPTION", "ORIGIN"}, "c1", "c2")
	if len(rows) == 3 {
		// ENABLED is rendered as 1/0 (or yes/no)
		var enabled = map[string]bool{"1": true, "yes": true, "0": false, "no": false}
		if got := strings.Join(append([]string{rows[1][0]}, rows[1][2:]...), "|"); got != "c1|*/5 5 * * *|root|firmware changelog cron|-|every five|cron" ||
			!enabled[rows[1][1]] {
			t.Errorf("row c1: %q", rows[1])
		}
		if state, known := enabled[rows[2][1]]; !known || state || rows[2][6] != "-" || rows[2][7] != "Firmware" {
			t.Errorf("row c2: %q", rows[2])
		}
	}
	wantSearchPhrases(t, f, sysCronSearchPath, "")
	wantNoMutations(t, f)

	t.Run("search phrase is passed on", func(t *testing.T) {
		var f = sysCronFake(t, sysCronRow(map[string]any{"uuid": "c1"}))
		wantExit(t, f.run("system", "cron", "list", "--search", "change log&x"), 0)
		wantSearchPhrases(t, f, sysCronSearchPath, "change log&x")
	})
}

func TestSysCronShow(t *testing.T) {
	t.Parallel()
	var target = sysCronRow(map[string]any{"uuid": "c-nightly", "description": "nightly", "parameters": "--quiet"})
	var rows = append([]map[string]any{target}, sysCronDecoys...)

	for _, args := range [][]string{{"--uuid", "c-nightly"}, {"--description", "nightly"}} {
		t.Run(sysName(args), func(t *testing.T) {
			t.Parallel()
			var f = sysCronFake(t, rows...)
			var r = f.run(append([]string{"system", "cron", "show"}, args...)...)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, "c-nightly", "nightly", "0 5 * * *", "firmware changelog cron (Firmware changelog update)", "--quiet")
			wantNotContains(t, "stdout", r.stdout, "c-nightly-backup", "c-pre-nightly")
			wantNoMutations(t, f)
		})
	}

	t.Run("ambiguous description is an error listing the candidates", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t, sysCronRow(map[string]any{"uuid": "c-a", "description": "dup"}),
			sysCronRow(map[string]any{"uuid": "c-b", "description": "dup"}))
		var r = f.run("system", "cron", "show", "--description", "dup")
		wantFailure(t, r, "c-a", "c-b")
	})
	t.Run("unknown description", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t, sysCronDecoys...)
		wantFailure(t, f.run("system", "cron", "show", "--description", "nightly"), "not found")
	})
	t.Run("unknown uuid", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t, sysCronDecoys...)
		wantFailure(t, f.run("system", "cron", "show", "--uuid", "c-nope"), "not found")
	})
	t.Run("selector required, no API call", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t)
		wantFailure(t, f.run("system", "cron", "show"), "uuid", "description")
		wantNoCalls(t, f)
	})
}

func TestSysCronCreate(t *testing.T) {
	t.Parallel()

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t)
		f.on("POST", sysCronAddPath, 200, answerAdded("c-new"))
		var r = f.run("system", "cron", "create", "--command", "firmware poll", "--description", "poll")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "c-new")
		var call = wantOneMutation(t, f, "POST", sysCronAddPath)
		wantJSON(t, call, map[string]any{"job": map[string]any{
			"enabled": "1", "minutes": "0", "hours": "0", "days": "*", "months": "*", "weekdays": "*", "who": "root",
			"command": "firmware poll", "description": "poll",
		}})
	})

	t.Run("all flags", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t)
		f.on("POST", sysCronAddPath, 200, answerAdded("c-new"))
		var r = f.run("system", "cron", "create", "--command", "system remote backup", "--description", "remote",
			"--parameters", "--now", "--minutes", "*/15", "--hours", "1-5", "--days", "1,15", "--months", "JAN",
			"--weekdays", "0", "--who", "nobody", "--enabled", "0")
		wantExit(t, r, 0)
		var call = wantOneMutation(t, f, "POST", sysCronAddPath)
		wantJSON(t, call, map[string]any{"job": map[string]any{
			"enabled": "0", "minutes": "*/15", "hours": "1-5", "days": "1,15", "months": "JAN", "weekdays": "0", "who": "nobody",
			"command": "system remote backup", "parameters": "--now", "description": "remote",
		}})
	})

	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"command is required", []string{"--description", "x"}, []string{"command"}},
		{"description is required", []string{"--command", "firmware poll"}, []string{"description"}},
		{"positional args are rejected", []string{"--command", "firmware poll", "--description", "x", "extra"}, []string{"extra"}},
	} {
		t.Run(tc.name+", no API call", func(t *testing.T) {
			t.Parallel()
			var f = sysCronFake(t)
			var r = f.run(append([]string{"system", "cron", "create"}, tc.args...)...)
			wantFailure(t, r, tc.wants...)
			wantNoCalls(t, f)
		})
	}

	t.Run("unknown command is rejected before any change", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t)
		var r = f.run("system", "cron", "create", "--command", "system halt", "--description", "x")
		wantFailure(t, r, "system halt", "cron commands")
		wantNoMutations(t, f)
	})

	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t)
		f.on("POST", sysCronAddPath, 200, answerValidation("job.hours", "Please specify a valid hour."))
		var r = f.run("system", "cron", "create", "--command", "firmware poll", "--description", "x", "--hours", "25")
		wantFailure(t, r, "job.hours", "Please specify a valid hour.")
	})
}

func TestSysCronUpdate(t *testing.T) {
	t.Parallel()
	var target = sysCronRow(map[string]any{"uuid": "c-nightly", "description": "nightly"})
	var rows = append([]map[string]any{target}, sysCronDecoys...)

	for _, tc := range []struct {
		name string
		args []string
		want map[string]any
	}{
		{"by uuid, only the changed field", []string{"--uuid", "c-nightly", "--minutes", "30"}, map[string]any{"minutes": "30"}},
		{"by description", []string{"--description", "nightly", "--hours", "4", "--enabled", "0"}, map[string]any{"hours": "4", "enabled": "0"}},
		{"clear parameters", []string{"--uuid", "c-nightly", "--parameters", ""}, map[string]any{"parameters": ""}},
		{"rename by uuid with --description", []string{"--uuid", "c-nightly", "--description", "renamed"}, map[string]any{"description": "renamed"}},
		{"rename by description with --new-description", []string{"--description", "nightly", "--new-description", "renamed"}, map[string]any{"description": "renamed"}},
		{"command is validated and sent", []string{"--uuid", "c-nightly", "--command", "cron restart"}, map[string]any{"command": "cron restart"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = sysCronFake(t, rows...)
			f.on("POST", sysCronSetPath+"c-nightly", 200, answerSaved)
			var r = f.run(append([]string{"system", "cron", "update"}, tc.args...)...)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, "c-nightly")
			var call = wantOneMutation(t, f, "POST", sysCronSetPath+"c-nightly")
			wantJSON(t, call, map[string]any{"job": tc.want})
		})
	}

	t.Run("job of another origin keeps its command and parameters", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t, sysCronRow(map[string]any{"uuid": "c-fw", "origin": "Firmware", "command": "firmware poll", "parameters": "--x"}))
		f.on("POST", sysCronSetPath+"c-fw", 200, answerSaved)
		wantExit(t, f.run("system", "cron", "update", "--uuid", "c-fw", "--hours", "3"), 0)
		var call = wantOneMutation(t, f, "POST", sysCronSetPath+"c-fw")
		wantJSON(t, call, map[string]any{"job": map[string]any{"hours": "3", "command": "firmware poll", "parameters": "--x"}})

		var f2 = sysCronFake(t, sysCronRow(map[string]any{"uuid": "c-fw", "origin": "Firmware", "command": "firmware poll"}))
		wantFailure(t, f2.run("system", "cron", "update", "--uuid", "c-fw", "--command", "cron restart"), "Firmware")
		wantNoMutations(t, f2)
	})

	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"nothing to update", []string{"--uuid", "c-nightly"}, []string{"nothing to update"}},
		{"empty description", []string{"--uuid", "c-nightly", "--description", ""}, []string{"description"}},
		{"both renames", []string{"--uuid", "c-nightly", "--description", "a", "--new-description", "b"}, []string{"new-description"}},
		{"unknown command", []string{"--uuid", "c-nightly", "--command", "system reboot"}, []string{"system reboot"}},
		{"ambiguous description", []string{"--description", "dup", "--hours", "1"}, []string{"c-d1", "c-d2"}},
		{"no selector", []string{"--hours", "1"}, []string{"uuid", "description"}},
	} {
		t.Run(tc.name+", no change", func(t *testing.T) {
			t.Parallel()
			var f = sysCronFake(t, append([]map[string]any{target,
				sysCronRow(map[string]any{"uuid": "c-d1", "description": "dup"}),
				sysCronRow(map[string]any{"uuid": "c-d2", "description": "dup"})}, sysCronDecoys...)...)
			var r = f.run(append([]string{"system", "cron", "update"}, tc.args...)...)
			wantFailure(t, r, tc.wants...)
			wantNoMutations(t, f)
		})
	}

	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t, rows...)
		f.on("POST", sysCronSetPath+"c-nightly", 200, `{"result":"failed","validations":{"job.minutes":["Please specify a valid minute."]}}`)
		wantFailure(t, f.run("system", "cron", "update", "--uuid", "c-nightly", "--minutes", "61"), "job.minutes", "Please specify a valid minute.")
	})
}

func TestSysCronRm(t *testing.T) {
	t.Parallel()
	var target = sysCronRow(map[string]any{"uuid": "c-nightly", "description": "nightly"})

	for _, args := range [][]string{{"--uuid", "c-nightly"}, {"--description", "nightly"}} {
		t.Run(sysName(args), func(t *testing.T) {
			t.Parallel()
			var f = sysCronFake(t, append([]map[string]any{target}, sysCronDecoys...)...)
			f.on("POST", sysCronDelPath+"c-nightly", 200, answerDeleted)
			var r = f.run(append([]string{"system", "cron", "rm"}, args...)...)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, "c-nightly")
			wantOneMutation(t, f, "POST", sysCronDelPath+"c-nightly")
		})
	}

	t.Run("jobs of other origins are refused", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t, sysCronRow(map[string]any{"uuid": "c-fw", "origin": "Firmware"}))
		wantFailure(t, f.run("system", "cron", "rm", "--uuid", "c-fw"), "Firmware")
		wantNoMutations(t, f)
	})
	t.Run("ambiguous description", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t, sysCronRow(map[string]any{"uuid": "c-a", "description": "dup"}),
			sysCronRow(map[string]any{"uuid": "c-b", "description": "dup"}))
		wantFailure(t, f.run("system", "cron", "rm", "--description", "dup"), "c-a", "c-b")
		wantNoMutations(t, f)
	})
	t.Run("not found", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t, target)
		wantFailure(t, f.run("system", "cron", "rm", "--uuid", "c-nope"), "not found")
		wantNoMutations(t, f)
	})
	t.Run("no selector, no API call", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t, target)
		wantFailure(t, f.run("system", "cron", "rm"), "uuid")
		wantNoCalls(t, f)
	})
}

func TestSysCronEnableDisable(t *testing.T) {
	t.Parallel()
	var target = sysCronRow(map[string]any{"uuid": "c-nightly", "description": "nightly", "enabled": "0"})

	for _, tc := range []struct {
		args    []string
		answer  string
		path    string
		wantOut string
	}{
		{[]string{"enable", "--uuid", "c-nightly"}, `{"result":"Enabled","changed":true}`, sysCronTogglePath + "c-nightly/1", "enabled successfully"},
		{[]string{"enable", "--description", "nightly"}, `{"result":"Enabled","changed":true}`, sysCronTogglePath + "c-nightly/1", "enabled successfully"},
		{[]string{"disable", "--uuid", "c-nightly"}, `{"result":"Disabled","changed":false}`, sysCronTogglePath + "c-nightly/0", "already disabled"},
		{[]string{"disable", "--description", "nightly"}, `{"result":"Disabled","changed":true}`, sysCronTogglePath + "c-nightly/0", "disabled successfully"},
	} {
		t.Run(sysName(tc.args), func(t *testing.T) {
			t.Parallel()
			var f = sysCronFake(t, append([]map[string]any{target}, sysCronDecoys...)...)
			f.on("POST", tc.path, 200, tc.answer)
			var r = f.run(append([]string{"system", "cron"}, tc.args...)...)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, tc.wantOut, "c-nightly")
			wantOneMutation(t, f, "POST", tc.path)
		})
	}

	t.Run("unknown uuid", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t)
		f.on("POST", sysCronTogglePath+"c-nope/1", 200, `{"result":"failed"}`)
		wantFailure(t, f.run("system", "cron", "enable", "--uuid", "c-nope"), "not found")
	})
	t.Run("ambiguous description", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t, sysCronRow(map[string]any{"uuid": "c-a", "description": "dup"}),
			sysCronRow(map[string]any{"uuid": "c-b", "description": "dup"}))
		wantFailure(t, f.run("system", "cron", "disable", "--description", "dup"), "c-a", "c-b")
		wantNoMutations(t, f)
	})
	t.Run("no selector, no API call", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t)
		wantFailure(t, f.run("system", "cron", "enable"), "uuid")
		wantNoCalls(t, f)
	})
}

func TestSysCronCommands(t *testing.T) {
	t.Parallel()
	var f = sysCronFake(t)
	var r = f.run("system", "cron", "commands")
	wantExit(t, r, 0)
	var rows = sysWantTable(t, r.stdout, []string{"COMMAND", "DESCRIPTION"},
		"cron restart", "firmware changelog cron", "firmware poll", "system remote backup")
	if len(rows) > 1 && rows[1][1] != "Restart Cron service" {
		t.Errorf("description of cron restart: %q", rows[1])
	}
	sysWantCalled(t, f, "GET", sysCronGetJobPath)
	wantNoMutations(t, f)
}

func TestSysCronApply(t *testing.T) {
	t.Parallel()
	var f = sysCronFake(t)
	f.on("POST", sysCronReconfigPath, 200, sysAnswerStatusOk)
	var r = f.run("system", "cron", "apply")
	wantExit(t, r, 0)
	wantOneMutation(t, f, "POST", sysCronReconfigPath)

	t.Run("failure status", func(t *testing.T) {
		t.Parallel()
		var f = sysCronFake(t)
		f.on("POST", sysCronReconfigPath, 200, `{"status":"failed"}`)
		wantFailure(t, f.run("system", "cron", "apply"), "failed")
	})
}
