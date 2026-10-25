package cli

import (
	"strings"
	"testing"
)

const (
	systemTunableSearchPath   = "/api/core/tunables/search_item"
	systemTunableAddPath      = "/api/core/tunables/add_item"
	systemTunableSetPath      = "/api/core/tunables/set_item/"
	systemTunableDelPath      = "/api/core/tunables/del_item/"
	systemTunableReconfigPath = "/api/core/tunables/reconfigure"

	// systemTunableBuiltinUuid mimics the md5 key of a not configured built-in row
	systemTunableBuiltinUuid = "e042e8fc0a6f5e0e1b4a4b7c1f7c1a11"

	systemTunableOverride = "t-override-0000-4000-8000-000000000001"
	systemTunableCustom   = "t-custom-0000-4000-8000-000000000002"
	systemTunableSame     = "t-same-0000-4000-8000-000000000003"
	systemTunableDup      = "t-dup-0000-4000-8000-000000000009"
)

// systemTunableRow is a search_item row as OPNsense 26.7 returns it
func systemTunableRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "tunable": "kern.ipc.maxsockbuf", "value": "8388608", "descr": "Maximum socket buffer size",
		"default_value": "4262144", "type": "w",
	}, overrides)
}

// systemTunableRows: a configured override, a custom tunable, a built-in default and decoys with similar names
func systemTunableRows() []map[string]any {
	return []map[string]any{
		systemTunableRow(map[string]any{"uuid": systemTunableOverride}),
		systemTunableRow(map[string]any{"uuid": systemTunableCustom, "tunable": "kern.custom.knob", "value": "7",
			"descr": "my custom knob", "default_value": "", "type": ""}),
		systemTunableRow(map[string]any{"uuid": systemTunableBuiltinUuid, "tunable": "vfs.read_max", "value": "64", "default_value": "32",
			"descr": "Cluster read-ahead max block count"}),
		systemTunableRow(map[string]any{"uuid": "a1b2c3d4e5f60718293a4b5c6d7e8f90", "tunable": "kern.ipc.maxsockbuf_extra", "value": "1",
			"type": "t", "descr": strings.Repeat("long description ", 6)}),
		systemTunableRow(map[string]any{"uuid": systemTunableSame, "tunable": "kern.custom.knob2", "value": "7",
			"descr": "", "default_value": "7"}),
	}
}

func systemTunableFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(systemTunableSearchPath, rows...)
	return f
}

var systemTunableHeader = []string{"#", "NAME", "VALUE", "DEFAULT", "TYPE", "SOURCE", "DESCRIPTION"}

func TestSystemTunablePrint(t *testing.T) {
	t.Parallel()
	var f = systemTunableFake(t, systemTunableRows()...)
	var r = f.run("/system/tunable", "print")
	wantExit(t, r, 0)
	var rows = systemCronWantTable(t, r.stdout, systemTunableHeader, 1,
		"kern.ipc.maxsockbuf", "kern.custom.knob", "vfs.read_max", "kern.ipc.maxsockbuf_extra", "kern.custom.knob2")
	if len(rows) == 6 {
		for i, want := range []string{"override", "custom", "built-in", "built-in", "override"} {
			if rows[i+1][5] != want {
				t.Errorf("SOURCE of row %d: %q, want %q", i+1, rows[i+1][5], want)
			}
		}
		if rows[1][4] != "runtime" || rows[2][4] != "-" || rows[4][4] != "boot-time" {
			t.Errorf("TYPE column: %q %q %q", rows[1][4], rows[2][4], rows[4][4])
		}
		if !strings.HasSuffix(rows[4][6], "...") || len(rows[4][6]) != 60 {
			t.Errorf("long description is not truncated to 60: %q", rows[4][6])
		}
	}
	wantSearchPhrases(t, f, systemTunableSearchPath, "")
	wantNoMutations(t, f)

	t.Run("changed only lists configured values differing from the default", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, systemTunableRows()...)
		var r = f.run("/system/tunable", "print", "changed")
		wantExit(t, r, 0)
		systemCronWantTable(t, r.stdout, systemTunableHeader, 1, "kern.ipc.maxsockbuf", "kern.custom.knob")
	})
	t.Run("the # of a changed print selects in a script", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, systemTunableRows()...)
		f.on("POST", systemTunableDelPath+systemTunableCustom, 200, answerDeleted)
		wantExit(t, f.runScript("/system/tunable\nprint changed\nremove 1\n"), 0)
		wantOneMutation(t, f, "POST", systemTunableDelPath+systemTunableCustom)
	})
	t.Run("search is passed on", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, systemTunableRows()...)
		wantExit(t, f.run("/system/tunable", "print", "search=kern.ipc"), 0)
		wantSearchPhrases(t, f, systemTunableSearchPath, "kern.ipc")
	})
	t.Run("detail", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, systemTunableRows()...)
		var r = f.run("/system/tunable", "print", "detail", "changed")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "0\n  uuid:", systemTunableOverride, "\n1\n", "name:", "kern.custom.knob", "source:")
		wantNotContains(t, "stdout", r.stdout, "vfs.read_max")
	})
	t.Run("json is the raw API rows", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, systemTunableRows()...)
		var r = f.run("/system/tunable", "print", "json", "changed")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != 2 || !strings.Contains(lines[0], `"default_value":"4262144"`) || !strings.Contains(lines[1], `"tunable":"kern.custom.knob"`) {
			t.Errorf("json output:\n%s", r.stdout)
		}
	})
}

func TestSystemTunableShow(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		selector string
		wants    []string
	}{
		{"kern.ipc.maxsockbuf", []string{systemTunableOverride, "value:", "8388608", "4262144", "source:       override", "type:         runtime"}},
		{"0", []string{systemTunableOverride}},
		{systemTunableCustom, []string{"kern.custom.knob", "my custom knob", "custom"}},
		{"vfs.read_max", []string{systemTunableBuiltinUuid, "runtime-value:", "64", "built-in"}},
	} {
		t.Run(tc.selector, func(t *testing.T) {
			t.Parallel()
			var f = systemTunableFake(t, systemTunableRows()...)
			var r = f.run("/system/tunable", "show", tc.selector)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, tc.wants...)
			wantNotContains(t, "stdout", r.stdout, "maxsockbuf_extra")
			wantNoMutations(t, f)
		})
	}

	t.Run("name configured twice is ambiguous", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, append(systemTunableRows(), systemTunableRow(map[string]any{"uuid": systemTunableDup}))...)
		wantFailure(t, f.run("/system/tunable", "show", "kern.ipc.maxsockbuf"), systemTunableOverride, systemTunableDup, "uuid")
	})
	t.Run("unknown name", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, systemTunableRows()...)
		wantFailure(t, f.run("/system/tunable", "show", "kern.ipc"), "not found")
	})
	t.Run("item required, no API call", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, systemTunableRows()...)
		wantFailure(t, f.run("/system/tunable", "show"), "item")
		wantNoCalls(t, f)
	})
}

func TestSystemTunableAdd(t *testing.T) {
	t.Parallel()

	t.Run("new name", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, systemTunableRows()...)
		f.on("POST", systemTunableAddPath, 200, answerAdded("t-new"))
		var r = f.run("/system/tunable", "add", "name=kern.ipc", "value=1", "description=d")
		wantExit(t, r, 0)
		if r.stdout != "t-new\n" {
			t.Errorf("stdout must be the uuid: %q", r.stdout)
		}
		if r.stderr != "" {
			t.Errorf("add must not print messages, the apply hint is in the help: %q", r.stderr)
		}
		wantJSON(t, wantOneMutation(t, f, "POST", systemTunableAddPath),
			map[string]any{"sysctl": map[string]any{"tunable": "kern.ipc", "value": "1", "descr": "d"}})
		wantSearchPhrases(t, f, systemTunableSearchPath, "kern.ipc")
	})
	t.Run("a built-in default is overridden", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, systemTunableRows()...)
		f.on("POST", systemTunableAddPath, 200, answerAdded("t-new"))
		wantExit(t, f.run("/system/tunable", "add", "name=vfs.read_max", "value=128"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemTunableAddPath),
			map[string]any{"sysctl": map[string]any{"tunable": "vfs.read_max", "value": "128", "descr": ""}})
	})
	t.Run("empty value uses the default", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t)
		f.on("POST", systemTunableAddPath, 200, answerAdded("t-new"))
		wantExit(t, f.run("/system/tunable", "add", "name=kern.x", "value="), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemTunableAddPath),
			map[string]any{"sysctl": map[string]any{"tunable": "kern.x", "value": "", "descr": ""}})
	})
	t.Run("configured name fails without replace", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, systemTunableRows()...)
		wantFailure(t, f.run("/system/tunable", "add", "name=kern.ipc.maxsockbuf", "value=1"), "configured already", systemTunableOverride, "replace")
		wantNoMutations(t, f)
	})
	t.Run("replace replaces the entry completely", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, systemTunableRows()...)
		f.on("POST", systemTunableSetPath+systemTunableCustom, 200, answerSaved)
		var r = f.run("/system/tunable", "add", "name=kern.custom.knob", "value=9", "replace")
		wantExit(t, r, 0)
		if r.stdout != systemTunableCustom+"\n" {
			t.Errorf("stdout must be the uuid: %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, "replaced the existing tunable kern.custom.knob")
		wantJSON(t, wantOneMutation(t, f, "POST", systemTunableSetPath+systemTunableCustom),
			map[string]any{"sysctl": map[string]any{"tunable": "kern.custom.knob", "value": "9", "descr": ""}})
	})
	t.Run("duplicates are refused", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, append(systemTunableRows(), systemTunableRow(map[string]any{"uuid": systemTunableDup}))...)
		wantFailure(t, f.run("/system/tunable", "add", "name=kern.ipc.maxsockbuf", "value=1", "replace"), systemTunableDup, systemTunableOverride)
		wantNoMutations(t, f)
	})
	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t)
		f.on("POST", systemTunableAddPath, 200, answerValidation("sysctl.value", "value is invalid"))
		wantFailure(t, f.run("/system/tunable", "add", "name=kern.x", "value=1"), "sysctl.value", "value is invalid")
	})

	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"name is required", []string{"value=1"}, []string{"name"}},
		{"value is required", []string{"name=kern.x"}, []string{"value"}},
		{"empty name", []string{"name=", "value=1"}, []string{"name must be a sysctl name"}},
		{"name with a space", []string{"name=kern.x y", "value=1"}, []string{"kern.x y"}},
		{"name with a newline", []string{"name=kern.x\nkern.y", "value=1"}, []string{"name must be a sysctl name"}},
		{"name with a double dot", []string{"name=kern..x", "value=1"}, []string{"name must be a sysctl name"}},
		{"value with a quote", []string{"name=kern.x", `value=1"`}, []string{"value must not contain double quotes"}},
		{"value with a newline", []string{"name=kern.x", "value=1\nkern.evil=1"}, []string{"value must not contain double quotes or control characters"}},
	} {
		t.Run(tc.name+", no API call", func(t *testing.T) {
			t.Parallel()
			var f = systemTunableFake(t, systemTunableRows()...)
			wantFailure(t, f.run(append([]string{"/system/tunable", "add"}, tc.args...)...), tc.wants...)
			wantNoCalls(t, f)
		})
	}
}

func TestSystemTunableSet(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		args []string
		uuid string
		want map[string]any
	}{
		{"configured tunable gets only the new value", []string{"kern.ipc.maxsockbuf", "value=16777216"}, systemTunableOverride,
			map[string]any{"value": "16777216"}},
		{"description and empty value", []string{systemTunableCustom, "value=", "description=new"}, systemTunableCustom,
			map[string]any{"value": "", "descr": "new"}},
		{"rename by index", []string{"1", "name=kern.custom.renamed"}, systemTunableCustom, map[string]any{"tunable": "kern.custom.renamed"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = systemTunableFake(t, systemTunableRows()...)
			f.on("POST", systemTunableSetPath+tc.uuid, 200, answerSaved)
			var r = f.run(append([]string{"/system/tunable", "set"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != "" || r.stderr != "" {
				t.Errorf("set must be silent: %q %q", r.stdout, r.stderr)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", systemTunableSetPath+tc.uuid), map[string]any{"sysctl": tc.want})
		})
	}

	t.Run("a built-in default gets an override", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, systemTunableRows()...)
		f.on("POST", systemTunableAddPath, 200, answerAdded("t-new"))
		var r = f.run("/system/tunable", "set", "vfs.read_max", "value=128", "description=faster")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "override", "t-new")
		wantJSON(t, wantOneMutation(t, f, "POST", systemTunableAddPath),
			map[string]any{"sysctl": map[string]any{"tunable": "vfs.read_max", "value": "128", "descr": "faster"}})
	})

	for _, tc := range []struct {
		name  string
		rows  []map[string]any
		args  []string
		wants []string
	}{
		{"nothing to change", systemTunableRows(), []string{"kern.custom.knob"}, []string{"nothing to change"}},
		{"built-in without value", systemTunableRows(), []string{"vfs.read_max", "description=x"}, []string{"built-in", "value="}},
		{"built-in rename", systemTunableRows(), []string{"vfs.read_max", "name=vfs.other", "value=1"}, []string{"can not be renamed"}},
		{"ambiguous name", append(systemTunableRows(), systemTunableRow(map[string]any{"uuid": systemTunableDup})),
			[]string{"kern.ipc.maxsockbuf", "value=1"}, []string{systemTunableDup}},
		{"unknown item", systemTunableRows(), []string{"kern.nope", "value=1"}, []string{"not found"}},
		{"bad value", systemTunableRows(), []string{"kern.custom.knob", "value=a\"b"}, []string{"double quotes"}},
		{"bad name", systemTunableRows(), []string{"kern.custom.knob", "name=a b"}, []string{"sysctl name"}},
	} {
		t.Run(tc.name+", no change", func(t *testing.T) {
			t.Parallel()
			var f = systemTunableFake(t, tc.rows...)
			wantFailure(t, f.run(append([]string{"/system/tunable", "set"}, tc.args...)...), tc.wants...)
			wantNoMutations(t, f)
		})
	}
}

func TestSystemTunableRemove(t *testing.T) {
	t.Parallel()
	for _, selector := range []string{"kern.custom.knob", systemTunableCustom, "1"} {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()
			var f = systemTunableFake(t, systemTunableRows()...)
			f.on("POST", systemTunableDelPath+systemTunableCustom, 200, answerDeleted)
			var r = f.run("/system/tunable", "remove", selector)
			wantExit(t, r, 0)
			if r.stdout != "" || r.stderr != "" {
				t.Errorf("remove must be silent: %q %q", r.stdout, r.stderr)
			}
			wantOneMutation(t, f, "POST", systemTunableDelPath+systemTunableCustom)
		})
	}

	t.Run("removing an override mentions the default", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, systemTunableRows()...)
		f.on("POST", systemTunableDelPath+systemTunableOverride, 200, answerDeleted)
		var r = f.run("/system/tunable", "remove", "kern.ipc.maxsockbuf")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "kern.ipc.maxsockbuf=4262144")
		wantOneMutation(t, f, "POST", systemTunableDelPath+systemTunableOverride)
	})
	t.Run("built-in defaults can not be removed", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, systemTunableRows()...)
		wantFailure(t, f.run("/system/tunable", "remove", "vfs.read_max"), "built-in", "set vfs.read_max value=")
		wantNoMutations(t, f)
	})
	t.Run("ambiguous name", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, append(systemTunableRows(), systemTunableRow(map[string]any{"uuid": systemTunableDup}))...)
		wantFailure(t, f.run("/system/tunable", "remove", "kern.ipc.maxsockbuf"), systemTunableDup, "uuid")
		wantNoMutations(t, f)
	})
	t.Run("unknown uuid", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, systemTunableRows()...)
		wantFailure(t, f.run("/system/tunable", "remove", "t-nope"), "not found")
		wantNoMutations(t, f)
	})
	t.Run("no item, no API call", func(t *testing.T) {
		t.Parallel()
		var f = systemTunableFake(t, systemTunableRows()...)
		wantFailure(t, f.run("/system/tunable", "remove"), "item")
		wantNoCalls(t, f)
	})
}

func TestSystemTunableApply(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", systemTunableReconfigPath, 200, `{"status":"ok"}`)
	var r = f.run("/system/tunable", "apply")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("apply must be silent: %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", systemTunableReconfigPath)
	if calls := f.calls(); len(calls) != 1 {
		t.Errorf("want only the reconfigure call, got %v", calls)
	}

	t.Run("failure status", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("POST", systemTunableReconfigPath, 200, `{"status":"failed"}`)
		wantFailure(t, f.run("/system/tunable", "apply"), "failed")
	})
}
