package cmd

import (
	"testing"
)

// sysTunableRows: a configured override, a custom tunable, a built-in default and decoys with similar names
func sysTunableRows() []map[string]any {
	return []map[string]any{
		sysTunableRow(map[string]any{"uuid": "t-override-0000-4000-8000-000000000001"}),
		sysTunableRow(map[string]any{"uuid": "t-custom-0000-4000-8000-000000000002", "tunable": "kern.custom.knob", "value": "7",
			"descr": "my custom knob", "default_value": "", "type": ""}),
		sysTunableRow(map[string]any{"uuid": sysTunableBuiltinUuid, "tunable": "vfs.read_max", "value": "64", "default_value": "32",
			"descr": "Cluster read-ahead max block count"}),
		sysTunableRow(map[string]any{"uuid": "a1b2c3d4e5f60718293a4b5c6d7e8f90", "tunable": "kern.ipc.maxsockbuf_extra", "value": "1"}),
		sysTunableRow(map[string]any{"uuid": "t-same-0000-4000-8000-000000000003", "tunable": "kern.custom.knob2", "value": "7",
			"descr": "", "default_value": "7"}),
	}
}

func sysTunableFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(sysTunableSearchPath, rows...)
	return f
}

func TestSysTunableList(t *testing.T) {
	t.Parallel()
	var f = sysTunableFake(t, sysTunableRows()...)
	var r = f.run("system", "tunable", "list")
	wantExit(t, r, 0)
	var rows = sysWantTable(t, r.stdout, []string{"UUID", "TUNABLE", "VALUE", "DEFAULT", "TYPE", "SOURCE", "DESCRIPTION"},
		"t-override-0000-4000-8000-000000000001", "t-custom-0000-4000-8000-000000000002", sysTunableBuiltinUuid,
		"a1b2c3d4e5f60718293a4b5c6d7e8f90", "t-same-0000-4000-8000-000000000003")
	if len(rows) == 6 {
		for i, want := range []string{"override", "custom", "built-in"} {
			if rows[i+1][5] != want {
				t.Errorf("SOURCE of row %d: %q, want %q", i+1, rows[i+1][5], want)
			}
		}
		if rows[1][4] != "runtime" {
			t.Errorf("TYPE of w: %q", rows[1][4])
		}
	}
	wantSearchPhrases(t, f, sysTunableSearchPath, "")
	wantNoMutations(t, f)

	t.Run("--changed only lists configured values differing from the default", func(t *testing.T) {
		t.Parallel()
		var f = sysTunableFake(t, sysTunableRows()...)
		var r = f.run("system", "tunable", "list", "--changed")
		wantExit(t, r, 0)
		sysWantTable(t, r.stdout, []string{"UUID", "TUNABLE", "VALUE", "DEFAULT", "TYPE", "SOURCE", "DESCRIPTION"},
			"t-override-0000-4000-8000-000000000001", "t-custom-0000-4000-8000-000000000002")
	})
	t.Run("--search is passed on", func(t *testing.T) {
		t.Parallel()
		var f = sysTunableFake(t, sysTunableRows()...)
		wantExit(t, f.run("system", "tunable", "list", "--search", "kern.ipc"), 0)
		wantSearchPhrases(t, f, sysTunableSearchPath, "kern.ipc")
	})
}

func TestSysTunableShow(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args  []string
		wants []string
	}{
		{[]string{"--name", "kern.ipc.maxsockbuf"}, []string{"t-override-0000-4000-8000-000000000001", "8388608", "4262144", "override"}},
		{[]string{"--uuid", "t-custom-0000-4000-8000-000000000002"}, []string{"kern.custom.knob", "my custom knob", "custom"}},
		{[]string{"--name", "vfs.read_max"}, []string{sysTunableBuiltinUuid, "Runtime value", "64", "built-in"}},
	} {
		t.Run(sysName(tc.args), func(t *testing.T) {
			t.Parallel()
			var f = sysTunableFake(t, sysTunableRows()...)
			var r = f.run(append([]string{"system", "tunable", "show"}, tc.args...)...)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, tc.wants...)
			wantNotContains(t, "stdout", r.stdout, "maxsockbuf_extra")
			wantNoMutations(t, f)
		})
	}

	t.Run("name configured twice is ambiguous", func(t *testing.T) {
		t.Parallel()
		var f = sysTunableFake(t, append(sysTunableRows(),
			sysTunableRow(map[string]any{"uuid": "t-dup-0000-4000-8000-000000000009"}))...)
		var r = f.run("system", "tunable", "show", "--name", "kern.ipc.maxsockbuf")
		wantFailure(t, r, "t-override-0000-4000-8000-000000000001", "t-dup-0000-4000-8000-000000000009", "--uuid")
	})
	t.Run("unknown name", func(t *testing.T) {
		t.Parallel()
		var f = sysTunableFake(t, sysTunableRows()...)
		wantFailure(t, f.run("system", "tunable", "show", "--name", "kern.ipc"), "not found")
	})
	for _, args := range [][]string{{}, {"--name", "a.b", "--uuid", "u"}} {
		t.Run("selector flags "+sysName(args)+", no API call", func(t *testing.T) {
			t.Parallel()
			var f = sysTunableFake(t, sysTunableRows()...)
			wantFailure(t, f.run(append([]string{"system", "tunable", "show"}, args...)...), "name", "uuid")
			wantNoCalls(t, f)
		})
	}
}

func TestSysTunableSet(t *testing.T) {
	t.Parallel()

	t.Run("configured tunable gets only the new value", func(t *testing.T) {
		t.Parallel()
		var f = sysTunableFake(t, sysTunableRows()...)
		var path = sysTunableSetPath + "t-override-0000-4000-8000-000000000001"
		f.on("POST", path, 200, answerSaved)
		var r = f.run("system", "tunable", "set", "--name", "kern.ipc.maxsockbuf", "--value", "16777216")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "t-override-0000-4000-8000-000000000001")
		wantJSON(t, wantOneMutation(t, f, "POST", path), map[string]any{"sysctl": map[string]any{"value": "16777216"}})
	})
	t.Run("description is sent when given", func(t *testing.T) {
		t.Parallel()
		var f = sysTunableFake(t, sysTunableRows()...)
		var path = sysTunableSetPath + "t-custom-0000-4000-8000-000000000002"
		f.on("POST", path, 200, answerSaved)
		wantExit(t, f.run("system", "tunable", "set", "--name", "kern.custom.knob", "--value", "", "--description", "new"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", path), map[string]any{"sysctl": map[string]any{"value": "", "descr": "new"}})
	})
	t.Run("built-in default is overridden with a new entry", func(t *testing.T) {
		t.Parallel()
		var f = sysTunableFake(t, sysTunableRows()...)
		f.on("POST", sysTunableAddPath, 200, answerAdded("t-new"))
		var r = f.run("system", "tunable", "set", "--name", "vfs.read_max", "--value", "128")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "t-new")
		wantJSON(t, wantOneMutation(t, f, "POST", sysTunableAddPath),
			map[string]any{"sysctl": map[string]any{"tunable": "vfs.read_max", "value": "128", "descr": ""}})
	})
	t.Run("unknown name is created, similar names are no match", func(t *testing.T) {
		t.Parallel()
		var f = sysTunableFake(t, sysTunableRows()...)
		f.on("POST", sysTunableAddPath, 200, answerAdded("t-new"))
		wantExit(t, f.run("system", "tunable", "set", "--name", "kern.ipc", "--value", "1", "--description", "d"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", sysTunableAddPath),
			map[string]any{"sysctl": map[string]any{"tunable": "kern.ipc", "value": "1", "descr": "d"}})
	})
	t.Run("duplicates are refused", func(t *testing.T) {
		t.Parallel()
		var f = sysTunableFake(t, append(sysTunableRows(),
			sysTunableRow(map[string]any{"uuid": "t-dup-0000-4000-8000-000000000009"}))...)
		wantFailure(t, f.run("system", "tunable", "set", "--name", "kern.ipc.maxsockbuf", "--value", "1"), "t-dup-0000-4000-8000-000000000009")
		wantNoMutations(t, f)
	})
	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = sysTunableFake(t)
		f.on("POST", sysTunableAddPath, 200, answerValidation("sysctl.value", "value is invalid"))
		wantFailure(t, f.run("system", "tunable", "set", "--name", "kern.x", "--value", "1"), "sysctl.value", "value is invalid")
	})

	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"name is required", []string{"--value", "1"}, []string{"name"}},
		{"value is required", []string{"--name", "kern.x"}, []string{"value"}},
		{"empty name", []string{"--name", "", "--value", "1"}, []string{"name"}},
		{"name with a space", []string{"--name", "kern.x y", "--value", "1"}, []string{"kern.x y"}},
		{"name with a newline", []string{"--name", "kern.x\nkern.y", "--value", "1"}, []string{"invalid tunable name"}},
		{"name with a double dot", []string{"--name", "kern..x", "--value", "1"}, []string{"invalid tunable name"}},
		{"value with a quote", []string{"--name", "kern.x", "--value", `1"`}, []string{"invalid tunable value"}},
		{"value with a newline", []string{"--name", "kern.x", "--value", "1\nkern.evil=1"}, []string{"invalid tunable value"}},
	} {
		t.Run(tc.name+", no API call", func(t *testing.T) {
			t.Parallel()
			var f = sysTunableFake(t, sysTunableRows()...)
			wantFailure(t, f.run(append([]string{"system", "tunable", "set"}, tc.args...)...), tc.wants...)
			wantNoCalls(t, f)
		})
	}
}

func TestSysTunableRm(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"--name", "kern.custom.knob"}, {"--uuid", "t-custom-0000-4000-8000-000000000002"}} {
		t.Run(sysName(args), func(t *testing.T) {
			t.Parallel()
			var f = sysTunableFake(t, sysTunableRows()...)
			var path = sysTunableDelPath + "t-custom-0000-4000-8000-000000000002"
			f.on("POST", path, 200, answerDeleted)
			var r = f.run(append([]string{"system", "tunable", "rm"}, args...)...)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, "t-custom-0000-4000-8000-000000000002")
			wantOneMutation(t, f, "POST", path)
		})
	}

	t.Run("removing an override mentions the default", func(t *testing.T) {
		t.Parallel()
		var f = sysTunableFake(t, sysTunableRows()...)
		var path = sysTunableDelPath + "t-override-0000-4000-8000-000000000001"
		f.on("POST", path, 200, answerDeleted)
		var r = f.run("system", "tunable", "rm", "--name", "kern.ipc.maxsockbuf")
		wantExit(t, r, 0)
		wantContains(t, "output", r.stdout+r.stderr, "4262144", "apply")
		wantOneMutation(t, f, "POST", path)
	})
	t.Run("built-in defaults can not be removed", func(t *testing.T) {
		t.Parallel()
		var f = sysTunableFake(t, sysTunableRows()...)
		wantFailure(t, f.run("system", "tunable", "rm", "--name", "vfs.read_max"), "built-in")
		wantNoMutations(t, f)
	})
	t.Run("ambiguous name", func(t *testing.T) {
		t.Parallel()
		var f = sysTunableFake(t, append(sysTunableRows(),
			sysTunableRow(map[string]any{"uuid": "t-dup-0000-4000-8000-000000000009"}))...)
		wantFailure(t, f.run("system", "tunable", "rm", "--name", "kern.ipc.maxsockbuf"), "t-dup-0000-4000-8000-000000000009", "--uuid")
		wantNoMutations(t, f)
	})
	t.Run("unknown uuid", func(t *testing.T) {
		t.Parallel()
		var f = sysTunableFake(t, sysTunableRows()...)
		wantFailure(t, f.run("system", "tunable", "rm", "--uuid", "t-nope"), "not found")
		wantNoMutations(t, f)
	})
	t.Run("no selector, no API call", func(t *testing.T) {
		t.Parallel()
		var f = sysTunableFake(t, sysTunableRows()...)
		wantFailure(t, f.run("system", "tunable", "rm"), "name", "uuid")
		wantNoCalls(t, f)
	})
}

func TestSysTunableApply(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", sysTunableReconfigPath, 200, sysAnswerStatusOk)
	wantExit(t, f.run("system", "tunable", "apply"), 0)
	wantOneMutation(t, f, "POST", sysTunableReconfigPath)
	if calls := f.calls(); len(calls) != 1 {
		t.Errorf("want only the reconfigure call, got %v", calls)
	}

	t.Run("failure status", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("POST", sysTunableReconfigPath, 200, `{"status":"failed"}`)
		wantFailure(t, f.run("system", "tunable", "apply"), "failed")
	})
}
