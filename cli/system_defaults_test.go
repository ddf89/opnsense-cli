package cli

import (
	"strings"
	"testing"
)

const (
	systemDefaultsGetPath   = "/api/core/defaults/get"
	systemDefaultsResetPath = "/api/core/defaults/factory_defaults"
	systemDefaultsAnswer    = `{"default_ip":"192.168.1.1"}`
)

func TestSystemDefaultsPrint(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", systemDefaultsGetPath, 200, systemDefaultsAnswer)
	var r = f.run("/system/defaults", "print")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != "default-ip:  192.168.1.1" {
		t.Errorf("stdout %q", r.stdout)
	}
	wantNoMutations(t, f)

	r = f.run("/system/defaults", "print", "json")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != systemDefaultsAnswer {
		t.Errorf("json %q", r.stdout)
	}

	t.Run("answer without default_ip is an error", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", systemDefaultsGetPath, 200, `{}`)
		wantFailure(t, f.run("/system/defaults", "print"), "default_ip")
	})
}

// a factory reset must never reach the API without confirmation
func TestSystemDefaultsResetGuard(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{},
		{"confirm=no"},
		{"yes"},
		{"confirm", "now"},
		{"force"},
		{"confirm=maybe"},
	} {
		t.Run(systemBackupName(args), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on("GET", systemDefaultsGetPath, 200, systemDefaultsAnswer)
			f.on("POST", systemDefaultsResetPath, 200, systemBackupStatusOk)
			var r = f.run(append([]string{"/system/defaults", "reset"}, args...)...)
			wantFailure(t, r)
			wantNoCalls(t, f)
		})
	}

	t.Run("the warning is shown without confirm", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		var r = f.run("/system/defaults", "reset")
		wantFailure(t, r, "confirm=yes")
		wantContains(t, "stderr", strings.ToLower(r.stderr), "factory reset", "api key", "no undo")
		wantNoCalls(t, f)
	})
	t.Run("a script does not reset", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		wantFailure(t, f.runScript("/system/defaults\nreset\n"), "confirm=yes")
		wantNoCalls(t, f)
	})
	t.Run("the warning is in the help", func(t *testing.T) {
		t.Parallel()
		var r = runOpn(t, nil, "/system/defaults", "reset", "?")
		wantExit(t, r, 0)
		wantContains(t, "help", r.stdout, "WHOLE configuration", "confirm")
	})
}

func TestSystemDefaultsReset(t *testing.T) {
	t.Parallel()

	t.Run("confirm is a single POST after checking the API", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", systemDefaultsGetPath, 200, systemDefaultsAnswer)
		f.on("POST", systemDefaultsResetPath, 200, systemBackupStatusOk)
		var r = f.run("/system/defaults", "reset", "confirm")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "192.168.1.1")
		wantOneMutation(t, f, "POST", systemDefaultsResetPath)
		var calls = f.calls()
		if len(calls) != 2 || calls[0].Method != "GET" || calls[0].Path != systemDefaultsGetPath {
			t.Errorf("want the GET of the defaults first, got %v", calls)
		}
	})
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"unknown endpoint", 200, ""},
		{"HTTP error", 500, `{"errorMessage":"boom"}`},
		{"no default_ip", 200, `{}`},
	} {
		t.Run("no reset when the defaults can not be read: "+tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			if tc.body != "" || tc.status != 200 {
				f.on("GET", systemDefaultsGetPath, tc.status, tc.body)
			}
			f.on("POST", systemDefaultsResetPath, 200, systemBackupStatusOk)
			wantFailure(t, f.run("/system/defaults", "reset", "confirm=yes"))
			systemBackupWantNoCallTo(t, f, systemDefaultsResetPath)
		})
	}
	t.Run("a not accepted reset is an error", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", systemDefaultsGetPath, 200, systemDefaultsAnswer)
		f.on("POST", systemDefaultsResetPath, 200, `{"status":"failed"}`)
		wantFailure(t, f.run("/system/defaults", "reset", "confirm"), "failed")
	})
}
