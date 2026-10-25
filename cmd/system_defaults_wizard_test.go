package cmd

import (
	"strings"
	"testing"
)

func TestSysDefaultsShow(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", sysDefaultsGetPath, 200, sysDefaults)
	var r = f.run("system", "defaults", "show")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "192.168.1.1")
	wantNoMutations(t, f)

	t.Run("answer without default_ip is an error", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", sysDefaultsGetPath, 200, `{}`)
		wantFailure(t, f.run("system", "defaults", "show"), "default_ip")
	})
}

// a factory reset must never reach the API without --yes
func TestSysDefaultsResetGuard(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{},
		{"--yes=false"},
		{"yes"},
		{"--yes", "now"},
		{"-y"},
		{"--force"},
	} {
		t.Run(sysName(args), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on("GET", sysDefaultsGetPath, 200, sysDefaults)
			f.on("POST", sysDefaultsResetPath, 200, sysAnswerStatusOk)
			var r = f.run(append([]string{"system", "defaults", "reset"}, args...)...)
			wantFailure(t, r)
			wantNoCalls(t, f)
		})
	}

	t.Run("the warning is shown without --yes", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		var r = f.run("system", "defaults", "reset")
		wantFailure(t, r, "--yes")
		wantContains(t, "stderr", strings.ToLower(r.stderr), "factory reset", "api key")
		wantNoCalls(t, f)
	})
}

func TestSysDefaultsReset(t *testing.T) {
	t.Parallel()

	t.Run("--yes is a single POST after checking the API", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", sysDefaultsGetPath, 200, sysDefaults)
		f.on("POST", sysDefaultsResetPath, 200, sysAnswerStatusOk)
		var r = f.run("system", "defaults", "reset", "--yes")
		wantExit(t, r, 0)
		wantContains(t, "output", r.stdout+r.stderr, "192.168.1.1")
		wantOneMutation(t, f, "POST", sysDefaultsResetPath)
		sysWantCalled(t, f, "GET", sysDefaultsGetPath)
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
				f.on("GET", sysDefaultsGetPath, tc.status, tc.body)
			}
			f.on("POST", sysDefaultsResetPath, 200, sysAnswerStatusOk)
			wantFailure(t, f.run("system", "defaults", "reset", "--yes"))
			sysWantNoCallTo(t, f, sysDefaultsResetPath)
		})
	}
	t.Run("a not accepted reset is an error", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", sysDefaultsGetPath, 200, sysDefaults)
		f.on("POST", sysDefaultsResetPath, 200, `{"status":"failed"}`)
		wantFailure(t, f.run("system", "defaults", "reset", "--yes"), "failed")
	})
}

func TestSysWizardShow(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", sysWizardGetPath, 200, sysWizard)
	var r = f.run("system", "wizard", "show")
	wantExit(t, r, 0)

	var fields = map[string]string{}
	for _, row := range sysTable(r.stdout) {
		fields[strings.TrimSuffix(row[0], ":")] = strings.Join(row[1:], " ")
	}
	for key, want := range map[string]string{
		"hostname": "OPNsense", "domain": "internal", "language": "en_US", "timezone": "Etc/UTC",
		"dns_servers": "9.9.9.9,1.1.1.1", "wan.ipv4_type": "dhcp", "lan.ipaddr": "192.168.1.1/24", "unbound.enabled": "1",
	} {
		if fields[key] != want {
			t.Errorf("%s: got %q, want %q", key, fields[key], want)
		}
	}
	// the (normally empty) password fields are never shown
	wantNotContains(t, "output", r.stdout+r.stderr, "s3cr3t", "password")
	wantNoMutations(t, f)

	t.Run("answer without wizard is an error", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", sysWizardGetPath, 200, `{"result":"failed"}`)
		wantFailure(t, f.run("system", "wizard", "show"), "wizard")
	})
	t.Run("there is no way to apply the wizard", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", sysWizardGetPath, 200, sysWizard)
		for _, args := range [][]string{{"system", "wizard", "set"}, {"system", "wizard", "configure"}, {"system", "wizard", "apply"}} {
			var r = f.run(args...)
			if r.code == 0 && !strings.Contains(r.stdout, "Usage") {
				t.Errorf("opn %v did something: %s", args, r)
			}
		}
		wantNoMutations(t, f)
	})
}

// --- cross-cutting checks for every system command that talks to the API

// sysApiCommands are all system commands that call the API, with minimal valid flags.
// Destructive ones are included: they only ever reach the fake server
var sysApiCommands = [][]string{
	{"system", "cron", "list"},
	{"system", "cron", "show", "--uuid", "c1"},
	{"system", "cron", "create", "--command", "firmware poll", "--description", "x"},
	{"system", "cron", "update", "--uuid", "c1", "--hours", "1"},
	{"system", "cron", "rm", "--uuid", "c1"},
	{"system", "cron", "enable", "--uuid", "c1"},
	{"system", "cron", "disable", "--uuid", "c1"},
	{"system", "cron", "commands"},
	{"system", "cron", "apply"},
	{"system", "tunable", "list"},
	{"system", "tunable", "show", "--name", "kern.x"},
	{"system", "tunable", "set", "--name", "kern.x", "--value", "1"},
	{"system", "tunable", "rm", "--uuid", "t1"},
	{"system", "tunable", "apply"},
	{"system", "logging", "show"},
	{"system", "logging", "set", "--maxpreserve", "10"},
	{"system", "logging", "destination", "list"},
	{"system", "logging", "destination", "show", "--uuid", "d1"},
	{"system", "logging", "destination", "create", "--hostname", "192.0.2.10"},
	{"system", "logging", "destination", "update", "--uuid", "d1", "--port", "1515"},
	{"system", "logging", "destination", "rm", "--uuid", "d1"},
	{"system", "logging", "destination", "enable", "--uuid", "d1"},
	{"system", "logging", "destination", "disable", "--uuid", "d1"},
	{"system", "logging", "service", "status"},
	{"system", "logging", "service", "restart"},
	{"system", "logging", "service", "reconfigure"},
	{"system", "logging", "stats"},
	{"system", "backup", "providers"},
	{"system", "backup", "list"},
	{"system", "backup", "download", "--output", "-"},
	{"system", "backup", "diff", "--from", "config-1.xml"},
	{"system", "backup", "revert", "--id", "config-1.xml", "--yes"},
	{"system", "backup", "rm", "--id", "config-1.xml", "--yes"},
	{"system", "defaults", "show"},
	{"system", "defaults", "reset", "--yes"},
	{"system", "wizard", "show"},
}

func TestSysMissingEnvironment(t *testing.T) {
	t.Parallel()
	var full = map[string]string{"OPN_URL": "https://127.0.0.1:1", "OPN_APIKEY": "k", "OPN_APISECRET": "s"}
	for _, missing := range []string{"OPN_URL", "OPN_APIKEY", "OPN_APISECRET"} {
		var env []string
		for name, value := range full {
			if name != missing {
				env = append(env, name+"="+value)
			}
		}
		for _, args := range sysApiCommands {
			t.Run(missing+"/"+strings.Join(args[1:], "_"), func(t *testing.T) {
				t.Parallel()
				wantFailure(t, runOpn(t, env, args...), missing)
			})
		}
	}
}

// every command authenticates with the api key / secret and stops at the first 401
func TestSysUnauthorized(t *testing.T) {
	t.Parallel()
	for _, args := range sysApiCommands {
		t.Run(strings.Join(args[1:], "_"), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			var env = []string{"OPN_URL=" + f.srv.URL, "OPN_APIKEY=" + testApiKey, "OPN_APISECRET=wrong", "OPN_NOSSLVERIFY=1"}
			var r = runOpn(t, env, args...)
			wantFailure(t, r, "401", "Authentication Failed")
			var calls = f.calls()
			if len(calls) != 1 {
				t.Errorf("want a single (rejected) API call, got %v", calls)
			}
			for _, call := range calls {
				if !call.HasAuth || call.User != testApiKey || call.Pass != "wrong" {
					t.Errorf("%s: basic auth not sent as given: %q/%q", call, call.User, call.Pass)
				}
			}
		})
	}
}

// OPNsense answers unknown endpoints (e.g. a version without the API) with an empty 200, that is never a success
func TestSysEmptyResponseIsAnError(t *testing.T) {
	t.Parallel()
	for _, args := range sysApiCommands {
		t.Run(strings.Join(args[1:], "_"), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			var r = f.run(args...)
			wantExit(t, r, 1)
			wantNotContains(t, "output", r.stdout+r.stderr, "success", "saved", "reverted", "scheduled", "applied", "reconfigured", "restarted")
			if r.stdout != "" {
				t.Errorf("a failed command printed to stdout: %q", r.stdout)
			}
		})
	}
}

// actions must be POSTed: OPNsense silently ignores a GET
func TestSysActionsArePosts(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args []string
		path string
		body string
	}{
		{[]string{"system", "cron", "apply"}, sysCronReconfigPath, sysAnswerStatusOk},
		{[]string{"system", "tunable", "apply"}, sysTunableReconfigPath, sysAnswerStatusOk},
		{[]string{"system", "logging", "service", "restart"}, sysSyslogRestartPath, `{"response":"OK"}`},
		{[]string{"system", "logging", "service", "reconfigure"}, sysSyslogReconfigurePath, sysAnswerStatusOk},
		{[]string{"system", "cron", "enable", "--uuid", "c1"}, sysCronTogglePath + "c1/1", `{"result":"Enabled","changed":true}`},
		{[]string{"system", "backup", "rm", "--id", sysBackupOldest, "--yes"}, sysBackupDeletePath + sysBackupOldest, `{"status":"deleted"}`},
	} {
		t.Run(strings.Join(tc.args[1:], "_"), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			// answer the action for any method, so a wrong method would succeed and be caught here
			for _, method := range []string{"GET", "POST", "PUT"} {
				f.on(method, tc.path, 200, tc.body)
			}
			wantExit(t, f.run(tc.args...), 0)
			for _, call := range f.calls() {
				if call.Path == tc.path && call.Method != "POST" {
					t.Errorf("%s sent as %s", tc.path, call.Method)
				}
			}
			sysWantCalled(t, f, "POST", tc.path)
		})
	}
}

func TestSysHelp(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args  []string
		wants []string
	}{
		{[]string{"--help"}, []string{"system"}},
		{[]string{"system", "--help"}, []string{"cron", "tunable", "logging", "backup", "defaults", "wizard"}},
		{[]string{"system", "cron", "--help"}, []string{"list", "show", "create", "update", "rm", "enable", "disable", "commands", "apply"}},
		{[]string{"system", "tunable", "--help"}, []string{"list", "show", "set", "rm", "apply"}},
		{[]string{"system", "logging", "--help"}, []string{"show", "set", "destination", "service", "stats"}},
		{[]string{"system", "logging", "destination", "--help"}, []string{"list", "show", "create", "update", "rm", "enable", "disable"}},
		{[]string{"system", "logging", "service", "--help"}, []string{"status", "restart", "reconfigure"}},
		{[]string{"system", "backup", "--help"}, []string{"providers", "list", "download", "diff", "revert", "rm"}},
		{[]string{"system", "defaults", "--help"}, []string{"show", "reset"}},
		{[]string{"system", "wizard", "--help"}, []string{"show"}},
		{[]string{"system", "defaults", "reset", "--help"}, []string{"--yes"}},
		{[]string{"system", "backup", "revert", "--help"}, []string{"--yes", "--id"}},
		{[]string{"system", "backup", "rm", "--help"}, []string{"--yes", "--id"}},
	} {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			t.Parallel()
			var r = runOpn(t, nil, tc.args...)
			wantExit(t, r, 0)
			wantContains(t, "help", r.stdout, tc.wants...)
		})
	}
}
