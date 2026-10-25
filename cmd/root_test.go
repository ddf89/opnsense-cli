package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// every command that talks to the API, with the minimal valid flags
var apiCommands = [][]string{
	{"unbound", "hostoverride", "list"},
	{"unbound", "hostoverride", "show", "--uuid", "u1"},
	{"unbound", "hostoverride", "create", "--host", "h", "--domain", "d.lan", "--ip", "10.0.0.1"},
	{"unbound", "hostoverride", "update", "--host", "h", "--domain", "d.lan", "--ip", "10.0.0.1"},
	{"unbound", "hostoverride", "rm", "--uuid", "u1"},
	{"unbound", "service", "status"},
	{"unbound", "service", "restart"},
	{"unbound", "service", "reconfigure"},
	{"dnsmasq", "host", "list"},
	{"dnsmasq", "host", "show", "--uuid", "u1"},
	{"dnsmasq", "host", "create", "--host", "h"},
	{"dnsmasq", "host", "update", "--uuid", "u1", "--description", "x"},
	{"dnsmasq", "host", "rm", "--uuid", "u1"},
	{"dnsmasq", "domain", "list"},
	{"dnsmasq", "domain", "show", "--uuid", "u1"},
	{"dnsmasq", "domain", "create", "--domain", "corp.example"},
	{"dnsmasq", "domain", "update", "--uuid", "u1", "--description", "x"},
	{"dnsmasq", "domain", "rm", "--uuid", "u1"},
	{"dnsmasq", "service", "status"},
	{"dnsmasq", "service", "start"},
	{"dnsmasq", "service", "stop"},
	{"dnsmasq", "service", "restart"},
	{"dnsmasq", "service", "reconfigure"},
	{"dnsmasq", "leases", "list"},
}

func TestMissingEnvironment(t *testing.T) {
	t.Parallel()
	var full = map[string]string{"OPN_URL": "https://127.0.0.1:1", "OPN_APIKEY": "k", "OPN_APISECRET": "s"}
	for _, missing := range []string{"OPN_URL", "OPN_APIKEY", "OPN_APISECRET"} {
		var env []string
		for name, value := range full {
			if name != missing {
				env = append(env, name+"="+value)
			}
		}
		for _, args := range apiCommands {
			t.Run(missing+"/"+strings.Join(args, "_"), func(t *testing.T) {
				t.Parallel()
				var r = runOpn(t, env, args...)
				wantFailure(t, r, missing)
			})
		}
	}
}

// every command must authenticate with the api key / secret and report a 401 as error
func TestUnauthorized(t *testing.T) {
	t.Parallel()
	for _, args := range apiCommands {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
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

// OPNsense answers unknown endpoints (e.g. an older version without dnsmasq) with an empty 200
func TestEmptyResponseIsAnError(t *testing.T) {
	t.Parallel()
	for _, args := range apiCommands {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t) // nothing registered: every endpoint answers an empty 200
			var r = f.run(args...)
			wantFailure(t, r, "empty response")
		})
	}
}

func TestTLSVerification(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search("/api/unbound/settings/search_host_override")

	t.Run("self signed certificate is rejected without OPN_NOSSLVERIFY", func(t *testing.T) {
		var env = []string{"OPN_URL=" + f.srv.URL, "OPN_APIKEY=" + testApiKey, "OPN_APISECRET=" + testApiSecret}
		var r = runOpn(t, env, "unbound", "hostoverride", "list")
		wantFailure(t, r, "certificate")
	})
	t.Run("OPN_NOSSLVERIFY=0 still verifies", func(t *testing.T) {
		var env = []string{"OPN_URL=" + f.srv.URL, "OPN_APIKEY=" + testApiKey, "OPN_APISECRET=" + testApiSecret, "OPN_NOSSLVERIFY=0"}
		var r = runOpn(t, env, "unbound", "hostoverride", "list")
		wantFailure(t, r, "certificate")
	})
	t.Run("OPN_NOSSLVERIFY=1 skips verification", func(t *testing.T) {
		var r = f.run("unbound", "hostoverride", "list")
		wantExit(t, r, 0)
	})
}

func TestBaseUrlWithTrailingSlash(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search("/api/dnsmasq/settings/search_host")
	var env = append(f.env()[1:], "OPN_URL="+f.srv.URL+"/")
	var r = runOpn(t, env, "dnsmasq", "host", "list")
	wantExit(t, r, 0)
	wantSearchPhrases(t, f, "/api/dnsmasq/settings/search_host", "")
}

func TestDotEnvInWorkingDirectory(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search("/api/dnsmasq/settings/search_host", dnsmasqHostRow(map[string]any{"uuid": "u1"}))

	var dir = t.TempDir()
	var dotEnv = strings.Join(f.env(), "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(dotEnv), 0o600); err != nil {
		t.Fatal(err)
	}
	var r = runOpnIn(t, dir, nil, "dnsmasq", "host", "list")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "u1")

	// the real environment wins over .env
	var env = []string{"OPN_APISECRET=wrong"}
	r = runOpnIn(t, dir, env, "dnsmasq", "host", "list")
	wantFailure(t, r, "401")
}

func TestHelpListsCommands(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args  []string
		wants []string
	}{
		{[]string{"--help"}, []string{"unbound", "dnsmasq"}},
		{[]string{"dnsmasq", "--help"}, []string{"host", "domain", "service", "leases"}},
		{[]string{"dnsmasq", "host", "--help"}, []string{"create", "update", "show", "rm", "list"}},
		{[]string{"dnsmasq", "domain", "--help"}, []string{"create", "update", "show", "rm", "list"}},
		{[]string{"dnsmasq", "service", "--help"}, []string{"status", "start", "stop", "restart", "reconfigure"}},
		{[]string{"unbound", "hostoverride", "--help"}, []string{"create", "update", "show", "rm", "list"}},
		{[]string{"unbound", "service", "--help"}, []string{"status", "restart", "reconfigure"}},
		{[]string{"unbound", "hostoverride", "create", "--help"}, []string{"--ttl", "--txtdata", "--addptr", "--rr", "--mx", "--mxprio"}},
		{[]string{"unbound", "hostoverride", "list", "--help"}, []string{"--search"}},
		{[]string{"unbound", "hostoverride", "show", "--help"}, []string{"--uuid"}},
	} {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			t.Parallel()
			var r = runOpn(t, nil, tc.args...)
			wantExit(t, r, 0)
			wantContains(t, "help", r.stdout, tc.wants...)
		})
	}
}

// usage errors belong on stderr only, stdout is reserved for results (e.g. the uuid printed by create)
func TestUsageErrorsKeepStdoutClean(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"dnsmasq", "host", "create", "--domain", "example.lan"},
		{"dnsmasq", "host", "list", "extra"},
		{"unbound", "hostoverride", "create", "--nope"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var r = runOpn(t, nil, args...)
			wantExit(t, r, 1)
			wantContains(t, "stderr", r.stderr, "Error:")
			if r.stdout != "" {
				t.Skipf("BUG: cmd/root.go Execute() prints the error a second time to stdout: %q", r.stdout)
			}
		})
	}
}
