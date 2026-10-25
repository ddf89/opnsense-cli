package cli

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

const (
	firewallRuleTransferDownloadPath = "/api/firewall/filter/download_rules"
	firewallRuleTransferUploadPath   = "/api/firewall/filter/upload_rules"
	firewallRuleTransferGetRulePath  = "/api/firewall/filter/get_rule"

	// firewallRuleTransferCsv is an export of OPNsense 26.7 (trimmed columns)
	firewallRuleTransferCsv = "@uuid;enabled;action;interface;source_net;destination_net;categories;description\n" +
		"d621e174-154f-4ebb-9465-6e2fac4b2bcb;1;pass;lan;lan;any;;\"Default allow LAN to any rule\"\n" +
		"6d19c02b-60ef-47a2-be81-d5a213fc394f;1;pass;lan;lan;any;web,mail;\"Default allow LAN IPv6 to any rule\"\n"

	// firewallRuleTransferGetRule is get_rule without uuid (trimmed): the field names of a rule
	firewallRuleTransferGetRule = `{"rule":{"enabled":"1","sort_order":"","prio_group":"","sequence":"1",` +
		`"action":{"pass":{"value":"Pass","selected":1},"block":{"value":"Block","selected":0}},` +
		`"interface":{"lan":{"value":"LAN","selected":0}},"source_net":"any","destination_net":"any","categories":{},"description":""}}`
)

func firewallRuleTransferFake(t *testing.T, export string) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.onFunc("GET", firewallRuleTransferDownloadPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/csv;charset=UTF-8")
		_, _ = w.Write([]byte(export))
	})
	f.on("GET", firewallRuleTransferGetRulePath, 200, firewallRuleTransferGetRule)
	return f
}

// firewallRuleTransferFile writes content to a new file in a temp dir and returns its path
func firewallRuleTransferFile(t *testing.T, name string, content string) string {
	t.Helper()
	var path = filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFirewallRuleExport(t *testing.T) {
	t.Parallel()
	t.Run("stdout", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleTransferFake(t, firewallRuleTransferCsv)
		var r = f.run("/firewall/rule", "export", "file=-")
		wantExit(t, r, 0)
		if r.stdout != firewallRuleTransferCsv {
			t.Errorf("stdout:\n%s", r.stdout)
		}
		wantNoMutations(t, f)
	})
	t.Run("file", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleTransferFake(t, firewallRuleTransferCsv)
		var path = filepath.Join(t.TempDir(), "rules.csv")
		var r = f.run("/firewall/rule", "export", path)
		wantExit(t, r, 0)
		if r.stdout != "" {
			t.Errorf("stdout must be empty: %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, "saved 2 firewall rules")
		var content, err = os.ReadFile(path)
		if err != nil || string(content) != firewallRuleTransferCsv {
			t.Errorf("file: %q %v", content, err)
		}
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", info.Mode())
		}
	})
	t.Run("an existing file needs overwrite", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleTransferFake(t, firewallRuleTransferCsv)
		var path = firewallRuleTransferFile(t, "rules.csv", "keep me")
		wantFailure(t, f.run("/firewall/rule", "export", "file="+path), "already exists", "overwrite")
		if content, _ := os.ReadFile(path); string(content) != "keep me" {
			t.Errorf("the file was changed: %q", content)
		}
		wantExit(t, f.run("/firewall/rule", "export", "file="+path, "overwrite"), 0)
		if content, _ := os.ReadFile(path); string(content) != firewallRuleTransferCsv {
			t.Errorf("overwrite did not replace the file: %q", content)
		}
	})
	t.Run("overwrite with stdout", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleTransferFake(t, firewallRuleTransferCsv)
		wantFailure(t, f.run("/firewall/rule", "export", "-", "overwrite"), "overwrite")
		wantNoCalls(t, f)
	})
	t.Run("no rules writes nothing", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleTransferFake(t, "")
		var path = filepath.Join(t.TempDir(), "rules.csv")
		var r = f.run("/firewall/rule", "export", path)
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "no firewall rules")
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("a file was written: %v", err)
		}
	})
	t.Run("HTTP error", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", firewallRuleTransferDownloadPath, 403, `{"status":403,"message":"Forbidden"}`)
		wantFailure(t, f.run("/firewall/rule", "export", "-"), "403", "Forbidden")
	})
}

func TestFirewallRuleImport(t *testing.T) {
	t.Parallel()
	t.Run("uploads the file", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleTransferFake(t, "")
		f.on("POST", firewallRuleTransferUploadPath, 200, `{"validations":[],"inserted":1,"updated":1,`+
			`"uuids":{"d621e174-154f-4ebb-9465-6e2fac4b2bcb":0,"6d19c02b-60ef-47a2-be81-d5a213fc394f":1},"fieldnames":["@uuid"]}`)
		var path = firewallRuleTransferFile(t, "my rules.csv", firewallRuleTransferCsv)
		var r = f.run("/firewall/rule", "import", path, "confirm=yes")
		wantExit(t, r, 0)
		if r.stdout != "" {
			t.Errorf("stdout must be empty: %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, "1 rules added, 1 updated")
		wantJSON(t, wantOneMutation(t, f, "POST", firewallRuleTransferUploadPath), map[string]any{
			"payload": firewallRuleTransferCsv, "filename": "my rules.csv"})
	})
	t.Run("needs confirmation", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleTransferFake(t, "")
		var path = firewallRuleTransferFile(t, "rules.csv", firewallRuleTransferCsv)
		wantFailure(t, f.run("/firewall/rule", "import", "file="+path), "confirm")
		wantNoCalls(t, f)
		// a script is not interactive either
		wantExit(t, f.runScript("/firewall/rule import "+path+"\n"), 1)
		wantNoCalls(t, f)
	})
	for name, content := range map[string]string{
		"empty":        "",
		"no rows":      "@uuid;enabled\n",
		"bad uuid":     "@uuid;enabled\n12345;1\n",
		"short row":    "@uuid;enabled;action\n;1\n",
		"broken quote": "@uuid;description\n;\"abc\"x\"\n\"",
	} {
		t.Run("invalid file "+name, func(t *testing.T) {
			t.Parallel()
			var f = firewallRuleTransferFake(t, "")
			var path = firewallRuleTransferFile(t, "rules.csv", content)
			wantFailure(t, f.run("/firewall/rule", "import", path, "confirm=yes"), path)
			wantFailure(t, f.run("/firewall/rule", "import", path))
			wantNoCalls(t, f)
		})
	}
	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleTransferFake(t, "")
		wantFailure(t, f.run("/firewall/rule", "import", "/nonexistent/rules.csv", "confirm=yes"), "no such file")
		wantNoCalls(t, f)
	})
	t.Run("stdin is refused", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleTransferFake(t, "")
		wantFailure(t, f.run("/firewall/rule", "import", "-", "confirm=yes"), "stdin")
		wantNoCalls(t, f)
	})
	t.Run("unknown columns are refused", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleTransferFake(t, "")
		var path = firewallRuleTransferFile(t, "rules.csv", "@uuid;enabled;descripton;sort_order\n;1;typo;5\n")
		wantFailure(t, f.run("/firewall/rule", "import", path, "confirm=yes"), "unknown columns descripton", "valid are: @uuid")
		wantNoMutations(t, f)
	})
	t.Run("rejected rows", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleTransferFake(t, "")
		f.on("POST", firewallRuleTransferUploadPath, 200, `{"validations":[{"sequence":1,"message":"Option [] not in list.","field":"interface"},`+
			`{"sequence":null,"message":"Duplicate key entry found"}],"inserted":2,"updated":0,"uuids":[],"fieldnames":["@uuid"]}`)
		var path = firewallRuleTransferFile(t, "rules.csv", "@uuid;enabled;interface\n;1;lan\n;1;nope\n")
		var r = f.run("/firewall/rule", "import", path, "confirm=yes")
		wantExit(t, r, 1)
		wantContains(t, "stderr", r.stderr, "line 3: interface: Option [] not in list.", "file: Duplicate key entry found", "check the rules")
		wantOneMutation(t, f, "POST", firewallRuleTransferUploadPath)
	})
	t.Run("refused upload", func(t *testing.T) {
		t.Parallel()
		var f = firewallRuleTransferFake(t, "")
		f.on("POST", firewallRuleTransferUploadPath, 200, `{"status":"failed"}`)
		var path = firewallRuleTransferFile(t, "rules.csv", firewallRuleTransferCsv)
		wantFailure(t, f.run("/firewall/rule", "import", path, "confirm=yes"), "refused")
	})
}
