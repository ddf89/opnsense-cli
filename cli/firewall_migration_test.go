package cli

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	firewallMigrationPath = "/api/firewall/migration/"

	// firewallMigrationCsv is a legacy rule export (list_legacy_rules.php, trimmed columns)
	firewallMigrationCsv = "@uuid;enabled;statetype;sequence;action;interface;source_net;destination_net;description\n" +
		"0b5c5b7e-8d1a-4f3e-9b2c-1a2b3c4d5e6f;1;keep;1;pass;lan;lan;any;\"legacy lan\"\n" +
		"1c6d6c8f-9e2b-4a4f-8c3d-2b3c4d5e6f70;0;keep;11;block;wan;any;any;\"legacy wan\"\n" +
		"2d7e7d90-af3c-4b50-9d4e-3c4d5e6f7081;1;keep;21;pass;opt1;opt1;any;\n"
)

// firewallMigrationFake answers the counts and downloads: filter has 3 legacy rules, outbound the given count
func firewallMigrationFake(t *testing.T, filterCount int, outboundCount int) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", firewallMigrationPath+"count_rules", 200, fmt.Sprintf(`{"status":"ok","count":%d}`, filterCount))
	f.on("GET", firewallMigrationPath+"count_outbound", 200, fmt.Sprintf(`{"status":"ok","count":%d}`, outboundCount))
	for method, content := range map[string]string{"download_rules": firewallMigrationCsv, "download_outbound": ""} {
		f.onFunc("GET", firewallMigrationPath+method, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/csv;charset=UTF-8")
			_, _ = w.Write([]byte(content))
		})
	}
	return f
}

func TestFirewallMigrationPrint(t *testing.T) {
	t.Parallel()
	var f = firewallMigrationFake(t, 3, 0)
	var r = f.run("/firewall/migration", "print")
	wantExit(t, r, 0)
	var rows = systemCronTable(r.stdout)
	if len(rows) != 3 || strings.Join(rows[0], "|") != "TYPE|COUNT|DESCRIPTION" ||
		strings.Join(rows[1], "|") != "filter|3|legacy firewall rules" || strings.Join(rows[2], "|") != "outbound|0|legacy outbound NAT rules" {
		t.Errorf("table:\n%s", r.stdout)
	}
	wantNoMutations(t, f)

	t.Run("json", func(t *testing.T) {
		t.Parallel()
		var f = firewallMigrationFake(t, 3, 7)
		var r = f.run("/firewall/migration", "print", "json")
		wantExit(t, r, 0)
		if r.stdout != "{\"count\":3,\"type\":\"filter\"}\n{\"count\":7,\"type\":\"outbound\"}\n" {
			t.Errorf("json:\n%s", r.stdout)
		}
	})
	t.Run("failed count", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", firewallMigrationPath+"count_rules", 200, `{"status":"failed"}`)
		wantFailure(t, f.run("/firewall/migration", "print"), "failed")
	})
}

func TestFirewallMigrationExport(t *testing.T) {
	t.Parallel()
	t.Run("stdout", func(t *testing.T) {
		t.Parallel()
		var f = firewallMigrationFake(t, 3, 0)
		var r = f.run("/firewall/migration", "export", "FILTER", "file=-")
		wantExit(t, r, 0)
		if r.stdout != firewallMigrationCsv {
			t.Errorf("stdout:\n%s", r.stdout)
		}
		wantNoMutations(t, f)
	})
	t.Run("file", func(t *testing.T) {
		t.Parallel()
		var f = firewallMigrationFake(t, 3, 0)
		var path = filepath.Join(t.TempDir(), "legacy.csv")
		var r = f.run("/firewall/migration", "export", "type=filter", "file="+path)
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "saved 3 legacy firewall rules")
		if content, err := os.ReadFile(path); err != nil || string(content) != firewallMigrationCsv {
			t.Errorf("file: %q %v", content, err)
		}
		wantFailure(t, f.run("/firewall/migration", "export", "filter", "file="+path), "already exists")
		wantExit(t, f.run("/firewall/migration", "export", "filter", "file="+path, "overwrite"), 0)
	})
	t.Run("no legacy rules writes nothing", func(t *testing.T) {
		t.Parallel()
		var f = firewallMigrationFake(t, 3, 0)
		var path = filepath.Join(t.TempDir(), "outbound.csv")
		var r = f.run("/firewall/migration", "export", "outbound", "file="+path)
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "no legacy outbound NAT rules")
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("a file was written: %v", err)
		}
	})
	for name, args := range map[string][]string{
		"unknown type":          {"nat", "file=-"},
		"no type":               {"file=-"},
		"no file":               {"filter"},
		"overwrite with stdout": {"filter", "file=-", "overwrite"},
	} {
		t.Run("invalid "+name, func(t *testing.T) {
			t.Parallel()
			var f = firewallMigrationFake(t, 3, 0)
			wantFailure(t, f.run(append([]string{"/firewall/migration", "export"}, args...)...))
			wantNoCalls(t, f)
		})
	}
}

func TestFirewallMigrationFlush(t *testing.T) {
	t.Parallel()
	for kind, method := range map[string]string{"filter": "flush", "outbound": "flush_outbound"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			var f = firewallMigrationFake(t, 3, 2)
			f.on("POST", firewallMigrationPath+method, 200, `{"status":"ok"}`)
			var r = f.run("/firewall/migration", "flush", kind, "confirm=yes")
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("flush must be silent: %q", r.stdout)
			}
			var call = wantOneMutation(t, f, "POST", firewallMigrationPath+method)
			if call.Body != "" {
				t.Errorf("want no body, got %q", call.Body)
			}
		})
	}
	t.Run("needs confirmation", func(t *testing.T) {
		t.Parallel()
		var f = firewallMigrationFake(t, 3, 2)
		wantFailure(t, f.run("/firewall/migration", "flush", "filter"), "confirm")
		wantFailure(t, f.run("/firewall/migration", "flush", "filter", "confirm=no"))
		wantExit(t, f.runScript("/firewall/migration\nflush outbound\n"), 1)
		wantNoCalls(t, f)
	})
	t.Run("nothing to flush", func(t *testing.T) {
		t.Parallel()
		var f = firewallMigrationFake(t, 0, 0)
		var r = f.run("/firewall/migration", "flush", "filter", "confirm=yes")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "nothing to flush")
		wantNoMutations(t, f)
	})
	t.Run("invalid type", func(t *testing.T) {
		t.Parallel()
		var f = firewallMigrationFake(t, 3, 2)
		wantFailure(t, f.run("/firewall/migration", "flush", "all", "confirm=yes"))
		wantNoCalls(t, f)
	})
	t.Run("failed", func(t *testing.T) {
		t.Parallel()
		var f = firewallMigrationFake(t, 3, 2)
		f.on("POST", firewallMigrationPath+"flush", 200, `{"status":"failed"}`)
		wantFailure(t, f.run("/firewall/migration", "flush", "filter", "confirm=yes"), "failed")
	})
	t.Run("read only user", func(t *testing.T) {
		t.Parallel()
		var f = firewallMigrationFake(t, 3, 2)
		f.on("POST", firewallMigrationPath+"flush", 403, `{"status":403,"message":"User api denied for write access (user-config-readonly set)"}`)
		wantFailure(t, f.run("/firewall/migration", "flush", "filter", "confirm=yes"), "denied for write access")
	})
}
