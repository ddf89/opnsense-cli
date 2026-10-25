package cli

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// firewallNatDnatCSV is download_rules of d_nat as OPNsense 26.7 writes it: source and destination are empty
const firewallNatDnatCSV = "@uuid;sequence;disabled;nordr;interface;ipprotocol;protocol;source;destination;target;local-port;poolopts;log;category;categories;descr;tag;tagged;nosync;natreflection;pass;associated-rule-id;created;updated\n" +
	"d-web;100;0;0;wan;inet;tcp;;;198.51.100.5;80;;0;;;web;;;0;;;;;\n" +
	"d-ssh;200;1;0;wan;inet;tcp;;;198.51.100.6;22;;0;;;ssh;;;0;;;;;\n"

func firewallNatCSVHandler(content string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/csv;charset=UTF-8")
		_, _ = w.Write([]byte(content))
	}
}

func TestFirewallNatExport(t *testing.T) {
	t.Parallel()

	t.Run("d_nat source and destination are expanded", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t, firewallNatDnatRows()[:3]...)
		f.onFunc("GET", firewallNatDnatPath+"download_rules", firewallNatCSVHandler(firewallNatDnatCSV))
		var file = filepath.Join(t.TempDir(), "dnat.csv")
		var r = f.run("/firewall/nat/destination", "export", file)
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "saved ", file) // the count needs v4 uuids, these are not
		var content, err = os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var lines = strings.Split(strings.TrimSpace(string(content)), "\n")
		if len(lines) != 3 ||
			!strings.HasPrefix(lines[0], "@uuid;sequence;disabled;nordr;interface;ipprotocol;protocol;source.network;source.port;source.not;destination.network;destination.port;destination.not;target;") ||
			!strings.HasPrefix(lines[1], "d-web;100;0;0;wan;inet;tcp;;;0;wanip;8080;0;198.51.100.5;80;") ||
			!strings.HasPrefix(lines[2], "d-ssh;200;1;0;wan;inet;tcp;;;0;wanip;2222;0;198.51.100.6;22;") {
			t.Errorf("export:\n%s", content)
		}
		if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("file mode: %v, %v", info.Mode(), err)
		}
		wantNoMutations(t, f)

		var again = f.run("/firewall/nat/destination", "export", file)
		wantFailure(t, again, "already exists", "overwrite")
		wantExit(t, f.run("/firewall/nat/destination", "export", file, "overwrite"), 0)
	})

	t.Run("other types are written as OPNsense exports them, - is stdout", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.onFunc("GET", firewallNatSnatPath+"download_rules", firewallNatCSVHandler(firewallNatSnatCSV))
		var r = f.run("/firewall/nat/source", "export", "-")
		wantExit(t, r, 0)
		if r.stdout != firewallNatSnatCSV {
			t.Errorf("stdout:\n%s", r.stdout)
		}
	})

	t.Run("no rules, nothing written", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.onFunc("GET", firewallNatNptPath+"download_rules", firewallNatCSVHandler(""))
		var file = filepath.Join(t.TempDir(), "npt.csv")
		var r = f.run("/firewall/nat/npt", "export", file)
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "there are no NPTv6 rules, nothing exported")
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Errorf("a file was written: %v", err)
		}
	})

	t.Run("overwrite with stdout", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		wantFailure(t, f.run("/firewall/nat/npt", "export", "-", "overwrite"), "overwrite has no effect")
		wantNoCalls(t, f)
	})
}

func TestFirewallNatImport(t *testing.T) {
	t.Parallel()

	var write = func(t *testing.T, content string) string {
		t.Helper()
		var file = filepath.Join(t.TempDir(), "rules.csv")
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	const valid = "@uuid;disabled;interface;protocol;destination.network;destination.port;target;local-port;descr\n" +
		";1;wan;tcp;wanip;8080;198.51.100.5;80;imported\n" +
		"0b5c5c2e-6f3a-4c39-9a4e-2f4f0d6a3c11;1;wan;tcp;wanip;8081;198.51.100.6;81;updated\n"

	t.Run("uploads the file after the column check", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t)
		f.on("POST", firewallNatDnatPath+"upload_rules", 200,
			`{"validations":[],"inserted":1,"updated":1,"uuids":{"a":0,"0b5c5c2e-6f3a-4c39-9a4e-2f4f0d6a3c11":1},"fieldnames":["@uuid"]}`)
		var file = write(t, valid)
		var r = f.run("/firewall/nat/destination", "import", file, "confirm=yes")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "1 rules added, 1 updated")
		wantJSON(t, wantOneMutation(t, f, "POST", firewallNatDnatPath+"upload_rules"), map[string]any{"payload": valid, "filename": "rules.csv"})
	})
	t.Run("rejected rows are reported by line", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t)
		f.on("POST", firewallNatDnatPath+"upload_rules", 200,
			`{"validations":[{"sequence":1,"field":"rule.target","message":"Address type should match"}],"inserted":2,"updated":0,"uuids":[]}`)
		var r = f.run("/firewall/nat/destination", "import", write(t, valid), "confirm=yes")
		wantExit(t, r, 1)
		wantContains(t, "stderr", r.stderr, "line 3: rule.target: Address type should match", "check the rules")
	})
	t.Run("unknown columns are refused", func(t *testing.T) {
		t.Parallel()
		var f = firewallNatDnatFake(t)
		var r = f.run("/firewall/nat/destination", "import", write(t, "@uuid;descr;destination_port\n;x;80\n"), "confirm=yes")
		wantExit(t, r, 1) // the column list contains "created", which upsets wantFailure
		wantContains(t, "stderr", r.stderr, "unknown columns destination_port", "destination.port")
		wantNoMutations(t, f)
	})
	for _, tc := range []struct {
		name    string
		content string
		wants   []string
	}{
		{"empty file", "", []string{"the file is empty"}},
		{"header only", "@uuid;descr\n", []string{"no rules"}},
		{"bad uuid", "@uuid;descr\nnot-a-uuid;x\n", []string{"line 2", "invalid @uuid"}},
		{"ragged rows", "@uuid;descr\n;x;y\n", []string{"not a valid CSV file"}},
	} {
		t.Run(tc.name+" is refused before the confirmation", func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			wantFailure(t, f.run("/firewall/nat/source", "import", write(t, tc.content)), tc.wants...)
			wantNoCalls(t, f)
		})
	}
	t.Run("needs confirm non-interactively", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		wantFailure(t, f.run("/firewall/nat/one-to-one", "import", write(t, valid)), "confirm=yes")
		wantNoCalls(t, f)
	})
	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		wantFailure(t, f.run("/firewall/nat/npt", "import", filepath.Join(t.TempDir(), "nope.csv"), "confirm=yes"), "file:")
		wantNoCalls(t, f)
	})
}
