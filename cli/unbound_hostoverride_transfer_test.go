package cli

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

const (
	unboundHostOverrideTransferDownloadPath = "/api/unbound/settings/download_host_overrides"
	unboundHostOverrideTransferUploadPath   = "/api/unbound/settings/upload_host_overrides"
	unboundHostOverrideTransferSearchPath   = "/api/unbound/settings/search_host_override"

	// unboundHostOverrideTransferCsv is an export as stable/26.7 writes it
	unboundHostOverrideTransferCsv = "@uuid;enabled;hostname;domain;rr;mxprio;mx;ttl;server;txtdata;addptr;aliases;description\n" +
		"d26f2774-c005-4187-8a0f-cae22db12285;1;web;example.lan;A;;;;192.0.2.21;;1;www.example.lan;\"web\"\n" +
		"2ce94aac-7b91-4619-9b71-600706ddaaf6;1;mail;example.lan;MX;10;mx.example.lan;;;;1;;\n"

	// unboundHostOverrideTransferGetHost is get_host_override without uuid (26.7): the field names of an entry
	unboundHostOverrideTransferGetHost = `{"host":{"enabled":"1","hostname":"","domain":"","rr":{"A":{"value":"A","selected":1}},` +
		`"mxprio":"","mx":"","ttl":"","server":"","txtdata":"","addptr":"1","aliases":{"":{"value":"","selected":1}},"description":""}}`
)

// unboundHostOverrideTransferFake answers the export with export, "" leaves the download unknown (26.7 to 26.7.7)
func unboundHostOverrideTransferFake(t *testing.T, export string) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	if export != "" {
		f.onFunc("GET", unboundHostOverrideTransferDownloadPath, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/csv;charset=UTF-8")
			_, _ = w.Write([]byte(export))
		})
	}
	f.on("GET", "/api/unbound/settings/get_host_override", 200, unboundHostOverrideTransferGetHost)
	f.search(unboundHostOverrideTransferSearchPath, unboundRow(nil))
	return f
}

func unboundHostOverrideTransferFile(t *testing.T, content string) string {
	t.Helper()
	var path = filepath.Join(t.TempDir(), "overrides.csv")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestUnboundHostOverrideExport(t *testing.T) {
	t.Parallel()
	t.Run("export", func(t *testing.T) {
		t.Parallel()
		var f = unboundHostOverrideTransferFake(t, unboundHostOverrideTransferCsv)
		var path = filepath.Join(t.TempDir(), "overrides.csv")
		var r = f.run("/unbound/host-override", "export", path)
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "saved 2 host overrides to "+path)
		if content, err := os.ReadFile(path); err != nil || string(content) != unboundHostOverrideTransferCsv {
			t.Errorf("file: %q, %v", content, err)
		}
		wantNoMutations(t, f)
	})
	t.Run("OPNsense without the endpoint", func(t *testing.T) {
		t.Parallel()
		var f = unboundHostOverrideTransferFake(t, "")
		wantFailure(t, f.run("/unbound/host-override", "export", "-"), "this OPNsense version has no CSV export/import of Unbound host overrides")
	})
}

func TestUnboundHostOverrideImport(t *testing.T) {
	t.Parallel()
	t.Run("import", func(t *testing.T) {
		t.Parallel()
		var f = unboundHostOverrideTransferFake(t, unboundHostOverrideTransferCsv)
		f.on("POST", unboundHostOverrideTransferUploadPath, 200,
			`{"validations":[],"inserted":0,"updated":2,"uuids":{"d26f2774-c005-4187-8a0f-cae22db12285":0,"2ce94aac-7b91-4619-9b71-600706ddaaf6":1},"fieldnames":["@uuid"]}`)
		var path = unboundHostOverrideTransferFile(t, unboundHostOverrideTransferCsv)
		var r = f.run("/unbound/host-override", "import", path, "confirm=yes")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "imported "+path+": 0 host overrides added, 2 updated")
		wantJSON(t, wantOneMutation(t, f, "POST", unboundHostOverrideTransferUploadPath),
			map[string]any{"payload": unboundHostOverrideTransferCsv, "filename": "overrides.csv"})
	})
	t.Run("needs confirmation", func(t *testing.T) {
		t.Parallel()
		var f = unboundHostOverrideTransferFake(t, unboundHostOverrideTransferCsv)
		var path = unboundHostOverrideTransferFile(t, unboundHostOverrideTransferCsv)
		wantFailure(t, f.run("/unbound/host-override", "import", path),
			"This adds host overrides and overwrites those matching by @uuid", "confirm=yes")
		wantNoCalls(t, f)
	})
	t.Run("@uuid checked before the confirmation", func(t *testing.T) {
		t.Parallel()
		var f = unboundHostOverrideTransferFake(t, unboundHostOverrideTransferCsv)
		var path = unboundHostOverrideTransferFile(t, "@uuid;hostname;domain\nnot-a-uuid;web;example.lan\n")
		wantFailure(t, f.run("/unbound/host-override", "import", path), path, `line 2: invalid @uuid "not-a-uuid"`)
		wantNoCalls(t, f)
	})
	t.Run("unknown columns", func(t *testing.T) {
		t.Parallel()
		var f = unboundHostOverrideTransferFake(t, unboundHostOverrideTransferCsv)
		var path = unboundHostOverrideTransferFile(t, "hostname;domain;ip\nweb;example.lan;192.0.2.1\n")
		wantFailure(t, f.run("/unbound/host-override", "import", path, "confirm=yes"), "unknown columns ip",
			"valid are: @uuid, addptr, aliases, description, domain, enabled, hostname, mx, mxprio, rr, server, ttl, txtdata")
		wantNoMutations(t, f)
	})
	t.Run("OPNsense without the endpoint", func(t *testing.T) {
		t.Parallel()
		var f = unboundHostOverrideTransferFake(t, "")
		var path = unboundHostOverrideTransferFile(t, "hostname;domain;rr;server\nweb;example.lan;A;192.0.2.1\n")
		wantFailure(t, f.run("/unbound/host-override", "import", path, "confirm=yes"),
			"this OPNsense version has no CSV export/import of Unbound host overrides")
	})
}
