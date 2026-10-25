package system

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	coreapi "opnsense-cli/opnsense/api"
)

type backupTestCall struct {
	Method string
	Path   string // escaped path as sent
}

// backupTestApi starts a test server answering with routes[METHOD + " " + escaped path] or an
// OPNsense like 404, and records all calls
func backupTestApi(t *testing.T, routes map[string]http.HandlerFunc) (*SystemApi, *[]backupTestCall) {
	t.Helper()
	var calls = new([]backupTestCall)
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var path = r.URL.EscapedPath()
		*calls = append(*calls, backupTestCall{r.Method, path})
		if handler, ok := routes[r.Method+" "+path]; ok {
			handler(w, r)
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"errorMessage":"Endpoint not found"}`))
	}))
	t.Cleanup(server.Close)

	var baseUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &SystemApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl, ApiKey: "k", ApiSecret: "s"}}, calls
}

func backupTestAnswer(status int, body string, headers ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i+1 < len(headers); i += 2 {
			w.Header().Set(headers[i], headers[i+1])
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

const backupTestProviders = `{"items":{"this":{"description":"This Firewall","dirname":"\/conf\/backup"},"abc":{"description":"Remote","dirname":"\/conf\/remote.backups\/abc"}}}`

// unsorted on purpose: .24 and .2372 share the 2 decimal time
const backupTestList = `{"items":[
{"time":"1792886029.21","time_iso":"2026-10-24T23:53:49+00:00","description":"/api/syslog/settings/toggle_destination/x/1 made changes","username":"root@192.168.1.2","filesize":39145,"id":"config-1792886029.212.xml"},
{"time":"1792886029.24","time_iso":"2026-10-24T23:53:49+00:00","description":"newest","username":"root@192.168.1.2","filesize":39146,"id":"config-1792886029.2372.xml"},
{"time":"1792886029.24","time_iso":"2026-10-24T23:53:49+00:00","description":"second","username":"root@192.168.1.2","filesize":39144,"id":"config-1792886029.236.xml"},
{"time":"1792885691.30","time_iso":"2026-10-24T23:48:11+00:00","description":"oldest","username":"admin@10.0.0.1","filesize":39764,"id":"config-1792885691.2978.xml"}
]}`

func TestBackupProviders(t *testing.T) {
	var api, _ = backupTestApi(t, map[string]http.HandlerFunc{
		"GET /api/core/backup/providers": backupTestAnswer(200, backupTestProviders),
	})

	var providers, err = api.BackupProviders()
	if err != nil {
		t.Fatal(err)
	}
	var want = []BackupProvider{
		{Name: "abc", Description: "Remote", Dirname: "/conf/remote.backups/abc"},
		{Name: "this", Description: "This Firewall", Dirname: "/conf/backup"},
	}
	if len(providers) != 2 || providers[0] != want[0] || providers[1] != want[1] {
		t.Errorf("providers = %+v", providers)
	}
}

func TestBackupList(t *testing.T) {
	var api, calls = backupTestApi(t, map[string]http.HandlerFunc{
		"GET /api/core/backup/backups/this": backupTestAnswer(200, backupTestList),
	})

	var backups, err = api.BackupList("")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, backup := range backups {
		ids = append(ids, backup.Id)
	}
	var want = "config-1792886029.2372.xml config-1792886029.236.xml config-1792886029.212.xml config-1792885691.2978.xml"
	if strings.Join(ids, " ") != want {
		t.Errorf("ids = %v, want newest first %s", ids, want)
	}

	var newest = backups[0]
	if newest.Description != "newest" || newest.Username != "root@192.168.1.2" || newest.Filesize != 39146 || newest.TimeIso != "2026-10-24T23:53:49+00:00" {
		t.Errorf("newest = %+v", newest)
	}
	var timestamp, ok = newest.Timestamp()
	if !ok || !timestamp.Equal(time.Unix(1792886029, 240_000_000)) {
		t.Errorf("Timestamp() = %v %v", timestamp, ok)
	}
	if len(*calls) != 1 {
		t.Errorf("calls = %v, want only the list call", *calls)
	}
}

func TestBackupTimestampInvalid(t *testing.T) {
	for _, value := range []string{"", "abc", "0"} {
		if _, ok := (Backup{Time: value}).Timestamp(); ok {
			t.Errorf("Timestamp(%q) ok", value)
		}
	}
}

func TestBackupListProvider(t *testing.T) {
	var api, calls = backupTestApi(t, map[string]http.HandlerFunc{
		"GET /api/core/backup/backups/abc":     backupTestAnswer(200, `{"items":[]}`),
		"GET /api/core/backup/backups/unknown": backupTestAnswer(200, `{"items":[]}`),
		"GET /api/core/backup/providers":       backupTestAnswer(200, backupTestProviders),
	})

	var backups, err = api.BackupList("abc")
	if err != nil || len(backups) != 0 {
		t.Errorf("known empty provider: %v %v", backups, err)
	}

	_, err = api.BackupList("unknown")
	if !coreapi.IsNotFound(err) || !strings.Contains(err.Error(), "provider unknown") {
		t.Errorf("err = %v, want not found provider", err)
	}
	if len(*calls) != 4 {
		t.Errorf("calls = %v", *calls)
	}
}

func TestBackupListHttpError(t *testing.T) {
	var api, _ = backupTestApi(t, map[string]http.HandlerFunc{
		"GET /api/core/backup/backups/this": backupTestAnswer(401, `{"status":401,"message":"Authentication Failed"}`),
	})
	var _, err = api.BackupList("this")
	var httpErr *coreapi.HttpError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != 401 {
		t.Errorf("err = %v, want *HttpError 401", err)
	}
}

func TestBackupDiff(t *testing.T) {
	var api, calls = backupTestApi(t, map[string]http.HandlerFunc{
		"GET /api/core/backup/backups/this": backupTestAnswer(200, backupTestList),
		// OPNsense runs "diff -u <second> <first>", so the newer backup must come first
		"GET /api/core/backup/diff/this/config-1792886029.2372.xml/config-1792885691.2978.xml": backupTestAnswer(200,
			`{"items":["--- \/conf\/backup\/config-1792885691.2978.xml","+++ \/conf\/backup\/config-1792886029.2372.xml","@@ -1,1 +1,1 @@","-  &lt;descr&gt;a &amp; b&lt;\/descr&gt;","+  &lt;descr attr=&quot;x&quot;&gt;c&lt;\/descr&gt;"]}`),
	})

	for _, to := range []string{"", BackupCurrent, "config-1792886029.2372.xml"} {
		*calls = nil
		var lines, err = api.BackupDiff("", "config-1792885691.2978.xml", to)
		if err != nil {
			t.Fatalf("to %q: %v", to, err)
		}
		var want = []string{
			"--- /conf/backup/config-1792885691.2978.xml",
			"+++ /conf/backup/config-1792886029.2372.xml",
			"@@ -1,1 +1,1 @@",
			"-  <descr>a & b</descr>",
			`+  <descr attr="x">c</descr>`,
		}
		if strings.Join(lines, "\n") != strings.Join(want, "\n") {
			t.Errorf("to %q: lines = %q", to, lines)
		}
		if len(*calls) != 2 {
			t.Errorf("to %q: calls = %v", to, *calls)
		}
	}
}

func TestBackupDiffSameBackup(t *testing.T) {
	var api, calls = backupTestApi(t, map[string]http.HandlerFunc{
		"GET /api/core/backup/backups/this": backupTestAnswer(200, backupTestList),
	})
	var lines, err = api.BackupDiff("this", "config-1792886029.2372.xml", BackupCurrent)
	if err != nil || len(lines) != 0 {
		t.Errorf("lines = %v, err = %v, want no differences", lines, err)
	}
	if len(*calls) != 1 {
		t.Errorf("calls = %v, want only the list call", *calls)
	}
}

func TestBackupDiffUnknownIds(t *testing.T) {
	var api, calls = backupTestApi(t, map[string]http.HandlerFunc{
		"GET /api/core/backup/backups/this": backupTestAnswer(200, backupTestList),
	})
	for _, c := range [][2]string{{"config-1.xml", ""}, {"config-1792885691.2978.xml", "config-2.xml"}} {
		var _, err = api.BackupDiff("", c[0], c[1])
		if !coreapi.IsNotFound(err) {
			t.Errorf("%v: err = %v, want not found", c, err)
		}
	}
	if _, err := api.BackupDiff("", "", BackupCurrent); err == nil || coreapi.IsNotFound(err) {
		t.Errorf("empty from: err = %v, want required error", err)
	}
	for _, call := range *calls {
		if strings.Contains(call.Path, "/diff/") {
			t.Errorf("unexpected diff call %v", call)
		}
	}
}

func TestBackupDiffEmptyHistory(t *testing.T) {
	var api, _ = backupTestApi(t, map[string]http.HandlerFunc{
		"GET /api/core/backup/backups/this": backupTestAnswer(200, `{"items":[]}`),
		"GET /api/core/backup/providers":    backupTestAnswer(200, backupTestProviders),
	})
	var _, err = api.BackupDiff("", "config-1.xml", "")
	if !coreapi.IsNotFound(err) {
		t.Errorf("err = %v, want not found", err)
	}
}

func TestBackupDownload(t *testing.T) {
	const config = "<?xml version=\"1.0\"?>\n<opnsense/>\n"
	var api, calls = backupTestApi(t, map[string]http.HandlerFunc{
		"GET /api/core/backup/download/this": backupTestAnswer(200, config,
			"Content-Type", "application/octet-stream",
			"Content-Disposition", "attachment; filename=config-OPNsense.internal-1792886037.3483.xml"),
		"GET /api/core/backup/download/this/config-1792885691.2978.xml": backupTestAnswer(200, config,
			"Content-Disposition", "attachment; filename=config-fw%2Fevil-1792885691.2978.xml"),
		"GET /api/core/backup/download/abc/config-1.xml": backupTestAnswer(200, config),
	})

	for _, id := range []string{"", BackupCurrent} {
		var content, filename, err = api.BackupDownload("", id)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != config || filename != "config-OPNsense.internal-1792886037.3483.xml" {
			t.Errorf("id %q: content %q, filename %q", id, content, filename)
		}
	}

	// the url encoded name is decoded, but a path is never accepted
	var _, filename, err = api.BackupDownload("this", "config-1792885691.2978.xml")
	if err != nil || filename != "evil-1792885691.2978.xml" {
		t.Errorf("filename = %q, err = %v", filename, err)
	}

	// without Content-Disposition the id is used
	_, filename, err = api.BackupDownload("abc", "config-1.xml")
	if err != nil || filename != "config-1.xml" {
		t.Errorf("filename = %q, err = %v", filename, err)
	}

	var paths []string
	for _, call := range *calls {
		paths = append(paths, call.Method+" "+call.Path)
	}
	if len(paths) != 4 {
		t.Errorf("calls = %v", paths)
	}
}

func TestBackupDownloadIdIsEscaped(t *testing.T) {
	var api, calls = backupTestApi(t, nil)
	var _, _, _ = api.BackupDownload("this", "../x y")
	if len(*calls) != 1 || (*calls)[0].Path != "/api/core/backup/download/this/..%2Fx%20y" {
		t.Errorf("calls = %v", *calls)
	}
}

func TestBackupDownloadErrors(t *testing.T) {
	var api, _ = backupTestApi(t, map[string]http.HandlerFunc{
		// OPNsense answers unknown ids and providers with an empty 200
		"GET /api/core/backup/download/this/config-1.xml": backupTestAnswer(200, ""),
		"GET /api/core/backup/download/nope":              backupTestAnswer(200, ""),
		"GET /api/core/backup/download/this":              backupTestAnswer(401, `{"status":401,"message":"Authentication Failed"}`),
		"GET /api/core/backup/download/plain":             backupTestAnswer(500, "  boom\n"),
	})

	var _, _, err = api.BackupDownload("this", "config-1.xml")
	if !coreapi.IsNotFound(err) || !strings.Contains(err.Error(), "config-1.xml") {
		t.Errorf("unknown id: err = %v", err)
	}
	_, _, err = api.BackupDownload("nope", "")
	if !coreapi.IsNotFound(err) {
		t.Errorf("unknown provider: err = %v", err)
	}

	var cases = []struct {
		provider string
		status   int
		message  string
	}{
		{"this", 401, "Authentication Failed"},
		{"plain", 500, "boom"},
		{"unrouted", 404, "Endpoint not found"},
	}
	for _, c := range cases {
		_, _, err = api.BackupDownload(c.provider, "")
		var httpErr *coreapi.HttpError
		if !errors.As(err, &httpErr) || httpErr.StatusCode != c.status || httpErr.Message != c.message {
			t.Errorf("%s: err = %v, want HTTP %d: %s", c.provider, err, c.status, c.message)
		}
	}
}

func TestBackupRevertAndDelete(t *testing.T) {
	var actions = []struct {
		method  string
		call    func(*SystemApi, string) error
		success string
	}{
		{"revert_backup", (*SystemApi).BackupRevert, "reverted"},
		{"delete_backup", (*SystemApi).BackupDelete, "deleted"},
	}
	for _, action := range actions {
		var answer string
		var api, calls = backupTestApi(t, map[string]http.HandlerFunc{
			"POST /api/core/backup/" + action.method + "/config-1792885691.2978.xml": func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(answer))
			},
		})

		answer = `{"status":"` + action.success + `"}`
		if err := action.call(api, "config-1792885691.2978.xml"); err != nil {
			t.Errorf("%s: unexpected error %v", action.method, err)
		}
		if len(*calls) != 1 || (*calls)[0].Method != "POST" {
			t.Errorf("%s: calls = %v, want one POST", action.method, *calls)
		}

		answer = `{"status":"not_found"}`
		if err := action.call(api, "config-1792885691.2978.xml"); !coreapi.IsNotFound(err) {
			t.Errorf("%s: err = %v, want not found", action.method, err)
		}

		// what OPNsense answers a GET
		answer = `{"status":"failed"}`
		if err := action.call(api, "config-1792885691.2978.xml"); err == nil || !strings.Contains(err.Error(), `"failed"`) {
			t.Errorf("%s: err = %v, want failed", action.method, err)
		}

		answer = ``
		if err := action.call(api, "config-1792885691.2978.xml"); err == nil {
			t.Errorf("%s: empty answer accepted", action.method)
		}

		*calls = nil
		for _, id := range []string{"", BackupCurrent} {
			if err := action.call(api, id); err == nil {
				t.Errorf("%s: id %q accepted", action.method, id)
			}
		}
		if len(*calls) != 0 {
			t.Errorf("%s: calls without id = %v", action.method, *calls)
		}
	}
}
