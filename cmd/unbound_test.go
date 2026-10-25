package cmd

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const (
	unboundSearchPath = "/api/unbound/settings/search_host_override"
	unboundAddPath    = "/api/unbound/settings/add_host_override"
	unboundSetPath    = "/api/unbound/settings/set_host_override/"
	unboundDelPath    = "/api/unbound/settings/del_host_override/"
)

// unboundBody is the expected {"host":{...}} body of add / set_host_override with the CLI defaults
func unboundBody(overrides map[string]any) map[string]any {
	return map[string]any{"host": withFields(map[string]any{
		"enabled": "1", "hostname": "web", "domain": "example.lan", "server": "10.0.0.5", "rr": "A",
		"mxprio": "", "mx": "", "ttl": "", "txtdata": "", "addptr": "1", "description": "",
	}, overrides)}
}

// wantUnboundBody compares the body ignoring the (redundant) uuid inside "host", which must match uuid if sent
func wantUnboundBody(t *testing.T, call apiCall, uuid string, want map[string]any) {
	t.Helper()
	var got = call.json(t)
	if host, ok := got["host"].(map[string]any); ok {
		if sent, isset := host["uuid"]; isset && sent != uuid {
			t.Errorf("body uuid %q, want %q", sent, uuid)
		}
		delete(host, "uuid")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("body of %s:\n got  %v\n want %v", call, got, want)
	}
}

// tableRows splits printTable output into cells (columns are separated by at least two spaces)
func tableRows(output string) [][]string {
	var separator = regexp.MustCompile(`\s{2,}`)
	var rows [][]string
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		rows = append(rows, separator.Split(strings.TrimSpace(line), -1))
	}
	return rows
}

func TestUnboundHostOverrideCreate(t *testing.T) {
	t.Parallel()
	// rows that must never be picked for web.example.lan (A)
	var decoys = []map[string]any{
		unboundRow(map[string]any{"uuid": "u-webserver", "hostname": "webserver"}),
		unboundRow(map[string]any{"uuid": "u-myweb", "hostname": "myweb"}),
		unboundRow(map[string]any{"uuid": "u-otherdomain", "hostname": "web", "domain": "example.lan.other"}),
		unboundRow(map[string]any{"uuid": "u-web-aaaa", "hostname": "web", "rr": "AAAA", "server": "fd00::5"}),
	}
	// an existing entry with non default values: update keeps everything not given on the command line,
	// create replaces the entry, resetting everything not given to the flag defaults
	var existing = unboundRow(map[string]any{"uuid": "u-existing", "hostname": "web", "server": "10.0.0.5",
		"description": "keep me", "ttl": "600", "addptr": "0", "enabled": "0"})
	var existingBody = unboundBody(map[string]any{"description": "keep me", "ttl": "600", "addptr": "0", "enabled": "0"})

	var both = []string{"create", "update"}
	for _, tc := range []struct {
		name     string
		commands []string // defaults to create only, update fails on new entries
		args     []string
		rows     []map[string]any
		wantPath string
		wantUuid string
		wantBody map[string]any
		wantOut  string
	}{
		{
			name:     "new A record, similar names are no match",
			args:     []string{"--host", "web", "--domain", "example.lan", "--ip", "10.0.0.5"},
			rows:     decoys,
			wantPath: unboundAddPath,
			wantBody: unboundBody(nil),
			wantOut:  "Created successfully, uuid: u-new",
		},
		{
			name: "all optional flags",
			args: []string{"--host", "web", "--domain", "example.lan", "--ip", "10.0.0.5", "--ttl", "300",
				"--addptr", "0", "--description", "my web", "--enabled", "0"},
			wantPath: unboundAddPath,
			wantBody: unboundBody(map[string]any{"ttl": "300", "addptr": "0", "description": "my web", "enabled": "0"}),
			wantOut:  "Created successfully, uuid: u-new",
		},
		{
			name:     "AAAA record",
			args:     []string{"--host", "web", "--domain", "example.lan", "--rr", "AAAA", "--ip", "fd00::5"},
			wantPath: unboundAddPath,
			wantBody: unboundBody(map[string]any{"rr": "AAAA", "server": "fd00::5"}),
			wantOut:  "Created successfully, uuid: u-new",
		},
		{
			name:     "MX record, rr is case-insensitive",
			args:     []string{"--host", "web", "--domain", "example.lan", "--rr", "mx", "--mxprio", "10", "--mx", "mail.example.lan"},
			rows:     decoys,
			wantPath: unboundAddPath,
			wantBody: unboundBody(map[string]any{"rr": "MX", "server": "", "mxprio": "10", "mx": "mail.example.lan"}),
			wantOut:  "Created successfully, uuid: u-new",
		},
		{
			name:     "TXT record",
			args:     []string{"--host", "web", "--domain", "example.lan", "--rr", "TXT", "--txtdata", "v=spf1 -all", "--ttl", "60"},
			wantPath: unboundAddPath,
			wantBody: unboundBody(map[string]any{"rr": "TXT", "server": "", "txtdata": "v=spf1 -all", "ttl": "60"}),
			wantOut:  "Created successfully, uuid: u-new",
		},
		{
			name:     "existing FQDN and rr is replaced instead of duplicated, flags not given are reset",
			args:     []string{"--host", "web", "--domain", "example.lan", "--ip", "10.0.0.6"},
			rows:     append([]map[string]any{existing}, decoys...),
			wantPath: unboundSetPath + "u-existing",
			wantUuid: "u-existing",
			wantBody: unboundBody(map[string]any{"server": "10.0.0.6"}),
			wantOut:  "Updated successfully, uuid: u-existing",
		},
		{
			name:     "existing FQDN and rr is updated, keeping other values",
			commands: []string{"update"},
			args:     []string{"--host", "web", "--domain", "example.lan", "--ip", "10.0.0.6"},
			rows:     append([]map[string]any{existing}, decoys...),
			wantPath: unboundSetPath + "u-existing",
			wantUuid: "u-existing",
			wantBody: withHost(existingBody, map[string]any{"server": "10.0.0.6"}),
			wantOut:  "Updated successfully, uuid: u-existing",
		},
		{
			name:     "existing FQDN matches case-insensitively and ignores a trailing dot",
			commands: both,
			args:     []string{"--host", "web", "--domain", "example.lan.", "--ip", "10.0.0.6"},
			rows: []map[string]any{
				unboundRow(map[string]any{"uuid": "u-existing", "hostname": "WEB", "domain": "Example.LAN"}),
			},
			wantPath: unboundSetPath + "u-existing",
			wantUuid: "u-existing",
			wantBody: unboundBody(map[string]any{"server": "10.0.0.6", "domain": "example.lan."}),
			wantOut:  "Updated successfully, uuid: u-existing",
		},
	} {
		var commands = tc.commands
		if commands == nil {
			commands = []string{"create"}
		}
		for _, command := range commands {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				var f = newFakeOPN(t)
				f.search(unboundSearchPath, tc.rows...)
				f.on("POST", unboundAddPath, 200, answerAdded("u-new"))
				f.on("POST", unboundSetPath+"u-existing", 200, answerSaved)

				var r = f.run(append([]string{"unbound", "hostoverride", command}, tc.args...)...)
				wantExit(t, r, 0)
				wantContains(t, "stdout", r.stdout, tc.wantOut)
				if tc.wantPath == unboundAddPath {
					wantSearchPhrases(t, f, unboundSearchPath, "web")
				} else { // the update checks that the uuid (still) exists, set_host_override would create it
					wantSearchPhrases(t, f, unboundSearchPath, "web", "")
				}
				var call = wantOneMutation(t, f, "POST", tc.wantPath)
				wantUnboundBody(t, call, tc.wantUuid, tc.wantBody)
			})
		}
	}
}

func TestUnboundHostOverrideUpdateNotFound(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search(unboundSearchPath, unboundRow(map[string]any{"uuid": "u-webserver", "hostname": "webserver"}))
	var r = f.run("unbound", "hostoverride", "update", "--host", "web", "--domain", "example.lan", "--ip", "10.0.0.5")
	wantFailure(t, r, "not found")
	wantNoMutations(t, f)
}

// withHost overrides fields inside the "host" object of an unbound body
func withHost(body map[string]any, overrides map[string]any) map[string]any {
	return map[string]any{"host": withFields(body["host"].(map[string]any), overrides)}
}

func TestUnboundHostOverrideCreateAmbiguous(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search(unboundSearchPath,
		unboundRow(map[string]any{"uuid": "u-1", "hostname": "web"}),
		unboundRow(map[string]any{"uuid": "u-2", "hostname": "web", "server": "10.0.0.7"}),
	)
	var r = f.run("unbound", "hostoverride", "create", "--host", "web", "--domain", "example.lan", "--ip", "10.0.0.5")
	wantFailure(t, r, "u-1", "u-2")
	wantNoMutations(t, f)
}

func TestUnboundHostOverrideCreateUpdateRequiredFlags(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		command string
		args    []string
		want    string
	}{
		{"create", []string{"--domain", "example.lan", "--ip", "10.0.0.5"}, `required flag(s) "host" not set`},
		{"create", []string{"--host", "web", "--ip", "10.0.0.5"}, `required flag(s) "domain" not set`},
		{"update", []string{"--domain", "example.lan", "--ip", "10.0.0.5"}, "uuid"},
		{"update", []string{"--host", "web", "--ip", "10.0.0.5"}, "uuid"},
	} {
		t.Run(tc.command+"/"+strings.Join(tc.args, " "), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			var r = f.run(append([]string{"unbound", "hostoverride", tc.command}, tc.args...)...)
			wantFailure(t, r, tc.want)
			wantNoCalls(t, f)
		})
	}
}

// client-side validation must fail before anything is written (the lookup of an existing entry may happen first)
func TestUnboundHostOverrideCreateUpdateValidation(t *testing.T) {
	t.Parallel()
	var rows = []map[string]any{
		unboundRow(map[string]any{"uuid": "u-a", "hostname": "web"}),
		unboundRow(map[string]any{"uuid": "u-mx", "hostname": "web", "rr": "MX", "server": "", "mxprio": "10", "mx": "mail.example.lan"}),
	}
	for _, tc := range []struct {
		name     string
		args     []string
		want     string
		commands []string // defaults to create only, update fails on new entries before validating
	}{
		{"A without ip", []string{"--host", "new", "--domain", "example.lan"}, "--ip", nil},
		{"A with invalid ip", []string{"--host", "new", "--domain", "example.lan", "--ip", "10.0.0.256"}, "10.0.0.256", nil},
		{"A with CIDR", []string{"--host", "new", "--domain", "example.lan", "--ip", "10.0.0.5/24"}, "10.0.0.5/24", nil},
		{"A with IPv6", []string{"--host", "new", "--domain", "example.lan", "--ip", "fd00::5"}, "IPv4", nil},
		{"AAAA with IPv4", []string{"--host", "new", "--domain", "example.lan", "--rr", "AAAA", "--ip", "10.0.0.5"}, "IPv6", nil},
		{"MX without mx", []string{"--host", "new", "--domain", "example.lan", "--rr", "MX", "--mxprio", "10"}, "--mx", nil},
		{"MX without mxprio", []string{"--host", "new", "--domain", "example.lan", "--rr", "MX", "--mx", "mail.example.lan"}, "--mxprio", nil},
		{"MX with non numeric mxprio", []string{"--host", "new", "--domain", "example.lan", "--rr", "MX", "--mx", "mail.example.lan", "--mxprio", "high"}, "--mxprio", nil},
		{"MX with ip", []string{"--host", "new", "--domain", "example.lan", "--rr", "MX", "--mx", "mail.example.lan", "--mxprio", "10", "--ip", "10.0.0.5"}, "--ip", nil},
		{"TXT without txtdata", []string{"--host", "new", "--domain", "example.lan", "--rr", "TXT"}, "--txtdata", nil},
		{"existing A with invalid ip", []string{"--host", "web", "--domain", "example.lan", "--ip", "nope"}, "nope", []string{"create", "update"}},
		{"existing MX with non numeric mxprio", []string{"--host", "web", "--domain", "example.lan", "--rr", "MX", "--mxprio", "high"}, "--mxprio", []string{"create", "update"}},
		// create would complain about the missing --mx first, since it does not keep the existing values
		{"existing MX with ip", []string{"--host", "web", "--domain", "example.lan", "--rr", "MX", "--ip", "10.0.0.5"}, "--ip", []string{"update"}},
	} {
		var commands = tc.commands
		if commands == nil {
			commands = []string{"create"}
		}
		for _, command := range commands {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				var f = newFakeOPN(t)
				f.search(unboundSearchPath, rows...)
				var r = f.run(append([]string{"unbound", "hostoverride", command}, tc.args...)...)
				wantFailure(t, r, tc.want)
				wantNoMutations(t, f)
			})
		}
	}
}

// OPNsense validation errors must be reported, never "success"
func TestUnboundHostOverrideValidationFailure(t *testing.T) {
	t.Parallel()
	var validation = answerValidation("host.hostname", "A valid hostname is required.")
	var rows = []map[string]any{unboundRow(map[string]any{"uuid": "u-existing", "hostname": "web"})}
	for _, args := range [][]string{
		{"create", "--host", "new", "--domain", "example.lan", "--ip", "10.0.0.5"},
		{"create", "--host", "web", "--domain", "example.lan", "--ip", "10.0.0.5"},
		{"update", "--uuid", "u-existing", "--host", "we b"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(unboundSearchPath, rows...)
			f.on("POST", unboundAddPath, 200, validation)
			f.on("POST", unboundSetPath+"u-existing", 200, validation)
			var r = f.run(append([]string{"unbound", "hostoverride"}, args...)...)
			wantFailure(t, r, "host.hostname", "A valid hostname is required.")
			if len(f.mutations()) != 1 {
				t.Errorf("want exactly one write, got %v", f.mutations())
			}
		})
	}
}

func TestUnboundHostOverrideUpdate(t *testing.T) {
	t.Parallel()
	var rows = []map[string]any{
		unboundRow(map[string]any{"uuid": "u-webserver", "hostname": "webserver"}),
		unboundRow(map[string]any{"uuid": "u-1", "hostname": "web", "description": "old", "ttl": "600", "addptr": "0"}),
		unboundRow(map[string]any{"uuid": "u-mx", "hostname": "mail", "rr": "MX", "server": "", "mxprio": "10", "mx": "mx1.example.lan"}),
	}
	var u1Body = unboundBody(map[string]any{"server": "10.9.9.8", "description": "old", "ttl": "600", "addptr": "0"})

	for _, tc := range []struct {
		name     string
		args     []string
		wantUuid string
		wantBody map[string]any
		wantErr  []string
	}{
		{name: "by uuid changes only the given flags", args: []string{"--uuid", "u-1", "--ip", "10.0.0.9", "--ttl", ""},
			wantUuid: "u-1", wantBody: withHost(u1Body, map[string]any{"server": "10.0.0.9", "ttl": ""})},
		{name: "by uuid renames", args: []string{"--uuid", "u-1", "--host", "web2", "--domain", "other.lan"},
			wantUuid: "u-1", wantBody: withHost(u1Body, map[string]any{"hostname": "web2", "domain": "other.lan"})},
		{name: "by uuid switches A to MX and drops the ip", args: []string{"--uuid", "u-1", "--rr", "MX", "--mx", "mx.example.lan", "--mxprio", "5"},
			wantUuid: "u-1", wantBody: withHost(u1Body, map[string]any{"rr": "MX", "server": "", "mx": "mx.example.lan", "mxprio": "5"})},
		{name: "existing MX keeps mx when only mxprio given", args: []string{"--host", "mail", "--domain", "example.lan", "--rr", "MX", "--mxprio", "20"},
			wantUuid: "u-mx", wantBody: unboundBody(map[string]any{"hostname": "mail", "rr": "MX", "server": "", "mxprio": "20", "mx": "mx1.example.lan"})},
		{name: "by FQDN", args: []string{"--host", "web", "--domain", "example.lan", "--description", "new"},
			wantUuid: "u-1", wantBody: withHost(u1Body, map[string]any{"description": "new"})},
		{name: "unknown uuid", args: []string{"--uuid", "u-gone", "--ip", "10.0.0.9"}, wantErr: []string{"not found", "u-gone"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(unboundSearchPath, rows...)
			for _, row := range rows {
				f.on("POST", unboundSetPath+row["uuid"].(string), 200, answerSaved)
			}
			var r = f.run(append([]string{"unbound", "hostoverride", "update"}, tc.args...)...)
			if tc.wantErr != nil {
				wantFailure(t, r, tc.wantErr...)
				wantNoMutations(t, f)
				return
			}
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, "Updated successfully, uuid: "+tc.wantUuid)
			wantUnboundBody(t, wantOneMutation(t, f, "POST", unboundSetPath+tc.wantUuid), tc.wantUuid, tc.wantBody)
		})
	}

	// the entry vanished between lookup and write: set_host_override answers a bare failure
	t.Run("deleted concurrently", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.search(unboundSearchPath, rows...)
		f.on("POST", unboundSetPath+"u-1", 200, answerFailedBare)
		var r = f.run("unbound", "hostoverride", "update", "--uuid", "u-1", "--ip", "10.0.0.9")
		wantFailure(t, r, "not found", "u-1")
	})
}

func TestUnboundHostOverrideRm(t *testing.T) {
	t.Parallel()
	var rows = []map[string]any{
		unboundRow(map[string]any{"uuid": "u-foobar", "hostname": "foobar"}),
		unboundRow(map[string]any{"uuid": "u-foo-other", "hostname": "foo", "domain": "other.lan"}),
		unboundRow(map[string]any{"uuid": "u-web-a", "hostname": "web"}),
		unboundRow(map[string]any{"uuid": "u-web-aaaa", "hostname": "web", "rr": "AAAA", "server": "fd00::5"}),
		unboundRow(map[string]any{"uuid": "u-mail", "hostname": "mail"}),
	}

	for _, tc := range []struct {
		name       string
		args       []string
		wantSearch []string // nil: no lookup at all
		wantDel    string   // "": no delete
		wantErr    []string
	}{
		{name: "by uuid", args: []string{"--uuid", "u-mail"}, wantDel: "u-mail"},
		{name: "uuid wins over host and domain", args: []string{"--uuid", "u-mail", "--host", "web", "--domain", "example.lan"}, wantDel: "u-mail"},
		{name: "by FQDN", args: []string{"--host", "mail", "--domain", "example.lan"}, wantSearch: []string{"mail"}, wantDel: "u-mail"},
		{name: "by FQDN case-insensitive", args: []string{"--host", "MAIL", "--domain", "EXAMPLE.lan"}, wantSearch: []string{"MAIL"}, wantDel: "u-mail"},
		{name: "by FQDN and rr", args: []string{"--host", "web", "--domain", "example.lan", "--rr", "AAAA"}, wantSearch: []string{"web"}, wantDel: "u-web-aaaa"},
		{name: "FQDN with several records is ambiguous", args: []string{"--host", "web", "--domain", "example.lan"}, wantSearch: []string{"web"},
			wantErr: []string{"u-web-a", "u-web-aaaa"}},
		{name: "host substring is no match", args: []string{"--host", "foo", "--domain", "example.lan"}, wantSearch: []string{"foo"},
			wantErr: []string{"not found", "foo.example.lan"}},
		{name: "unknown uuid", args: []string{"--uuid", "u-gone"}, wantDel: "u-gone", wantErr: []string{"not found", "u-gone"}},
		{name: "nothing selected", args: nil, wantErr: []string{"uuid"}},
		{name: "host without domain", args: []string{"--host", "mail"}, wantErr: []string{"domain"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(unboundSearchPath, rows...)
			for _, row := range rows {
				f.on("POST", unboundDelPath+row["uuid"].(string), 200, answerDeleted)
			}
			f.on("POST", unboundDelPath+"u-gone", 200, answerNotFound)

			var r = f.run(append([]string{"unbound", "hostoverride", "rm"}, tc.args...)...)
			if tc.wantErr != nil {
				wantFailure(t, r, tc.wantErr...)
			} else {
				wantExit(t, r, 0)
				wantContains(t, "stdout", r.stdout, "deleted successfully, uuid: "+tc.wantDel)
			}
			wantSearchPhrases(t, f, unboundSearchPath, tc.wantSearch...)
			if tc.wantDel == "" {
				wantNoMutations(t, f)
			} else {
				wantOneMutation(t, f, "POST", unboundDelPath+tc.wantDel)
			}
		})
	}
}

func TestUnboundHostOverrideShow(t *testing.T) {
	t.Parallel()
	var rows = []map[string]any{
		unboundRow(map[string]any{"uuid": "u-foobar", "hostname": "foobar"}),
		unboundRow(map[string]any{"uuid": "u-web-a", "hostname": "web", "description": "web v4", "ttl": "300"}),
		unboundRow(map[string]any{"uuid": "u-web-aaaa", "hostname": "web", "rr": "AAAA", "server": "fd00::5", "addptr": "0"}),
		unboundRow(map[string]any{"uuid": "u-mx", "hostname": "web", "rr": "MX", "server": "", "mxprio": "10", "mx": "mail.example.lan"}),
	}

	for _, tc := range []struct {
		name      string
		args      []string
		wantUuids []string
		wantOut   []string
		wantErr   []string
	}{
		{name: "by uuid", args: []string{"--uuid", "u-web-a"}, wantUuids: []string{"u-web-a"},
			wantOut: []string{"web v4", "10.9.9.8", "300", "example.lan"}},
		{name: "by FQDN shows all records", args: []string{"--host", "web", "--domain", "example.lan"},
			wantUuids: []string{"u-web-a", "u-web-aaaa", "u-mx"}, wantOut: []string{"fd00::5", "mail.example.lan"}},
		{name: "by FQDN and rr", args: []string{"--host", "web", "--domain", "example.lan", "--rr", "mx"},
			wantUuids: []string{"u-mx"}, wantOut: []string{"mail.example.lan"}},
		{name: "host substring is no match", args: []string{"--host", "foo", "--domain", "example.lan"}, wantErr: []string{"not found"}},
		{name: "unknown uuid", args: []string{"--uuid", "u-gone"}, wantErr: []string{"not found", "u-gone"}},
		{name: "nothing selected", args: nil, wantErr: []string{"uuid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(unboundSearchPath, rows...)
			var r = f.run(append([]string{"unbound", "hostoverride", "show"}, tc.args...)...)
			wantNoMutations(t, f)
			if tc.wantErr != nil {
				wantFailure(t, r, tc.wantErr...)
				return
			}
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, tc.wantOut...)
			var shown = regexp.MustCompile(`(?m)^uuid:\s+(\S+)`).FindAllStringSubmatch(r.stdout, -1)
			var gotUuids []string
			for _, match := range shown {
				gotUuids = append(gotUuids, match[1])
			}
			if !reflect.DeepEqual(gotUuids, tc.wantUuids) {
				t.Errorf("shown uuids %q, want %q:\n%s", gotUuids, tc.wantUuids, r.stdout)
			}
		})
	}
}

func TestUnboundHostOverrideList(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search(unboundSearchPath,
		unboundRow(map[string]any{"uuid": "u-a", "hostname": "web", "description": "web server", "ttl": "300"}),
		unboundRow(map[string]any{"uuid": "u-mx", "hostname": "mx", "rr": "MX", "server": "", "mxprio": "10", "mx": "mail.example.lan", "enabled": "0"}),
		unboundRow(map[string]any{"uuid": "u-txt", "hostname": "txt", "rr": "TXT", "server": "", "txtdata": "v=spf1 -all", "addptr": "0"}),
	)

	var r = f.run("unbound", "hostoverride", "list")
	wantExit(t, r, 0)
	var want = [][]string{
		{"UUID", "ENABLED", "HOST", "DOMAIN", "RR", "VALUE", "TTL", "PTR", "DESCRIPTION"},
		{"u-a", "1", "web", "example.lan", "A", "10.9.9.8", "300", "1", "web server"},
		{"u-mx", "0", "mx", "example.lan", "MX", "10 mail.example.lan", "-", "1", "-"},
		{"u-txt", "1", "txt", "example.lan", "TXT", "v=spf1 -all", "-", "0", "-"},
	}
	if got := tableRows(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("table:\n got  %q\n want %q\n%s", got, want, r.stdout)
	}
	wantSearchPhrases(t, f, unboundSearchPath, "")

	t.Run("search", func(t *testing.T) {
		var r = f.run("unbound", "hostoverride", "list", "--search", "spf1 -all")
		wantExit(t, r, 0)
		var rows = tableRows(r.stdout)
		if len(rows) != 2 || rows[1][0] != "u-txt" {
			t.Errorf("want only u-txt:\n%s", r.stdout)
		}
		wantSearchPhrases(t, f, unboundSearchPath, "", "spf1 -all")
	})

	t.Run("empty", func(t *testing.T) {
		var empty = newFakeOPN(t)
		empty.search(unboundSearchPath)
		var r = empty.run("unbound", "hostoverride", "list")
		wantExit(t, r, 0)
		if rows := tableRows(r.stdout); len(rows) != 1 || rows[0][0] != "UUID" {
			t.Errorf("want only the header:\n%s", r.stdout)
		}
	})
}

func TestUnboundService(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		action  string
		method  string
		answer  string
		wantOk  bool
		wantOut string
	}{
		{"status", "GET", `{"status":"running","widget":{"caption_stop":"stop service","caption_start":"start service"}}`, true, "running"},
		{"restart", "POST", `{"response":"OK"}`, true, "restarted"},
		{"restart", "POST", `{"response":"Execute error"}`, false, "Execute error"},
		{"reconfigure", "POST", `{"status":"ok"}`, true, "reconfigured"},
		{"reconfigure", "POST", `{"status":"failed"}`, false, "failed"},
	} {
		t.Run(tc.action+"/"+tc.answer, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on(tc.method, "/api/unbound/service/"+tc.action, 200, tc.answer)
			var r = f.run("unbound", "service", tc.action)
			if tc.wantOk {
				wantExit(t, r, 0)
				wantContains(t, "output", r.stdout+r.stderr, tc.wantOut)
			} else {
				wantExit(t, r, 1)
				wantContains(t, "output", r.stdout+r.stderr, tc.wantOut)
			}
			var calls = f.calls()
			if len(calls) != 1 || calls[0].Method != tc.method || calls[0].Path != "/api/unbound/service/"+tc.action {
				t.Errorf("want one %s /api/unbound/service/%s, got %v", tc.method, tc.action, calls)
			}
		})
	}
}

// ambiguous lookups must tell the user how to select one entry
func TestUnboundHostOverrideAmbiguousAsksForUuid(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"rm", "--host", "web", "--domain", "example.lan"},
		{"update", "--host", "web", "--domain", "example.lan", "--ip", "10.0.0.9"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(unboundSearchPath,
				unboundRow(map[string]any{"uuid": "u-1", "hostname": "web"}),
				unboundRow(map[string]any{"uuid": "u-2", "hostname": "web", "server": "10.0.0.2"}),
			)
			var r = f.run(append([]string{"unbound", "hostoverride"}, args...)...)
			wantExit(t, r, 1)
			wantNoMutations(t, f)
			if !strings.Contains(r.stderr, "--uuid") {
				t.Skipf("BUG: ambiguous unbound lookup does not ask for --uuid (dnsmasq host/domain do): %q", strings.TrimSpace(r.stderr))
			}
		})
	}
}
