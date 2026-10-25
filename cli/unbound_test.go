package cli

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

// unboundBody is the expected {"host":{...}} body of add / set_host_override with the add defaults
func unboundBody(overrides map[string]any) map[string]any {
	return map[string]any{"host": withFields(map[string]any{
		"enabled": "1", "hostname": "web", "domain": "example.lan", "server": "10.0.0.5", "rr": "A",
		"mxprio": "", "mx": "", "ttl": "", "txtdata": "", "addptr": "1", "description": "",
	}, overrides)}
}

// unboundWithHost overrides fields inside the "host" object of an unbound body
func unboundWithHost(body map[string]any, overrides map[string]any) map[string]any {
	return map[string]any{"host": withFields(body["host"].(map[string]any), overrides)}
}

// unboundWantBody compares the body ignoring the (redundant) uuid inside "host", which must match uuid if sent
func unboundWantBody(t *testing.T, call apiCall, uuid string, want map[string]any) {
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

// unboundTableRows splits table output into cells (columns are separated by at least two spaces)
func unboundTableRows(output string) [][]string {
	var separator = regexp.MustCompile(`\s{2,}`)
	var rows [][]string
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		rows = append(rows, separator.Split(strings.TrimSpace(line), -1))
	}
	return rows
}

func TestUnboundHostOverrideAdd(t *testing.T) {
	t.Parallel()
	// rows that must never be picked for web.example.lan (A)
	var decoys = []map[string]any{
		unboundRow(map[string]any{"uuid": "u-webserver", "hostname": "webserver"}),
		unboundRow(map[string]any{"uuid": "u-myweb", "hostname": "myweb"}),
		unboundRow(map[string]any{"uuid": "u-otherdomain", "hostname": "web", "domain": "example.lan.other"}),
		unboundRow(map[string]any{"uuid": "u-web-aaaa", "hostname": "web", "rr": "AAAA", "server": "fd00::5"}),
	}
	// an existing entry with non default values: add replace resets everything not given to the defaults
	var existing = unboundRow(map[string]any{"uuid": "u-existing", "hostname": "web", "server": "10.0.0.5",
		"description": "keep me", "ttl": "600", "addptr": "0", "enabled": "0"})

	for _, tc := range []struct {
		name     string
		args     []string
		rows     []map[string]any
		wantPath string
		wantUuid string
		wantBody map[string]any
		wantOut  string
	}{
		{
			name:     "new A record, similar names are no match",
			args:     []string{"host=web", "domain=example.lan", "ip=10.0.0.5"},
			rows:     decoys,
			wantPath: unboundAddPath,
			wantBody: unboundBody(nil),
			wantOut:  "u-new",
		},
		{
			name: "all optional arguments",
			args: []string{"host=web", "domain=example.lan", "ip=10.0.0.5", "ttl=300", "ptr=no", "description=my web",
				"disabled"},
			wantPath: unboundAddPath,
			wantBody: unboundBody(map[string]any{"ttl": "300", "addptr": "0", "description": "my web", "enabled": "0"}),
			wantOut:  "u-new",
		},
		{
			name:     "AAAA record",
			args:     []string{"host=web", "domain=example.lan", "rr=AAAA", "ip=fd00::5"},
			wantPath: unboundAddPath,
			wantBody: unboundBody(map[string]any{"rr": "AAAA", "server": "fd00::5"}),
			wantOut:  "u-new",
		},
		{
			name:     "MX record, rr is case-insensitive",
			args:     []string{"host=web", "domain=example.lan", "rr=mx", "mx-priority=10", "mx=mail.example.lan"},
			rows:     decoys,
			wantPath: unboundAddPath,
			wantBody: unboundBody(map[string]any{"rr": "MX", "server": "", "mxprio": "10", "mx": "mail.example.lan"}),
			wantOut:  "u-new",
		},
		{
			name:     "TXT record",
			args:     []string{"host=web", "domain=example.lan", "rr=TXT", "txtdata=v=spf1 -all", "ttl=60"},
			wantPath: unboundAddPath,
			wantBody: unboundBody(map[string]any{"rr": "TXT", "server": "", "txtdata": "v=spf1 -all", "ttl": "60"}),
			wantOut:  "u-new",
		},
		{
			name:     "replace: existing FQDN and rr is replaced, arguments not given are reset",
			args:     []string{"host=web", "domain=example.lan", "ip=10.0.0.6", "replace"},
			rows:     append([]map[string]any{existing}, decoys...),
			wantPath: unboundSetPath + "u-existing",
			wantUuid: "u-existing",
			wantBody: unboundBody(map[string]any{"server": "10.0.0.6"}),
			wantOut:  "u-existing",
		},
		{
			name: "replace matches case-insensitively and ignores a trailing dot",
			args: []string{"host=web", "domain=example.lan.", "ip=10.0.0.6", "replace"},
			rows: []map[string]any{
				unboundRow(map[string]any{"uuid": "u-existing", "hostname": "WEB", "domain": "Example.LAN"}),
			},
			wantPath: unboundSetPath + "u-existing",
			wantUuid: "u-existing",
			wantBody: unboundBody(map[string]any{"server": "10.0.0.6", "domain": "example.lan."}),
			wantOut:  "u-existing",
		},
		{
			name:     "replace without an existing entry adds",
			args:     []string{"host=web", "domain=example.lan", "ip=10.0.0.5", "replace"},
			rows:     decoys,
			wantPath: unboundAddPath,
			wantBody: unboundBody(nil),
			wantOut:  "u-new",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(unboundSearchPath, tc.rows...)
			f.on("POST", unboundAddPath, 200, answerAdded("u-new"))
			f.on("POST", unboundSetPath+"u-existing", 200, answerSaved)

			var r = f.run(append([]string{"/unbound/host-override", "add"}, tc.args...)...)
			wantExit(t, r, 0)
			if strings.TrimSpace(r.stdout) != tc.wantOut {
				t.Errorf("stdout %q, want only the uuid %q", r.stdout, tc.wantOut)
			}
			// replacing an entry says so on stderr, like the other add ... replace
			if replaced := strings.Contains(r.stderr, "replaced the existing host override"); replaced != (tc.wantPath != unboundAddPath) {
				t.Errorf("stderr %q", r.stderr)
			}
			if tc.wantPath == unboundAddPath {
				wantSearchPhrases(t, f, unboundSearchPath, "web")
			} else { // the update checks that the uuid (still) exists, set_host_override would create it
				wantSearchPhrases(t, f, unboundSearchPath, "web", "")
			}
			unboundWantBody(t, wantOneMutation(t, f, "POST", tc.wantPath), tc.wantUuid, tc.wantBody)
		})
	}
}

func TestUnboundHostOverrideAddExisting(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search(unboundSearchPath, unboundRow(map[string]any{"uuid": "u-existing", "hostname": "web"}))
	var r = f.run("/unbound/host-override", "add", "host=web", "domain=example.lan", "ip=10.0.0.5")
	wantFailure(t, r, "web.example.lan/A exists already", "u-existing", "replace")
	wantNoMutations(t, f)
}

func TestUnboundHostOverrideAddAmbiguous(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search(unboundSearchPath,
		unboundRow(map[string]any{"uuid": "u-1", "hostname": "web"}),
		unboundRow(map[string]any{"uuid": "u-2", "hostname": "web", "server": "10.0.0.7"}),
	)
	var r = f.run("/unbound/host-override", "add", "host=web", "domain=example.lan", "ip=10.0.0.5", "replace")
	wantFailure(t, r, "u-1", "u-2")
	wantNoMutations(t, f)
}

func TestUnboundHostOverrideRequiredArgs(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"add", "domain=example.lan", "ip=10.0.0.5"},
		{"add", "host=web", "ip=10.0.0.5"},
		{"set", "ip=10.0.0.5"},
		{"set", "web.example.lan"},
		{"show"},
		{"remove"},
		{"enable"},
		{"disable"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			var r = f.run(append([]string{"/unbound/host-override"}, args...)...)
			wantFailure(t, r, args[0]+":")
			wantNoCalls(t, f)
		})
	}
}

// client-side validation must fail before any API call
func TestUnboundHostOverrideAddValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"A without ip", []string{"host=new", "domain=example.lan"}, "ip="},
		{"A with invalid ip", []string{"host=new", "domain=example.lan", "ip=10.0.0.256"}, "10.0.0.256"},
		{"A with CIDR", []string{"host=new", "domain=example.lan", "ip=10.0.0.5/24"}, "10.0.0.5/24"},
		{"A with IPv6", []string{"host=new", "domain=example.lan", "ip=fd00::5"}, "IPv4"},
		{"AAAA with IPv4", []string{"host=new", "domain=example.lan", "rr=AAAA", "ip=10.0.0.5"}, "IPv6"},
		{"unknown rr", []string{"host=new", "domain=example.lan", "rr=CNAME", "ip=10.0.0.5"}, "CNAME"},
		{"empty rr", []string{"host=new", "domain=example.lan", "rr=", "ip=10.0.0.5"}, "rr must be one of"},
		{"MX without mx", []string{"host=new", "domain=example.lan", "rr=MX", "mx-priority=10"}, "mx="},
		{"MX without mx-priority", []string{"host=new", "domain=example.lan", "rr=MX", "mx=mail.example.lan"}, "mx-priority="},
		{"MX with non numeric mx-priority", []string{"host=new", "domain=example.lan", "rr=MX", "mx=mail.example.lan", "mx-priority=high"}, "mx-priority"},
		{"MX with ip", []string{"host=new", "domain=example.lan", "rr=MX", "mx=mail.example.lan", "mx-priority=10", "ip=10.0.0.5"}, "ip="},
		{"TXT without txtdata", []string{"host=new", "domain=example.lan", "rr=TXT"}, "txtdata="},
		{"TXT with ip", []string{"host=new", "domain=example.lan", "rr=TXT", "txtdata=x", "ip=10.0.0.5"}, "ip="},
		{"negative ttl", []string{"host=new", "domain=example.lan", "ip=10.0.0.5", "ttl=-1"}, "ttl"},
		{"bad ptr", []string{"host=new", "domain=example.lan", "ip=10.0.0.5", "ptr=maybe"}, "ptr"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			var r = f.run(append([]string{"/unbound/host-override", "add"}, tc.args...)...)
			wantFailure(t, r, tc.want)
			wantNoCalls(t, f)
		})
	}
}

// set validates the merged entry: the lookup happens, nothing is written
func TestUnboundHostOverrideSetValidation(t *testing.T) {
	t.Parallel()
	var rows = []map[string]any{
		unboundRow(map[string]any{"uuid": "u-a", "hostname": "web"}),
		unboundRow(map[string]any{"uuid": "u-mx", "hostname": "mail", "rr": "MX", "server": "", "mxprio": "10", "mx": "mx1.example.lan"}),
	}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"A with invalid ip", []string{"web.example.lan", "ip=nope"}, "nope"},
		{"A with IPv6", []string{"web.example.lan", "ip=fd00::1"}, "IPv4"},
		{"A to AAAA keeps the IPv4 address", []string{"web.example.lan", "rr=AAAA"}, "IPv6"},
		{"A emptied ip", []string{"web.example.lan", "ip="}, "ip="},
		{"A to MX without mx", []string{"web.example.lan", "rr=MX"}, "mx="},
		{"MX with non numeric mx-priority", []string{"mail.example.lan", "mx-priority=high"}, "mx-priority"},
		{"MX with ip", []string{"mail.example.lan", "ip=10.0.0.5"}, "ip="},
		{"A to TXT with ip", []string{"web.example.lan", "rr=TXT", "txtdata=x", "ip=10.0.0.5"}, "ip="},
		{"MX emptied mx", []string{"mail.example.lan", "mx="}, "mx="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(unboundSearchPath, rows...)
			var r = f.run(append([]string{"/unbound/host-override", "set"}, tc.args...)...)
			wantFailure(t, r, tc.want)
			wantNoMutations(t, f)
		})
	}
}

// OPNsense validation errors must be reported, never success
func TestUnboundHostOverrideValidationFailure(t *testing.T) {
	t.Parallel()
	var validation = answerValidation("host.hostname", "A valid hostname is required.")
	var rows = []map[string]any{unboundRow(map[string]any{"uuid": "u-existing", "hostname": "web"})}
	for _, args := range [][]string{
		{"add", "host=new", "domain=example.lan", "ip=10.0.0.5"},
		{"add", "host=web", "domain=example.lan", "ip=10.0.0.5", "replace"},
		{"set", "u-existing", "host=we b"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(unboundSearchPath, rows...)
			f.on("POST", unboundAddPath, 200, validation)
			f.on("POST", unboundSetPath+"u-existing", 200, validation)
			var r = f.run(append([]string{"/unbound/host-override"}, args...)...)
			wantFailure(t, r, "host.hostname", "A valid hostname is required.")
			if r.stdout != "" {
				t.Errorf("want no output on stdout, got %q", r.stdout)
			}
			if len(f.mutations()) != 1 {
				t.Errorf("want exactly one write, got %v", f.mutations())
			}
		})
	}
}

func TestUnboundHostOverrideSet(t *testing.T) {
	t.Parallel()
	var rows = []map[string]any{
		unboundRow(map[string]any{"uuid": "u-webserver", "hostname": "webserver"}),
		unboundRow(map[string]any{"uuid": "u-1", "hostname": "web", "description": "old", "ttl": "600", "addptr": "0"}),
		unboundRow(map[string]any{"uuid": "u-mx", "hostname": "mail", "rr": "MX", "server": "", "mxprio": "10", "mx": "mx1.example.lan"}),
		unboundRow(map[string]any{"uuid": "u-mail-a", "hostname": "mail", "server": "10.0.0.25"}),
	}
	var u1Body = unboundBody(map[string]any{"server": "10.9.9.8", "description": "old", "ttl": "600", "addptr": "0"})
	var mxBody = unboundBody(map[string]any{"hostname": "mail", "rr": "MX", "server": "", "mxprio": "10", "mx": "mx1.example.lan"})

	for _, tc := range []struct {
		name     string
		args     []string
		wantUuid string
		wantBody map[string]any
		wantErr  []string
	}{
		{name: "by uuid changes only the given fields", args: []string{"u-1", "ip=10.0.0.9", "ttl="},
			wantUuid: "u-1", wantBody: unboundWithHost(u1Body, map[string]any{"server": "10.0.0.9", "ttl": ""})},
		{name: "by uuid renames", args: []string{"item=u-1", "host=web2", "domain=other.lan"},
			wantUuid: "u-1", wantBody: unboundWithHost(u1Body, map[string]any{"hostname": "web2", "domain": "other.lan"})},
		{name: "switches A to MX and drops the ip", args: []string{"u-1", "rr=MX", "mx=mx.example.lan", "mx-priority=5"},
			wantUuid: "u-1", wantBody: unboundWithHost(u1Body, map[string]any{"rr": "MX", "server": "", "mx": "mx.example.lan", "mxprio": "5"})},
		{name: "switches A to TXT and drops the ip", args: []string{"u-1", "rr=txt", "txtdata=hello"},
			wantUuid: "u-1", wantBody: unboundWithHost(u1Body, map[string]any{"rr": "TXT", "server": "", "txtdata": "hello"})},
		{name: "existing MX keeps mx when only mx-priority given", args: []string{"mail.example.lan/MX", "mx-priority=20"},
			wantUuid: "u-mx", wantBody: unboundWithHost(mxBody, map[string]any{"mxprio": "20"})},
		{name: "by FQDN", args: []string{"web.example.lan", "description=new"},
			wantUuid: "u-1", wantBody: unboundWithHost(u1Body, map[string]any{"description": "new"})},
		{name: "by FQDN case-insensitive with trailing dot", args: []string{"WEB.Example.lan.", "ptr=yes", "disabled"},
			wantUuid: "u-1", wantBody: unboundWithHost(u1Body, map[string]any{"addptr": "1", "enabled": "0"})},
		{name: "by FQDN/RR with trailing dot", args: []string{"mail.example.lan./a", "ip=10.0.0.26"},
			wantUuid: "u-mail-a", wantBody: unboundBody(map[string]any{"hostname": "mail", "server": "10.0.0.26"})},
		{name: "by index of the list", args: []string{"2", "mx=mx2.example.lan"},
			wantUuid: "u-mx", wantBody: unboundWithHost(mxBody, map[string]any{"mx": "mx2.example.lan"})},
		{name: "unknown uuid", args: []string{"u-gone", "ip=10.0.0.9"}, wantErr: []string{"not found", "u-gone"}},
		{name: "host substring is no match", args: []string{"we.example.lan", "ip=10.0.0.9"}, wantErr: []string{"not found", "we.example.lan"}},
		{name: "index out of range", args: []string{"4", "ip=10.0.0.9"}, wantErr: []string{"not found", "#4"}},
		{name: "ambiguous FQDN asks for #, uuid or RR", args: []string{"mail.example.lan", "ip=10.0.0.9"},
			wantErr: []string{"u-mx", "u-mail-a", "# from print", "uuid", "mail.example.lan/<RR>"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(unboundSearchPath, rows...)
			for _, row := range rows {
				f.on("POST", unboundSetPath+row["uuid"].(string), 200, answerSaved)
			}
			var r = f.run(append([]string{"/unbound/host-override", "set"}, tc.args...)...)
			if tc.wantErr != nil {
				wantFailure(t, r, tc.wantErr...)
				wantNoMutations(t, f)
				return
			}
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("set must be silent, got %q", r.stdout)
			}
			unboundWantBody(t, wantOneMutation(t, f, "POST", unboundSetPath+tc.wantUuid), tc.wantUuid, tc.wantBody)
		})
	}

	// the entry vanished between lookup and write: set_host_override answers a bare failure
	t.Run("deleted concurrently", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.search(unboundSearchPath, rows...)
		f.on("POST", unboundSetPath+"u-1", 200, answerFailedBare)
		var r = f.run("/unbound/host-override", "set", "u-1", "ip=10.0.0.9")
		wantFailure(t, r, "not found", "u-1")
	})
}

func TestUnboundHostOverrideRemove(t *testing.T) {
	t.Parallel()
	var rows = []map[string]any{
		unboundRow(map[string]any{"uuid": "u-foobar", "hostname": "foobar"}),
		unboundRow(map[string]any{"uuid": "u-foo-other", "hostname": "foo", "domain": "other.lan"}),
		unboundRow(map[string]any{"uuid": "u-web-a", "hostname": "web"}),
		unboundRow(map[string]any{"uuid": "u-web-aaaa", "hostname": "web", "rr": "AAAA", "server": "fd00::5"}),
		unboundRow(map[string]any{"uuid": "u-mail", "hostname": "mail"}),
	}

	for _, tc := range []struct {
		name    string
		args    []string
		wantDel string // "": no delete
		wantErr []string
	}{
		{name: "by uuid", args: []string{"u-mail"}, wantDel: "u-mail"},
		{name: "by FQDN", args: []string{"mail.example.lan"}, wantDel: "u-mail"},
		{name: "by FQDN case-insensitive", args: []string{"MAIL.EXAMPLE.lan"}, wantDel: "u-mail"},
		{name: "by FQDN and rr", args: []string{"web.example.lan/aaaa"}, wantDel: "u-web-aaaa"},
		{name: "by index of the list", args: []string{"1"}, wantDel: "u-foo-other"},
		{name: "FQDN with several records is ambiguous", args: []string{"web.example.lan"},
			wantErr: []string{"u-web-a", "u-web-aaaa", "web.example.lan/<RR>"}},
		{name: "host substring is no match", args: []string{"foo.example.lan"}, wantErr: []string{"not found", "foo.example.lan"}},
		{name: "wrong rr is no match", args: []string{"mail.example.lan/MX"}, wantErr: []string{"not found", "mail.example.lan/MX"}},
		{name: "unknown uuid", args: []string{"u-gone"}, wantErr: []string{"not found", "u-gone"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(unboundSearchPath, rows...)
			for _, row := range rows {
				f.on("POST", unboundDelPath+row["uuid"].(string), 200, answerDeleted)
			}
			var r = f.run(append([]string{"/unbound/host-override", "remove"}, tc.args...)...)
			if tc.wantErr != nil {
				wantFailure(t, r, tc.wantErr...)
				wantNoMutations(t, f)
				return
			}
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("remove must be silent, got %q", r.stdout)
			}
			wantOneMutation(t, f, "POST", unboundDelPath+tc.wantDel)
		})
	}

	// removed between lookup and delete
	t.Run("deleted concurrently", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.search(unboundSearchPath, rows...)
		f.on("POST", unboundDelPath+"u-mail", 200, answerNotFound)
		var r = f.run("/unbound/host-override", "remove", "u-mail")
		wantFailure(t, r, "not found", "u-mail")
	})
}

func TestUnboundHostOverrideEnableDisable(t *testing.T) {
	t.Parallel()
	var rows = []map[string]any{
		unboundRow(map[string]any{"uuid": "u-on", "hostname": "on", "description": "on host"}),
		unboundRow(map[string]any{"uuid": "u-off", "hostname": "off", "enabled": "0", "ttl": "60"}),
	}
	for _, tc := range []struct {
		command, item string
		wantUuid      string // "": no write
		wantBody      map[string]any
		wantStderr    string
	}{
		{"disable", "on.example.lan", "u-on", unboundBody(map[string]any{"hostname": "on", "server": "10.9.9.8", "description": "on host", "enabled": "0"}), ""},
		{"enable", "u-off", "u-off", unboundBody(map[string]any{"hostname": "off", "server": "10.9.9.8", "ttl": "60"}), ""},
		{"enable", "on.example.lan", "", nil, "host override on.example.lan/A is already enabled"},
		{"disable", "1", "", nil, "host override off.example.lan/A is already disabled"},
	} {
		t.Run(tc.command+" "+tc.item, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(unboundSearchPath, rows...)
			for _, row := range rows {
				f.on("POST", unboundSetPath+row["uuid"].(string), 200, answerSaved)
			}
			var r = f.run("/unbound/host-override", tc.command, tc.item)
			wantExit(t, r, 0)
			if r.stdout != "" || !strings.Contains(r.stderr, tc.wantStderr) || (tc.wantStderr == "" && r.stderr != "") {
				t.Errorf("%s: stdout %q, stderr %q, want stderr %q", tc.command, r.stdout, r.stderr, tc.wantStderr)
			}
			if tc.wantUuid == "" {
				wantNoMutations(t, f)
				return
			}
			unboundWantBody(t, wantOneMutation(t, f, "POST", unboundSetPath+tc.wantUuid), tc.wantUuid, tc.wantBody)
		})
	}

	t.Run("unknown", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.search(unboundSearchPath, rows...)
		var r = f.run("/unbound/host-override", "disable", "nope.example.lan")
		wantFailure(t, r, "not found", "nope.example.lan")
		wantNoMutations(t, f)
	})
}

func TestUnboundHostOverrideShow(t *testing.T) {
	t.Parallel()
	var rows = []map[string]any{
		unboundRow(map[string]any{"uuid": "u-foobar", "hostname": "foobar"}),
		unboundRow(map[string]any{"uuid": "u-web-a", "hostname": "web", "description": "web v4", "ttl": "300"}),
		unboundRow(map[string]any{"uuid": "u-web-aaaa", "hostname": "web", "rr": "AAAA", "server": "fd00::5", "addptr": "0"}),
		unboundRow(map[string]any{"uuid": "u-mx", "hostname": "web", "rr": "MX", "server": "", "mxprio": "10", "mx": "mail.example.lan", "enabled": "0"}),
	}

	for _, tc := range []struct {
		name     string
		item     string
		wantUuid string
		wantOut  []string
		wantErr  []string
	}{
		{name: "by uuid", item: "u-web-a", wantUuid: "u-web-a",
			wantOut: []string{"description:  web v4", "ip:           10.9.9.8", "ttl:          300", "domain:       example.lan", "disabled:     no", "ptr:          yes"}},
		{name: "by FQDN/RR", item: "web.example.lan/mx", wantUuid: "u-mx",
			wantOut: []string{"mx:           mail.example.lan", "mx-priority:  10", "rr:           MX", "disabled:     yes"}},
		{name: "by FQDN", item: "foobar.example.lan", wantUuid: "u-foobar"},
		{name: "by index", item: "2", wantUuid: "u-web-aaaa", wantOut: []string{"fd00::5", "ptr:          no"}},
		{name: "FQDN with several records", item: "web.example.lan", wantErr: []string{"u-web-a", "u-web-aaaa", "u-mx", "web.example.lan/<RR>"}},
		{name: "host substring is no match", item: "foo.example.lan", wantErr: []string{"not found"}},
		{name: "unknown uuid", item: "u-gone", wantErr: []string{"not found", "u-gone"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(unboundSearchPath, rows...)
			var r = f.run("/unbound/host-override", "show", tc.item)
			wantNoMutations(t, f)
			if tc.wantErr != nil {
				wantFailure(t, r, tc.wantErr...)
				return
			}
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, tc.wantOut...)
			wantContains(t, "stdout", r.stdout, "uuid:         "+tc.wantUuid+"\n")
		})
	}
}

func TestUnboundHostOverridePrint(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search(unboundSearchPath,
		unboundRow(map[string]any{"uuid": "u-a", "hostname": "web", "description": "web server", "ttl": "300"}),
		unboundRow(map[string]any{"uuid": "u-mx", "hostname": "mx", "rr": "MX", "server": "", "mxprio": "10", "mx": "mail.example.lan", "enabled": "0"}),
		unboundRow(map[string]any{"uuid": "u-txt", "hostname": "txt", "rr": "TXT", "server": "", "txtdata": "v=spf1 -all", "addptr": "0"}),
	)

	var r = f.run("/unbound/host-override", "print")
	wantExit(t, r, 0)
	var want = [][]string{
		{"#", "DISABLED", "HOST", "DOMAIN", "RR", "VALUE", "TTL", "PTR", "DESCRIPTION"},
		{"0", "no", "web", "example.lan", "A", "10.9.9.8", "300", "yes", "web server"},
		{"1", "yes", "mx", "example.lan", "MX", "10 mail.example.lan", "-", "yes", "-"},
		{"2", "no", "txt", "example.lan", "TXT", "v=spf1 -all", "-", "no", "-"},
	}
	if got := unboundTableRows(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("table:\n got  %q\n want %q\n%s", got, want, r.stdout)
	}
	wantSearchPhrases(t, f, unboundSearchPath, "")

	t.Run("search", func(t *testing.T) {
		var f = newFakeOPN(t)
		f.search(unboundSearchPath, unboundRow(map[string]any{"uuid": "u-a"}),
			unboundRow(map[string]any{"uuid": "u-txt", "hostname": "txt", "rr": "TXT", "server": "", "txtdata": "v=spf1 -all"}))
		var r = f.run("/unbound/host-override", "print", "search=spf1 -all")
		wantExit(t, r, 0)
		var rows = unboundTableRows(r.stdout)
		if len(rows) != 2 || rows[1][2] != "txt" {
			t.Errorf("want only txt:\n%s", r.stdout)
		}
		wantSearchPhrases(t, f, unboundSearchPath, "spf1 -all")
	})

	t.Run("detail", func(t *testing.T) {
		var r = f.run("/unbound/host-override", "print", "detail")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "0\n  uuid:         u-a\n", "\n1\n  uuid:         u-mx\n", "  mx-priority:  10\n",
			"\n2\n  uuid:         u-txt\n", "  txtdata:      v=spf1 -all\n")
	})

	t.Run("json", func(t *testing.T) {
		var r = f.run("/unbound/host-override", "print", "json")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != 3 {
			t.Fatalf("want 3 ndjson lines, got:\n%s", r.stdout)
		}
		// the raw API objects, with fields the CLI does not know
		wantContains(t, "json", lines[1], `"uuid":"u-mx"`, `"%rr":"A (IPv4 address)"`, `"isAlias":false`, `"enabled":"0"`)
	})

	t.Run("empty", func(t *testing.T) {
		var empty = newFakeOPN(t)
		empty.search(unboundSearchPath)
		var r = empty.run("/unbound/host-override", "print")
		wantExit(t, r, 0)
		if rows := unboundTableRows(r.stdout); len(rows) != 1 || rows[0][0] != "#" {
			t.Errorf("want only the header:\n%s", r.stdout)
		}
	})
}

// a # refers to the rows of the last print in the session, also when print was filtered
func TestUnboundHostOverrideIndexAfterPrint(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var rows = []map[string]any{
		unboundRow(map[string]any{"uuid": "u-a", "hostname": "alpha"}),
		unboundRow(map[string]any{"uuid": "u-b", "hostname": "beta", "description": "pick me"}),
	}
	f.search(unboundSearchPath, rows...)
	f.on("POST", unboundDelPath+"u-b", 200, answerDeleted)
	var r = f.runScript("/unbound/host-override\nprint search=pick\nremove 0\n")
	wantExit(t, r, 0)
	wantOneMutation(t, f, "POST", unboundDelPath+"u-b")
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
		{"status", "GET", `{"status":"running","widget":{"caption_stop":"stop service","caption_start":"start service"}}`, true, "status:  running\n"},
		{"restart", "POST", `{"response":"OK"}`, true, ""},
		{"restart", "POST", `{"response":"Execute error"}`, false, "Execute error"},
		{"reconfigure", "POST", `{"status":"ok"}`, true, ""},
		{"reconfigure", "POST", `{"status":"failed"}`, false, "failed"},
	} {
		t.Run(tc.action+"/"+tc.answer, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on(tc.method, "/api/unbound/service/"+tc.action, 200, tc.answer)
			var r = f.run("/unbound/service", tc.action)
			if tc.wantOk {
				wantExit(t, r, 0)
				if r.stdout != tc.wantOut {
					t.Errorf("stdout %q, want %q", r.stdout, tc.wantOut)
				}
			} else {
				wantFailure(t, r, tc.wantOut)
			}
			var calls = f.calls()
			if len(calls) != 1 || calls[0].Method != tc.method || calls[0].Path != "/api/unbound/service/"+tc.action {
				t.Errorf("want one %s /api/unbound/service/%s, got %v", tc.method, tc.action, calls)
			}
		})
	}
}

func TestUnboundHelp(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var r = f.run("/unbound/host-override", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "print", "show", "add", "set", "remove", "enable", "disable")
	var add = f.run("/unbound/host-override", "add", "?")
	wantExit(t, add, 0)
	wantContains(t, "stdout", add.stdout, "rr=A|AAAA|MX|TXT", "mx-priority=<number>", "replace[=yes|no]", "disabled[=yes|no]")
	wantNoCalls(t, f)
}
