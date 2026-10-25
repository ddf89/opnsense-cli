package cmd

import (
	"reflect"
	"strings"
	"testing"
)

const (
	dnsmasqHostSearchPath = "/api/dnsmasq/settings/search_host"
	dnsmasqHostAddPath    = "/api/dnsmasq/settings/add_host"
	dnsmasqHostSetPath    = "/api/dnsmasq/settings/set_host/"
	dnsmasqHostDelPath    = "/api/dnsmasq/settings/del_host/"
)

// rows that must never be picked for web.example.lan
var dnsmasqHostDecoys = []map[string]any{
	dnsmasqHostRow(map[string]any{"uuid": "u-webserver", "host": "webserver"}),
	dnsmasqHostRow(map[string]any{"uuid": "u-myweb", "host": "myweb"}),
	dnsmasqHostRow(map[string]any{"uuid": "u-web-other", "host": "web", "domain": "other.lan"}),
	dnsmasqHostRow(map[string]any{"uuid": "u-web-nodomain", "host": "web", "domain": ""}),
	dnsmasqHostRow(map[string]any{"uuid": "u-probe", "descr": "web frontend"}),
}

// dnsmasqHostBody is the full {"host":{...}} body create sends, with all defaults
func dnsmasqHostBody(overrides map[string]any) map[string]any {
	return map[string]any{"host": withFields(map[string]any{
		"host": "web", "domain": "example.lan", "local": "0", "ip": "", "cnames": "", "client_id": "", "hwaddr": "",
		"lease_time": "", "ignore": "0", "descr": "", "comments": "", "aliases": "",
	}, overrides)}
}

func TestDnsmasqHostCreate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		args       []string
		rows       []map[string]any
		wantPath   string
		wantBody   map[string]any
		wantUuid   string
		wantSearch string
	}{
		{
			name:       "minimal, similar names are no match",
			args:       []string{"--host", "web", "--domain", "example.lan", "--ip", "10.0.0.5"},
			rows:       dnsmasqHostDecoys,
			wantPath:   dnsmasqHostAddPath,
			wantBody:   dnsmasqHostBody(map[string]any{"ip": "10.0.0.5"}),
			wantUuid:   "u-new",
			wantSearch: "web",
		},
		{
			name: "all flags, lists are trimmed, normalized and joined",
			args: []string{"--host", "web", "--domain", "example.lan",
				"--ip", "10.0.0.5, fd00:0:0::5", "--ip", "10.0.0.6",
				"--hwaddr", "AA-BB-CC-DD-EE-01", "--hwaddr", "aa:bb:cc:dd:ee:02",
				"--cname", "a.example.lan,b.example.lan", "--alias", "www.example.lan",
				"--client-id", "01:aa", "--lease-time", "3600", "--local", "--ignore",
				"--description", "web server", "--comments", "managed by cli"},
			wantPath: dnsmasqHostAddPath,
			wantBody: dnsmasqHostBody(map[string]any{
				"ip": "10.0.0.5,fd00::5,10.0.0.6", "hwaddr": "aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02",
				"cnames": "a.example.lan,b.example.lan", "aliases": "www.example.lan", "client_id": "01:aa",
				"lease_time": "3600", "local": "1", "ignore": "1", "descr": "web server", "comments": "managed by cli",
			}),
			wantUuid:   "u-new",
			wantSearch: "web",
		},
		{
			name:       "without domain only matches entries without domain",
			args:       []string{"--host", "web", "--hwaddr", "aa:bb:cc:dd:ee:01"},
			rows:       dnsmasqHostDecoys,
			wantPath:   dnsmasqHostSetPath + "u-web-nodomain",
			wantBody:   dnsmasqHostBody(map[string]any{"domain": "", "hwaddr": "aa:bb:cc:dd:ee:01"}),
			wantUuid:   "u-web-nodomain",
			wantSearch: "web",
		},
		{
			name: "existing FQDN is overwritten instead of duplicated",
			args: []string{"--host", "web", "--domain", "example.lan", "--ip", "10.0.0.7"},
			rows: append([]map[string]any{
				dnsmasqHostRow(map[string]any{"uuid": "u-existing", "host": "Web", "domain": "Example.lan"}),
			}, dnsmasqHostDecoys...),
			wantPath:   dnsmasqHostSetPath + "u-existing",
			wantBody:   dnsmasqHostBody(map[string]any{"ip": "10.0.0.7"}),
			wantUuid:   "u-existing",
			wantSearch: "web",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(dnsmasqHostSearchPath, tc.rows...)
			f.on("POST", dnsmasqHostAddPath, 200, answerAdded("u-new"))
			for _, row := range tc.rows {
				f.on("POST", dnsmasqHostSetPath+row["uuid"].(string), 200, answerSaved)
			}

			var r = f.run(append([]string{"dnsmasq", "host", "create"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != tc.wantUuid+"\n" {
				t.Errorf("stdout %q, want only the uuid %q", r.stdout, tc.wantUuid)
			}
			if tc.wantPath != dnsmasqHostAddPath {
				wantContains(t, "stderr", r.stderr, "updated")
			}
			wantSearchPhrases(t, f, dnsmasqHostSearchPath, tc.wantSearch)
			wantJSON(t, wantOneMutation(t, f, "POST", tc.wantPath), tc.wantBody)
		})
	}
}

func TestDnsmasqHostCreateErrors(t *testing.T) {
	t.Parallel()
	var duplicates = []map[string]any{
		dnsmasqHostRow(map[string]any{"uuid": "u-dup1", "host": "web"}),
		dnsmasqHostRow(map[string]any{"uuid": "u-dup2", "host": "web"}),
	}
	for _, tc := range []struct {
		name      string
		args      []string
		rows      []map[string]any
		answer    string
		wantErr   []string
		wantCalls bool
	}{
		{name: "missing host", args: []string{"--domain", "example.lan"}, wantErr: []string{`"host"`}},
		{name: "positional argument", args: []string{"--host", "web", "extra"}, wantErr: []string{"extra"}},
		{name: "invalid ip", args: []string{"--host", "web", "--ip", "10.0.0.256"}, wantErr: []string{"--ip", "10.0.0.256"}},
		{name: "ip with CIDR", args: []string{"--host", "web", "--ip", "10.0.0.5/24"}, wantErr: []string{"--ip", "10.0.0.5/24"}},
		{name: "one invalid ip of several", args: []string{"--host", "web", "--ip", "10.0.0.5,nope"}, wantErr: []string{"--ip", "nope"}},
		{name: "invalid mac", args: []string{"--host", "web", "--hwaddr", "aa:bb:cc:dd:ee"}, wantErr: []string{"--hwaddr", "aa:bb:cc:dd:ee"}},
		{name: "invalid lease time", args: []string{"--host", "web", "--lease-time", "1h"}, wantErr: []string{"--lease-time", "1h"}},
		{name: "negative lease time", args: []string{"--host", "web", "--lease-time", "-5"}, wantErr: []string{"--lease-time"}},
		{name: "duplicate FQDN", args: []string{"--host", "web", "--domain", "example.lan"}, rows: duplicates,
			wantErr: []string{"u-dup1", "u-dup2"}, wantCalls: true},
		{name: "OPNsense validation", args: []string{"--host", "web", "--ip", "10.0.0.5"},
			answer:  answerValidation("host.ip", "Please specify a valid network segment or IP address."),
			wantErr: []string{"host.ip", "Please specify a valid network segment or IP address."}, wantCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(dnsmasqHostSearchPath, tc.rows...)
			if tc.answer != "" {
				f.on("POST", dnsmasqHostAddPath, 200, tc.answer)
			}
			var r = f.run(append([]string{"dnsmasq", "host", "create"}, tc.args...)...)
			wantFailure(t, r, tc.wantErr...)
			if !tc.wantCalls {
				wantNoCalls(t, f)
			}
			if tc.answer == "" {
				wantNoMutations(t, f)
			}
		})
	}
}

func TestDnsmasqHostUpdate(t *testing.T) {
	t.Parallel()
	var rows = append([]map[string]any{
		dnsmasqHostRow(map[string]any{"uuid": "u-web", "host": "web"}),
		dnsmasqHostRow(map[string]any{"uuid": "u-dup1", "host": "dup"}),
		dnsmasqHostRow(map[string]any{"uuid": "u-dup2", "host": "dup"}),
		dnsmasqHostRow(map[string]any{"uuid": "u-invalid", "host": "invalid"}),
	}, dnsmasqHostDecoys...)

	for _, tc := range []struct {
		name       string
		args       []string
		wantSearch []string // nil: no lookup, "" is the existence check of the uuid before set_host
		wantUuid   string   // "": no set call
		wantFields map[string]any
		wantErr    []string
		noCalls    bool
	}{
		{name: "by uuid sends only the given field", args: []string{"--uuid", "u-web", "--description", "new descr"},
			wantSearch: []string{""}, wantUuid: "u-web", wantFields: map[string]any{"descr": "new descr"}},
		{name: "by FQDN", args: []string{"--host", "web", "--domain", "example.lan", "--ip", "10.0.0.8", "--hwaddr", "AA:BB:CC:DD:EE:08"},
			wantSearch: []string{"web", ""}, wantUuid: "u-web", wantFields: map[string]any{"ip": "10.0.0.8", "hwaddr": "aa:bb:cc:dd:ee:08"}},
		{name: "by FQDN without domain", args: []string{"--host", "web", "--comments", "c"},
			wantSearch: []string{"web", ""}, wantUuid: "u-web-nodomain", wantFields: map[string]any{"comments": "c"}},
		{name: "empty values clear fields", args: []string{"--uuid", "u-web", "--cname", "", "--ip", "", "--description", ""},
			wantSearch: []string{""}, wantUuid: "u-web", wantFields: map[string]any{"cnames": "", "ip": "", "descr": ""}},
		{name: "booleans", args: []string{"--uuid", "u-web", "--local", "--ignore=false"},
			wantSearch: []string{""}, wantUuid: "u-web", wantFields: map[string]any{"local": "1", "ignore": "0"}},
		{name: "rename by uuid", args: []string{"--uuid", "u-web", "--host", "web2", "--domain", "other.lan"},
			wantSearch: []string{""}, wantUuid: "u-web", wantFields: map[string]any{"host": "web2", "domain": "other.lan"}},
		{name: "rename by FQDN", args: []string{"--host", "web", "--domain", "example.lan", "--new-host", "web2", "--new-domain", ""},
			wantSearch: []string{"web", ""}, wantUuid: "u-web", wantFields: map[string]any{"host": "web2", "domain": ""}},
		// set_host would create a well-formed unknown uuid, so it must not be called
		{name: "unknown uuid fails and creates nothing", args: []string{"--uuid", "u-gone", "--host", "ghost", "--ip", "10.6.9.9"},
			wantSearch: []string{""}, wantErr: []string{"not found", "u-gone"}},
		{name: "OPNsense validation", args: []string{"--uuid", "u-invalid", "--alias", "bad alias"},
			wantSearch: []string{""}, wantUuid: "u-invalid", wantFields: map[string]any{"aliases": "bad alias"}, wantErr: []string{"host.aliases", "invalid hostname"}},
		{name: "FQDN not found", args: []string{"--host", "nope", "--domain", "example.lan", "--description", "x"},
			wantSearch: []string{"nope"}, wantErr: []string{"not found"}},
		{name: "host substring is no match", args: []string{"--host", "we", "--domain", "example.lan", "--description", "x"},
			wantSearch: []string{"we"}, wantErr: []string{"not found"}},
		{name: "ambiguous FQDN asks for uuid", args: []string{"--host", "dup", "--domain", "example.lan", "--description", "x"},
			wantSearch: []string{"dup"}, wantErr: []string{"u-dup1", "u-dup2", "--uuid"}},
		{name: "nothing selected", args: []string{"--description", "x"}, wantErr: []string{"--uuid"}, noCalls: true},
		{name: "invalid ip", args: []string{"--uuid", "u-web", "--ip", "300.1.1.1"}, wantErr: []string{"300.1.1.1"}, noCalls: true},
		{name: "invalid mac", args: []string{"--uuid", "u-web", "--hwaddr", "zz:bb:cc:dd:ee:ff"}, wantErr: []string{"zz:bb:cc:dd:ee:ff"}, noCalls: true},
		{name: "nothing to update by uuid", args: []string{"--uuid", "u-web"}, wantErr: []string{"nothing to update"}, noCalls: true},
		{name: "empty new hostname", args: []string{"--uuid", "u-web", "--new-host", ""}, wantErr: []string{"hostname"}, noCalls: true},
		{name: "host and new-host with uuid", args: []string{"--uuid", "u-web", "--host", "a", "--new-host", "b"}, wantErr: []string{"--new-host"}, noCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(dnsmasqHostSearchPath, rows...)
			for _, row := range rows {
				f.on("POST", dnsmasqHostSetPath+row["uuid"].(string), 200, answerSaved)
			}
			f.on("POST", dnsmasqHostSetPath+"u-gone", 200, answerFailedBare)
			f.on("POST", dnsmasqHostSetPath+"u-invalid", 200, answerValidation("host.aliases", "invalid hostname"))

			var r = f.run(append([]string{"dnsmasq", "host", "update"}, tc.args...)...)
			if tc.wantErr != nil {
				wantFailure(t, r, tc.wantErr...)
			} else {
				wantExit(t, r, 0)
				if r.stdout != tc.wantUuid+"\n" {
					t.Errorf("stdout %q, want only the uuid %q", r.stdout, tc.wantUuid)
				}
			}
			if tc.noCalls {
				wantNoCalls(t, f)
				return
			}
			wantSearchPhrases(t, f, dnsmasqHostSearchPath, tc.wantSearch...)
			if tc.wantUuid == "" {
				wantNoMutations(t, f)
				return
			}
			wantJSON(t, wantOneMutation(t, f, "POST", dnsmasqHostSetPath+tc.wantUuid), map[string]any{"host": tc.wantFields})
		})
	}
}

// "nothing to update" is a pure client-side check, but it runs after the FQDN lookup
func TestDnsmasqHostUpdateNothingToUpdateByFQDN(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search(dnsmasqHostSearchPath, dnsmasqHostRow(map[string]any{"uuid": "u-web", "host": "web"}))
	var r = f.run("dnsmasq", "host", "update", "--host", "web", "--domain", "example.lan")
	wantFailure(t, r, "nothing to update")
	wantNoMutations(t, f)
}

func TestDnsmasqHostRm(t *testing.T) {
	t.Parallel()
	var rows = append([]map[string]any{
		dnsmasqHostRow(map[string]any{"uuid": "u-web", "host": "web"}),
		dnsmasqHostRow(map[string]any{"uuid": "u-dup1", "host": "dup"}),
		dnsmasqHostRow(map[string]any{"uuid": "u-dup2", "host": "dup"}),
	}, dnsmasqHostDecoys...)

	for _, tc := range []struct {
		name       string
		args       []string
		wantSearch []string
		wantDel    string
		wantErr    []string
	}{
		{name: "by uuid", args: []string{"--uuid", "u-web"}, wantDel: "u-web"},
		{name: "uuid wins over host", args: []string{"--uuid", "u-webserver", "--host", "web", "--domain", "example.lan"}, wantDel: "u-webserver"},
		{name: "by FQDN", args: []string{"--host", "WEB", "--domain", "example.lan"}, wantSearch: []string{"WEB"}, wantDel: "u-web"},
		{name: "by host without domain", args: []string{"--host", "web"}, wantSearch: []string{"web"}, wantDel: "u-web-nodomain"},
		{name: "host substring is no match", args: []string{"--host", "webs", "--domain", "example.lan"}, wantSearch: []string{"webs"},
			wantErr: []string{"not found", "webs.example.lan"}},
		{name: "ambiguous asks for uuid", args: []string{"--host", "dup", "--domain", "example.lan"}, wantSearch: []string{"dup"},
			wantErr: []string{"u-dup1", "u-dup2", "--uuid"}},
		{name: "unknown uuid", args: []string{"--uuid", "u-gone"}, wantDel: "u-gone", wantErr: []string{"not found", "u-gone"}},
		{name: "nothing selected", wantErr: []string{"--uuid", "--host"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(dnsmasqHostSearchPath, rows...)
			for _, row := range rows {
				f.on("POST", dnsmasqHostDelPath+row["uuid"].(string), 200, answerDeleted)
			}
			f.on("POST", dnsmasqHostDelPath+"u-gone", 200, answerNotFound)

			var r = f.run(append([]string{"dnsmasq", "host", "rm"}, tc.args...)...)
			if tc.wantErr != nil {
				wantFailure(t, r, tc.wantErr...)
			} else {
				wantExit(t, r, 0)
				wantContains(t, "stdout", r.stdout, tc.wantDel)
			}
			wantSearchPhrases(t, f, dnsmasqHostSearchPath, tc.wantSearch...)
			if tc.wantDel == "" {
				wantNoMutations(t, f)
			} else {
				wantOneMutation(t, f, "POST", dnsmasqHostDelPath+tc.wantDel)
			}
		})
	}
}

func TestDnsmasqHostShow(t *testing.T) {
	t.Parallel()
	var rows = append([]map[string]any{
		dnsmasqHostRow(map[string]any{"uuid": "u-web", "host": "web", "local": "1", "lease_time": "3600", "set_tag": "mytag"}),
		dnsmasqHostRow(map[string]any{"uuid": "u-dup1", "host": "dup"}),
		dnsmasqHostRow(map[string]any{"uuid": "u-dup2", "host": "dup"}),
	}, dnsmasqHostDecoys...)

	for _, tc := range []struct {
		name    string
		args    []string
		want    [][2]string
		wantErr []string
	}{
		{name: "by uuid", args: []string{"--uuid", "u-web"}, want: [][2]string{
			{"UUID", "u-web"}, {"Host", "web"}, {"Domain", "example.lan"}, {"IP", "10.1.1.1,fd00::1"},
			{"CNAMEs", "alias1.example.lan,alias2.example.lan"}, {"Aliases", "www.example.lan"},
			{"HW address", "aa:bb:cc:dd:ee:ff"}, {"Lease time", "3600"}, {"Local", "yes"}, {"Ignore", "no"},
			{"Tag", "mytag"}, {"Description", "probe host"},
		}},
		{name: "by FQDN", args: []string{"--host", "web", "--domain", "EXAMPLE.LAN"}, want: [][2]string{{"UUID", "u-web"}}},
		{name: "by host without domain", args: []string{"--host", "web"}, want: [][2]string{{"UUID", "u-web-nodomain"}}},
		{name: "unknown uuid", args: []string{"--uuid", "u-gone"}, wantErr: []string{"not found", "u-gone"}},
		{name: "host substring is no match", args: []string{"--host", "eb", "--domain", "example.lan"}, wantErr: []string{"not found"}},
		{name: "ambiguous asks for uuid", args: []string{"--host", "dup", "--domain", "example.lan"}, wantErr: []string{"u-dup1", "u-dup2", "--uuid"}},
		{name: "nothing selected", wantErr: []string{"--uuid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(dnsmasqHostSearchPath, rows...)
			var r = f.run(append([]string{"dnsmasq", "host", "show"}, tc.args...)...)
			wantNoMutations(t, f)
			if tc.wantErr != nil {
				wantFailure(t, r, tc.wantErr...)
				return
			}
			wantExit(t, r, 0)
			var got = parseFields(r.stdout)
			for _, field := range tc.want {
				if got[field[0]] != field[1] {
					t.Errorf("field %q = %q, want %q\n%s", field[0], got[field[0]], field[1], r.stdout)
				}
			}
		})
	}
}

// parseFields parses printFields output ("key:<padding>value" lines)
func parseFields(output string) map[string]string {
	var fields = map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if key, value, ok := strings.Cut(line, ":"); ok {
			fields[key] = strings.TrimSpace(value)
		}
	}
	return fields
}

func TestDnsmasqHostList(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search(dnsmasqHostSearchPath,
		dnsmasqHostRow(map[string]any{"uuid": "u-probe"}),
		dnsmasqHostRow(map[string]any{"uuid": "u-bare", "host": "bare", "domain": "", "ip": "", "cnames": "", "hwaddr": "", "descr": ""}),
	)

	var r = f.run("dnsmasq", "host", "list")
	wantExit(t, r, 0)
	var want = [][]string{
		{"UUID", "HOST", "DOMAIN", "IP", "HWADDR", "CNAMES", "DESCRIPTION"},
		{"u-probe", "probe", "example.lan", "10.1.1.1, fd00::1", "aa:bb:cc:dd:ee:ff", "alias1.example.lan, alias2.example.lan", "probe host"},
		{"u-bare", "bare", "-", "-", "-", "-", "-"},
	}
	if got := tableRows(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("table:\n got  %q\n want %q\n%s", got, want, r.stdout)
	}

	r = f.run("dnsmasq", "host", "list", "--search", "BARE")
	wantExit(t, r, 0)
	if rows := tableRows(r.stdout); len(rows) != 2 || rows[1][0] != "u-bare" {
		t.Errorf("--search: want only u-bare:\n%s", r.stdout)
	}
	wantSearchPhrases(t, f, dnsmasqHostSearchPath, "", "BARE")
	wantNoMutations(t, f)
}
