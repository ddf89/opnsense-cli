package cli

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const (
	dnsmasqHostSearchPath = "/api/dnsmasq/settings/search_host"
	dnsmasqHostAddPath    = "/api/dnsmasq/settings/add_host"
	dnsmasqHostSetPath    = "/api/dnsmasq/settings/set_host/"
	dnsmasqHostDelPath    = "/api/dnsmasq/settings/del_host/"
)

// dnsmasqTableRows splits print output into rows of cells (columns are separated by 2+ spaces)
func dnsmasqTableRows(output string) [][]string {
	var separator = regexp.MustCompile(`\s{2,}`)
	var rows [][]string
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		rows = append(rows, separator.Split(strings.TrimSpace(line), -1))
	}
	return rows
}

// dnsmasqParseFields parses show output ("name:<padding>value" lines)
func dnsmasqParseFields(output string) map[string]string {
	var fields = map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if key, value, ok := strings.Cut(line, ":"); ok {
			fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return fields
}

// rows that must never be picked for web.example.lan
var dnsmasqHostDecoys = []map[string]any{
	dnsmasqHostRow(map[string]any{"uuid": "u-webserver", "host": "webserver"}),
	dnsmasqHostRow(map[string]any{"uuid": "u-myweb", "host": "myweb"}),
	dnsmasqHostRow(map[string]any{"uuid": "u-web-other", "host": "web", "domain": "other.lan"}),
	dnsmasqHostRow(map[string]any{"uuid": "u-web-nodomain", "host": "web", "domain": ""}),
	dnsmasqHostRow(map[string]any{"uuid": "u-probe", "descr": "web frontend"}),
}

// dnsmasqHostBody is the full {"host":{...}} body add sends, with all defaults
func dnsmasqHostBody(overrides map[string]any) map[string]any {
	return map[string]any{"host": withFields(map[string]any{
		"host": "web", "domain": "example.lan", "local": "0", "ip": "", "cnames": "", "client_id": "", "hwaddr": "",
		"lease_time": "", "ignore": "0", "descr": "", "comments": "", "aliases": "",
	}, overrides)}
}

// newDnsmasqHostFake serves search_host with rows, set_host / del_host for every row and add_host answering u-new
func newDnsmasqHostFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	var f = newFakeOPN(t)
	f.search(dnsmasqHostSearchPath, rows...)
	f.on("POST", dnsmasqHostAddPath, 200, answerAdded("u-new"))
	for _, row := range rows {
		f.on("POST", dnsmasqHostSetPath+row["uuid"].(string), 200, answerSaved)
		f.on("POST", dnsmasqHostDelPath+row["uuid"].(string), 200, answerDeleted)
	}
	return f
}

func TestDnsmasqHostAdd(t *testing.T) {
	t.Parallel()
	var existing = append([]map[string]any{
		dnsmasqHostRow(map[string]any{"uuid": "u-existing", "host": "Web", "domain": "Example.lan"}),
	}, dnsmasqHostDecoys...)

	for _, tc := range []struct {
		name         string
		args         []string
		rows         []map[string]any
		wantPath     string
		wantBody     map[string]any
		wantUuid     string
		wantReplaced bool
	}{
		{
			name:     "minimal, similar names are no match",
			args:     []string{"host=web", "domain=example.lan", "ip=10.0.0.5"},
			rows:     dnsmasqHostDecoys,
			wantPath: dnsmasqHostAddPath,
			wantBody: dnsmasqHostBody(map[string]any{"ip": "10.0.0.5"}),
			wantUuid: "u-new",
		},
		{
			name: "all fields, lists are trimmed, normalized and joined",
			args: []string{"host=web", "domain=example.lan",
				"ip=10.0.0.5, fd00:0:0::5,10.0.0.6", "hwaddr=AA-BB-CC-DD-EE-01,aa:bb:cc:dd:ee:02",
				"cname=a.example.lan,b.example.lan", "alias=www.example.lan",
				"client-id=01:aa", "lease-time=3600", "local", "ignore=yes",
				"description=web server", "comments=managed by cli"},
			wantPath: dnsmasqHostAddPath,
			wantBody: dnsmasqHostBody(map[string]any{
				"ip": "10.0.0.5,fd00::5,10.0.0.6", "hwaddr": "aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02",
				"cnames": "a.example.lan,b.example.lan", "aliases": "www.example.lan", "client_id": "01:aa",
				"lease_time": "3600", "local": "1", "ignore": "1", "descr": "web server", "comments": "managed by cli",
			}),
			wantUuid: "u-new",
		},
		{
			name:         "replace without domain only matches entries without domain",
			args:         []string{"host=web", "hwaddr=aa:bb:cc:dd:ee:01", "replace"},
			rows:         dnsmasqHostDecoys,
			wantPath:     dnsmasqHostSetPath + "u-web-nodomain",
			wantBody:     dnsmasqHostBody(map[string]any{"domain": "", "hwaddr": "aa:bb:cc:dd:ee:01"}),
			wantUuid:     "u-web-nodomain",
			wantReplaced: true,
		},
		{
			name:         "replace overwrites an existing FQDN completely",
			args:         []string{"host=web", "domain=example.lan", "ip=10.0.0.7", "replace"},
			rows:         existing,
			wantPath:     dnsmasqHostSetPath + "u-existing",
			wantBody:     dnsmasqHostBody(map[string]any{"ip": "10.0.0.7"}),
			wantUuid:     "u-existing",
			wantReplaced: true,
		},
		{
			name:     "replace of a new FQDN adds",
			args:     []string{"host=web", "domain=example.lan", "replace"},
			rows:     dnsmasqHostDecoys,
			wantPath: dnsmasqHostAddPath,
			wantBody: dnsmasqHostBody(nil),
			wantUuid: "u-new",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newDnsmasqHostFake(t, tc.rows...)
			var r = f.run(append([]string{"/dnsmasq", "host", "add"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != tc.wantUuid+"\n" {
				t.Errorf("stdout %q, want only the uuid %q", r.stdout, tc.wantUuid)
			}
			if tc.wantReplaced {
				wantContains(t, "stderr", r.stderr, "replaced")
			}
			wantSearchPhrases(t, f, dnsmasqHostSearchPath, "web")
			wantJSON(t, wantOneMutation(t, f, "POST", tc.wantPath), tc.wantBody)
		})
	}
}

func TestDnsmasqHostAddErrors(t *testing.T) {
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
		{name: "missing host", args: []string{"domain=example.lan"}, wantErr: []string{"host=", "required"}},
		{name: "empty host", args: []string{"host="}, wantErr: []string{"host", "must not be empty"}},
		{name: "stray word", args: []string{"host=web", "extra"}, wantErr: []string{"extra"}},
		{name: "invalid ip", args: []string{"host=web", "ip=10.0.0.256"}, wantErr: []string{"ip", "10.0.0.256"}},
		{name: "ip with CIDR", args: []string{"host=web", "ip=10.0.0.5/24"}, wantErr: []string{"ip", "10.0.0.5/24"}},
		{name: "one invalid ip of several", args: []string{"host=web", "ip=10.0.0.5,nope"}, wantErr: []string{"ip", "nope"}},
		{name: "invalid mac", args: []string{"host=web", "hwaddr=aa:bb:cc:dd:ee"}, wantErr: []string{"hwaddr", "aa:bb:cc:dd:ee"}},
		{name: "invalid lease time", args: []string{"host=web", "lease-time=1h"}, wantErr: []string{"lease-time", "1h"}},
		{name: "negative lease time", args: []string{"host=web", "lease-time=-5"}, wantErr: []string{"lease-time", "-5"}},
		{name: "invalid flag value", args: []string{"host=web", "local=maybe"}, wantErr: []string{"local", "maybe"}},
		{name: "existing FQDN without replace", args: []string{"host=WEB", "domain=example.lan", "ip=10.0.0.1"},
			rows:    []map[string]any{dnsmasqHostRow(map[string]any{"uuid": "u-web", "host": "web"})},
			wantErr: []string{"WEB.example.lan", "exists", "u-web"}, wantCalls: true},
		{name: "existing host without domain", args: []string{"host=web"}, rows: dnsmasqHostDecoys,
			wantErr: []string{"web", "exists", "u-web-nodomain", "replace"}, wantCalls: true},
		{name: "duplicate FQDN", args: []string{"host=web", "domain=example.lan"}, rows: duplicates,
			wantErr: []string{"u-dup1", "u-dup2"}, wantCalls: true},
		{name: "duplicate FQDN with replace", args: []string{"host=web", "domain=example.lan", "replace"}, rows: duplicates,
			wantErr: []string{"u-dup1", "u-dup2", "remove the duplicates"}, wantCalls: true},
		{name: "OPNsense validation", args: []string{"host=web", "ip=10.0.0.5"},
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
			var r = f.run(append([]string{"/dnsmasq", "host", "add"}, tc.args...)...)
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

// dnsmasqHostSetRows are the rows of the set / remove / show tests
var dnsmasqHostSetRows = append([]map[string]any{
	dnsmasqHostRow(map[string]any{"uuid": "u-web", "host": "web"}),
	dnsmasqHostRow(map[string]any{"uuid": "u-dup1", "host": "dup"}),
	dnsmasqHostRow(map[string]any{"uuid": "u-dup2", "host": "dup"}),
	dnsmasqHostRow(map[string]any{"uuid": "u-invalid", "host": "invalid"}),
}, dnsmasqHostDecoys...)

func TestDnsmasqHostSet(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		args       []string
		lookups    int    // GETs of search_host: the selection, then the existence check before set_host
		wantUuid   string // "": no set call
		wantFields map[string]any
		wantErr    []string
		noCalls    bool
	}{
		{name: "by uuid sends only the given field", args: []string{"u-web", "description=new descr"},
			lookups: 2, wantUuid: "u-web", wantFields: map[string]any{"descr": "new descr"}},
		{name: "by FQDN", args: []string{"web.example.lan", "ip=10.0.0.8", "hwaddr=AA:BB:CC:DD:EE:08"},
			lookups: 2, wantUuid: "u-web", wantFields: map[string]any{"ip": "10.0.0.8", "hwaddr": "aa:bb:cc:dd:ee:08"}},
		{name: "by FQDN, case and trailing dot ignored", args: []string{"item=WEB.Example.LAN.", "comments=c"},
			lookups: 2, wantUuid: "u-web", wantFields: map[string]any{"comments": "c"}},
		{name: "a host without domain is named by its hostname", args: []string{"web", "comments=c"},
			lookups: 2, wantUuid: "u-web-nodomain", wantFields: map[string]any{"comments": "c"}},
		{name: "by unique hostname", args: []string{"myweb", "comments=c"},
			lookups: 2, wantUuid: "u-myweb", wantFields: map[string]any{"comments": "c"}},
		{name: "by index without print is the list position", args: []string{"1", "comments=c"},
			lookups: 2, wantUuid: "u-dup1", wantFields: map[string]any{"comments": "c"}},
		{name: "empty values clear fields", args: []string{"u-web", "cname=", "ip=", "description="},
			lookups: 2, wantUuid: "u-web", wantFields: map[string]any{"cnames": "", "ip": "", "descr": ""}},
		{name: "booleans", args: []string{"u-web", "local", "ignore=no"},
			lookups: 2, wantUuid: "u-web", wantFields: map[string]any{"local": "1", "ignore": "0"}},
		{name: "rename", args: []string{"u-web", "host=web2", "domain=other.lan"},
			lookups: 2, wantUuid: "u-web", wantFields: map[string]any{"host": "web2", "domain": "other.lan"}},
		{name: "rename by FQDN, empty domain", args: []string{"web.example.lan", "host=web2", "domain="},
			lookups: 2, wantUuid: "u-web", wantFields: map[string]any{"host": "web2", "domain": ""}},
		{name: "rename to its own name in other case", args: []string{"u-web", "host=WEB"},
			lookups: 2, wantUuid: "u-web", wantFields: map[string]any{"host": "WEB"}},
		{name: "rename onto an existing FQDN", args: []string{"u-web", "host=webserver"},
			lookups: 1, wantErr: []string{"webserver.example.lan", "u-webserver"}},
		{name: "move onto an existing FQDN", args: []string{"u-web", "domain=other.lan"},
			lookups: 1, wantErr: []string{"web.other.lan", "u-web-other"}},
		{name: "unknown uuid", args: []string{"u-gone", "host=ghost", "ip=10.6.9.9"},
			lookups: 1, wantErr: []string{"not found", "u-gone"}},
		{name: "index out of range", args: []string{"42", "comments=c"},
			lookups: 1, wantErr: []string{"not found", "#42"}},
		{name: "OPNsense validation", args: []string{"u-invalid", "alias=bad alias"},
			lookups: 2, wantUuid: "u-invalid", wantFields: map[string]any{"aliases": "bad alias"}, wantErr: []string{"host.aliases", "invalid hostname"}},
		{name: "FQDN not found", args: []string{"nope.example.lan", "description=x"},
			lookups: 1, wantErr: []string{"not found", "nope.example.lan"}},
		{name: "host substring is no match", args: []string{"we.example.lan", "description=x"},
			lookups: 1, wantErr: []string{"not found"}},
		{name: "ambiguous FQDN asks for # or uuid", args: []string{"dup.example.lan", "description=x"},
			lookups: 1, wantErr: []string{"u-dup1", "u-dup2", "uuid"}},
		{name: "ambiguous hostname", args: []string{"dup", "description=x"},
			lookups: 1, wantErr: []string{"u-dup1", "u-dup2", "uuid"}},
		{name: "nothing selected", args: []string{"description=x"}, wantErr: []string{"item", "required"}, noCalls: true},
		{name: "invalid ip", args: []string{"u-web", "ip=300.1.1.1"}, wantErr: []string{"300.1.1.1"}, noCalls: true},
		{name: "invalid mac", args: []string{"u-web", "hwaddr=zz:bb:cc:dd:ee:ff"}, wantErr: []string{"zz:bb:cc:dd:ee:ff"}, noCalls: true},
		{name: "nothing to set", args: []string{"u-web"}, wantErr: []string{"nothing to change"}, noCalls: true},
		{name: "empty hostname", args: []string{"u-web", "host="}, wantErr: []string{"host", "must not be empty"}, noCalls: true},
		{name: "replace is no set argument", args: []string{"u-web", "replace=yes"}, wantErr: []string{"replace"}, noCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newDnsmasqHostFake(t, dnsmasqHostSetRows...)
			f.on("POST", dnsmasqHostSetPath+"u-invalid", 200, answerValidation("host.aliases", "invalid hostname"))

			var r = f.run(append([]string{"/dnsmasq", "host", "set"}, tc.args...)...)
			if tc.wantErr != nil {
				wantFailure(t, r, tc.wantErr...)
			} else {
				wantExit(t, r, 0)
				if r.stdout != "" || r.stderr != "" {
					t.Errorf("set must be silent:\n%s", r)
				}
			}
			if tc.noCalls {
				wantNoCalls(t, f)
				return
			}
			wantSearchPhrases(t, f, dnsmasqHostSearchPath, make([]string, tc.lookups)...)
			if tc.wantUuid == "" {
				wantNoMutations(t, f)
				return
			}
			wantJSON(t, wantOneMutation(t, f, "POST", dnsmasqHostSetPath+tc.wantUuid), map[string]any{"host": tc.wantFields})
		})
	}
}

// the # of a set refers to the last print of the menu in the same session, also a filtered one
func TestDnsmasqHostSetByPrintIndex(t *testing.T) {
	t.Parallel()
	var f = newDnsmasqHostFake(t, dnsmasqHostSetRows...)
	var r = f.runScript("/dnsmasq/host\nprint search=dup\nset 1 description=second\nremove 0\n")
	wantExit(t, r, 0)
	if rows := dnsmasqTableRows(r.stdout); len(rows) != 3 || rows[1][0] != "0" || rows[2][1] != "dup" {
		t.Errorf("print search=dup:\n%s", r.stdout)
	}
	var mutations = f.mutations()
	if len(mutations) != 2 || mutations[0].Path != dnsmasqHostSetPath+"u-dup2" || mutations[1].Path != dnsmasqHostDelPath+"u-dup1" {
		t.Fatalf("want set u-dup2 and del u-dup1, got %v", mutations)
	}
	wantJSON(t, mutations[0], map[string]any{"host": map[string]any{"descr": "second"}})
}

func TestDnsmasqHostRemove(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		args    []string
		wantDel string
		wantErr []string
		noCalls bool
	}{
		{name: "by uuid", args: []string{"u-web"}, wantDel: "u-web"},
		{name: "by FQDN", args: []string{"WEB.example.lan"}, wantDel: "u-web"},
		{name: "by named item", args: []string{"item=u-webserver"}, wantDel: "u-webserver"},
		{name: "by host without domain", args: []string{"web"}, wantDel: "u-web-nodomain"},
		{name: "by index", args: []string{"0"}, wantDel: "u-web"},
		{name: "host substring is no match", args: []string{"webs.example.lan"}, wantErr: []string{"not found", "webs.example.lan"}},
		{name: "ambiguous asks for # or uuid", args: []string{"dup.example.lan"}, wantErr: []string{"u-dup1", "u-dup2", "uuid"}},
		{name: "unknown uuid", args: []string{"u-gone"}, wantErr: []string{"not found", "u-gone"}},
		{name: "nothing selected", wantErr: []string{"item", "required"}, noCalls: true},
		{name: "two items", args: []string{"u-web", "u-dup1"}, wantErr: []string{"item given twice"}, noCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newDnsmasqHostFake(t, dnsmasqHostSetRows...)
			f.on("POST", dnsmasqHostDelPath+"u-gone", 200, answerNotFound)

			var r = f.run(append([]string{"/dnsmasq", "host", "remove"}, tc.args...)...)
			if tc.wantErr != nil {
				wantFailure(t, r, tc.wantErr...)
			} else {
				wantExit(t, r, 0)
				if r.stdout != "" {
					t.Errorf("remove must be silent: %q", r.stdout)
				}
			}
			if tc.noCalls {
				wantNoCalls(t, f)
			}
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
		want    map[string]string
		wantErr []string
	}{
		{name: "by uuid", args: []string{"u-web"}, want: map[string]string{
			"uuid": "u-web", "host": "web", "domain": "example.lan", "ip": "10.1.1.1,fd00::1",
			"cname": "alias1.example.lan,alias2.example.lan", "alias": "www.example.lan",
			"hwaddr": "aa:bb:cc:dd:ee:ff", "client-id": "", "lease-time": "3600", "local": "yes", "ignore": "no",
			"tag": "mytag", "description": "probe host", "comments": "",
		}},
		{name: "by FQDN", args: []string{"web.EXAMPLE.LAN"}, want: map[string]string{"uuid": "u-web"}},
		{name: "by host without domain", args: []string{"web"}, want: map[string]string{"uuid": "u-web-nodomain"}},
		{name: "unknown uuid", args: []string{"u-gone"}, wantErr: []string{"not found", "u-gone"}},
		{name: "host substring is no match", args: []string{"eb.example.lan"}, wantErr: []string{"not found"}},
		{name: "ambiguous asks for # or uuid", args: []string{"dup.example.lan"}, wantErr: []string{"u-dup1", "u-dup2", "uuid"}},
		{name: "nothing selected", wantErr: []string{"item", "required"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newDnsmasqHostFake(t, rows...)
			var r = f.run(append([]string{"/dnsmasq", "host", "show"}, tc.args...)...)
			wantNoMutations(t, f)
			if tc.wantErr != nil {
				wantFailure(t, r, tc.wantErr...)
				return
			}
			wantExit(t, r, 0)
			var got = dnsmasqParseFields(r.stdout)
			for key, want := range tc.want {
				if value, ok := got[key]; !ok || value != want {
					t.Errorf("field %q = %q, want %q\n%s", key, value, want, r.stdout)
				}
			}
		})
	}
}

func TestDnsmasqHostPrint(t *testing.T) {
	t.Parallel()
	var f = newDnsmasqHostFake(t,
		dnsmasqHostRow(map[string]any{"uuid": "u-probe"}),
		dnsmasqHostRow(map[string]any{"uuid": "u-bare", "host": "bare", "domain": "", "ip": "", "cnames": "", "hwaddr": "", "descr": ""}),
	)

	var r = f.run("/dnsmasq", "host", "print")
	wantExit(t, r, 0)
	var want = [][]string{
		{"#", "HOST", "DOMAIN", "IP", "HWADDR", "CNAME", "DESCRIPTION"},
		{"0", "probe", "example.lan", "10.1.1.1, fd00::1", "aa:bb:cc:dd:ee:ff", "alias1.example.lan, alias2.example.lan", "probe host"},
		{"1", "bare", "-", "-", "-", "-", "-"},
	}
	if got := dnsmasqTableRows(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("table:\n got  %q\n want %q\n%s", got, want, r.stdout)
	}

	r = f.run("/dnsmasq/host", "print", "search=BARE")
	wantExit(t, r, 0)
	if rows := dnsmasqTableRows(r.stdout); len(rows) != 2 || rows[1][1] != "bare" {
		t.Errorf("search: want only bare:\n%s", r.stdout)
	}

	r = f.run("/dnsmasq/host", "print", "detail")
	wantExit(t, r, 0)
	wantContains(t, "detail", r.stdout, "0\n", "  uuid:", "u-probe", "1\n", "u-bare", "  hwaddr:", "  lease-time:")

	r = f.run("/dnsmasq/host", "print", "json")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 2 {
		t.Fatalf("json: want 2 lines:\n%s", r.stdout)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil || first["uuid"] != "u-probe" || first["cnames"] != "alias1.example.lan,alias2.example.lan" {
		t.Errorf("json: want the raw row, got %v (%v)", first, err)
	}

	wantSearchPhrases(t, f, dnsmasqHostSearchPath, "", "BARE", "", "")
	wantNoMutations(t, f)
}

func TestDnsmasqComplete(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.search(dnsmasqHostSearchPath,
		dnsmasqHostRow(map[string]any{"uuid": "u-web", "host": "web"}),
		dnsmasqHostRow(map[string]any{"uuid": "u-bare", "host": "printer", "domain": ""}))
	f.search(dnsmasqDomainSearchPath,
		dnsmasqDomainRow(map[string]any{"uuid": "u-corp"}),
		dnsmasqDomainRow(map[string]any{"uuid": "u-lab", "domain": "lab.example"}))
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/dnsmasq/host remove w":  {"web.example.lan"},
		"/dnsmasq/host show p":    {"printer"},
		"/dnsmasq/host set item=": {"item=printer", "item=web.example.lan"},
		"/dnsmasq/domain show ":   {"corp.example", "item=", "lab.example"},
		"/dnsmasq/domain set l":   {"lab.example"},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}
