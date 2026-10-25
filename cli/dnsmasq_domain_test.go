package cli

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const (
	dnsmasqDomainSearchPath = "/api/dnsmasq/settings/search_domain"
	dnsmasqDomainAddPath    = "/api/dnsmasq/settings/add_domain"
	dnsmasqDomainSetPath    = "/api/dnsmasq/settings/set_domain/"
	dnsmasqDomainDelPath    = "/api/dnsmasq/settings/del_domain/"
	dnsmasqDomainGetPath    = "/api/dnsmasq/settings/get_domain/"
)

var dnsmasqDomainRows = []map[string]any{
	dnsmasqDomainRow(map[string]any{"uuid": "u-corp"}),
	dnsmasqDomainRow(map[string]any{"uuid": "u-sub", "domain": "sub.corp.example", "ip": "10.0.0.60"}),
	dnsmasqDomainRow(map[string]any{"uuid": "u-org", "domain": "corp.example.org"}),
	dnsmasqDomainRow(map[string]any{"uuid": "u-multi1", "domain": "multi.example", "ip": "10.0.1.1", "port": ""}),
	dnsmasqDomainRow(map[string]any{"uuid": "u-multi2", "domain": "multi.example", "ip": "fd00::1", "port": ""}),
	dnsmasqDomainRow(map[string]any{"uuid": "u-local", "domain": "local.example", "ip": "", "port": "", "descr": ""}),
}

// newDnsmasqDomainFake serves search / get / set / del for rows and add_domain answering u-new
func newDnsmasqDomainFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	var f = newFakeOPN(t)
	f.search(dnsmasqDomainSearchPath, rows...)
	f.on("POST", dnsmasqDomainAddPath, 200, answerAdded("u-new"))
	for _, row := range rows {
		var uuid = row["uuid"].(string)
		f.on("POST", dnsmasqDomainSetPath+uuid, 200, answerSaved)
		f.on("POST", dnsmasqDomainDelPath+uuid, 200, answerDeleted)
		f.onFunc("GET", dnsmasqDomainGetPath+uuid, dnsmasqDomainGetHandler(row))
	}
	// unknown uuids: get answers an empty array, set a bare failure, del "not found"
	f.on("GET", dnsmasqDomainGetPath+"u-gone", 200, `[]`)
	f.on("POST", dnsmasqDomainSetPath+"u-gone", 200, answerFailedBare)
	f.on("POST", dnsmasqDomainDelPath+"u-gone", 200, answerNotFound)
	return f
}

// dnsmasqDomainGetHandler answers get_domain/<uuid> like OPNsense: no uuid, option fields as {"key":{"value":..,"selected":0|1}}
func dnsmasqDomainGetHandler(row map[string]any) http.HandlerFunc {
	var item = map[string]any{}
	for key, value := range row {
		if key != "uuid" {
			item[key] = value
		}
	}
	var selected = func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	item["ipset"] = map[string]any{
		"":        map[string]any{"value": "none", "selected": selected(row["ipset"] == "")},
		"myalias": map[string]any{"value": "myalias", "selected": selected(row["ipset"] == "myalias")},
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"domainoverride": item})
	}
}

func dnsmasqDomainBody(overrides map[string]any) map[string]any {
	return map[string]any{"domainoverride": withFields(map[string]any{
		"sequence": "1", "domain": "corp.example", "ip": "10.0.0.53", "port": "", "srcip": "", "descr": "",
	}, overrides)}
}

func TestDnsmasqDomainAdd(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		args         []string
		wantPath     string
		wantBody     map[string]any
		wantUuid     string
		wantSearch   string
		wantReplaced bool
	}{
		{
			name:       "same domain, other ip adds another server",
			args:       []string{"domain=corp.example", "ip=10.0.0.54"},
			wantPath:   dnsmasqDomainAddPath,
			wantBody:   dnsmasqDomainBody(map[string]any{"ip": "10.0.0.54"}),
			wantUuid:   "u-new",
			wantSearch: "corp.example",
		},
		{
			name: "all fields, IPs normalized",
			args: []string{"domain=new.example", "ip=FD00:0::53", "port=5353", "source-ip=10.0.0.1",
				"sequence=7", "description=new dns"},
			wantPath: dnsmasqDomainAddPath,
			wantBody: dnsmasqDomainBody(map[string]any{"domain": "new.example", "ip": "fd00::53", "port": "5353",
				"srcip": "10.0.0.1", "sequence": "7", "descr": "new dns"}),
			wantUuid:   "u-new",
			wantSearch: "new.example",
		},
		{
			name:       "subdomain and suffix entries are no match",
			args:       []string{"domain=corp.example", "ip=10.0.0.60"},
			wantPath:   dnsmasqDomainAddPath,
			wantBody:   dnsmasqDomainBody(map[string]any{"ip": "10.0.0.60"}),
			wantUuid:   "u-new",
			wantSearch: "corp.example",
		},
		{
			name:         "replace overwrites the same domain and ip, fields not given are reset",
			args:         []string{"domain=corp.example", "ip=10.0.0.53", "description=updated", "replace"},
			wantPath:     dnsmasqDomainSetPath + "u-corp",
			wantBody:     dnsmasqDomainBody(map[string]any{"descr": "updated"}),
			wantUuid:     "u-corp",
			wantSearch:   "corp.example",
			wantReplaced: true,
		},
		{
			name:         "replace matches the domain case-insensitively without trailing dot, ip semantically",
			args:         []string{"domain=Multi.Example.", "ip=FD00:0::1", "replace"},
			wantPath:     dnsmasqDomainSetPath + "u-multi2",
			wantBody:     dnsmasqDomainBody(map[string]any{"domain": "Multi.Example.", "ip": "fd00::1"}),
			wantUuid:     "u-multi2",
			wantSearch:   "multi.example",
			wantReplaced: true,
		},
		{
			name:         "replace of a local domain without ip",
			args:         []string{"domain=local.example", "replace=yes"},
			wantPath:     dnsmasqDomainSetPath + "u-local",
			wantBody:     dnsmasqDomainBody(map[string]any{"domain": "local.example", "ip": ""}),
			wantUuid:     "u-local",
			wantSearch:   "local.example",
			wantReplaced: true,
		},
		{
			name:       "replace of a new ip adds",
			args:       []string{"domain=multi.example", "ip=10.0.1.2", "replace"},
			wantPath:   dnsmasqDomainAddPath,
			wantBody:   dnsmasqDomainBody(map[string]any{"domain": "multi.example", "ip": "10.0.1.2"}),
			wantUuid:   "u-new",
			wantSearch: "multi.example",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newDnsmasqDomainFake(t, dnsmasqDomainRows...)
			var r = f.run(append([]string{"/dnsmasq", "domain", "add"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != tc.wantUuid+"\n" {
				t.Errorf("stdout %q, want only the uuid %q", r.stdout, tc.wantUuid)
			}
			if tc.wantReplaced {
				wantContains(t, "stderr", r.stderr, "replaced")
			}
			wantSearchPhrases(t, f, dnsmasqDomainSearchPath, tc.wantSearch)
			wantJSON(t, wantOneMutation(t, f, "POST", tc.wantPath), tc.wantBody)
		})
	}
}

func TestDnsmasqDomainAddErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		args      []string
		answer    string
		wantErr   []string
		wantCalls bool
	}{
		{name: "missing domain", args: []string{"ip=10.0.0.53"}, wantErr: []string{"domain=", "required"}},
		{name: "empty domain", args: []string{"domain="}, wantErr: []string{"domain", "must not be empty"}},
		{name: "invalid ip", args: []string{"domain=x.example", "ip=10.0.0.256"}, wantErr: []string{"ip", "10.0.0.256"}},
		{name: "ip with port", args: []string{"domain=x.example", "ip=10.0.0.53#5353"}, wantErr: []string{"ip", "10.0.0.53#5353"}},
		{name: "two ips", args: []string{"domain=x.example", "ip=10.0.0.53,10.0.0.54"}, wantErr: []string{"ip"}},
		{name: "port 0", args: []string{"domain=x.example", "port=0"}, wantErr: []string{"port", "1 to 65535"}},
		{name: "port too large", args: []string{"domain=x.example", "port=65536"}, wantErr: []string{"port", "65536"}},
		{name: "port not a number", args: []string{"domain=x.example", "port=dns"}, wantErr: []string{"port", "dns"}},
		{name: "invalid source ip", args: []string{"domain=x.example", "source-ip=eth0"}, wantErr: []string{"source-ip", "eth0"}},
		{name: "sequence 0", args: []string{"domain=x.example", "sequence=0"}, wantErr: []string{"sequence", "1 to 99999"}},
		{name: "empty sequence", args: []string{"domain=x.example", "sequence="}, wantErr: []string{"sequence", "must not be empty"}},
		{name: "same domain and ip without replace", args: []string{"domain=DUP.example", "ip=10.0.0.9"},
			wantErr: []string{"already forwarded", "10.0.0.9", "u-dup1", "replace"}, wantCalls: true},
		{name: "ambiguous duplicates with replace", args: []string{"domain=dup.example", "ip=10.0.0.9", "replace"},
			wantErr: []string{"u-dup1", "u-dup2", "remove the duplicates"}, wantCalls: true},
		{name: "OPNsense validation", args: []string{"domain=x.example", "ip=10.0.0.53"},
			answer:  answerValidation("domainoverride.domain", "A valid domain name is required."),
			wantErr: []string{"domainoverride.domain", "A valid domain name is required."}, wantCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.search(dnsmasqDomainSearchPath,
				dnsmasqDomainRow(map[string]any{"uuid": "u-dup1", "domain": "dup.example", "ip": "10.0.0.9"}),
				dnsmasqDomainRow(map[string]any{"uuid": "u-dup2", "domain": "dup.example", "ip": "10.0.0.9"}),
			)
			if tc.answer != "" {
				f.on("POST", dnsmasqDomainAddPath, 200, tc.answer)
			}
			var r = f.run(append([]string{"/dnsmasq", "domain", "add"}, tc.args...)...)
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

func TestDnsmasqDomainSet(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		args       []string
		wantUuid   string // "": no set call
		wantFields map[string]any
		wantErr    []string
		noCalls    bool
	}{
		{name: "by uuid sends only the given field", args: []string{"u-corp", "port=5300"},
			wantUuid: "u-corp", wantFields: map[string]any{"port": "5300"}},
		{name: "by domain", args: []string{"corp.example", "description=renamed", "sequence=3"},
			wantUuid: "u-corp", wantFields: map[string]any{"descr": "renamed", "sequence": "3"}},
		{name: "by index", args: []string{"4", "ip=FD00:0::2", "source-ip=fd00::10"},
			wantUuid: "u-multi2", wantFields: map[string]any{"ip": "fd00::2", "srcip": "fd00::10"}},
		{name: "empty values clear fields", args: []string{"u-corp", "port=", "description=", "ip="},
			wantUuid: "u-corp", wantFields: map[string]any{"port": "", "descr": "", "ip": ""}},
		{name: "new domain", args: []string{"CORP.example.", "domain=corp2.example"},
			wantUuid: "u-corp", wantFields: map[string]any{"domain": "corp2.example"}},
		{name: "new domain and ip of a domain with several servers", args: []string{"u-multi1", "domain=multi2.example", "ip=fd00::1"},
			wantUuid: "u-multi1", wantFields: map[string]any{"domain": "multi2.example", "ip": "fd00::1"}},
		{name: "ip of another server of the domain", args: []string{"u-multi1", "ip=FD00::1"},
			wantErr: []string{"already forwarded", "fd00::1", "u-multi2"}},
		{name: "domain onto another entry", args: []string{"u-corp", "domain=multi.example", "ip=10.0.1.1"},
			wantErr: []string{"already forwarded", "u-multi1"}},
		{name: "unknown uuid", args: []string{"u-gone", "port=53"}, wantErr: []string{"not found", "u-gone"}},
		{name: "domain not found", args: []string{"nope.example", "port=53"}, wantErr: []string{"not found", "nope.example"}},
		{name: "parent domain is no match", args: []string{"example", "port=53"}, wantErr: []string{"not found"}},
		{name: "ambiguous asks for # or uuid", args: []string{"multi.example", "port=53"},
			wantErr: []string{"u-multi1", "10.0.1.1", "u-multi2", "fd00::1", "uuid"}},
		{name: "OPNsense validation", args: []string{"u-sub", "domain=bad domain"},
			wantUuid: "u-sub", wantFields: map[string]any{"domain": "bad domain"}, wantErr: []string{"domainoverride.domain", "A valid domain name is required."}},
		{name: "nothing selected", args: []string{"port=53"}, wantErr: []string{"item", "required"}, noCalls: true},
		{name: "nothing to set", args: []string{"u-corp"}, wantErr: []string{"nothing to change"}, noCalls: true},
		{name: "empty domain", args: []string{"u-corp", "domain="}, wantErr: []string{"domain", "must not be empty"}, noCalls: true},
		{name: "empty sequence", args: []string{"u-corp", "sequence="}, wantErr: []string{"sequence", "must not be empty"}, noCalls: true},
		{name: "invalid ip", args: []string{"u-corp", "ip=corp-dns"}, wantErr: []string{"ip", "corp-dns"}, noCalls: true},
		{name: "invalid port", args: []string{"u-corp", "port=99999"}, wantErr: []string{"port"}, noCalls: true},
		{name: "invalid source ip", args: []string{"u-corp", "source-ip=1.2.3"}, wantErr: []string{"source-ip"}, noCalls: true},
		{name: "invalid sequence", args: []string{"u-corp", "sequence=100000"}, wantErr: []string{"sequence"}, noCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newDnsmasqDomainFake(t, dnsmasqDomainRows...)
			f.on("POST", dnsmasqDomainSetPath+"u-sub", 200, answerValidation("domainoverride.domain", "A valid domain name is required."))
			var r = f.run(append([]string{"/dnsmasq", "domain", "set"}, tc.args...)...)
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
			if tc.wantUuid == "" {
				wantNoMutations(t, f)
				return
			}
			wantJSON(t, wantOneMutation(t, f, "POST", dnsmasqDomainSetPath+tc.wantUuid), map[string]any{"domainoverride": tc.wantFields})
		})
	}
}

func TestDnsmasqDomainRemove(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		args    []string
		wantDel string
		wantErr []string
		noCalls bool
	}{
		{name: "by uuid", args: []string{"u-corp"}, wantDel: "u-corp"},
		{name: "by domain", args: []string{"CORP.example."}, wantDel: "u-corp"},
		{name: "by index", args: []string{"3"}, wantDel: "u-multi1"},
		{name: "unknown uuid", args: []string{"u-gone"}, wantErr: []string{"not found", "u-gone"}},
		{name: "domain not found", args: []string{"corp"}, wantErr: []string{"not found"}},
		{name: "ambiguous asks for # or uuid", args: []string{"multi.example"}, wantErr: []string{"u-multi1", "u-multi2", "uuid"}},
		{name: "nothing selected", wantErr: []string{"item", "required"}, noCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newDnsmasqDomainFake(t, dnsmasqDomainRows...)
			var r = f.run(append([]string{"/dnsmasq", "domain", "remove"}, tc.args...)...)
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
				wantOneMutation(t, f, "POST", dnsmasqDomainDelPath+tc.wantDel)
			}
		})
	}
}

func TestDnsmasqDomainShow(t *testing.T) {
	t.Parallel()
	var rows = append([]map[string]any{dnsmasqDomainRow(map[string]any{"uuid": "u-ipset", "domain": "ipset.example", "ipset": "myalias"})},
		dnsmasqDomainRows...)
	for _, tc := range []struct {
		name    string
		args    []string
		want    map[string]string
		wantErr []string
		noCalls bool
	}{
		{name: "by uuid", args: []string{"u-corp"}, want: map[string]string{
			"uuid": "u-corp", "sequence": "1", "domain": "corp.example", "ip": "10.0.0.53", "port": "5353",
			"source-ip": "", "ipset": "", "description": "corp dns"}},
		{name: "by index", args: []string{"5"}, want: map[string]string{"uuid": "u-multi2", "ip": "fd00::1"}},
		{name: "selected ipset option", args: []string{"ipset.example"}, want: map[string]string{"uuid": "u-ipset", "ipset": "myalias"}},
		{name: "unknown uuid", args: []string{"u-gone"}, wantErr: []string{"not found", "u-gone"}},
		{name: "ambiguous asks for # or uuid", args: []string{"multi.example"}, wantErr: []string{"u-multi1", "u-multi2", "uuid"}},
		{name: "nothing selected", wantErr: []string{"item", "required"}, noCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newDnsmasqDomainFake(t, rows...)
			var r = f.run(append([]string{"/dnsmasq", "domain", "show"}, tc.args...)...)
			wantNoMutations(t, f)
			if tc.noCalls {
				wantNoCalls(t, f)
			}
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

func TestDnsmasqDomainPrint(t *testing.T) {
	t.Parallel()
	var f = newDnsmasqDomainFake(t, dnsmasqDomainRows...)
	var r = f.run("/dnsmasq", "domain", "print")
	wantExit(t, r, 0)
	var rows = dnsmasqTableRows(r.stdout)
	var want = [][]string{
		{"#", "SEQUENCE", "DOMAIN", "IP", "PORT", "SOURCE-IP", "DESCRIPTION"},
		{"0", "1", "corp.example", "10.0.0.53", "5353", "-", "corp dns"},
	}
	if len(rows) != len(dnsmasqDomainRows)+1 || !reflect.DeepEqual(rows[:2], want) {
		t.Errorf("table:\n got  %q\n want %q...\n%s", rows, want, r.stdout)
	}
	if last, wantLast := rows[len(rows)-1], []string{"5", "1", "local.example", "-", "-", "-", "-"}; !reflect.DeepEqual(last, wantLast) {
		t.Errorf("empty cells: got %q, want %q", last, wantLast)
	}

	r = f.run("/dnsmasq/domain", "print", "search=multi")
	wantExit(t, r, 0)
	if rows := dnsmasqTableRows(r.stdout); len(rows) != 3 {
		t.Errorf("search=multi: want 2 rows:\n%s", r.stdout)
	}

	r = f.run("/dnsmasq/domain", "print", "detail", "search=local")
	wantExit(t, r, 0)
	wantContains(t, "detail", r.stdout, "0\n", "  uuid:", "u-local", "  source-ip:", "  sequence:")

	r = f.run("/dnsmasq/domain", "print", "json")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); len(lines) != len(dnsmasqDomainRows) || err != nil || first["uuid"] != "u-corp" || first["srcip"] != "" {
		t.Errorf("json: want the raw rows, got %v (%v)\n%s", first, err, r.stdout)
	}

	wantSearchPhrases(t, f, dnsmasqDomainSearchPath, "", "multi", "local", "")
	wantNoMutations(t, f)
}
