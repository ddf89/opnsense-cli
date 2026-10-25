package cmd

import (
	"encoding/json"
	"net/http"
	"reflect"
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

// newDnsmasqDomainFake serves search / get / set / del for dnsmasqDomainRows and add_domain answering u-new
func newDnsmasqDomainFake(t *testing.T) *fakeOPN {
	var f = newFakeOPN(t)
	f.search(dnsmasqDomainSearchPath, dnsmasqDomainRows...)
	f.on("POST", dnsmasqDomainAddPath, 200, answerAdded("u-new"))
	for _, row := range dnsmasqDomainRows {
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
	var selected = row["ipset"]
	item["ipset"] = map[string]any{
		"":        map[string]any{"value": "none", "selected": boolToSelected(selected == "")},
		"myalias": map[string]any{"value": "myalias", "selected": boolToSelected(selected == "myalias")},
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"domainoverride": item})
	}
}

func boolToSelected(b bool) int {
	if b {
		return 1
	}
	return 0
}

func dnsmasqDomainBody(overrides map[string]any) map[string]any {
	return map[string]any{"domainoverride": withFields(map[string]any{
		"sequence": "1", "domain": "corp.example", "ip": "10.0.0.53", "port": "", "srcip": "", "descr": "",
	}, overrides)}
}

func TestDnsmasqDomainCreate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		args       []string
		wantPath   string
		wantBody   map[string]any
		wantUuid   string
		wantSearch string
	}{
		{
			name:       "same domain, other ip creates another entry",
			args:       []string{"--domain", "corp.example", "--ip", "10.0.0.54"},
			wantPath:   dnsmasqDomainAddPath,
			wantBody:   dnsmasqDomainBody(map[string]any{"ip": "10.0.0.54"}),
			wantUuid:   "u-new",
			wantSearch: "corp.example",
		},
		{
			name: "all flags",
			args: []string{"--domain", "new.example", "--ip", "fd00::53", "--port", "5353", "--srcip", "10.0.0.1",
				"--sequence", "7", "--description", "new dns"},
			wantPath: dnsmasqDomainAddPath,
			wantBody: dnsmasqDomainBody(map[string]any{"domain": "new.example", "ip": "fd00::53", "port": "5353",
				"srcip": "10.0.0.1", "sequence": "7", "descr": "new dns"}),
			wantUuid:   "u-new",
			wantSearch: "new.example",
		},
		{
			name:       "subdomain and suffix entries are no match",
			args:       []string{"--domain", "corp.example", "--ip", "10.0.0.60"},
			wantPath:   dnsmasqDomainAddPath,
			wantBody:   dnsmasqDomainBody(map[string]any{"ip": "10.0.0.60"}),
			wantUuid:   "u-new",
			wantSearch: "corp.example",
		},
		{
			name:       "existing domain and ip is updated, flags not given are reset",
			args:       []string{"--domain", "corp.example", "--ip", "10.0.0.53", "--description", "updated"},
			wantPath:   dnsmasqDomainSetPath + "u-corp",
			wantBody:   dnsmasqDomainBody(map[string]any{"descr": "updated"}),
			wantUuid:   "u-corp",
			wantSearch: "corp.example",
		},
		{
			name:       "domain matches case-insensitively without trailing dot, ip semantically",
			args:       []string{"--domain", "Multi.Example.", "--ip", "FD00:0::1"},
			wantPath:   dnsmasqDomainSetPath + "u-multi2",
			wantBody:   dnsmasqDomainBody(map[string]any{"domain": "Multi.Example.", "ip": "FD00:0::1"}),
			wantUuid:   "u-multi2",
			wantSearch: "multi.example",
		},
		{
			name:       "local domain without ip",
			args:       []string{"--domain", "local.example"},
			wantPath:   dnsmasqDomainSetPath + "u-local",
			wantBody:   dnsmasqDomainBody(map[string]any{"domain": "local.example", "ip": ""}),
			wantUuid:   "u-local",
			wantSearch: "local.example",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newDnsmasqDomainFake(t)
			var r = f.run(append([]string{"dnsmasq", "domain", "create"}, tc.args...)...)
			wantExit(t, r, 0)
			if r.stdout != tc.wantUuid+"\n" {
				t.Errorf("stdout %q, want only the uuid %q", r.stdout, tc.wantUuid)
			}
			wantSearchPhrases(t, f, dnsmasqDomainSearchPath, tc.wantSearch)
			wantJSON(t, wantOneMutation(t, f, "POST", tc.wantPath), tc.wantBody)
		})
	}
}

func TestDnsmasqDomainCreateErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		args      []string
		answer    string
		wantErr   []string
		wantCalls bool
	}{
		{name: "missing domain", args: []string{"--ip", "10.0.0.53"}, wantErr: []string{`"domain"`}},
		{name: "invalid ip", args: []string{"--domain", "x.example", "--ip", "10.0.0.256"}, wantErr: []string{"--ip", "10.0.0.256"}},
		{name: "ip with port", args: []string{"--domain", "x.example", "--ip", "10.0.0.53#5353"}, wantErr: []string{"--ip"}},
		{name: "port 0", args: []string{"--domain", "x.example", "--port", "0"}, wantErr: []string{"--port"}},
		{name: "port too large", args: []string{"--domain", "x.example", "--port", "65536"}, wantErr: []string{"--port", "65536"}},
		{name: "port not a number", args: []string{"--domain", "x.example", "--port", "dns"}, wantErr: []string{"--port", "dns"}},
		{name: "invalid srcip", args: []string{"--domain", "x.example", "--srcip", "eth0"}, wantErr: []string{"--srcip", "eth0"}},
		{name: "sequence 0", args: []string{"--domain", "x.example", "--sequence", "0"}, wantErr: []string{"--sequence"}},
		{name: "empty sequence", args: []string{"--domain", "x.example", "--sequence", ""}, wantErr: []string{"--sequence"}},
		{name: "ambiguous duplicates", args: []string{"--domain", "dup.example", "--ip", "10.0.0.9"},
			wantErr: []string{"u-dup1", "u-dup2"}, wantCalls: true},
		{name: "OPNsense validation", args: []string{"--domain", "x.example", "--ip", "10.0.0.53"},
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
			var r = f.run(append([]string{"dnsmasq", "domain", "create"}, tc.args...)...)
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

func TestDnsmasqDomainUpdate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		args       []string
		wantUuid   string // "": no set call
		wantFields map[string]any
		wantErr    []string
		noCalls    bool
	}{
		{name: "by uuid sends only the given field", args: []string{"--uuid", "u-corp", "--port", "5300"},
			wantUuid: "u-corp", wantFields: map[string]any{"port": "5300"}},
		{name: "by domain", args: []string{"--domain", "corp.example", "--description", "renamed", "--sequence", "3"},
			wantUuid: "u-corp", wantFields: map[string]any{"descr": "renamed", "sequence": "3"}},
		{name: "by domain and ip", args: []string{"--domain", "multi.example", "--ip", "fd00::1", "--new-ip", "fd00::2", "--srcip", "fd00::10"},
			wantUuid: "u-multi2", wantFields: map[string]any{"ip": "fd00::2", "srcip": "fd00::10"}},
		{name: "empty values clear fields", args: []string{"--uuid", "u-corp", "--port", "", "--description", "", "--new-ip", ""},
			wantUuid: "u-corp", wantFields: map[string]any{"port": "", "descr": "", "ip": ""}},
		{name: "new domain", args: []string{"--domain", "corp.example", "--new-domain", "corp2.example"},
			wantUuid: "u-corp", wantFields: map[string]any{"domain": "corp2.example"}},
		{name: "unknown uuid", args: []string{"--uuid", "u-gone", "--port", "53"}, wantErr: []string{"not found", "u-gone"}},
		{name: "domain not found", args: []string{"--domain", "nope.example", "--port", "53"}, wantErr: []string{"not found", "nope.example"}},
		{name: "parent domain is no match", args: []string{"--domain", "example", "--port", "53"}, wantErr: []string{"not found"}},
		{name: "ambiguous asks for uuid", args: []string{"--domain", "multi.example", "--port", "53"},
			wantErr: []string{"u-multi1", "u-multi2", "--uuid"}},
		{name: "OPNsense validation", args: []string{"--uuid", "u-sub", "--new-domain", "bad domain"},
			wantUuid: "u-sub", wantFields: map[string]any{"domain": "bad domain"}, wantErr: []string{"domainoverride.domain", "A valid domain name is required."}},
		{name: "nothing selected", args: []string{"--port", "53"}, wantErr: []string{"--uuid", "--domain"}, noCalls: true},
		{name: "uuid and domain", args: []string{"--uuid", "u-corp", "--domain", "corp.example", "--port", "53"}, wantErr: []string{"--uuid"}, noCalls: true},
		{name: "nothing to update", args: []string{"--uuid", "u-corp"}, wantErr: []string{"Nothing to update"}, noCalls: true},
		{name: "empty new domain", args: []string{"--uuid", "u-corp", "--new-domain", ""}, wantErr: []string{"--new-domain"}, noCalls: true},
		{name: "empty sequence", args: []string{"--uuid", "u-corp", "--sequence", ""}, wantErr: []string{"--sequence"}, noCalls: true},
		{name: "invalid new ip", args: []string{"--uuid", "u-corp", "--new-ip", "corp-dns"}, wantErr: []string{"--new-ip", "corp-dns"}, noCalls: true},
		{name: "invalid port", args: []string{"--uuid", "u-corp", "--port", "99999"}, wantErr: []string{"--port"}, noCalls: true},
		{name: "invalid srcip", args: []string{"--uuid", "u-corp", "--srcip", "1.2.3"}, wantErr: []string{"--srcip"}, noCalls: true},
		{name: "invalid sequence", args: []string{"--uuid", "u-corp", "--sequence", "100000"}, wantErr: []string{"--sequence"}, noCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newDnsmasqDomainFake(t)
			if tc.wantUuid == "u-sub" {
				f.on("POST", dnsmasqDomainSetPath+"u-sub", 200, answerValidation("domainoverride.domain", "A valid domain name is required."))
			}
			var r = f.run(append([]string{"dnsmasq", "domain", "update"}, tc.args...)...)
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
			if tc.wantUuid == "" {
				wantNoMutations(t, f)
				return
			}
			wantJSON(t, wantOneMutation(t, f, "POST", dnsmasqDomainSetPath+tc.wantUuid), map[string]any{"domainoverride": tc.wantFields})
		})
	}
}

func TestDnsmasqDomainRm(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		args    []string
		wantDel string
		wantErr []string
		noCalls bool
	}{
		{name: "by uuid", args: []string{"--uuid", "u-corp"}, wantDel: "u-corp"},
		{name: "by domain", args: []string{"--domain", "CORP.example."}, wantDel: "u-corp"},
		{name: "by domain and ip", args: []string{"--domain", "multi.example", "--ip", "10.0.1.1"}, wantDel: "u-multi1"},
		{name: "unknown uuid", args: []string{"--uuid", "u-gone"}, wantErr: []string{"not found", "u-gone"}},
		{name: "domain not found", args: []string{"--domain", "corp"}, wantErr: []string{"not found"}},
		{name: "domain and wrong ip", args: []string{"--domain", "corp.example", "--ip", "10.0.0.54"}, wantErr: []string{"not found"}},
		{name: "ambiguous asks for uuid", args: []string{"--domain", "multi.example"}, wantErr: []string{"u-multi1", "u-multi2", "--uuid"}},
		{name: "nothing selected", wantErr: []string{"--uuid"}, noCalls: true},
		{name: "uuid and domain", args: []string{"--uuid", "u-corp", "--domain", "corp.example"}, wantErr: []string{"--uuid"}, noCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newDnsmasqDomainFake(t)
			var r = f.run(append([]string{"dnsmasq", "domain", "rm"}, tc.args...)...)
			if tc.wantErr != nil {
				wantFailure(t, r, tc.wantErr...)
			} else {
				wantExit(t, r, 0)
				wantContains(t, "stdout", r.stdout, tc.wantDel)
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
	for _, tc := range []struct {
		name    string
		args    []string
		want    map[string]string
		wantErr []string
		noCalls bool
	}{
		{name: "by uuid", args: []string{"--uuid", "u-corp"}, want: map[string]string{
			"uuid": "u-corp", "sequence": "1", "domain": "corp.example", "ip": "10.0.0.53", "port": "5353",
			"srcip": "", "ipset": "", "description": "corp dns"}},
		{name: "by domain and ip", args: []string{"--domain", "multi.example", "--ip", "fd00::1"}, want: map[string]string{"uuid": "u-multi2", "ip": "fd00::1"}},
		{name: "unknown uuid", args: []string{"--uuid", "u-gone"}, wantErr: []string{"not found", "u-gone"}},
		{name: "ambiguous asks for uuid", args: []string{"--domain", "multi.example"}, wantErr: []string{"u-multi1", "u-multi2", "--uuid"}},
		{name: "nothing selected", wantErr: []string{"--uuid"}, noCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = newDnsmasqDomainFake(t)
			var r = f.run(append([]string{"dnsmasq", "domain", "show"}, tc.args...)...)
			wantNoMutations(t, f)
			if tc.noCalls {
				wantNoCalls(t, f)
			}
			if tc.wantErr != nil {
				wantFailure(t, r, tc.wantErr...)
				return
			}
			wantExit(t, r, 0)
			var got = parseFields(r.stdout)
			for key, want := range tc.want {
				if value, ok := got[key]; !ok || value != want {
					t.Errorf("field %q = %q, want %q\n%s", key, value, want, r.stdout)
				}
			}
		})
	}

	t.Run("selected ipset option", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		var row = dnsmasqDomainRow(map[string]any{"uuid": "u-ipset", "ipset": "myalias"})
		f.onFunc("GET", dnsmasqDomainGetPath+"u-ipset", dnsmasqDomainGetHandler(row))
		var r = f.run("dnsmasq", "domain", "show", "--uuid", "u-ipset")
		wantExit(t, r, 0)
		if got := parseFields(r.stdout)["ipset"]; got != "myalias" {
			t.Errorf("ipset = %q, want myalias\n%s", got, r.stdout)
		}
	})
}

func TestDnsmasqDomainList(t *testing.T) {
	t.Parallel()
	var f = newDnsmasqDomainFake(t)
	var r = f.run("dnsmasq", "domain", "list")
	wantExit(t, r, 0)
	var rows = tableRows(r.stdout)
	var want = [][]string{
		{"UUID", "SEQ", "DOMAIN", "IP", "PORT", "SRCIP", "DESCRIPTION"},
		{"u-corp", "1", "corp.example", "10.0.0.53", "5353", "-", "corp dns"},
	}
	if len(rows) != len(dnsmasqDomainRows)+1 || !reflect.DeepEqual(rows[:2], want) {
		t.Errorf("table:\n got  %q\n want %q...\n%s", rows, want, r.stdout)
	}
	if last, wantLast := rows[len(rows)-1], []string{"u-local", "1", "local.example", "-", "-", "-", "-"}; !reflect.DeepEqual(last, wantLast) {
		t.Errorf("empty cells: got %q, want %q", last, wantLast)
	}

	r = f.run("dnsmasq", "domain", "list", "--search", "multi")
	wantExit(t, r, 0)
	if rows := tableRows(r.stdout); len(rows) != 3 {
		t.Errorf("--search multi: want 2 rows:\n%s", r.stdout)
	}
	wantSearchPhrases(t, f, dnsmasqDomainSearchPath, "", "multi")
	wantNoMutations(t, f)
}
