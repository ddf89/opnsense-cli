package cli

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const (
	firewallGroupSearchPath   = "/api/firewall/group/search_item"
	firewallGroupGetPath      = "/api/firewall/group/get_item"
	firewallGroupAddPath      = "/api/firewall/group/add_item"
	firewallGroupSetPath      = "/api/firewall/group/set_item/"
	firewallGroupDelPath      = "/api/firewall/group/del_item/"
	firewallGroupReconfigPath = "/api/firewall/group/reconfigure"
)

// firewallGroupRow is a search_item row as OPNsense 26.7 returns it
func firewallGroupRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "ifname": "office", "members": "lan,opt1", "%members": "LAN, OFFICE", "nogroup": "0", "sequence": "0",
		"descr": "office nets",
	}, overrides)
}

// firewallGroupBuiltin is a built-in group row, its uuid is its name
func firewallGroupBuiltin(name string, descr string) map[string]any {
	return map[string]any{"uuid": name, "ifname": name, "members": "", "nogroup": "", "sequence": "10", "descr": descr}
}

// firewallGroupGet is get_item without uuid, with the member options
const firewallGroupGet = `{"group":{"ifname":"","members":{"lan":{"value":"LAN","selected":0},"lo0":{"value":"Loopback","selected":0},` +
	`"opt1":{"value":"OFFICE","selected":0},"wan":{"value":"WAN","selected":0}},"nogroup":"0","sequence":"0","descr":""}}`

func firewallGroupRows() []map[string]any {
	return []map[string]any{
		firewallGroupBuiltin("enc0", "IPsec encapsulation"),
		firewallGroupRow(map[string]any{"uuid": "g-office"}),
		firewallGroupRow(map[string]any{"uuid": "g-dmz", "ifname": "dmz_nets", "members": "wan", "%members": "WAN", "nogroup": "1",
			"sequence": "20", "descr": ""}),
		firewallGroupBuiltin("openvpn", "OpenVPN (Group)"),
	}
}

func firewallGroupFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(firewallGroupSearchPath, rows...)
	f.on("GET", firewallGroupGetPath, 200, firewallGroupGet)
	return f
}

// firewallGroupLines returns the non empty output lines, trimmed and with runs of spaces reduced to "|"
func firewallGroupLines(output string) []string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, strings.Join(systemCronColumnSeparator.Split(line, -1), "|"))
		}
	}
	return lines
}

func TestFirewallGroupPrint(t *testing.T) {
	t.Parallel()
	var f = firewallGroupFake(t, firewallGroupRows()...)
	var r = f.run("/firewall/group", "print")
	wantExit(t, r, 0)
	var want = []string{
		"#|NAME|MEMBERS|SEQUENCE|NO-GROUP|BUILT-IN|DESCRIPTION",
		"0|enc0|-|10|no|yes|IPsec encapsulation",
		"1|office|lan,opt1|0|no|no|office nets",
		"2|dmz_nets|wan|20|yes|no|-",
		"3|openvpn|-|10|no|yes|OpenVPN (Group)",
	}
	if got := firewallGroupLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	wantSearchPhrases(t, f, firewallGroupSearchPath, "")
	wantNoMutations(t, f)

	t.Run("search, json and detail", func(t *testing.T) {
		t.Parallel()
		var f = firewallGroupFake(t, firewallGroupRows()...)
		var searched = f.run("/firewall/group", "print", "search=dmz")
		wantExit(t, searched, 0)
		wantContains(t, "stdout", searched.stdout, "dmz_nets")
		wantNotContains(t, "stdout", searched.stdout, "office")

		var asJSON = f.run("/firewall/group", "print", "json")
		wantExit(t, asJSON, 0)
		var lines = strings.Split(strings.TrimSpace(asJSON.stdout), "\n")
		var second map[string]any
		if len(lines) != 4 || json.Unmarshal([]byte(lines[1]), &second) != nil || second["%members"] != "LAN, OFFICE" {
			t.Errorf("want the raw rows, got %q", asJSON.stdout)
		}

		var detail = f.run("/firewall/group", "print", "detail")
		wantExit(t, detail, 0)
		wantContains(t, "stdout", detail.stdout, "uuid:", "g-office", "member-names:", "LAN, OFFICE", "built-in:")
		wantSearchPhrases(t, f, firewallGroupSearchPath, "dmz", "", "")
	})
}

func TestFirewallGroupShow(t *testing.T) {
	t.Parallel()
	for _, selector := range []string{"1", "g-office", "office", "OFFICE"} {
		var f = firewallGroupFake(t, firewallGroupRows()...)
		var r = f.run("/firewall/group", "show", selector)
		wantExit(t, r, 0)
		var want = []string{"uuid:|g-office", "name:|office", "members:|lan,opt1", "member-names:|LAN, OFFICE", "sequence:|0",
			"no-group:|no", "built-in:|no", "description:|office nets"}
		if got := firewallGroupLines(r.stdout); !reflect.DeepEqual(got, want) {
			t.Errorf("show %s:\n got  %q\n want %q", selector, got, want)
		}
	}
	var f = firewallGroupFake(t, firewallGroupRows()...)
	wantExit(t, f.run("/firewall/group", "show", "openvpn"), 0)
	wantFailure(t, f.run("/firewall/group", "show", "offic"), "not found")
	wantNoMutations(t, f)
}

func TestFirewallGroupAdd(t *testing.T) {
	t.Parallel()
	var f = firewallGroupFake(t, firewallGroupRows()...)
	f.on("POST", firewallGroupAddPath, 200, answerAdded("g-new"))
	var r = f.run("/firewall/group", "add", "name=branch", "members=LAN,wan", "sequence=7", "no-group", "description=branch nets")
	wantExit(t, r, 0)
	if r.stdout != "g-new\n" {
		t.Errorf("want the uuid on stdout, got %q", r.stdout)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", firewallGroupAddPath), map[string]any{"group": map[string]any{
		"ifname": "branch", "members": "lan,wan", "sequence": "7", "nogroup": "1", "descr": "branch nets",
	}})

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		var f = firewallGroupFake(t)
		f.on("POST", firewallGroupAddPath, 200, answerAdded("g-new"))
		wantExit(t, f.run("/firewall/group", "add", "name=branch", "members=opt1"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", firewallGroupAddPath), map[string]any{"group": map[string]any{
			"ifname": "branch", "members": "opt1", "sequence": "0", "nogroup": "0", "descr": "",
		}})
	})

	t.Run("refused before any call", func(t *testing.T) {
		t.Parallel()
		for _, args := range [][]string{
			{"name=branch"},
			{"members=lan"},
			{"name=1branch", "members=lan"},
			{"name=branch2", "members=lan"},
			{"name=branch-x", "members=lan"},
			{"name=abcdefghijklmnop", "members=lan"},
			{"name=branch", "members=lan,lan"},
			{"name=branch", "members=lan", "sequence=10000"},
			{"name=branch", "members=lan", "sequence=-1"},
		} {
			var f = firewallGroupFake(t)
			wantFailure(t, f.run(append([]string{"/firewall/group", "add"}, args...)...))
			wantNoCalls(t, f)
		}
	})

	t.Run("refused before any mutation", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			args []string
			want string
		}{
			{[]string{"name=branch", "members=lan,opt9"}, `unknown interface "opt9"`},
			{[]string{"name=branch", "members="}, "at least one member"},
			{[]string{"name=Lan", "members=wan"}, "lan is the name of an interface"},
			// interface identifiers are refused even when the interface is not offered (here: no wan member option
			// is needed, lan alone is offered); names ending in a digit (opt1, lo0) fail the name rules already
			{[]string{"name=WAN", "members=lan"}, "wan is the name of an interface"},
			{[]string{"name=office", "members=wan"}, "exists already"},
			{[]string{"name=openvpn", "members=wan", "replace"}, "built-in"},
		} {
			var f = firewallGroupFake(t, firewallGroupRows()...)
			wantFailure(t, f.run(append([]string{"/firewall/group", "add"}, tc.args...)...), tc.want)
			wantNoMutations(t, f)
		}
	})

	t.Run("replace", func(t *testing.T) {
		t.Parallel()
		var f = firewallGroupFake(t, firewallGroupRows()...)
		f.on("POST", firewallGroupSetPath+"g-office", 200, answerSaved)
		var r = f.run("/firewall/group", "add", "name=office", "members=wan", "replace")
		wantExit(t, r, 0)
		if r.stdout != "g-office\n" {
			t.Errorf("want the uuid on stdout, got %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, "replaced")
		wantJSON(t, wantOneMutation(t, f, "POST", firewallGroupSetPath+"g-office"), map[string]any{"group": map[string]any{
			"ifname": "office", "members": "wan", "sequence": "0", "nogroup": "0", "descr": "",
		}})
	})

	t.Run("validation error of OPNsense", func(t *testing.T) {
		t.Parallel()
		var f = firewallGroupFake(t)
		f.on("POST", firewallGroupAddPath, 200, answerValidation("group.ifname", "Group name already exists."))
		wantFailure(t, f.run("/firewall/group", "add", "name=branch", "members=lan"), "group.ifname", "already exists")
	})
}

func TestFirewallGroupSet(t *testing.T) {
	t.Parallel()
	var f = firewallGroupFake(t, firewallGroupRows()...)
	f.on("POST", firewallGroupSetPath+"g-dmz", 200, answerSaved)
	var r = f.run("/firewall/group", "set", "dmz_nets", "members=opt1,lan", "no-group=no", "description=")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("set must be silent: %q", r.stdout)
	}
	// the current name is always sent, a set_item without ifname would rename the group to "" in all rules
	wantJSON(t, wantOneMutation(t, f, "POST", firewallGroupSetPath+"g-dmz"), map[string]any{"group": map[string]any{
		"ifname": "dmz_nets", "members": "opt1,lan", "nogroup": "0", "descr": "",
	}})

	t.Run("rename", func(t *testing.T) {
		t.Parallel()
		var f = firewallGroupFake(t, firewallGroupRows()...)
		f.on("POST", firewallGroupSetPath+"g-office", 200, answerSaved)
		wantExit(t, f.run("/firewall/group", "set", "1", "name=branch", "sequence=3"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", firewallGroupSetPath+"g-office"), map[string]any{"group": map[string]any{
			"ifname": "branch", "sequence": "3",
		}})
	})

	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			args []string
			want string
		}{
			{[]string{"office"}, "nothing to change"},
			{[]string{"openvpn", "description=x"}, "built-in"},
			{[]string{"office", "name=wan"}, "wan is the name of an interface"},
			{[]string{"office", "members=opt9"}, `unknown interface "opt9"`},
			{[]string{"office", "members="}, "at least one member"},
			{[]string{"office", "name=9x"}, "must be 1-15"},
			{[]string{"nope", "description=x"}, "not found"},
		} {
			var f = firewallGroupFake(t, firewallGroupRows()...)
			wantFailure(t, f.run(append([]string{"/firewall/group", "set"}, tc.args...)...), tc.want)
			wantNoMutations(t, f)
		}
	})
}

func TestFirewallGroupRemove(t *testing.T) {
	t.Parallel()
	var f = firewallGroupFake(t, firewallGroupRows()...)
	f.on("POST", firewallGroupDelPath+"g-office", 200, answerDeleted)
	var r = f.run("/firewall/group", "remove", "office")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("remove must be silent: %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", firewallGroupDelPath+"g-office")

	t.Run("in use", func(t *testing.T) {
		t.Parallel()
		var f = firewallGroupFake(t, firewallGroupRows()...)
		f.on("POST", firewallGroupDelPath+"g-office", 500, `{"errorMessage":"Cannot delete group. Currently in use by \n`+
			`[OPNsense.Firewall.Filter.rules.rule.d621e174-154f-4ebb-9465-6e2fac4b2bcb] allow office ","errorTitle":"Group in use"}`)
		wantFailure(t, f.run("/firewall/group", "remove", "office"),
			"Cannot delete group. Currently in use by [OPNsense.Firewall.Filter.rules.rule.d621e174-154f-4ebb-9465-6e2fac4b2bcb] allow office")
	})

	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		var f = firewallGroupFake(t, firewallGroupRows()...)
		wantFailure(t, f.run("/firewall/group", "remove", "enc0"), "built-in")
		wantFailure(t, f.run("/firewall/group", "remove", "nope"), "not found")
		wantNoMutations(t, f)
	})
}

func TestFirewallGroupApply(t *testing.T) {
	t.Parallel()
	var f = firewallGroupFake(t)
	f.on("POST", firewallGroupReconfigPath, 200, `{"status":"ok"}`)
	var r = f.run("/firewall/group", "apply")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("apply must be silent: %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", firewallGroupReconfigPath)

	var failing = firewallGroupFake(t)
	failing.on("POST", firewallGroupReconfigPath, 200, `{"status":"failed"}`)
	wantFailure(t, failing.run("/firewall/group", "apply"), "failed")
}

func TestFirewallGroupComplete(t *testing.T) {
	t.Parallel()
	var f = firewallGroupFake(t, firewallGroupRows()...)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/firewall/group remove o":             {"office", "openvpn"},
		"/firewall/group set item=d":           {"item=dmz_nets"},
		"/firewall/group add members=lan,":     {"members=lan,lan", "members=lan,lo0", "members=lan,opt1", "members=lan,wan"},
		"/firewall/group set office members=w": {"members=wan"},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}

func TestFirewallGroupHelp(t *testing.T) {
	t.Parallel()
	var f = firewallGroupFake(t)
	var r = f.run("/firewall/group", "add", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "name=<string>", "members=<list>", "sequence=<number>", "no-group[=yes|no]",
		"description=<string>", "replace", "/firewall/group apply")
	wantNoCalls(t, f)
}
