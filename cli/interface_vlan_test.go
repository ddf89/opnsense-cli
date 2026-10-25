package cli

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Tests of the generic item menu (interface_menu.go) through /interface/vlan, plus the VLAN specifics

const (
	interfaceVlanSearchPath  = "/api/interfaces/vlan_settings/search_item"
	interfaceVlanGetPath     = "/api/interfaces/vlan_settings/get_item"
	interfaceVlanAddPath     = "/api/interfaces/vlan_settings/add_item"
	interfaceVlanSetPath     = "/api/interfaces/vlan_settings/set_item/"
	interfaceVlanDelPath     = "/api/interfaces/vlan_settings/del_item/"
	interfaceVlanApplyPath   = "/api/interfaces/vlan_settings/reconfigure"
	interfaceAssignmentPath  = "/api/interfaces/assignment/search_item"
	interfaceVlanGetDefaults = `{"vlan":{"if":{"vtnet0":{"value":"vtnet0 (52:54:00:12:34:56) [LAN]","selected":0},` +
		`"vtnet1":{"value":"vtnet1 (52:54:00:12:34:57) [WAN]","selected":0}},"tag":"",` +
		`"pcp":{"1":{"value":"Background (1, lowest)","selected":0},"0":{"value":"Best Effort (0, default)","selected":1}},` +
		`"proto":{"":{"value":"Automatic","selected":1},"802.1q":{"value":"802.1q","selected":0},"802.1ad":{"value":"802.1ad","selected":0}},` +
		`"descr":"","vlanif":""}}`
)

var interfaceColumnSeparator = regexp.MustCompile(`\s{2,}`)

// interfaceLines splits output into trimmed non-empty lines with the columns joined by "|"
func interfaceLines(output string) []string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, strings.Join(interfaceColumnSeparator.Split(line, -1), "|"))
		}
	}
	return lines
}

// interfaceVlanRows are vlan_settings/search_item rows of OPNsense 26.7: the QinQ device is assigned (opt2)
func interfaceVlanRows() []map[string]any {
	return []map[string]any{
		{"uuid": "v-guest", "if": "vtnet0", "%if": "vtnet0 (52:54:00:12:34:56) [LAN]", "tag": "10", "pcp": "3",
			"%pcp": "Critical Applications (3)", "proto": "", "descr": "guests", "vlanif": "vlan01"},
		{"uuid": "v-inner", "if": "vlan01", "%if": "vlan01 (Tag: 10, Parent: vtnet0)", "tag": "7", "pcp": "0",
			"%pcp": "Best Effort (0, default)", "proto": "802.1ad", "descr": "", "vlanif": "qinq01 [OPT2]"},
	}
}

func interfaceVlanFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(interfaceVlanSearchPath, rows...)
	f.search(interfaceAssignmentPath, map[string]any{"uuid": "opt2", "identifier": "opt2", "descr": "inner", "if": "qinq01", "lock": "0"})
	f.on("GET", interfaceVlanGetPath, 200, interfaceVlanGetDefaults)
	return f
}

func TestInterfaceVlanPrint(t *testing.T) {
	t.Parallel()
	var f = interfaceVlanFake(t, interfaceVlanRows()...)
	var r = f.run("/interface/vlan", "print")
	wantExit(t, r, 0)
	var want = []string{"#|DEVICE|PARENT|TAG|PCP|PROTO|DESCRIPTION", "0|vlan01|vtnet0|10|3|auto|guests", "1|qinq01|vlan01|7|0|802.1ad|-"}
	if got := interfaceLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}

	var searched = f.run("/interface/vlan", "print", "search=guest")
	wantExit(t, searched, 0)
	if got := interfaceLines(searched.stdout); len(got) != 2 || !strings.Contains(got[1], "guests") {
		t.Errorf("search: %q", got)
	}

	var asJSON = f.run("/interface/vlan", "print", "json")
	wantExit(t, asJSON, 0)
	var lines = strings.Split(strings.TrimSpace(asJSON.stdout), "\n")
	var first map[string]any
	if len(lines) != 2 || json.Unmarshal([]byte(lines[1]), &first) != nil || first["vlanif"] != "qinq01 [OPT2]" {
		t.Errorf("want the raw rows, got %q", asJSON.stdout)
	}

	var detail = f.run("/interface/vlan", "print", "detail")
	wantExit(t, detail, 0)
	wantContains(t, "stdout", detail.stdout, "uuid:", "v-inner", "device:", "qinq01", "assigned:", "opt2", "proto:", "802.1ad")
	wantNotContains(t, "stdout", detail.stdout, "name:")
	wantSearchPhrases(t, f, interfaceVlanSearchPath, "", "guest", "", "")
	wantNoMutations(t, f)
}

func TestInterfaceVlanShow(t *testing.T) {
	t.Parallel()
	var f = interfaceVlanFake(t, interfaceVlanRows()...)
	for _, selector := range []string{"1", "v-inner", "qinq01", "QINQ01"} {
		var r = f.run("/interface/vlan", "show", selector)
		wantExit(t, r, 0)
		var want = []string{"uuid:|v-inner", "device:|qinq01", "assigned:|opt2", "parent:|vlan01", "tag:|7", "pcp:|0",
			"proto:|802.1ad", "description:"}
		if got := interfaceLines(r.stdout); !reflect.DeepEqual(got, want) {
			t.Errorf("show %s:\n got  %q\n want %q", selector, got, want)
		}
	}
	wantExit(t, f.run("/interface/vlan", "show", "guests"), 0)
	wantFailure(t, f.run("/interface/vlan", "show", "vlan0"), "not found")
	wantFailure(t, f.run("/interface/vlan", "show", "2"), "not found")
	wantNoMutations(t, f)
}

func TestInterfaceVlanAdd(t *testing.T) {
	t.Parallel()
	var f = interfaceVlanFake(t, interfaceVlanRows()...)
	f.on("POST", interfaceVlanAddPath, 200, answerAdded("v-guest"))
	var r = f.run("/interface/vlan", "add", "parent=vtnet0", "tag=20", "pcp=5", "proto=802.1Q", "name=vlan0.20", "description=voice")
	wantExit(t, r, 0)
	if r.stdout != "v-guest\n" || !strings.Contains(r.stderr, "device vlan01") {
		t.Errorf("want the uuid on stdout and the device as a hint, got:\n%s", r)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", interfaceVlanAddPath), map[string]any{"vlan": map[string]any{
		"if": "vtnet0", "tag": "20", "pcp": "5", "proto": "802.1q", "vlanif": "vlan0.20", "descr": "voice"}})

	t.Run("only given fields", func(t *testing.T) {
		t.Parallel()
		var f = interfaceVlanFake(t)
		f.on("POST", interfaceVlanAddPath, 200, answerAdded("v-new"))
		wantExit(t, f.run("/interface/vlan", "add", "parent=vtnet0", "tag=4000", "proto=auto"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", interfaceVlanAddPath), map[string]any{"vlan": map[string]any{
			"if": "vtnet0", "tag": "4000", "proto": ""}})
	})

	t.Run("refused before any call", func(t *testing.T) {
		t.Parallel()
		for _, args := range [][]string{{}, {"parent=vtnet0"}, {"tag=10"}, {"parent=vtnet0", "tag=0"}, {"parent=vtnet0", "tag=4095"},
			{"parent=vtnet0", "tag=x"}, {"parent=vtnet0", "tag=10", "pcp=8"}, {"parent=vtnet0", "tag=10", "proto=802.1x"},
			{"parent=vtnet 0", "tag=10"}, {"parent=vtnet0", "tag=10", "name=eth0"}, {"parent=vtnet0", "tag=10", "name=vlan1"},
			{"parent=vtnet0", "tag=10", "description=a\nb"}} {
			var f = interfaceVlanFake(t)
			wantFailure(t, f.run(append([]string{"/interface/vlan", "add"}, args...)...))
			wantNoCalls(t, f)
		}
	})

	t.Run("exists", func(t *testing.T) {
		t.Parallel()
		var f = interfaceVlanFake(t, interfaceVlanRows()...)
		wantFailure(t, f.run("/interface/vlan", "add", "parent=vtnet0", "tag=10"), "exists already", "v-guest", "replace")
		wantNoMutations(t, f)
	})

	t.Run("replace", func(t *testing.T) {
		t.Parallel()
		var f = interfaceVlanFake(t, interfaceVlanRows()...)
		f.on("POST", interfaceVlanSetPath+"v-guest", 200, answerSaved)
		var r = f.run("/interface/vlan", "add", "parent=vtnet0", "tag=10", "description=new", "replace")
		wantExit(t, r, 0)
		if r.stdout != "v-guest\n" {
			t.Errorf("want the uuid on stdout, got %q", r.stdout)
		}
		// the fields not given get their defaults, the device name stays
		wantJSON(t, wantOneMutation(t, f, "POST", interfaceVlanSetPath+"v-guest"), map[string]any{"vlan": map[string]any{
			"if": "vtnet0", "tag": "10", "pcp": "0", "proto": "", "vlanif": "vlan01", "descr": "new"}})
	})

	t.Run("validation error of OPNsense with argument names", func(t *testing.T) {
		t.Parallel()
		var f = interfaceVlanFake(t)
		f.on("POST", interfaceVlanAddPath, 200, `{"result":"failed","validations":{"vlan.if":"Option [] not in list.","vlan.vlanif":["The device name prefix \"qinq\" is required."]}}`)
		var r = f.run("/interface/vlan", "add", "parent=vlan09", "tag=10")
		wantFailure(t, r, "parent: Option [] not in list.", "name: The device name prefix")
		wantNotContains(t, "output", r.stderr, "vlan.if")
	})
}

func TestInterfaceVlanSet(t *testing.T) {
	t.Parallel()
	var f = interfaceVlanFake(t, interfaceVlanRows()...)
	f.on("POST", interfaceVlanSetPath+"v-inner", 200, answerSaved)
	var r = f.run("/interface/vlan", "set", "qinq01", "pcp=6", "description=inner")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("set must be silent: %q", r.stdout)
	}
	// parent, tag and device name are always sent: set_item regenerates the name from them
	wantJSON(t, wantOneMutation(t, f, "POST", interfaceVlanSetPath+"v-inner"), map[string]any{"vlan": map[string]any{
		"if": "vlan01", "tag": "7", "vlanif": "qinq01", "pcp": "6", "descr": "inner"}})

	t.Run("new device name", func(t *testing.T) {
		t.Parallel()
		var f = interfaceVlanFake(t, interfaceVlanRows()...)
		f.on("POST", interfaceVlanSetPath+"v-guest", 200, answerSaved)
		wantExit(t, f.run("/interface/vlan", "set", "0", "parent=vtnet1", "name="), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", interfaceVlanSetPath+"v-guest"), map[string]any{"vlan": map[string]any{
			"if": "vtnet1", "tag": "10", "vlanif": ""}})
	})

	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		var f = interfaceVlanFake(t, interfaceVlanRows()...)
		wantFailure(t, f.run("/interface/vlan", "set", "vlan01"), "nothing to change")
		wantFailure(t, f.run("/interface/vlan", "set", "vlan01", "tag=0"))
		wantFailure(t, f.run("/interface/vlan", "set", "vlan09", "tag=5"), "not found")
		wantNoMutations(t, f)
	})
}

func TestInterfaceVlanRemoveAndApply(t *testing.T) {
	t.Parallel()
	var f = interfaceVlanFake(t, interfaceVlanRows()...)
	f.on("POST", interfaceVlanDelPath+"v-guest", 200, answerDeleted)
	var r = f.run("/interface/vlan", "remove", "guests")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("remove must be silent: %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", interfaceVlanDelPath+"v-guest")

	t.Run("in use", func(t *testing.T) {
		t.Parallel()
		var f = interfaceVlanFake(t, interfaceVlanRows()...)
		f.on("POST", interfaceVlanDelPath+"v-inner", 500, `{"errorMessage":"This VLAN cannot be deleted because it is assigned as an interface.","errorTitle":"Error"}`)
		// OPNsense's message says "cannot be deleted", so wantFailure's "deleted" check does not apply
		var r = f.run("/interface/vlan", "remove", "qinq01")
		wantExit(t, r, 1)
		wantContains(t, "stderr", r.stderr, "cannot remove VLAN v-inner", "assigned as an interface")
	})

	t.Run("apply", func(t *testing.T) {
		t.Parallel()
		var f = interfaceVlanFake(t)
		f.on("POST", interfaceVlanApplyPath, 200, `{"status":"ok"}`)
		var r = f.run("/interface/vlan", "apply")
		wantExit(t, r, 0)
		if r.stdout != "" {
			t.Errorf("apply must be silent: %q", r.stdout)
		}
		if got := wantOneMutation(t, f, "POST", interfaceVlanApplyPath); strings.TrimSpace(got.Body) != "{}" {
			t.Errorf("want a {} body, got %q", got.Body)
		}
		wantExit(t, f.run("/interface/vlan", "reconfigure"), 0)

		var failing = interfaceVlanFake(t)
		failing.on("POST", interfaceVlanApplyPath, 200, `{"status":"failed"}`)
		wantFailure(t, failing.run("/interface/vlan", "apply"), "VLAN reconfigure failed")
	})
}

func TestInterfaceVlanComplete(t *testing.T) {
	t.Parallel()
	var f = interfaceVlanFake(t, interfaceVlanRows()...)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/interface/vlan add parent=": {"parent=vtnet0", "parent=vtnet1"},
		"/interface/vlan remove q":    {"qinq01"},
		"/interface/vlan add proto=":  {"proto=802.1ad", "proto=802.1q", "proto=auto"},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}
