package cli

import (
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const (
	interfaceAssignmentApi         = "/api/interfaces/assignment/"
	interfaceAssignmentPendingPath = interfaceAssignmentApi + "pending"
	interfaceAssignmentApplyPath   = interfaceAssignmentApi + "reconfigure"
	// interfaceAssignmentForm is assignment/get_item of OPNsense 26.7 (shortened): the device choices
	interfaceAssignmentForm = `{"interface":{"descr":"","identifier":"","if":{` +
		`"vtnet0":{"value":"vtnet0 (52:54:00:12:34:56)","optgroup":"Hardware","selected":0},` +
		`"vtnet1":{"value":"vtnet1 (52:54:00:12:34:57)","optgroup":"Hardware","selected":0},` +
		`"vlan01":{"value":"vlan01 (vtnet0, tag 10)","optgroup":"VLAN","selected":0},` +
		`"lo1":{"value":"lo1 (router id)","optgroup":"Loopback","selected":0},` +
		`"lo2":{"value":"lo2 (spare)","optgroup":"Loopback","selected":0}},"lock":"1","enable":"1"}}`
	// interfaceAssignmentOverview is overview/interfaces_info: opt2 holds 127.0.0.1, the address of the fake
	// server the CLI talks to (the access interface); opt3 is configured but staged for removal in some tests
	interfaceAssignmentOverview = `{"rows":[` +
		`{"device":"vtnet0","identifier":"lan","description":"LAN","ipv4":[{"ipaddr":"192.168.1.1/24"}],"ipv6":[]},` +
		`{"device":"vtnet1","identifier":"wan","description":"WAN","ipv4":[{"ipaddr":"10.0.2.15/24"}],"ipv6":[]},` +
		`{"device":"lo0","identifier":"lo0","description":"Loopback","ipv4":[{"ipaddr":"10.255.255.1/32"}],"ipv6":[]},` +
		`{"device":"vlan01","identifier":"opt1","description":"guests","ipv4":[],"ipv6":[]},` +
		`{"device":"lo1","identifier":"opt2","description":"mgmt","addr4":"127.0.0.1/8","ipv4":[{"ipaddr":"127.0.0.1/8"}],"ipv6":[]}]}`
)

// interfaceAssignmentRow is an assignment/search_item row of OPNsense 26.7 (shortened)
func interfaceAssignmentRow(identifier string, description string, device string, overrides map[string]any) map[string]any {
	var row = map[string]any{"uuid": identifier, "identifier": identifier, "descr": description, "if": device,
		"%if": device + " (52:54:00:00:00:01)", "optgroup": "Hardware", "pending_action": "", "lock": "0", "enable": "1",
		"type4": "", "type6": "", "ipaddr": "", "ipaddrv6": ""}
	if description == "" {
		row["%descr"] = strings.ToUpper(identifier)
	}
	maps.Copy(row, overrides)
	return row
}

// interfaceAssignmentFake is a fake OPNsense with stateful assignments: add_item, set_item and del_item change
// the rows search_item returns, like OPNsense stages them
type interfaceAssignmentFake struct {
	*fakeOPN
	mu      sync.Mutex
	rows    []map[string]any
	pending bool
}

func newInterfaceAssignmentFake(t *testing.T, rows ...map[string]any) *interfaceAssignmentFake {
	t.Helper()
	var f = &interfaceAssignmentFake{fakeOPN: newFakeOPN(t)}
	if rows == nil {
		rows = []map[string]any{
			interfaceAssignmentRow("wan", "", "vtnet1", map[string]any{"type4": "dhcp", "%type4": "DHCP"}),
			interfaceAssignmentRow("lan", "", "vtnet0", map[string]any{"type4": "staticv4", "%type4": "Static IPv4", "ipaddr": "192.168.1.1/24"}),
			interfaceAssignmentRow("opt1", "guests", "vlan01", map[string]any{"optgroup": "VLAN", "lock": "1"}),
			interfaceAssignmentRow("opt2", "mgmt", "lo1", nil),
		}
	}
	f.rows = rows
	f.on("GET", interfaceAssignmentApi+"get_item", 200, interfaceAssignmentForm)
	f.on("GET", interfaceOverviewPath, 200, interfaceAssignmentOverview)
	f.onFunc("GET", interfaceAssignmentApi+"search_item", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": f.rows, "rowCount": len(f.rows), "total": len(f.rows), "current": 1})
	})
	f.onFunc("GET", interfaceAssignmentPendingPath, func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var status = "ok"
		if f.pending {
			status = "pending"
		}
		_, _ = io.WriteString(w, `{"status":"`+status+`"}`)
	})
	f.onFunc("POST", interfaceAssignmentApi+"add_item", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Interface map[string]any `json:"interface"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		defer f.mu.Unlock()
		var row = interfaceAssignmentRow("opt3", "", "", map[string]any{"pending_action": "update", "lock": "1"})
		maps.Copy(row, body.Interface)
		f.rows = append(f.rows, row)
		f.pending = true
		_, _ = io.WriteString(w, `{"result":"saved","uuid":"opt3"}`)
	})
	for _, row := range f.rows {
		var identifier = row["identifier"].(string)
		f.onFunc("POST", interfaceAssignmentApi+"set_item/"+identifier, func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Interface map[string]any `json:"interface"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, current := range f.rows {
				if current["identifier"] == identifier {
					maps.Copy(current, body.Interface)
					if _, relink := body.Interface["if"]; relink {
						current["pending_action"] = "relink"
						f.pending = true
					}
					if _, enable := body.Interface["enable"]; enable && current["pending_action"] == "" {
						current["pending_action"] = "update"
						f.pending = true
					}
				}
			}
			_, _ = io.WriteString(w, `{"result":"saved"}`)
		})
		f.onFunc("POST", interfaceAssignmentApi+"del_item/"+identifier, func(w http.ResponseWriter, _ *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			var kept []map[string]any
			for _, current := range f.rows {
				if current["identifier"] != identifier {
					kept = append(kept, current)
				}
			}
			f.rows = kept
			f.pending = true
			_, _ = io.WriteString(w, `{"result":"deleted"}`)
		})
	}
	f.on("POST", interfaceAssignmentApplyPath, 200, `{"status":"ok"}`)
	return f
}

func (f *interfaceAssignmentFake) row(identifier string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, row := range f.rows {
		if row["identifier"] == identifier {
			return maps.Clone(row)
		}
	}
	return nil
}

func TestInterfaceAssignmentPrint(t *testing.T) {
	t.Parallel()
	var f = newInterfaceAssignmentFake(t)
	f.rows[2]["pending_action"] = "relink"
	f.rows[3]["enable"] = "0"
	f.pending = true
	var r = f.run("/interface/assignment", "print")
	wantExit(t, r, 0)
	var want = []string{"#|IDENTIFIER|DESCRIPTION|DEVICE|DISABLED|LOCKED|PENDING",
		"0|wan|WAN|vtnet1|no|no|-", "1|lan|LAN|vtnet0|no|no|-", "2|opt1|guests|vlan01|no|yes|relink", "3|opt2|mgmt|lo1|yes|no|-"}
	if got := interfaceLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	wantContains(t, "stderr", r.stderr, "staged", "/interface/assignment apply")

	var detail = f.run("/interface/assignment", "print", "detail")
	wantContains(t, "stdout", detail.stdout, "device-info:", "vtnet1 (52:54:00:00:00:01)", "group:", "VLAN", "pending:", "relink",
		"ipv4-type:", "Static IPv4", "192.168.1.1/24")
	var asJSON = f.run("/interface/assignment", "print", "json")
	if lines := strings.Split(strings.TrimSpace(asJSON.stdout), "\n"); len(lines) != 4 || !strings.Contains(lines[2], `"identifier":"opt1"`) {
		t.Errorf("want the raw rows, got %q", asJSON.stdout)
	}

	// nothing staged: no hint
	f.pending = false
	wantNotContains(t, "stderr", f.run("/interface/assignment", "print").stderr, "staged")
	wantNoMutations(t, f.fakeOPN)
}

func TestInterfaceAssignmentShow(t *testing.T) {
	t.Parallel()
	var f = newInterfaceAssignmentFake(t)
	for _, selector := range []string{"opt1", "guests", "vlan01", "2"} {
		var r = f.run("/interface/assignment", "show", selector)
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "identifier:", "opt1", "device:", "vlan01", "locked:", "yes", "protected:", "no")
	}
	wantContains(t, "stdout", f.run("/interface/assignment", "show", "wan").stdout, "protected:", "WAN interface")
	wantContains(t, "stdout", f.run("/interface/assignment", "show", "mgmt").stdout, "protected:", "API connection", "127.0.0.1")
	wantFailure(t, f.run("/interface/assignment", "show", "opt9"), "not found")
	wantNoMutations(t, f.fakeOPN)
}

func TestInterfaceAssignmentAdd(t *testing.T) {
	t.Parallel()
	var f = newInterfaceAssignmentFake(t)
	var r = f.run("/interface/assignment", "add", "device=lo2", "description=spare_1", "locked=no")
	wantExit(t, r, 0)
	if r.stdout != "opt3\n" {
		t.Errorf("add must print the identifier, got %q", r.stdout)
	}
	var call = wantOneMutation(t, f.fakeOPN, "POST", interfaceAssignmentApi+"add_item")
	wantJSON(t, call, map[string]any{"interface": map[string]any{"if": "lo2", "descr": "spare_1", "lock": "0"}})

	var disabled = newInterfaceAssignmentFake(t)
	wantExit(t, disabled.run("/interface/assignment", "add", "device=lo2", "disabled"), 0)
	wantJSON(t, wantOneMutation(t, disabled.fakeOPN, "POST", interfaceAssignmentApi+"add_item"),
		map[string]any{"interface": map[string]any{"if": "lo2", "enable": "0"}})

	// refused before anything is changed
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"device=vlan01"}, "assigned already to opt1"},
		{[]string{"device=lo9"}, "OPNsense offers: lo1, lo2, vlan01, vtnet0, vtnet1"},
		{[]string{"device=lo2", "description=guests"}, "taken by interface opt1"},
		{[]string{"device=lo2", "description=WAN"}, "taken by interface wan"},
		{[]string{"device=lo2", "description=lan"}, "taken by interface lan"},
		{[]string{"device=lo2", "description=has-dash"}, "only letters, digits and underscores"},
		{[]string{"device=lo2", "description=has space"}, "only letters, digits and underscores"},
		{[]string{"description=x"}, "device"},
	} {
		var refused = newInterfaceAssignmentFake(t)
		wantFailure(t, refused.run(append([]string{"/interface/assignment", "add"}, tc.args...)...), tc.want)
		wantNoMutations(t, refused.fakeOPN)
	}

	var invalid = newInterfaceAssignmentFake(t)
	invalid.on("POST", interfaceAssignmentApi+"add_item", 200,
		`{"result":"failed","validations":{"interface.descr":"Description should be a string between 1 and 255 characters."}}`)
	wantFailure(t, invalid.run("/interface/assignment", "add", "device=lo2", "description=x"), "description", "between 1 and 255")
}

func TestInterfaceAssignmentSet(t *testing.T) {
	t.Parallel()
	var f = newInterfaceAssignmentFake(t)
	wantExit(t, f.run("/interface/assignment", "set", "opt1", "description=visitors", "locked=no"), 0)
	wantJSON(t, wantOneMutation(t, f.fakeOPN, "POST", interfaceAssignmentApi+"set_item/opt1"),
		map[string]any{"interface": map[string]any{"descr": "visitors", "lock": "0"}})

	var relink = newInterfaceAssignmentFake(t)
	wantExit(t, relink.run("/interface/assignment", "set", "guests", "device=lo2", "disabled"), 0)
	wantJSON(t, wantOneMutation(t, relink.fakeOPN, "POST", interfaceAssignmentApi+"set_item/opt1"),
		map[string]any{"interface": map[string]any{"if": "lo2", "enable": "0"}})
	if row := relink.row("opt1"); row["pending_action"] != "relink" {
		t.Errorf("relink not staged: %v", row)
	}

	// the description and lock of lan/wan may change without confirmation, their device and enabled state only with
	var lan = newInterfaceAssignmentFake(t)
	wantExit(t, lan.run("/interface/assignment", "set", "lan", "description=inside"), 0)
	wantOneMutation(t, lan.fakeOPN, "POST", interfaceAssignmentApi+"set_item/lan")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"wan", "device=lo2"}, "Changing the device of wan can cut off the access to the firewall (it is the WAN interface), " +
			"there is no rollback. Not run: add confirm=yes"},
		{[]string{"lan", "device=lo2", "description=x"}, "Changing the device of lan can cut off"},
		{[]string{"lan", "device=lo2", "disabled"}, "Changing the device of and disabling lan can cut off"},
		{[]string{"0", "disabled"}, "Disabling wan can cut off"},
		{[]string{"mgmt", "device=lo2"}, "Changing the device of opt2 can cut off the access to the firewall " +
			"(the API connection goes to its address 127.0.0.1), there is no rollback. Not run: add confirm=yes"},
		{[]string{"opt2", "disabled=yes"}, "Disabling opt2 can cut off"},
		{[]string{"opt9", "device=lo2"}, "not found"},
		{[]string{"opt1", "device=vtnet0"}, "assigned already to lan"},
		{[]string{"opt1", "description=mgmt"}, "taken by interface opt2"},
		{[]string{"opt1"}, "nothing to change"},
		{[]string{"opt9", "description=x"}, "not found"},
	} {
		var refused = newInterfaceAssignmentFake(t)
		var r = refused.run(append([]string{"/interface/assignment", "set"}, tc.args...)...)
		wantFailure(t, r, tc.want)
		wantContains(t, "stderr", r.stderr, tc.want)
		wantNoMutations(t, refused.fakeOPN)
	}
	// confirmed: sent like for any other interface
	for _, tc := range []struct {
		args []string
		path string
		body map[string]any
	}{
		{[]string{"wan", "device=lo2", "confirm=yes"}, "set_item/wan", map[string]any{"if": "lo2"}},
		{[]string{"mgmt", "disabled", "confirm"}, "set_item/opt2", map[string]any{"enable": "0"}},
	} {
		var confirmed = newInterfaceAssignmentFake(t)
		wantExit(t, confirmed.run(append([]string{"/interface/assignment", "set"}, tc.args...)...), 0)
		wantJSON(t, wantOneMutation(t, confirmed.fakeOPN, "POST", interfaceAssignmentApi+tc.path), map[string]any{"interface": tc.body})
	}
	// the same device is not a relink, enabling never asks
	var same = newInterfaceAssignmentFake(t)
	wantExit(t, same.run("/interface/assignment", "set", "wan", "device=vtnet1", "disabled=no", "description=outside"), 0)
	wantOneMutation(t, same.fakeOPN, "POST", interfaceAssignmentApi+"set_item/wan")

	// OPNsense ignored the change (a change back to the applied value while another one is staged)
	var ignored = newInterfaceAssignmentFake(t)
	ignored.on("POST", interfaceAssignmentApi+"set_item/opt1", 200, `{"result":"saved"}`)
	wantFailure(t, ignored.run("/interface/assignment", "set", "opt1", "disabled"), "kept the staged enabled state of opt1", "apply")
}

func TestInterfaceAssignmentEnableDisable(t *testing.T) {
	t.Parallel()
	var f = newInterfaceAssignmentFake(t)
	wantExit(t, f.run("/interface/assignment", "disable", "opt1"), 0)
	wantJSON(t, wantOneMutation(t, f.fakeOPN, "POST", interfaceAssignmentApi+"set_item/opt1"), map[string]any{"interface": map[string]any{"enable": "0"}})
	var enable = newInterfaceAssignmentFake(t)
	wantExit(t, enable.run("/interface/assignment", "enable", "wan"), 0)
	wantJSON(t, wantOneMutation(t, enable.fakeOPN, "POST", interfaceAssignmentApi+"set_item/wan"), map[string]any{"interface": map[string]any{"enable": "1"}})
	for _, selector := range []string{"wan", "lan", "mgmt"} {
		var refused = newInterfaceAssignmentFake(t)
		wantFailure(t, refused.run("/interface/assignment", "disable", selector), "Disabling", "cut off the access", "confirm=yes")
		wantNoMutations(t, refused.fakeOPN)
	}
	var confirmed = newInterfaceAssignmentFake(t)
	wantExit(t, confirmed.run("/interface/assignment", "disable", "lan", "confirm=yes"), 0)
	wantJSON(t, wantOneMutation(t, confirmed.fakeOPN, "POST", interfaceAssignmentApi+"set_item/lan"), map[string]any{"interface": map[string]any{"enable": "0"}})
	wantFailure(t, newInterfaceAssignmentFake(t).run("/interface/assignment", "disable", "opt9"), "not found")
}

func TestInterfaceAssignmentRemove(t *testing.T) {
	t.Parallel()
	// always dangerous: nothing changed without confirm=yes
	var plain = newInterfaceAssignmentFake(t, interfaceAssignmentRow("wan", "", "vtnet1", nil),
		interfaceAssignmentRow("opt4", "spare", "lo2", nil))
	var unconfirmed = plain.run("/interface/assignment", "remove", "spare")
	wantFailure(t, unconfirmed, "This unassigns the interface", "firewall and NAT rules", "confirm=yes")
	wantNotContains(t, "stderr", unconfirmed.stderr, "cut off")
	wantNoMutations(t, plain.fakeOPN)
	var r = plain.run("/interface/assignment", "remove", "spare", "confirm=yes")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("remove must be silent: %q", r.stdout)
	}
	wantOneMutation(t, plain.fakeOPN, "POST", interfaceAssignmentApi+"del_item/opt4")

	// protected ones warn first; locked and unknown ones fail before asking
	for _, tc := range []struct {
		selector string
		want     string
	}{
		{"wan", "Removing wan can cut off the access to the firewall (it is the WAN interface), there is no rollback. This unassigns"},
		{"lan", "Removing lan can cut off"},
		{"mgmt", "Removing opt2 can cut off the access to the firewall (the API connection"},
		{"opt1", "interface opt1 is locked, unlock it first with: set opt1 locked=no"},
		{"opt9", "not found"},
	} {
		var refused = newInterfaceAssignmentFake(t)
		var r = refused.run("/interface/assignment", "remove", tc.selector)
		wantFailure(t, r, tc.want)
		if strings.Contains(tc.want, "cut off") {
			wantContains(t, "stderr", r.stderr, "confirm=yes")
		} else {
			wantNotContains(t, "stderr", r.stderr, "confirm=yes")
		}
		wantNoMutations(t, refused.fakeOPN)
	}
	var locked = newInterfaceAssignmentFake(t)
	wantFailure(t, locked.run("/interface/assignment", "remove", "opt1", "confirm=yes"), "opt1 is locked")
	wantNoMutations(t, locked.fakeOPN)
	var protected = newInterfaceAssignmentFake(t)
	wantExit(t, protected.run("/interface/assignment", "remove", "lan", "confirm=yes"), 0)
	wantOneMutation(t, protected.fakeOPN, "POST", interfaceAssignmentApi+"del_item/lan")

	var inUse = newInterfaceAssignmentFake(t, interfaceAssignmentRow("opt4", "spare", "lo2", nil))
	inUse.on("POST", interfaceAssignmentApi+"del_item/opt4", 500,
		`{"errorMessage":"The interface is part of a group. Please remove it from the group to continue","errorTitle":"[opt4] in use"}`)
	wantFailure(t, inUse.run("/interface/assignment", "remove", "opt4", "confirm=yes"), "cannot remove interface opt4", "part of a group")
}

func TestInterfaceAssignmentApply(t *testing.T) {
	t.Parallel()
	// dangerous: without confirm=yes nothing is changed
	var unconfirmed = newInterfaceAssignmentFake(t)
	unconfirmed.rows[2]["pending_action"] = "relink"
	unconfirmed.pending = true
	var refusedRun = unconfirmed.run("/interface/assignment", "apply")
	wantFailure(t, refusedRun, "This applies all staged assignment changes", "firewall rules are reloaded", "confirm=yes")
	wantNotContains(t, "stderr", refusedRun.stderr, "cut off")
	wantNoMutations(t, unconfirmed.fakeOPN)

	// nothing staged: no question and no reconfigure (it would reload DHCP, DNS and the firewall for nothing)
	for _, args := range [][]string{{"apply"}, {"apply", "confirm=yes"}} {
		var nothing = newInterfaceAssignmentFake(t)
		var r = nothing.run(append([]string{"/interface/assignment"}, args...)...)
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "nothing to apply")
		wantNoMutations(t, nothing.fakeOPN)
	}
	var r runResult

	var staged = newInterfaceAssignmentFake(t)
	staged.rows[2]["pending_action"] = "relink"
	staged.pending = true
	r = staged.run("/interface/assignment", "reconfigure", "confirm=yes")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "applying: opt1 relink")
	wantOneMutation(t, staged.fakeOPN, "POST", interfaceAssignmentApplyPath)

	var failing = newInterfaceAssignmentFake(t)
	failing.pending = true
	failing.on("POST", interfaceAssignmentApplyPath, 200, `{"status":"failed"}`)
	wantFailure(t, failing.run("/interface/assignment", "apply", "confirm=yes"), "reconfigure failed")

	// a staged change of lan, wan or the access interface (also one made elsewhere) warns first
	for _, tc := range []struct {
		identifier string
		want       string
	}{
		{"wan", "Applying the staged change (update) of wan can cut off the access to the firewall (it is the WAN interface), " +
			"there is no rollback. This applies all staged"},
		{"lan", "Applying the staged change (update) of lan can cut off"},
		{"opt2", "Applying the staged change (update) of opt2 can cut off the access to the firewall (the API connection"},
	} {
		var staged = func() *interfaceAssignmentFake {
			var f = newInterfaceAssignmentFake(t)
			for _, row := range f.rows {
				if row["identifier"] == tc.identifier {
					row["pending_action"] = "update"
				}
			}
			f.pending = true
			return f
		}
		var refused = staged()
		wantFailure(t, refused.run("/interface/assignment", "apply"), tc.want, "confirm=yes")
		wantNoMutations(t, refused.fakeOPN)
		var confirmed = staged()
		wantExit(t, confirmed.run("/interface/assignment", "apply", "confirm=yes"), 0)
		wantOneMutation(t, confirmed.fakeOPN, "POST", interfaceAssignmentApplyPath)
	}

	// lan staged for removal: configured (overview) but no longer listed
	var removed = newInterfaceAssignmentFake(t, interfaceAssignmentRow("wan", "", "vtnet1", nil),
		interfaceAssignmentRow("opt1", "guests", "vlan01", nil), interfaceAssignmentRow("opt2", "mgmt", "lo1", nil))
	removed.pending = true
	wantFailure(t, removed.run("/interface/assignment", "apply"), "Applying the staged removal of lan can cut off", "confirm=yes")
	wantNoMutations(t, removed.fakeOPN)

	// the access interface can not be told: no question without knowing what to warn about, confirm=yes applies
	var unknown = newInterfaceAssignmentFake(t)
	unknown.on("GET", interfaceOverviewPath, 500, `{"errorMessage":"boom"}`)
	unknown.pending = true
	wantFailure(t, unknown.run("/interface/assignment", "apply"), "cannot check which interface the API connection uses")
	wantNoMutations(t, unknown.fakeOPN)
	wantExit(t, unknown.run("/interface/assignment", "apply", "confirm=yes"), 0)
	wantOneMutation(t, unknown.fakeOPN, "POST", interfaceAssignmentApplyPath)
}

func TestInterfaceAssignmentGuard(t *testing.T) {
	t.Parallel()
	var guard = interfaceAssignmentGuard{protected: map[string]string{"wan": "it is the WAN interface"}}
	if got, want := guard.warning("wan", "changing the device of"),
		"Changing the device of wan can cut off the access to the firewall (it is the WAN interface), there is no rollback."; got != want {
		t.Errorf("warning:\n got  %q\n want %q", got, want)
	}
	if got := guard.warning("opt1", "disabling"); got != "" {
		t.Errorf("unprotected warning: %q", got)
	}
	if err := guard.refuse("wan", "disable"); err == nil || !strings.Contains(err.Error(), "refusing to disable wan: it is the WAN interface") {
		t.Errorf("refuse: %v", err)
	}
	if err := guard.refuse("opt1", "disable"); err != nil {
		t.Errorf("unprotected refuse: %v", err)
	}
}

func TestInterfaceAssignmentHelp(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var r = f.run("/interface/assignment", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "print", "show", "add", "set", "remove", "enable", "disable", "apply")
	wantContains(t, "stdout", f.run("/interface/assignment", "set", "?").stdout, "Asks for confirmation before changing the device of",
		"With confirm=yes it runs without asking", "confirm[=yes|no]")
	wantContains(t, "stdout", f.run("/interface/assignment", "apply", "?").stdout, "Asks for confirmation when changes are staged")
	wantNoCalls(t, f)
}
