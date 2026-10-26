package interfaces

import (
	"reflect"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

// testAssignmentRows are assignment/search_item rows of OPNsense 26.7 (shortened): wan, and opt1 with a staged
// relink and disabled
const testAssignmentRows = `{"uuid":"wan","descr":"","%descr":"WAN","identifier":"wan","pending_action":"","optgroup":"Hardware",` +
	`"if":"vtnet1","%if":"vtnet1 (52:54:00:12:34:57)","lock":"0","enable":"1","type4":"dhcp","%type4":"DHCP","type6":"dhcp6",` +
	`"%type6":"DHCPv6","ipaddr":"","ipaddrv6":""},` +
	`{"uuid":"opt1","descr":"guests","identifier":"opt1","pending_action":"relink","optgroup":"Loopback","if":"lo1",` +
	`"%if":"lo1 (router id)","lock":"1","enable":"0","type4":"","type6":"","ipaddr":"","ipaddrv6":""}`

func TestAssignments(t *testing.T) {
	var api, requests = newTestApi(t, func(r testRequest) (int, string) {
		return 200, `{"rows":[` + testAssignmentRows + `]}`
	})
	var assignments, err = api.Assignments()
	if err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Method != "GET" || got.Path != "/api/interfaces/assignment/search_item" {
		t.Errorf("unexpected request %+v", got)
	}
	if len(assignments) != 2 {
		t.Fatalf("got %+v", assignments)
	}
	var wan = assignments[0]
	if wan.Identifier != "wan" || wan.Description != "WAN" || wan.Device != "vtnet1" || wan.DeviceText != "vtnet1 (52:54:00:12:34:57)" ||
		wan.Locked || !wan.Enabled || wan.PendingAction != "" || wan.Group != "Hardware" || wan.IPv4Type != "DHCP" || wan.IPv6Type != "DHCPv6" {
		t.Errorf("unexpected wan %+v", wan)
	}
	if opt := assignments[1]; opt.Description != "guests" || !opt.Locked || opt.Enabled || opt.Device != "lo1" ||
		opt.PendingAction != AssignmentPendingRelink {
		t.Errorf("unexpected opt1 %+v", opt)
	}

	if _, err := api.AssignmentGet("opt1"); err != nil {
		t.Errorf("AssignmentGet: %v", err)
	}
	if _, err := api.AssignmentGet("opt9"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	var before = len(*requests)
	if _, err := api.AssignmentGet("../x"); err == nil || len(*requests) != before {
		t.Errorf("an invalid identifier must fail before any call: %v", err)
	}
}

func TestAssignmentDevices(t *testing.T) {
	var api, _ = newTestApi(t, func(r testRequest) (int, string) {
		return 200, `{"interface":{"descr":"","if":{"vtnet0":{"value":"vtnet0 (52:54:00:12:34:56)","optgroup":"Hardware",` +
			`"data":{"icon":"fa fa-plug"},"selected":1},"lo1":{"value":"lo1 (router id)","optgroup":"Loopback","selected":0}},"lock":"1"}}`
	})
	var devices, err = api.AssignmentDevices()
	if err != nil {
		t.Fatal(err)
	}
	var want = []Option{{Key: "vtnet0", Value: "vtnet0 (52:54:00:12:34:56)", Selected: true}, {Key: "lo1", Value: "lo1 (router id)"}}
	if !reflect.DeepEqual(devices, want) {
		t.Errorf("got %+v", devices)
	}
}

func TestAssignmentCreate(t *testing.T) {
	var api, requests = newTestApi(t, func(r testRequest) (int, string) {
		if r.Method == "POST" {
			// add_item answers the uuid the model had before it was renamed to the identifier
			return 200, `{"result":"saved","uuid":"2f3c0a4e-1b2c-4d5e-8f90-123456789abc"}`
		}
		return 200, `{"rows":[` + testAssignmentRows + `]}`
	})
	var device, description, locked = "lo1", "guests", false
	var identifier, err = api.AssignmentCreate(AssignmentChange{Device: &device, Description: &description, Locked: &locked})
	if err != nil || identifier != "opt1" {
		t.Fatalf("got %q / %v", identifier, err)
	}
	var post = (*requests)[0]
	var want = map[string]any{"interface": map[string]any{"if": "lo1", "descr": "guests", "lock": "0"}}
	if post.Method != "POST" || post.Path != "/api/interfaces/assignment/add_item" || !reflect.DeepEqual(post.Body, want) {
		t.Errorf("unexpected request %+v", post)
	}
	if _, err := api.AssignmentCreate(AssignmentChange{Description: &description}); err == nil || len(*requests) != 2 {
		t.Errorf("a missing device must fail before any call: %v", err)
	}
}

func TestAssignmentUpdate(t *testing.T) {
	var rows = testAssignmentRows
	var api, requests = newTestApi(t, func(r testRequest) (int, string) {
		if r.Method == "POST" {
			rows = strings.Replace(rows, `"descr":"guests"`, `"descr":"visitors"`, 1)
			return 200, `{"result":"saved"}`
		}
		return 200, `{"rows":[` + rows + `]}`
	})
	var description = "visitors"
	if err := api.AssignmentUpdate("opt1", AssignmentChange{Description: &description}); err != nil {
		t.Fatal(err)
	}
	var post = (*requests)[1]
	if post.Method != "POST" || post.Path != "/api/interfaces/assignment/set_item/opt1" ||
		!reflect.DeepEqual(post.Body, map[string]any{"interface": map[string]any{"descr": "visitors"}}) {
		t.Errorf("unexpected request %+v", post)
	}

	// OPNsense ignored it: a change back to the applied value while the relink is staged
	var enabled = true
	if err := api.AssignmentUpdate("opt1", AssignmentChange{Enabled: &enabled}); err == nil || !strings.Contains(err.Error(), "kept the staged enabled state of opt1") {
		t.Errorf("want the ignored change reported, got %v", err)
	}
	// unknown: no set_item (it could create the record)
	var before = len(*requests)
	if err := api.AssignmentUpdate("opt9", AssignmentChange{Description: &description}); !coreapi.IsNotFound(err) || len(*requests) != before+1 {
		t.Errorf("want not found after one search, got %v", err)
	}
	if err := api.AssignmentUpdate("opt1", AssignmentChange{}); err == nil {
		t.Error("an empty change must fail")
	}
}

func TestAssignmentRemove(t *testing.T) {
	var status, answer = 200, `{"result":"deleted"}`
	var api, requests = newTestApi(t, func(r testRequest) (int, string) {
		return status, answer
	})
	if err := api.AssignmentRemove("opt1"); err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Method != "POST" || got.Path != "/api/interfaces/assignment/del_item/opt1" {
		t.Errorf("unexpected request %+v", got)
	}
	status, answer = 500, `{"errorMessage":"Interface locked, unset lock first before removal","errorTitle":"locked"}`
	if err := api.AssignmentRemove("opt1"); err == nil || err.Error() != "cannot remove interface opt1: Interface locked, unset lock first before removal" {
		t.Errorf("unexpected error %v", err)
	}
	status, answer = 200, `{"result":"not found"}`
	if err := api.AssignmentRemove("opt9"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	// del_item takes a comma separated list, one identifier only here
	var before = len(*requests)
	for _, identifier := range []string{"", "opt1,opt2", "opt1/x"} {
		if err := api.AssignmentRemove(identifier); err == nil {
			t.Errorf("%q must be refused", identifier)
		}
	}
	if len(*requests) != before {
		t.Error("invalid identifiers must fail before any call")
	}
}

func TestAssignmentPendingAndApply(t *testing.T) {
	var answer = `{"status":"pending"}`
	var api, requests = newTestApi(t, func(r testRequest) (int, string) {
		return 200, answer
	})
	if pending, err := api.AssignmentPending(); err != nil || !pending {
		t.Errorf("got %v / %v", pending, err)
	}
	answer = `{"status":"ok"}`
	if pending, err := api.AssignmentPending(); err != nil || pending {
		t.Errorf("got %v / %v", pending, err)
	}
	answer = `{"status":"weird"}`
	if _, err := api.AssignmentPending(); err == nil {
		t.Error("want an error for an unknown status")
	}
	if got := (*requests)[0]; got.Method != "GET" || got.Path != "/api/interfaces/assignment/pending" {
		t.Errorf("unexpected request %+v", got)
	}

	answer = `{"status":"ok"}`
	if err := api.AssignmentApply(); err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[len(*requests)-1]; got.Method != "POST" || got.Path != "/api/interfaces/assignment/reconfigure" {
		t.Errorf("unexpected request %+v", got)
	}
	answer = `{"status":"failed"}`
	if err := api.AssignmentApply(); err == nil || !strings.Contains(err.Error(), `status "failed"`) {
		t.Errorf("want an error, got %v", err)
	}
}
