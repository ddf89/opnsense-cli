//go:build integration

package integrationinterfaces

import (
	"errors"
	"strings"
	"testing"

	"opnsense-cli/opnsense/api/interfaces"
)

// TestCliTap drives /interface/tap (OPNsense 26.7.9 and later) through the opn binary: add (prints the uuid and
// the device), print, show, set, apply when only this run has TAP devices, the refused removal of an assigned TAP
// (only staged, the unassignment is applied when nothing else is staged) and the removal
func TestCliTap(t *testing.T) {
	var ifs = ifApi(t)
	if _, err := ifs.List(interfaces.Taps); errors.Is(err, interfaces.ErrUnsupported) {
		var refused = mustFailOpn(t, "/interface/tap", "print")
		requireContains(t, refused, refused.stderr, "TAP devices need OPNsense 26.7.9 or later")
		t.Skip(err.Error())
	} else if err != nil {
		t.Fatalf("list TAPs: %v", err)
	}

	var description = testDescription("tap")
	var added = mustOpn(t, "/interface/tap", "add", "description="+description)
	var uuid = uuidFrom(t, added)
	removeCleanup(t, ifs, interfaces.Taps, uuid)
	var item, err = ifs.Get(interfaces.Taps, uuid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	var device = interfaces.Taps.Device(item)
	if !strings.HasPrefix(device, "tap0") || item.Get("description") != description {
		t.Fatalf("unexpected TAP %+v", item)
	}
	requireContains(t, added, added.stderr, "device "+device)

	var printed = mustOpn(t, "/interface/tap", "print")
	requireContains(t, printed, printed.stdout, "DEVICE", "DESCRIPTION", device, description)
	mustOpn(t, "/interface/tap", "set", device, "description="+description+" 2")
	var shown = mustOpn(t, "/interface/tap", "show", uuid)
	requireContains(t, shown, shown.stdout, "device:", device, "assigned:", "description:", description+" 2")
	mustFailOpn(t, "/interface/tap", "add")

	var applied = onlyOwnItems(t, ifs, interfaces.Taps)
	if applied {
		mustOpn(t, "/interface/tap", "apply")
		if _, found := overviewDevice(t, ifs, device); !found {
			t.Errorf("after apply the overview must show %s", device)
		}
	}

	if !assignmentStartClean {
		t.Logf("not testing the removal of an assigned TAP: %s", assignmentStartReason)
	} else {
		// assigned (staged only): OPNsense would delete it, opn refuses
		var unlocked = false
		var name = assignmentPrefix() + "_tap"
		var identifier, assignErr = ifs.AssignmentCreate(interfaces.AssignmentChange{Device: &device, Description: &name, Locked: &unlocked})
		if assignErr != nil {
			t.Fatalf("assign %s: %v", device, assignErr)
		}
		t.Cleanup(func() { assignmentCleanup(t, ifs, identifier) })
		var refused = mustFailOpn(t, "/interface/tap", "remove", uuid)
		requireContains(t, refused, refused.stderr, "cannot remove TAP "+device, "assigned as interface "+identifier)
		var assigned *interfaces.AssignedError
		if err := ifs.Remove(interfaces.Taps, uuid); !errors.As(err, &assigned) || assigned.Identifier != identifier {
			t.Errorf("library Remove of an assigned TAP: %v", err)
		}
		if _, err := ifs.Get(interfaces.Taps, uuid); err != nil {
			t.Fatalf("the assigned TAP must still exist: %v", err)
		}
		assignmentCleanup(t, ifs, identifier)
	}

	mustOpn(t, "/interface/tap", "remove", description+" 2")
	if _, err := ifs.Get(interfaces.Taps, uuid); err == nil {
		t.Errorf("TAP %s still listed after remove", uuid)
	}
	if applied && onlyOwnItems(t, ifs, interfaces.Taps) {
		mustOpn(t, "/interface/tap", "apply")
		if _, found := overviewDevice(t, ifs, device); found {
			t.Errorf("after remove and apply %s must be gone", device)
		}
	}
}
