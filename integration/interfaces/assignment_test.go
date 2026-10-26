//go:build integration

package integrationinterfaces

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/interfaces"
)

// Assignment tests: a loopback of this run is assigned, renamed, disabled/enabled, applied, unassigned and applied
// again. The assignment apply (reconfigure) applies EVERY staged assignment change and reloads DHCP, DNS and the
// firewall rules, so it only runs when nothing was staged when the run started and nothing but this run's
// assignment is staged now. lan and wan are never changed live (their protection is unit tested with fakes).

var (
	// assignmentStartClean is true when no assignment change was staged when the run started
	assignmentStartClean bool
	// assignmentStartHidden are the identifiers in config.xml (overview) that assignment search does not list
	// when the run started (virtual interfaces like lo0), a new one is a staged removal
	assignmentStartHidden map[string]bool
	// assignmentStartReason tells why the run can not apply assignments
	assignmentStartReason string
)

var assignmentIdentifierPattern = regexp.MustCompile(`^opt[0-9]+$`)

// assignmentPrefix is the description prefix of this run's assignments (descriptions allow only [A-Za-z0-9_])
func assignmentPrefix() string {
	return strings.ReplaceAll(runPrefix, "-", "_")
}

// assignmentHidden returns the identifiers configured (overview) but not listed by assignment search
func assignmentHidden(ifs *interfaces.InterfacesApi) (map[string]bool, []interfaces.Assignment, error) {
	var overview, err = ifs.Overview("")
	if err != nil {
		return nil, nil, err
	}
	var list, listErr = ifs.Assignments()
	if listErr != nil {
		return nil, nil, listErr
	}
	var listed = map[string]bool{}
	for _, assignment := range list {
		listed[assignment.Identifier] = true
	}
	var hidden = map[string]bool{}
	for _, entry := range overview {
		if entry.Identifier != "" && !listed[entry.Identifier] {
			hidden[entry.Identifier] = true
		}
	}
	return hidden, list, nil
}

// assignmentBaseline records whether assignment changes were staged before this run (then nothing is applied)
func assignmentBaseline() {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		assignmentStartReason = err.Error()
		return
	}
	var ifs = &interfaces.InterfacesApi{OPNsense: core}
	var pending, pendingErr = ifs.AssignmentPending()
	if pendingErr != nil {
		assignmentStartReason = "assignment pending: " + pendingErr.Error()
		return
	}
	if pending {
		assignmentStartReason = "assignment changes were staged before this run, they are not applied by tests"
		return
	}
	var hidden, _, hiddenErr = assignmentHidden(ifs)
	if hiddenErr != nil {
		assignmentStartReason = hiddenErr.Error()
		return
	}
	assignmentStartHidden = hidden
	assignmentStartClean = true
}

// assignmentOnlyOwnStaged tells whether the staged assignment changes are only those of the given identifiers of
// this run: no other listed interface has a pending action (lan and wan included) and no other interface is staged
// for removal. The reason is "" when they are
func assignmentOnlyOwnStaged(ifs *interfaces.InterfacesApi, own map[string]bool) string {
	if !assignmentStartClean {
		return assignmentStartReason
	}
	var hidden, list, err = assignmentHidden(ifs)
	if err != nil {
		return err.Error()
	}
	var seen = map[string]bool{}
	for _, assignment := range list {
		seen[assignment.Identifier] = true
		if assignment.PendingAction != "" && !own[assignment.Identifier] {
			return fmt.Sprintf("%s has the staged change %q", assignment.Identifier, assignment.PendingAction)
		}
		if own[assignment.Identifier] && !strings.HasPrefix(assignment.Description, assignmentPrefix()) {
			return fmt.Sprintf("%s does not carry the run prefix: %+v", assignment.Identifier, assignment)
		}
	}
	if !seen["lan"] || !seen["wan"] {
		return "lan or wan is not listed (staged for removal?)"
	}
	for identifier := range hidden {
		if !assignmentStartHidden[identifier] && !own[identifier] {
			return fmt.Sprintf("%s is staged for removal by someone else", identifier)
		}
	}
	return ""
}

// sweepAssignments unassigns this run's leftover assignments and applies that when only they are staged
func sweepAssignments(ifs *interfaces.InterfacesApi) []string {
	var list, err = ifs.Assignments()
	if err != nil {
		return nil
	}
	var removed []string
	var own = map[string]bool{}
	for _, assignment := range list {
		if !strings.HasPrefix(assignment.Description, assignmentPrefix()) || !assignmentIdentifierPattern.MatchString(assignment.Identifier) {
			continue
		}
		own[assignment.Identifier] = true
		if assignment.Locked {
			var unlocked = false
			if err := ifs.AssignmentUpdate(assignment.Identifier, interfaces.AssignmentChange{Locked: &unlocked}); err != nil {
				fmt.Fprintf(os.Stderr, "integration/interfaces: sweep could not unlock %s: %v\n", assignment.Identifier, err)
				continue
			}
		}
		if err := ifs.AssignmentRemove(assignment.Identifier); err != nil {
			fmt.Fprintf(os.Stderr, "integration/interfaces: sweep could not unassign %s: %v\n", assignment.Identifier, err)
			continue
		}
		removed = append(removed, "assignment "+assignment.Identifier)
	}
	if len(removed) == 0 {
		return nil
	}
	if reason := assignmentOnlyOwnStaged(ifs, own); reason != "" {
		fmt.Fprintf(os.Stderr, "integration/interfaces: sweep does not apply the unassignment of %v: %s\n", removed, reason)
		return removed
	}
	if err := ifs.AssignmentApply(); err != nil {
		fmt.Fprintf(os.Stderr, "integration/interfaces: sweep could not apply the unassignment: %v\n", err)
	}
	return removed
}

// requireOnlyOwnStaged stops the test (fatal) when anything but identifier is staged
func requireOnlyOwnStaged(t *testing.T, ifs *interfaces.InterfacesApi, identifier string) {
	t.Helper()
	if reason := assignmentOnlyOwnStaged(ifs, map[string]bool{identifier: true}); reason != "" {
		t.Fatalf("not applying the assignment changes: %s", reason)
	}
}

func overviewIdentifiers(t *testing.T, ifs *interfaces.InterfacesApi) []string {
	t.Helper()
	var list, err = ifs.Overview("")
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	var pairs = make([]string, 0, len(list))
	for _, entry := range list {
		pairs = append(pairs, entry.Device+"="+entry.Identifier)
	}
	sort.Strings(pairs)
	return pairs
}

// assignmentLoopback creates and applies a loopback of this run and returns its device; it is removed (and the
// loopbacks applied) when the test ends. Skips the test when other loopbacks exist (their apply would touch them)
func assignmentLoopback(t *testing.T, ifs *interfaces.InterfacesApi, label string) string {
	t.Helper()
	var uuid, err = ifs.Create(interfaces.Loopbacks, map[string]string{"description": testDescription(label)})
	if err != nil {
		t.Fatalf("create loopback: %v", err)
	}
	// cleanups run last first: remove the loopback, then apply the loopbacks
	t.Cleanup(func() {
		if onlyOwnItems(t, ifs, interfaces.Loopbacks) {
			if err := ifs.Reconfigure(interfaces.Loopbacks); err != nil {
				t.Errorf("loopback apply in cleanup: %v", err)
			}
		}
	})
	removeCleanup(t, ifs, interfaces.Loopbacks, uuid)
	var item, _ = ifs.Get(interfaces.Loopbacks, uuid)
	var device = interfaces.Loopbacks.Device(item)
	if !strings.HasPrefix(device, "lo") || device == "lo0" {
		t.Fatalf("unexpected loopback device %q", device)
	}
	if !onlyOwnItems(t, ifs, interfaces.Loopbacks) {
		t.Skip("other loopbacks exist, the loopback apply would touch them")
	}
	if err := ifs.Reconfigure(interfaces.Loopbacks); err != nil {
		t.Fatalf("loopback apply: %v", err)
	}
	return device
}

// TestAssignmentLifecycle assigns a loopback of this run through the opn binary, relinks it to a second one,
// disables it and removes it again, applying each step
func TestAssignmentLifecycle(t *testing.T) {
	var ifs = ifApi(t)
	if !assignmentStartClean {
		t.Skip(assignmentStartReason)
	}
	var startAssignments = mustOpn(t, "/interface/assignment", "print")
	var startOverview = overviewIdentifiers(t, ifs)
	var startOverviewPrint = mustOpn(t, "/interface/overview", "print")
	// registered first, runs after all other cleanups: everything must be back to the start
	t.Cleanup(func() {
		if end := mustOpn(t, "/interface/assignment", "print"); end.stdout != startAssignments.stdout {
			t.Errorf("assignments differ from the start:\nstart:\n%s\nend:\n%s", startAssignments.stdout, end.stdout)
		}
		if end := overviewIdentifiers(t, ifs); strings.Join(end, " ") != strings.Join(startOverview, " ") {
			t.Errorf("overview devices differ from the start: %v / %v", startOverview, end)
		}
		if end := mustOpn(t, "/interface/overview", "print"); end.stdout != startOverviewPrint.stdout {
			t.Errorf("overview print differs from the start:\nstart:\n%s\nend:\n%s", startOverviewPrint.stdout, end.stdout)
		}
	})

	// the devices: two loopbacks of this run (cleanups: registered first, run last)
	var device = assignmentLoopback(t, ifs, "assignment")
	var device2 = assignmentLoopback(t, ifs, "relink")
	var devices, devicesErr = ifs.AssignmentDevices()
	if devicesErr != nil {
		t.Fatalf("AssignmentDevices: %v", devicesErr)
	}
	var offered []string
	for _, option := range devices {
		offered = append(offered, option.Key)
	}
	if !strings.Contains(" "+strings.Join(offered, " ")+" ", " "+device2+" ") {
		t.Errorf("the devices offered for assignments lack %s: %v", device2, offered)
	}

	// add
	var description = assignmentPrefix() + "_a"
	var added = mustOpn(t, "/interface/assignment", "add", "device="+device, "description="+description)
	var identifier = strings.TrimSpace(added.stdout)
	if !assignmentIdentifierPattern.MatchString(identifier) || strings.Contains(startAssignments.stdout, " "+identifier+" ") {
		t.Fatalf("add must print the new optN identifier:\n%s", added)
	}
	t.Cleanup(func() { assignmentCleanup(t, ifs, identifier) })
	var assignment, getErr = ifs.AssignmentGet(identifier)
	if getErr != nil {
		t.Fatalf("AssignmentGet: %v", getErr)
	}
	if assignment.Device != device || assignment.Description != description || !assignment.Locked || !assignment.Enabled ||
		assignment.PendingAction != interfaces.AssignmentPendingUpdate {
		t.Errorf("new assignment %+v", assignment)
	}
	if pending, err := ifs.AssignmentPending(); err != nil || !pending {
		t.Errorf("after add the change must be staged: %v / %v", pending, err)
	}
	requireOnlyOwnStaged(t, ifs, identifier)

	// refused before anything is sent
	var duplicate = mustFailOpn(t, "/interface/assignment", "add", "device="+device)
	requireContains(t, duplicate, duplicate.stderr, "assigned already to "+identifier)
	mustFailOpn(t, "/interface/assignment", "set", identifier, "description=no-dashes")
	mustFailOpn(t, "/interface/assignment", "set", identifier, "description=WAN")

	// OPNsense's own description check (confirms the pattern the CLI validates with)
	var dashed = assignmentPrefix() + "-dash"
	if err := ifs.AssignmentUpdate(identifier, interfaces.AssignmentChange{Description: &dashed}); err == nil {
		t.Errorf("OPNsense accepted the description %q, the CLI pattern is too strict", dashed)
	} else if validation := (*api.ValidationError)(nil); !errors.As(err, &validation) {
		t.Errorf("want a validation error for %q, got %v", dashed, err)
	}

	// set, show, select by description
	var renamed = assignmentPrefix() + "_b"
	mustOpn(t, "/interface/assignment", "set", identifier, "description="+renamed)
	var shown = mustOpn(t, "/interface/assignment", "show", renamed)
	requireContains(t, shown, shown.stdout, "identifier:", identifier, "device:", device, "locked:", "yes", "pending:", "update", "protected:")
	var printed = mustOpn(t, "/interface/assignment", "print")
	requireContains(t, printed, printed.stdout, identifier, renamed, device, "PENDING", "update")
	requireContains(t, printed, printed.stderr, "apply")

	// remove: the lock is checked before the confirmation is asked (by the CLI, and by OPNsense)
	var lockedUnconfirmed = mustFailOpn(t, "/interface/assignment", "remove", identifier)
	requireContains(t, lockedUnconfirmed, lockedUnconfirmed.stderr, "locked")
	var locked = mustFailOpn(t, "/interface/assignment", "remove", identifier, "confirm=yes")
	requireContains(t, locked, locked.stderr, "locked")
	if err := ifs.AssignmentRemove(identifier); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("OPNsense must refuse to remove a locked assignment: %v", err)
	}

	// a new interface is not in config.xml yet (no enable there): disabling it before the apply is a change back
	// to the "applied" value, OPNsense ignores it
	var ignored = mustFailOpn(t, "/interface/assignment", "disable", identifier)
	requireContains(t, ignored, ignored.stderr, "kept the staged")

	// apply the assignment
	requireOnlyOwnStaged(t, ifs, identifier)
	var applied = mustOpn(t, "/interface/assignment", "apply", "confirm=yes")
	requireContains(t, applied, applied.stderr, "applying: "+identifier+" update")
	if pending, err := ifs.AssignmentPending(); err != nil || pending {
		t.Errorf("after apply nothing may be staged: %v / %v", pending, err)
	}
	if current, _ := ifs.AssignmentGet(identifier); current.PendingAction != "" || !current.Enabled || current.Description != renamed {
		t.Errorf("after apply: %+v", current)
	}
	if entry, found := overviewDevice(t, ifs, device); !found || entry.Identifier != identifier {
		t.Errorf("after apply the overview must show %s as %s: %+v", device, identifier, entry)
	}
	var nothing = mustOpn(t, "/interface/assignment", "apply", "confirm=yes")
	requireContains(t, nothing, nothing.stderr, "nothing to apply")

	// relink to the second loopback and disable; enable and disable again before the apply work here, the
	// staged relink keeps the record different from config.xml
	mustOpn(t, "/interface/assignment", "set", identifier, "device="+device2, "disabled")
	if current, _ := ifs.AssignmentGet(identifier); current.Device != device2 || current.Enabled || current.PendingAction != interfaces.AssignmentPendingRelink {
		t.Errorf("after set device and disabled: %+v", current)
	}
	mustOpn(t, "/interface/assignment", "enable", identifier)
	if current, _ := ifs.AssignmentGet(identifier); !current.Enabled {
		t.Errorf("after enable: %+v", current)
	}
	mustOpn(t, "/interface/assignment", "disable", identifier)
	requireOnlyOwnStaged(t, ifs, identifier)
	mustOpn(t, "/interface/assignment", "apply", "confirm=yes")
	if current, _ := ifs.AssignmentGet(identifier); current.PendingAction != "" || current.Enabled || current.Device != device2 {
		t.Errorf("after the relink apply: %+v", current)
	}
	if entry, found := overviewDevice(t, ifs, device2); !found || entry.Identifier != identifier {
		t.Errorf("after the relink apply the overview must show %s as %s: %+v", device2, identifier, entry)
	}
	if entry, found := overviewDevice(t, ifs, device); !found || entry.Identifier != "" {
		t.Errorf("after the relink apply %s must be unassigned: %+v", device, entry)
	}

	// unassign
	mustOpn(t, "/interface/assignment", "set", identifier, "locked=no")
	var unconfirmed = mustFailOpn(t, "/interface/assignment", "remove", identifier)
	requireContains(t, unconfirmed, unconfirmed.stderr, "This unassigns the interface", "confirm=yes")
	mustOpn(t, "/interface/assignment", "remove", identifier, "confirm=yes")
	if _, err := ifs.AssignmentGet(identifier); !api.IsNotFound(err) {
		t.Errorf("a staged removal is not listed: %v", err)
	}
	if entry, _ := overviewDevice(t, ifs, device2); entry.Identifier != identifier {
		t.Errorf("before apply the removal is only staged: %+v", entry)
	}
	requireOnlyOwnStaged(t, ifs, identifier)
	mustOpn(t, "/interface/assignment", "apply", "confirm=yes")
	if pending, err := ifs.AssignmentPending(); err != nil || pending {
		t.Errorf("after the removal apply nothing may be staged: %v / %v", pending, err)
	}
	if entry, found := overviewDevice(t, ifs, device2); !found || entry.Identifier != "" {
		t.Errorf("after the removal apply %s must be unassigned: %+v", device2, entry)
	}
}

// assignmentCleanup unassigns identifier when the test left it and applies that when only it is staged
func assignmentCleanup(t *testing.T, ifs *interfaces.InterfacesApi, identifier string) {
	t.Helper()
	var current, err = ifs.AssignmentGet(identifier)
	switch {
	case api.IsNotFound(err):
	case err != nil:
		t.Errorf("cleanup of %s: %v", identifier, err)
		return
	case !strings.HasPrefix(current.Description, assignmentPrefix()):
		t.Errorf("cleanup: %s is not this run's assignment any more: %+v", identifier, current)
		return
	default:
		if current.Locked {
			var unlocked = false
			if err := ifs.AssignmentUpdate(identifier, interfaces.AssignmentChange{Locked: &unlocked}); err != nil {
				t.Errorf("cleanup unlock of %s: %v", identifier, err)
				return
			}
		}
		if err := ifs.AssignmentRemove(identifier); err != nil {
			t.Errorf("cleanup removal of %s: %v", identifier, err)
			return
		}
	}
	if pending, _ := ifs.AssignmentPending(); !pending {
		return
	}
	if reason := assignmentOnlyOwnStaged(ifs, map[string]bool{identifier: true}); reason != "" {
		t.Errorf("cleanup does not apply the removal of %s: %s", identifier, reason)
		return
	}
	if err := ifs.AssignmentApply(); err != nil {
		t.Errorf("cleanup apply: %v", err)
	}
}
