//go:build integration

package integrationinterfaces

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/interfaces"
	"opnsense-cli/opnsense/api/system"
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
	var hidden, list, hiddenErr = assignmentHidden(ifs)
	if hiddenErr != nil {
		assignmentStartReason = hiddenErr.Error()
		return
	}
	var unset, unsetErr = assignmentPdLenUnset(core, list)
	if unsetErr != nil {
		assignmentStartReason = unsetErr.Error()
		return
	}
	if len(unset) > 0 {
		assignmentStartReason = fmt.Sprintf("OPNsense 26.7.8 would stage a spurious update of %s with any assignment change "+
			"(dhcp6-ia-pd-len is missing from their config, one apply of them stores it), the tests can not apply",
			strings.Join(unset, ", "))
		return
	}
	assignmentStartHidden = hidden
	assignmentStartClean = true
}

// assignmentPdLenUnset returns the assigned interfaces that get a spurious staged "update" from ANY assignment
// change on OPNsense 26.7.8: its model requires dhcp6-ia-pd-len with the default 0 (upstream 5b9fc04efb,
// 5dd91f6085) and compares the model with config.xml when saving, where interfaces configured before lack the
// field. An apply of such an interface stores it. Nothing is returned when the model has no default for it, or on
// OPNsense 26.7.9 and later, which compare a missing field as 0 and drop it for interfaces without DHCPv6
func assignmentPdLenUnset(core *api.OPNsense, list []interfaces.Assignment) ([]string, error) {
	var fixed, versionErr = assignmentPdLenFixed(core)
	if versionErr != nil {
		return nil, versionErr
	}
	if fixed {
		return nil, nil
	}
	var record struct {
		Interface map[string]json.RawMessage `json:"interface"`
	}
	var endpoint = core.EndpointForPluginControllerMethod("interfaces", "assignment", "get_item") + "/lan"
	if err := core.DoJSON("GET", endpoint, nil, &record); err != nil {
		return nil, fmt.Errorf("assignment get_item lan: %w", err)
	}
	var options map[string]struct {
		Selected int `json:"selected"`
	}
	if raw, found := record.Interface["dhcp6-ia-pd-len"]; !found || json.Unmarshal(raw, &options) != nil || options["0"].Selected != 1 {
		return nil, nil
	}

	var content, _, err = (&system.SystemApi{OPNsense: core}).BackupDownload("", "")
	if err != nil {
		return nil, fmt.Errorf("reading config.xml: %w", err)
	}
	var config struct {
		Interfaces struct {
			Items []struct {
				XMLName xml.Name
				PdLen   *string `xml:"dhcp6-ia-pd-len"`
			} `xml:",any"`
		} `xml:"interfaces"`
	}
	if err := xml.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("parsing config.xml: %w", err)
	}
	var stored = map[string]bool{}
	for _, item := range config.Interfaces.Items {
		stored[item.XMLName.Local] = item.PdLen != nil
	}
	var unset []string
	for _, assignment := range list {
		if have, configured := stored[assignment.Identifier]; configured && !have {
			unset = append(unset, assignment.Identifier)
		}
	}
	return unset, nil
}

// assignmentPdLenFixedRelease is the first OPNsense release without the spurious dhcp6-ia-pd-len update
var assignmentPdLenFixedRelease = []int{26, 7, 9}

var assignmentVersionPattern = regexp.MustCompile(`^OPNsense ([0-9]+)\.([0-9]+)(?:\.([0-9]+))?`)

// assignmentPdLenFixed tells whether the OPNsense release (as system_information reports it, e.g. "OPNsense
// 26.7.9_1-amd64") has the fix of the spurious dhcp6-ia-pd-len update
func assignmentPdLenFixed(core *api.OPNsense) (bool, error) {
	var check, err = core.Check(context.Background(), 30*time.Second)
	if err != nil {
		return false, fmt.Errorf("reading the OPNsense version: %w", err)
	}
	var release, releaseErr = assignmentRelease(check.Versions)
	if releaseErr != nil {
		return false, releaseErr
	}
	return slices.Compare(release, assignmentPdLenFixedRelease) >= 0, nil
}

// assignmentRelease returns the release numbers (26.7 as 26, 7, 0) of the OPNsense entry of system_information's
// versions
func assignmentRelease(versions []string) ([]int, error) {
	for _, version := range versions {
		var match = assignmentVersionPattern.FindStringSubmatch(version)
		if match == nil {
			continue
		}
		var release = make([]int, 3)
		for i, part := range match[1:] {
			if part != "" {
				release[i], _ = strconv.Atoi(part)
			}
		}
		return release, nil
	}
	return nil, fmt.Errorf("no OPNsense version in %q", versions)
}

// TestAssignmentRelease checks the version parsing of the dhcp6-ia-pd-len gate (no instance needed)
func TestAssignmentRelease(t *testing.T) {
	for version, fixed := range map[string]bool{"OPNsense 26.7-amd64": false, "OPNsense 26.7.8_2-amd64": false,
		"OPNsense 26.7.9-amd64": true, "OPNsense 26.7.9_1-amd64": true, "OPNsense 26.7.10-amd64": true, "OPNsense 27.1.r1-amd64": true} {
		var release, err = assignmentRelease([]string{version, "FreeBSD 15.1-RELEASE-p6"})
		if err != nil || (slices.Compare(release, assignmentPdLenFixedRelease) >= 0) != fixed {
			t.Errorf("%s: %v / %v", version, release, err)
		}
	}
	if _, err := assignmentRelease([]string{"FreeBSD 15.1"}); err == nil {
		t.Error("want an error without an OPNsense version")
	}
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
		// later tests must not stage more on top of this
		assignmentStartClean, assignmentStartReason = false, "an earlier test found foreign staged changes: "+reason
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

	// a new interface is not in config.xml yet (no enable there): before 26.7.8 disabling it before the apply is a
	// change back to the "applied" value that OPNsense ignores (the CLI reports it); 26.7.8 stages it, then it is
	// enabled again so the apply below assigns it enabled
	var disabled = runOpn(t, "/interface/assignment", "disable", identifier)
	if disabled.exitCode != 0 {
		requireContains(t, disabled, disabled.stderr, "kept the staged")
	} else {
		mustOpn(t, "/interface/assignment", "enable", identifier)
	}

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
