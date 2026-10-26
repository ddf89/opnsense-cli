//go:build integration

package integrationinterfaces

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/interfaces"
)

// Address tests: a loopback of this run is assigned, gets a static IPv4 (203.0.113.0/24, TEST-NET-3, used by no
// other test here) and IPv6 (2001:db8::/32) address, an MTU and the private block rule, which are applied, the IPv4
// address is changed (applied), everything is cleared (applied) and the interface is unassigned again (applied). Applies run only when nothing but this run's
// assignment is staged (requireOnlyOwnStaged). lan and wan are only read: the refusal to change them is checked,
// it fails before anything is sent. No gateway is configured live: OPNsense's own refusal of an unknown gateway
// is checked (a failed validation saves nothing). Leftover assignments are swept by TestMain (sweepAssignments).

// addressOverview returns the running addresses of a device ("" when it has none)
func addressOverview(t *testing.T, ifs *interfaces.InterfacesApi, device string) (string, string) {
	t.Helper()
	var entry, found = overviewDevice(t, ifs, device)
	if !found {
		t.Fatalf("%s is not in the overview", device)
	}
	var v4, v6 []string
	for _, address := range entry.IPv4 {
		v4 = append(v4, address.Address)
	}
	for _, address := range entry.IPv6 {
		if !strings.HasPrefix(strings.ToLower(address.Address), "fe80:") {
			v6 = append(v6, address.Address)
		}
	}
	return strings.Join(v4, ","), strings.Join(v6, ",")
}

func TestAddressLifecycle(t *testing.T) {
	var ifs = ifApi(t)
	if !assignmentStartClean {
		t.Skip(assignmentStartReason)
	}
	var startPrint = mustOpn(t, "/interface/address", "print")
	var startOverview = overviewIdentifiers(t, ifs)
	// registered first, runs after all other cleanups: everything must be back to the start
	t.Cleanup(func() {
		if end := mustOpn(t, "/interface/address", "print"); end.stdout != startPrint.stdout {
			t.Errorf("addresses differ from the start:\nstart:\n%s\nend:\n%s", startPrint.stdout, end.stdout)
		}
		if end := overviewIdentifiers(t, ifs); strings.Join(end, " ") != strings.Join(startOverview, " ") {
			t.Errorf("overview devices differ from the start: %v / %v", startOverview, end)
		}
	})
	requireContains(t, startPrint, startPrint.stdout, "IPV4-TYPE", "GATEWAY", "PENDING", " wan ", " lan ")

	// lan and wan: shown as protected, every change refused before anything is sent
	var shown = mustOpn(t, "/interface/address", "show", "wan")
	requireContains(t, shown, shown.stdout, "ipv4-type:", "protected:", "yes, it is the WAN interface")
	for _, args := range [][]string{{"wan", "mtu=1400"}, {"lan", "block-bogons=no"}, {"lan", "ipv4-type=static", "ipv4=192.168.1.1/24"}} {
		var refused = mustFailOpn(t, append([]string{"/interface/address", "set"}, args...)...)
		requireContains(t, refused, refused.stderr, "refusing to change the address of "+args[0])
	}
	if pending, err := ifs.AssignmentPending(); err != nil || pending {
		t.Fatalf("the refused changes staged something: %v / %v", pending, err)
	}

	// an assigned loopback of this run (cleanups run last first: unassign, then remove the loopback)
	var device = assignmentLoopback(t, ifs, "address")
	var description = assignmentPrefix() + "_addr"
	var unlocked = false
	var identifier, createErr = ifs.AssignmentCreate(interfaces.AssignmentChange{Device: &device, Description: &description, Locked: &unlocked})
	if createErr != nil {
		t.Fatalf("AssignmentCreate: %v", createErr)
	}
	if !assignmentIdentifierPattern.MatchString(identifier) {
		t.Fatalf("unexpected identifier %q", identifier)
	}
	t.Cleanup(func() { assignmentCleanup(t, ifs, identifier) })
	requireOnlyOwnStaged(t, ifs, identifier)

	var octet = 1 + runVni%250
	var ipv4 = fmt.Sprintf("203.0.113.%d/24", octet)
	var ipv6 = fmt.Sprintf("2001:db8:%x::1/64", runVni%0xffff)

	// refused by the CLI before anything is sent
	var mismatch = mustFailOpn(t, "/interface/address", "set", identifier, "ipv4-type=dhcp", "ipv4="+ipv4)
	requireContains(t, mismatch, mismatch.stderr, "ipv4= needs ipv4-type=static")
	var noType = mustFailOpn(t, "/interface/address", "set", description, "ipv4="+ipv4)
	requireContains(t, noType, noType.stderr, "ipv4= needs ipv4-type=static (the type is none)")
	var noGateway = mustFailOpn(t, "/interface/address", "set", identifier, "ipv4-type=static", "ipv4="+ipv4, "gateway4="+assignmentPrefix()+"_gw")
	requireContains(t, noGateway, noGateway.stderr, "gateway4:")
	// OPNsense's own check of the gateway (the CLI checks the choices); a failed validation saves nothing
	var static4, fakeGateway = interfaces.AddressType4Static, assignmentPrefix() + "_gw"
	var gatewayErr = ifs.AddressUpdate(identifier, interfaces.AddressChange{Type4: &static4, IPv4: &ipv4, Gateway4: &fakeGateway})
	var validation *api.ValidationError
	if !errors.As(gatewayErr, &validation) || validation.Validations["interface.gateway"] == "" {
		t.Errorf("want OPNsense to refuse an unknown gateway, got %v", gatewayErr)
	}
	if current, _ := ifs.AddressGet(identifier); current.Type4 != "" || current.IPv4 != "" || current.Gateway4 != "" {
		t.Errorf("the refused change was saved: %+v", current)
	}

	// static addresses, MTU and the private block rule: staged
	mustOpn(t, "/interface/address", "set", identifier, "ipv4-type=static", "ipv4="+ipv4, "ipv6-type=static", "ipv6="+ipv6,
		"mtu=1400", "block-private")
	var address, getErr = ifs.AddressGet(identifier)
	if getErr != nil {
		t.Fatalf("AddressGet: %v", getErr)
	}
	if address.Type4 != interfaces.AddressType4Static || address.IPv4 != ipv4 || address.Type6 != interfaces.AddressType6Static ||
		address.IPv6 != ipv6 || address.MTU != "1400" || !address.BlockPrivate || address.PendingAction != interfaces.AssignmentPendingUpdate {
		t.Errorf("after set: %+v", address)
	}
	var printed = mustOpn(t, "/interface/address", "print")
	requireContains(t, printed, printed.stdout, identifier, description, "static", ipv4, ipv6, "1400", "update")
	requireContains(t, printed, printed.stderr, "/interface/assignment apply")
	var detail = mustOpn(t, "/interface/address", "show", description)
	requireContains(t, detail, detail.stdout, "ipv4:", ipv4, "mtu:", "1400", "block-private:", "yes", "protected:", "no")
	if pending, err := ifs.AssignmentPending(); err != nil || !pending {
		t.Errorf("an address change must be staged: %v / %v", pending, err)
	}

	// apply: the addresses are configured
	requireOnlyOwnStaged(t, ifs, identifier)
	mustOpn(t, "/interface/assignment", "apply", "confirm=yes")
	if current, _ := ifs.AddressGet(identifier); current.PendingAction != "" || current.IPv4 != ipv4 || current.MTU != "1400" {
		t.Errorf("after apply: %+v", current)
	}
	var running4, running6 = addressOverview(t, ifs, device)
	if running4 != ipv4 || !strings.Contains(running6, strings.TrimSuffix(ipv6, "/64")) {
		t.Errorf("after apply %s must run %s and %s, it has %q and %q", device, ipv4, ipv6, running4, running6)
	}
	if entry, _ := overviewDevice(t, ifs, device); string(entry.Mtu) != "1400" {
		t.Errorf("after apply the MTU of %s must be 1400: %q", device, entry.Mtu)
	}

	// a new address replaces the static one in the configuration (a new IPv6 address too)
	var ipv4b = fmt.Sprintf("203.0.113.%d/24", octet+1)
	mustOpn(t, "/interface/address", "set", identifier, "ipv4="+ipv4b)
	requireOnlyOwnStaged(t, ifs, identifier)
	mustOpn(t, "/interface/assignment", "apply", "confirm=yes")
	running4, _ = addressOverview(t, ifs, device)
	if running4 != ipv4b {
		t.Errorf("after the address change %s must run only %s: %q", device, ipv4b, running4)
	}

	// a change back to the applied value while another change is staged is ignored by OPNsense: set fails
	mustOpn(t, "/interface/address", "set", identifier, "mtu=1300")
	var ignored = mustFailOpn(t, "/interface/address", "set", identifier, "mtu=1400")
	requireContains(t, ignored, ignored.stderr, "kept the staged mtu of "+identifier)

	// clear everything again and apply: the configuration has no address type any more. OPNsense 26.7 leaves the
	// running addresses and the MTU on the device until it is reset (relink, removal, reboot), that is only logged
	mustOpn(t, "/interface/address", "set", identifier, "ipv4-type=none", "ipv6-type=none", "mtu=", "block-private=no")
	if current, _ := ifs.AddressGet(identifier); current.Type4 != "" || current.IPv4 != "" || current.Type6 != "" || current.IPv6 != "" ||
		current.MTU != "" || current.BlockPrivate {
		t.Errorf("after clearing: %+v", current)
	}
	requireOnlyOwnStaged(t, ifs, identifier)
	mustOpn(t, "/interface/assignment", "apply", "confirm=yes")
	if current, _ := ifs.AddressGet(identifier); current.PendingAction != "" || current.Type4 != "" || current.Type6 != "" {
		t.Errorf("after clearing and apply: %+v", current)
	}
	var entry, _ = overviewDevice(t, ifs, device)
	if entry.LinkType != "none" || entry.LinkTypeV6 != "none" {
		t.Errorf("after clearing and apply the overview must show the link types none: %q %q", entry.LinkType, entry.LinkTypeV6)
	}
	running4, running6 = addressOverview(t, ifs, device)
	t.Logf("after clearing and apply %s runs %q %q with MTU %s (OPNsense 26.7 keeps them until the device is reset)",
		device, running4, running6, entry.Mtu)
	// the cleanup unassigns the interface and applies that, then removes the loopback
}
