package cli

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"opnsense-cli/opnsense/api/interfaces"
)

// /interface/assignment: Interfaces > Assignments (api/interfaces/assignment): which device is which interface
// (lan, wan, optN). Changes are staged by OPNsense and applied together with apply (POST reconfigure).
//
// Access protection: changing the device of, disabling or removing the lan or wan assignment, or the assignment
// whose addresses include the address the API connection goes to, is refused (there is no confirm=yes override):
// OPNsense has no rollback for an assignment apply, a wrong relink of the interface the CLI talks through ends
// the remote access for good, and such a change belongs on the console or in the GUI. apply is refused while one
// of these interfaces has a staged change (made elsewhere, e.g. in the GUI)

const interfaceAssignmentItemHelp = "the #, identifier (opt1), description or device of the assignment"

const interfaceAssignmentApplyHint = `Changes are staged, run "/interface/assignment apply" to apply them.`

const interfaceAssignmentProtectedHelp = `The device of the lan and wan assignment and of the assignment the API connection goes through (when its
address is one of the firewall's addresses) can not be changed here, nor can they be disabled or removed:
that can cut off the access to the firewall, use the console or the GUI for it.`

func init() {
	var menu = Root.Menu("interface/assignment")
	menu.Help = "interface assignments: which device is lan, wan, optN (Interfaces > Assignments)"
	var item = Arg{Name: "item", Help: interfaceAssignmentItemHelp, Positional: true, Required: true, Complete: interfaceCompleteIdentifiers}
	var fields = func(add bool) []Arg {
		return []Arg{
			{Name: "device", Required: add, Help: "the network device, like vlan0.10, lo1, vtnet2", Validate: interfaceValidateName,
				Complete: interfaceAssignmentCompleteDevices},
			{Name: "description", Help: "letters, digits and underscores, unique (empty: OPNsense shows the identifier in upper case)",
				Validate: interfaceAssignmentValidateDescription},
			{Name: "locked", Type: Bool, Help: "prevent the removal (new assignments are locked unless locked=no is given)"},
			{Name: "disabled", Type: Bool, Help: "the interface is disabled (new assignments are enabled)"},
		}
	}
	menu.Add(
		&Command{Name: "print", Help: "list the assigned interfaces with their devices and staged changes",
			Long: `PENDING is the staged change of an interface that apply will make: update (new assignment or changed
setting), relink (changed device). Interfaces staged for removal are no longer listed. A hint on stderr tells
when changes wait for apply.`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every assignment"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
				{Name: "search", Help: "only assignments where any field contains this text"},
			}, Run: interfaceAssignmentPrint},
		&Command{Name: "show", Help: "show all fields of one assignment", Args: []Arg{item}, Run: interfaceAssignmentShow},
		&Command{Name: "add", Help: "assign a device as the next free optN interface, prints the identifier",
			Long: `The new interface is enabled, locked (unless locked=no) and has no address configuration (set it in the GUI).
A device can only be assigned once.
` + interfaceAssignmentApplyHint + `

  add device=vlan0.10 description=guests locked=no`,
			Args: fields(true), Run: interfaceAssignmentAdd},
		&Command{Name: "set", Help: "change fields of an assignment, the others are kept",
			Long: `A new description or lock is saved at once, a new device (relink) and disabled are staged for apply.
OPNsense ignores a change back to the applied value while a change of the interface is staged (disable, then
enable before apply): set fails then, apply the staged change first.
` + interfaceAssignmentProtectedHelp + `
` + interfaceAssignmentApplyHint,
			Args: append([]Arg{item}, fields(false)...), Check: interfaceAssignmentCheckSet, Run: interfaceAssignmentSet},
		&Command{Name: "remove", Help: "unassign an interface (staged for apply)",
			Long: `OPNsense refuses locked interfaces (unlock with set <item> locked=no first) and members of an interface group,
bridge, GRE or GIF tunnel. When the removal is applied, the interface is taken out of every firewall filter,
NAT, NPT and 1:1 rule, and rules left without an interface are deleted; other references (DHCP, DNS, routes)
are not cleaned.
` + interfaceAssignmentProtectedHelp + `
` + interfaceAssignmentApplyHint,
			Confirm: "This unassigns the interface; when applied it is taken out of all firewall and NAT rules, and rules left without an interface are removed.",
			Args:    []Arg{item}, Run: interfaceAssignmentRemove},
		&Command{Name: "enable", Help: "enable an interface (staged for apply)", Args: []Arg{item}, Run: interfaceAssignmentEnabler(true)},
		&Command{Name: "disable", Help: "disable an interface (staged for apply)",
			Long: interfaceAssignmentProtectedHelp, Args: []Arg{item}, Run: interfaceAssignmentEnabler(false)},
		&Command{Name: "apply", Aliases: []string{"reconfigure"}, Help: "apply the staged assignment changes",
			Long: `Applies every staged change, also those made in the GUI: the changed interfaces are reset and configured
again (removed ones are taken down), their routing, IPsec and dynamic DNS are reconfigured, the DHCP and DNS
services are reloaded, removed interfaces are deleted from the firewall and NAT rules, and the firewall rules
are reloaded. Nothing is sent when no change is staged. apply is refused while the lan or wan interface, or the
one the API connection goes through, has a staged change: apply that in the GUI.`,
			Confirm: "This applies all staged assignment changes: the changed interfaces are reconfigured, DHCP and DNS are reloaded, removed interfaces are taken out of the firewall/NAT rules and the firewall rules are reloaded.",
			Run:     interfaceAssignmentApply},
	)
}

// --- validation and lookups

func interfaceAssignmentValidateDescription(value string) error {
	if !interfaces.AssignmentDescriptionPattern.MatchString(value) {
		return fmt.Errorf("only letters, digits and underscores (at most 255), got %q", value)
	}
	return nil
}

func interfaceAssignmentCheckSet(args *Args) error {
	for _, name := range []string{"device", "description", "locked", "disabled"} {
		if args.Has(name) {
			return nil
		}
	}
	return errors.New("set: nothing to change, give at least one field (type \"set ?\" for help)")
}

func interfaceAssignmentIdentifier(assignment interfaces.Assignment) string {
	return assignment.Identifier
}

func interfaceAssignmentNames(assignment interfaces.Assignment) []string {
	return []string{assignment.Description, assignment.Device}
}

func interfaceAssignmentSelect(c *Context, list []interfaces.Assignment, selector string) (interfaces.Assignment, error) {
	return Select(c, selector, list, interfaceAssignmentIdentifier, interfaceAssignmentNames)
}

func interfaceAssignmentCompleteDevices(c *Context) []string {
	var api, err = interfaceApi(c)
	if err != nil {
		return nil
	}
	var devices, listErr = api.AssignmentDevices()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(devices))
	for _, device := range devices {
		names = append(names, device.Key)
	}
	return names
}

// interfaceAssignmentCheckDevice fails when OPNsense does not offer the device or another interface has it
func interfaceAssignmentCheckDevice(api *interfaces.InterfacesApi, list []interfaces.Assignment, device string, self string) error {
	for _, assignment := range list {
		if assignment.Device == device && assignment.Identifier != self {
			return fmt.Errorf("device %s is assigned already to %s", device, assignment.Identifier)
		}
	}
	var devices, err = api.AssignmentDevices()
	if err != nil {
		return err
	}
	var choices = make([]string, 0, len(devices))
	for _, choice := range devices {
		if choice.Key == device {
			return nil
		}
		choices = append(choices, choice.Key)
	}
	sort.Strings(choices)
	return fmt.Errorf("device %s can not be assigned, OPNsense offers: %s", device, strings.Join(choices, ", "))
}

// interfaceAssignmentCheckDescription fails when another interface has this description or identifier (selecting by
// description would be ambiguous, and an interface named like another one's key confuses rules and groups)
func interfaceAssignmentCheckDescription(list []interfaces.Assignment, description string, self string) error {
	if description == "" {
		return nil
	}
	for _, assignment := range list {
		if assignment.Identifier == self {
			continue
		}
		if strings.EqualFold(assignment.Description, description) || strings.EqualFold(assignment.Identifier, description) {
			return fmt.Errorf("description %q is taken by interface %s", description, assignment.Identifier)
		}
	}
	return nil
}

// --- access protection

// interfaceAssignmentGuard knows which interfaces must not be relinked, disabled or removed remotely
type interfaceAssignmentGuard struct {
	// protected maps identifiers to the reason
	protected map[string]string
	// configured are the identifiers in config.xml (the overview), including interfaces staged for removal
	configured map[string]bool
}

// interfaceAssignmentGuardFor protects lan, wan and the interface holding the address of the API connection
func interfaceAssignmentGuardFor(c *Context, api *interfaces.InterfacesApi) (interfaceAssignmentGuard, error) {
	var guard = interfaceAssignmentGuard{
		protected:  map[string]string{"lan": "it is the LAN interface", "wan": "it is the WAN interface"},
		configured: map[string]bool{},
	}
	var overview, err = api.Overview("")
	if err != nil {
		return guard, fmt.Errorf("cannot check which interface the API connection uses: %w", err)
	}
	var targets = interfaceAssignmentApiAddresses(c, api)
	for _, entry := range overview {
		if entry.Identifier == "" {
			continue
		}
		guard.configured[entry.Identifier] = true
		var addresses = []string{entry.Addr4, entry.Addr6}
		for _, address := range append(entry.IPv4, entry.IPv6...) {
			addresses = append(addresses, address.Address)
		}
		for _, address := range addresses {
			var host, _, _ = strings.Cut(address, "/")
			var ip = net.ParseIP(host)
			for _, target := range targets {
				if ip != nil && ip.Equal(target) {
					guard.protected[entry.Identifier] = fmt.Sprintf("the API connection goes to its address %s", target)
				}
			}
		}
	}
	return guard, nil
}

// interfaceAssignmentApiAddresses are the addresses the host of the API URL resolves to, none when unknown
func interfaceAssignmentApiAddresses(c *Context, api *interfaces.InterfacesApi) []net.IP {
	var host = api.BaseUrl.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	var resolved, err = net.DefaultResolver.LookupIPAddr(c, host)
	if err != nil {
		return nil
	}
	var ips = make([]net.IP, 0, len(resolved))
	for _, address := range resolved {
		ips = append(ips, address.IP)
	}
	return ips
}

func (guard interfaceAssignmentGuard) refuse(identifier string, what string) error {
	if reason, protected := guard.protected[identifier]; protected {
		return fmt.Errorf("refusing to %s %s: %s, doing that remotely can cut off the access to the firewall (use the console or the GUI)",
			what, identifier, reason)
	}
	return nil
}

// --- print and show

func interfaceAssignmentDetail(assignment interfaces.Assignment) [][2]string {
	return [][2]string{
		{"identifier", assignment.Identifier},
		{"description", assignment.Description},
		{"device", assignment.Device},
		{"device-info", assignment.DeviceText},
		{"group", assignment.Group},
		{"disabled", YesNo(Flag(!assignment.Enabled))},
		{"locked", YesNo(Flag(assignment.Locked))},
		{"pending", assignment.PendingAction},
		{"ipv4-type", assignment.IPv4Type},
		{"ipv4", assignment.IPv4},
		{"ipv6-type", assignment.IPv6Type},
		{"ipv6", assignment.IPv6},
	}
}

func interfaceAssignmentPrint(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var assignments, listErr = api.AssignmentSearch(args.String("search"))
	if listErr != nil {
		return listErr
	}
	var identifiers = make([]string, len(assignments))
	for i, assignment := range assignments {
		identifiers[i] = assignment.Identifier
	}
	switch {
	case args.Bool("json"):
		for _, assignment := range assignments {
			if err := c.JSON(assignment.Raw); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var blocks = make([][][2]string, len(assignments))
		for i, assignment := range assignments {
			blocks[i] = interfaceAssignmentDetail(assignment)
		}
		c.Details(blocks, identifiers)
	default:
		var rows = make([][]string, len(assignments))
		for i, assignment := range assignments {
			rows[i] = []string{assignment.Identifier, assignment.Description, assignment.Device,
				YesNo(Flag(!assignment.Enabled)), YesNo(Flag(assignment.Locked)), assignment.PendingAction}
		}
		c.Items([]string{"IDENTIFIER", "DESCRIPTION", "DEVICE", "DISABLED", "LOCKED", "PENDING"}, rows, identifiers)
	}
	if pending, pendingErr := api.AssignmentPending(); pendingErr == nil && pending {
		c.Infof(`assignment changes are staged, run "/interface/assignment apply" to apply them`)
	}
	return nil
}

func interfaceAssignmentShow(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var list, listErr = api.Assignments()
	if listErr != nil {
		return listErr
	}
	var assignment, selectErr = interfaceAssignmentSelect(c, list, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var fields = interfaceAssignmentDetail(assignment)
	if guard, guardErr := interfaceAssignmentGuardFor(c, api); guardErr == nil {
		var protected = "no"
		if reason, found := guard.protected[assignment.Identifier]; found {
			protected = "yes, " + reason
		}
		fields = append(fields, [2]string{"protected", protected})
	}
	c.Fields(fields)
	return nil
}

// --- changes

func interfaceAssignmentChange(args *Args) interfaces.AssignmentChange {
	var change interfaces.AssignmentChange
	if args.Has("device") {
		var device = strings.TrimSpace(args.String("device"))
		change.Device = &device
	}
	if args.Has("description") {
		var description = strings.TrimSpace(args.String("description"))
		change.Description = &description
	}
	if args.Has("locked") {
		var locked = args.Bool("locked")
		change.Locked = &locked
	}
	if args.Has("disabled") {
		var enabled = !args.Bool("disabled")
		change.Enabled = &enabled
	}
	return change
}

// interfaceAssignmentTranslate renames the fields of an OPNsense validation error (interface.if) to the arguments
func interfaceAssignmentTranslate(err error) error {
	return (&interfaceSpec{fields: []interfaceField{
		{Arg: Arg{Name: "device"}, api: "if"},
		{Arg: Arg{Name: "description"}, api: "descr"},
		{Arg: Arg{Name: "locked"}, api: "lock"},
		{Arg: Arg{Name: "disabled"}, api: "enable"},
	}}).translate(err)
}

func interfaceAssignmentAdd(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var change = interfaceAssignmentChange(args)
	var list, listErr = api.Assignments()
	if listErr != nil {
		return listErr
	}
	if change.Description != nil {
		if err := interfaceAssignmentCheckDescription(list, *change.Description, ""); err != nil {
			return err
		}
	}
	if err := interfaceAssignmentCheckDevice(api, list, *change.Device, ""); err != nil {
		return err
	}
	var identifier, createErr = api.AssignmentCreate(change)
	if createErr != nil {
		return interfaceAssignmentTranslate(createErr)
	}
	c.Println(identifier)
	return nil
}

func interfaceAssignmentSet(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var list, listErr = api.Assignments()
	if listErr != nil {
		return listErr
	}
	var assignment, selectErr = interfaceAssignmentSelect(c, list, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var change = interfaceAssignmentChange(args)
	var relink = change.Device != nil && *change.Device != assignment.Device
	if relink || change.Enabled != nil && !*change.Enabled {
		var guard, guardErr = interfaceAssignmentGuardFor(c, api)
		if guardErr != nil {
			return guardErr
		}
		if relink {
			if err := guard.refuse(assignment.Identifier, "change the device of"); err != nil {
				return err
			}
		}
		if change.Enabled != nil && !*change.Enabled {
			if err := guard.refuse(assignment.Identifier, "disable"); err != nil {
				return err
			}
		}
	}
	if change.Description != nil {
		if err := interfaceAssignmentCheckDescription(list, *change.Description, assignment.Identifier); err != nil {
			return err
		}
	}
	if relink {
		if err := interfaceAssignmentCheckDevice(api, list, *change.Device, assignment.Identifier); err != nil {
			return err
		}
	}
	return interfaceAssignmentTranslate(api.AssignmentUpdate(assignment.Identifier, change))
}

func interfaceAssignmentEnabler(enable bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = interfaceApi(c)
		if err != nil {
			return err
		}
		var list, listErr = api.Assignments()
		if listErr != nil {
			return listErr
		}
		var assignment, selectErr = interfaceAssignmentSelect(c, list, args.String("item"))
		if selectErr != nil {
			return selectErr
		}
		if !enable {
			var guard, guardErr = interfaceAssignmentGuardFor(c, api)
			if guardErr != nil {
				return guardErr
			}
			if err := guard.refuse(assignment.Identifier, "disable"); err != nil {
				return err
			}
		}
		return api.AssignmentUpdate(assignment.Identifier, interfaces.AssignmentChange{Enabled: &enable})
	}
}

func interfaceAssignmentRemove(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var list, listErr = api.Assignments()
	if listErr != nil {
		return listErr
	}
	var assignment, selectErr = interfaceAssignmentSelect(c, list, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var guard, guardErr = interfaceAssignmentGuardFor(c, api)
	if guardErr != nil {
		return guardErr
	}
	if err := guard.refuse(assignment.Identifier, "remove"); err != nil {
		return err
	}
	if assignment.Locked {
		return fmt.Errorf("interface %s is locked, unlock it first with: set %s locked=no", assignment.Identifier, assignment.Identifier)
	}
	return api.AssignmentRemove(assignment.Identifier)
}

func interfaceAssignmentApply(c *Context, _ *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var pending, pendingErr = api.AssignmentPending()
	if pendingErr != nil {
		return pendingErr
	}
	if !pending {
		c.Infof("no assignment changes are staged, nothing to apply")
		return nil
	}
	var list, listErr = api.Assignments()
	if listErr != nil {
		return listErr
	}
	var guard, guardErr = interfaceAssignmentGuardFor(c, api)
	if guardErr != nil {
		return guardErr
	}
	var listed = map[string]bool{}
	var changes []string
	for _, assignment := range list {
		listed[assignment.Identifier] = true
		if assignment.PendingAction == "" {
			continue
		}
		if err := guard.refuse(assignment.Identifier, "apply the staged change ("+assignment.PendingAction+") of"); err != nil {
			return err
		}
		changes = append(changes, assignment.Identifier+" "+assignment.PendingAction)
	}
	var identifiers = make([]string, 0, len(guard.protected))
	for identifier := range guard.protected {
		identifiers = append(identifiers, identifier)
	}
	sort.Strings(identifiers)
	for _, identifier := range identifiers {
		if guard.configured[identifier] && !listed[identifier] {
			return guard.refuse(identifier, "apply the staged removal of")
		}
	}
	if len(changes) > 0 {
		c.Infof("applying: %s (and staged removals)", strings.Join(changes, ", "))
	} else {
		c.Infof("applying the staged removals")
	}
	return api.AssignmentApply()
}
