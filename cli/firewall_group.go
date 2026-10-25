package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/firewall"
	"strconv"
	"strings"
)

// /firewall/group: Firewall > Groups, interface groups. Rules on a group apply to all its member interfaces. Items
// are selected by the # of print, the uuid or the group name. The built-in groups enc0, openvpn and wireguard are
// listed but can not be changed

const firewallGroupItemHelp = "the #, uuid or name of the group"

const firewallGroupApplyHint = `Changes are only saved, run "/firewall/group apply" to apply them.`

// firewallGroupFieldArgs are the field arguments of add (with the OPNsense defaults) and set
func firewallGroupFieldArgs(add bool) []Arg {
	var defaultValue = func(value string) string {
		if add {
			return value
		}
		return ""
	}
	var name = Arg{Name: "name", Help: "the group name: 1-15 letters, digits and _, not starting or ending with a digit",
		Required: add, Validate: firewallGroupValidateName}
	if !add {
		name.Help = "rename the group, rules using it are changed to the new name"
	}
	return []Arg{
		name,
		{Name: "members", Help: "the member interfaces like lan,opt1 (comma separated)", Type: List, Required: add,
			Validate: firewallGroupValidateMembers, Complete: firewallGroupInterfaceNames},
		{Name: "sequence", Help: "sorts the groups (0-9999)", Type: Int, Default: defaultValue("0"), Validate: ValidateRange(0, 9999)},
		{Name: "no-group", Help: "don't combine the members under the group in the interfaces menu", Type: Bool, Default: defaultValue("no")},
		{Name: "description", Help: "any text"},
	}
}

func init() {
	var menu = Root.Menu("firewall/group")
	menu.Help = "interface groups, for rules on several interfaces (Firewall > Groups)"
	var item = Arg{Name: "item", Help: firewallGroupItemHelp, Positional: true, Required: true, Complete: firewallGroupItemNames}
	menu.Add(
		&Command{Name: "print", Help: "list the interface groups",
			Long: `BUILT-IN groups (enc0, openvpn, wireguard) are provided by OPNsense and can not be changed.`,
			Args: []Arg{
				{Name: "detail", Help: "show all fields of every group", Type: Bool},
				{Name: "json", Help: "one JSON object per line, as the API returns them", Type: Bool},
				{Name: "search", Help: "only groups where any field contains this text"},
			}, Run: firewallGroupPrint},
		&Command{Name: "show", Help: "show all fields of one group", Args: []Arg{item}, Run: firewallGroupShow},
		&Command{Name: "add", Help: "add an interface group, prints its uuid",
			Long: `The name must not be the name of an interface. If a group with this name exists already, add fails unless
replace is given, then that group is replaced completely (arguments not given are reset to their defaults).
` + firewallGroupApplyHint,
			Args: append(firewallGroupFieldArgs(true), Arg{Name: "replace", Help: "replace the group with the same name", Type: Bool}),
			Run:  firewallGroupAdd},
		&Command{Name: "set", Help: "change fields of a group, the others are kept",
			Long: `name= renames the group, OPNsense changes the rules using it to the new name.
` + firewallGroupApplyHint,
			Args: append([]Arg{item}, firewallGroupFieldArgs(false)...), Check: firewallGroupCheckSet, Run: firewallGroupSet},
		&Command{Name: "remove", Help: "remove a group",
			Long: `A group used by rules can not be removed, the error names the rules.
` + firewallGroupApplyHint,
			Args: []Arg{item}, Run: firewallGroupRemove},
		&Command{Name: "apply", Help: "apply the group changes (registers the interface groups, reloads the filter)", Run: firewallGroupApply},
	)
}

// --- validation

func firewallGroupValidateName(value string) error {
	if err := firewall.GroupValidateName(value); err != nil {
		return fmt.Errorf("must be 1-15 letters, digits and _, not starting or ending with a digit, got %q", value)
	}
	return nil
}

func firewallGroupValidateMembers(value string) error {
	var seen = map[string]bool{}
	for _, member := range splitList(value) {
		if strings.Contains(member, " ") {
			return fmt.Errorf("must be interface names like lan,opt1, got %q", member)
		}
		if seen[member] {
			return fmt.Errorf("%s is given twice", member)
		}
		seen[member] = true
	}
	return nil
}

func firewallGroupCheckSet(args *Args) error {
	for _, name := range args.Given() {
		if name != "item" {
			return nil
		}
	}
	return errors.New("set: nothing to change, give at least one field like members= or description= (type \"set ?\" for help)")
}

// firewallGroupCheckMembers checks members= against the interfaces OPNsense offers, interface names are completed
// to their case in OPNsense
func firewallGroupCheckMembers(api *firewall.FirewallApi, members []string) ([]string, error) {
	var interfaces, err = api.GroupInterfaces()
	if err != nil {
		return nil, err
	}
	var names = make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		names = append(names, iface.Name)
	}
	var result = make([]string, 0, len(members))
	for _, member := range members {
		var found = ""
		for _, iface := range interfaces {
			if strings.EqualFold(iface.Name, member) {
				found = iface.Name
			}
		}
		if found == "" {
			return nil, fmt.Errorf("members: unknown interface %q, the interfaces are: %s", member, strings.Join(names, ", "))
		}
		result = append(result, found)
	}
	if len(result) == 0 {
		return nil, errors.New("members: a group needs at least one member interface")
	}
	return result, nil
}

// --- lookups

// firewallGroupSearch returns the matching groups in API order, with the raw API objects for json output
func firewallGroupSearch(api *firewall.FirewallApi, searchPhrase string) ([]firewall.Group, []json.RawMessage, error) {
	var endpoint = api.EndpointForPluginControllerMethod("firewall", "group", "search_item")
	var rows, err = coreapi.Search[json.RawMessage](api.OPNsense, endpoint, searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var groups = make([]firewall.Group, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &groups[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected group from OPNsense: %w", err)
		}
	}
	return groups, rows, nil
}

func firewallGroupUuid(group firewall.Group) string {
	return group.Uuid
}

func firewallGroupNames(group firewall.Group) []string {
	return []string{group.Name}
}

// firewallGroupSelect loads all groups and finds the one selector refers to
func firewallGroupSelect(c *Context, api *firewall.FirewallApi, selector string) (firewall.Group, error) {
	var groups, _, err = firewallGroupSearch(api, "")
	if err != nil {
		return firewall.Group{}, err
	}
	return Select(c, selector, groups, firewallGroupUuid, firewallGroupNames)
}

// firewallGroupItemNames completes item names from the API
func firewallGroupItemNames(c *Context) []string {
	var api, err = firewallApi(c)
	if err != nil {
		return nil
	}
	var groups, _, searchErr = firewallGroupSearch(api, "")
	if searchErr != nil {
		return nil
	}
	var names = make([]string, 0, len(groups))
	for _, group := range groups {
		names = append(names, group.Name)
	}
	return names
}

// firewallGroupInterfaceNames completes members= with the interfaces which can be members
func firewallGroupInterfaceNames(c *Context) []string {
	var api, err = firewallApi(c)
	if err != nil {
		return nil
	}
	var interfaces, listErr = api.GroupInterfaces()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		names = append(names, iface.Name)
	}
	return names
}

// --- output

// firewallGroupFields are the fields of show and print detail, named like the arguments of add and set
func firewallGroupFields(group firewall.Group) [][2]string {
	return [][2]string{
		{"uuid", group.Uuid},
		{"name", group.Name},
		{"members", strings.Join(group.Members, ",")},
		{"member-names", group.MembersText},
		{"sequence", strconv.Itoa(group.Sequence)},
		{"no-group", YesNo(Flag(group.NoGroup))},
		{"built-in", YesNo(Flag(group.IsBuiltin()))},
		{"description", group.Description},
	}
}

func firewallGroupPrint(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var groups, raw, searchErr = firewallGroupSearch(api, args.String("search"))
	if searchErr != nil {
		return searchErr
	}

	var uuids = make([]string, len(groups))
	for i, group := range groups {
		uuids[i] = group.Uuid
	}
	switch {
	case args.Bool("json"):
		for _, row := range raw {
			c.Println(string(row))
		}
	case args.Bool("detail"):
		var items = make([][][2]string, len(groups))
		for i, group := range groups {
			items[i] = firewallGroupFields(group)
		}
		c.Details(items, uuids)
	default:
		var rows = make([][]string, len(groups))
		for i, group := range groups {
			rows[i] = []string{group.Name, strings.Join(group.Members, ","), strconv.Itoa(group.Sequence),
				YesNo(Flag(group.NoGroup)), YesNo(Flag(group.IsBuiltin())), group.Description}
		}
		c.Items([]string{"NAME", "MEMBERS", "SEQUENCE", "NO-GROUP", "BUILT-IN", "DESCRIPTION"}, rows, uuids)
	}
	return nil
}

func firewallGroupShow(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var group, selectErr = firewallGroupSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	c.Fields(firewallGroupFields(group))
	return nil
}

// --- changes

// firewallGroupPatch returns the given field arguments (members already checked), with all also the defaults of
// the arguments not given
func firewallGroupPatch(args *Args, members []string, all bool) firewall.GroupPatch {
	var patch firewall.GroupPatch
	if args.Has("name") {
		var name = args.String("name")
		patch.Name = &name
	}
	if all || args.Has("members") {
		patch.Members = &members
	}
	if all || args.Has("sequence") {
		var sequence = args.Int("sequence")
		patch.Sequence = &sequence
	}
	if all || args.Has("no-group") {
		var noGroup = args.Bool("no-group")
		patch.NoGroup = &noGroup
	}
	if all || args.Has("description") {
		var description = args.String("description")
		patch.Description = &description
	}
	return patch
}

func firewallGroupAdd(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var members, membersErr = firewallGroupCheckMembers(api, args.List("members"))
	if membersErr != nil {
		return membersErr
	}

	var name = args.String("name")
	var existing, findErr = api.GroupGetByName(name)
	if findErr != nil && !coreapi.IsNotFound(findErr) {
		return findErr
	}
	var patch = firewallGroupPatch(args, members, true)
	switch {
	case findErr != nil:
		var uuid, createErr = api.GroupCreate(firewall.Group{Name: name, Members: members, Sequence: *patch.Sequence,
			NoGroup: *patch.NoGroup, Description: *patch.Description})
		if createErr != nil {
			return createErr
		}
		c.Println(uuid)
		return nil
	case existing.IsBuiltin():
		return fmt.Errorf("%s is a built-in group, it can not be replaced", existing.Name)
	case !args.Bool("replace"):
		return fmt.Errorf("a group named %s exists already (%s), change it with set or replace it with add ... replace",
			existing.Name, existing.Uuid)
	}
	if err := api.GroupUpdate(existing.Uuid, patch); err != nil {
		return err
	}
	c.Infof("replaced the existing group %s", existing.Name)
	c.Println(existing.Uuid)
	return nil
}

func firewallGroupSet(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var group, selectErr = firewallGroupSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if group.IsBuiltin() {
		return fmt.Errorf("%s is a built-in group and can not be changed", group.Name)
	}
	var members []string
	if args.Has("members") {
		var checkErr error
		if members, checkErr = firewallGroupCheckMembers(api, args.List("members")); checkErr != nil {
			return checkErr
		}
	}
	return api.GroupUpdate(group.Uuid, firewallGroupPatch(args, members, false))
}

func firewallGroupRemove(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var group, selectErr = firewallGroupSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if group.IsBuiltin() {
		return fmt.Errorf("%s is a built-in group and can not be removed", group.Name)
	}
	return api.GroupRemove(group.Uuid)
}

func firewallGroupApply(c *Context, _ *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	return api.GroupReconfigure()
}
