package cli

import (
	"errors"
	"fmt"
	"opnsense-cli/opnsense/api/auth"
	"slices"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// /system/group: System > Access > Groups (api/auth/group). Items are selected by the # of print, the uuid or the
// name. The admins group (gid 1999) is protected: opn refuses to remove or rename it, to take privileges away from
// it and to take root or the user of the API key in use out of it

const systemGroupItemHelp = "the #, uuid or name of the group"

const systemGroupProtectedHelp = `The admins group (gid 1999) is protected: opn refuses to remove or rename it, to take
privileges away from it and to take root or the user of the API key opn uses out of it.`

// systemGroupFieldArgs are the field arguments of add and set
func systemGroupFieldArgs(add bool) []Arg {
	var name = Arg{Name: "name", Help: "the group name (1-32 letters, digits, . - _)", Required: add, Validate: auth.GroupValidateName}
	if !add {
		name.Help = "rename the group"
	}
	return []Arg{
		name,
		{Name: "description", Help: "the description"},
		{Name: "members", Type: List, Help: "the member users by name or uid (replaces the list, \"\" for none)", Complete: systemUserItemNames},
		{Name: "privileges", Type: List, Help: "privileges granted to the members, by id like page-all (replaces the list, \"\" for none)",
			Complete: systemPrivilegeIds},
		{Name: "source-networks", Type: List, Help: "networks the members may log in from like 192.168.1.0/24 (\"\" for anywhere)"},
	}
}

func init() {
	var menu = Root.Menu("system/group")
	menu.Help = "groups of users and their privileges (System > Access > Groups)"
	var item = Arg{Name: "item", Help: systemGroupItemHelp, Positional: true, Required: true, Complete: systemGroupItemNames}
	menu.Add(
		&Command{Name: "print", Help: "list the groups",
			Args: []Arg{
				{Name: "detail", Help: "show all fields of every group", Type: Bool},
				{Name: "json", Help: "one JSON object per line, as the API returns them", Type: Bool},
				{Name: "search", Help: "only groups where any field contains this text"},
			}, Run: systemGroupPrint},
		&Command{Name: "show", Help: "show all fields of one group", Args: []Arg{item}, Run: systemGroupShow},
		&Command{Name: "add", Help: "add a group, prints its uuid",
			Long: `If a group with this name exists already, add fails unless replace is given: then all its fields are
replaced (fields not given are cleared).

  add name=operators members=alice,bob privileges=page-status-ntp,page-diagnostics-ping

` + systemGroupProtectedHelp,
			Args: append(systemGroupFieldArgs(true), Arg{Name: "replace", Help: "replace the group with the same name", Type: Bool}),
			Run:  systemGroupAdd},
		&Command{Name: "set", Help: "change fields of a group, the others are kept",
			Long: systemGroupProtectedHelp,
			Args: append([]Arg{item}, systemGroupFieldArgs(false)...), Check: systemGroupCheckSet, Run: systemGroupSet},
		&Command{Name: "remove", Help: "remove a group",
			Long:    `The members keep their accounts but lose the privileges of the group. opn refuses to remove the admins group (gid 1999).`,
			Confirm: "This removes the group, its members lose its privileges.",
			Args:    []Arg{item}, Run: systemGroupRemove},
	)
}

// systemGroupIsAdmins tells whether the group is the protected admins group
func systemGroupIsAdmins(group auth.Group) bool {
	return group.Gid == auth.AdminsGid || group.Name == "admins"
}

// systemGroupGuard refuses changes that could lock out administrators
func systemGroupGuard(c *Context, api *auth.AuthApi, group auth.Group, fields auth.GroupFields) error {
	if !systemGroupIsAdmins(group) {
		return nil
	}
	var refuse = func(what string) error {
		return fmt.Errorf("refusing to %s the admins group (protected by opn)", what)
	}
	if fields.Name != nil && *fields.Name != group.Name {
		return refuse("rename")
	}
	if fields.Privileges != nil {
		for _, privilege := range group.Privileges {
			if !slices.Contains(*fields.Privileges, privilege) {
				return refuse("take privilege " + privilege + " away from")
			}
		}
	}
	if fields.Members != nil {
		var users, err = api.UserList()
		if err != nil {
			return err
		}
		var owner, ownerErr = systemUserApiKeyOwner(c, api)
		if ownerErr != nil {
			return ownerErr
		}
		for _, uid := range group.Members {
			var index = slices.IndexFunc(users, func(user auth.User) bool { return user.Uid == uid })
			if index >= 0 && systemUserProtection(users[index], owner) != "" && !slices.Contains(*fields.Members, uid) {
				return refuse(fmt.Sprintf("take %q out of", users[index].Name))
			}
		}
	}
	return nil
}

// --- lookups

func systemGroupUuid(group auth.Group) string {
	return group.Uuid
}

func systemGroupNames(group auth.Group) []string {
	return []string{group.Name}
}

func systemGroupSelect(c *Context, api *auth.AuthApi, selector string) (auth.Group, error) {
	var groups, err = api.GroupList()
	if err != nil {
		return auth.Group{}, err
	}
	return Select(c, selector, groups, systemGroupUuid, systemGroupNames)
}

func systemGroupItemNames(c *Context) []string {
	var api, err = systemUserApi(c)
	if err != nil {
		return nil
	}
	var groups, listErr = api.GroupList()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(groups))
	for _, group := range groups {
		names = append(names, group.Name)
	}
	return names
}

// systemGroupMemberUids resolves user names (case-insensitive) or uids to uids
func systemGroupMemberUids(users []auth.User, selectors []string) ([]string, error) {
	var uids = make([]string, 0, len(selectors))
	for _, selector := range selectors {
		var index = slices.IndexFunc(users, func(user auth.User) bool {
			return strings.EqualFold(user.Name, selector) || user.Uid == selector
		})
		if index < 0 {
			return nil, &coreapi.NotFoundError{Name: fmt.Sprintf("user %q", selector)}
		}
		if !slices.Contains(uids, users[index].Uid) {
			uids = append(uids, users[index].Uid)
		}
	}
	return uids, nil
}

// systemGroupMemberNames renders uids as user names (stale uids of removed users as they are)
func systemGroupMemberNames(users []auth.User, uids []string) []string {
	var names = make([]string, 0, len(uids))
	for _, uid := range uids {
		var index = slices.IndexFunc(users, func(user auth.User) bool { return user.Uid == uid })
		if index < 0 {
			names = append(names, uid)
		} else {
			names = append(names, users[index].Name)
		}
	}
	return names
}

// --- output

func systemGroupFields(group auth.Group, users []auth.User) [][2]string {
	return [][2]string{
		{"uuid", group.Uuid},
		{"gid", group.Gid},
		{"name", group.Name},
		{"scope", group.Scope},
		{"description", group.Description},
		{"members", strings.Join(systemGroupMemberNames(users, group.Members), ",")},
		{"privileges", strings.Join(group.Privileges, ",")},
		{"source-networks", strings.Join(group.SourceNetworks, ",")},
	}
}

func systemGroupPrint(c *Context, args *Args) error {
	var api, err = systemUserApi(c)
	if err != nil {
		return err
	}
	var groups, searchErr = api.GroupSearch(args.String("search"))
	if searchErr != nil {
		return searchErr
	}
	var uuids = make([]string, len(groups))
	for i, group := range groups {
		uuids[i] = group.Uuid
	}
	if args.Bool("json") {
		for _, group := range groups {
			if err := c.JSON(group.Raw); err != nil {
				return err
			}
		}
		return nil
	}
	var users, usersErr = api.UserList()
	if usersErr != nil {
		return usersErr
	}
	if args.Bool("detail") {
		var items = make([][][2]string, len(groups))
		for i, group := range groups {
			items[i] = systemGroupFields(group, users)
		}
		c.Details(items, uuids)
		return nil
	}
	var rows = make([][]string, len(groups))
	for i, group := range groups {
		rows[i] = []string{group.Name, group.Gid, strings.Join(systemGroupMemberNames(users, group.Members), ","),
			strings.Join(group.Privileges, ","), group.Description}
	}
	c.Items([]string{"NAME", "GID", "MEMBERS", "PRIVILEGES", "DESCRIPTION"}, rows, uuids)
	return nil
}

func systemGroupShow(c *Context, args *Args) error {
	var api, err = systemUserApi(c)
	if err != nil {
		return err
	}
	var group, selectErr = systemGroupSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var users, usersErr = api.UserList()
	if usersErr != nil {
		return usersErr
	}
	c.Fields(systemGroupFields(group, users))
	return nil
}

// --- changes

func systemGroupCheckSet(args *Args) error {
	for _, name := range args.Given() {
		if name != "item" {
			return nil
		}
	}
	return errors.New("nothing to change, give the fields to set (type \"set ?\" for help)")
}

// systemGroupFieldsFrom builds the fields to send from the arguments; with all every field is set (add)
func systemGroupFieldsFrom(api *auth.AuthApi, args *Args, all bool) (auth.GroupFields, error) {
	var fields auth.GroupFields
	if all || args.Has("name") {
		var name = args.String("name")
		fields.Name = &name
	}
	if all || args.Has("description") {
		var description = args.String("description")
		fields.Description = &description
	}
	if all || args.Has("members") {
		var uids = []string{}
		if selectors := args.List("members"); len(selectors) > 0 {
			var users, err = api.UserList()
			if err != nil {
				return fields, err
			}
			if uids, err = systemGroupMemberUids(users, selectors); err != nil {
				return fields, err
			}
		}
		fields.Members = &uids
	}
	if all || args.Has("privileges") {
		var ids, err = systemUserPrivilegeIds(api, args.List("privileges"))
		if err != nil {
			return fields, err
		}
		fields.Privileges = &ids
	}
	if all || args.Has("source-networks") {
		var networks = args.List("source-networks")
		if networks == nil {
			networks = []string{}
		}
		fields.SourceNetworks = &networks
	}
	return fields, nil
}

func systemGroupAdd(c *Context, args *Args) error {
	var api, err = systemUserApi(c)
	if err != nil {
		return err
	}
	var name = args.String("name")
	var existing, findErr = api.GroupGetByName(name)
	if findErr != nil && !coreapi.IsNotFound(findErr) {
		return findErr
	}
	if findErr == nil && !args.Bool("replace") {
		return fmt.Errorf("a group named %q exists already (%s), change it with set or replace it with add ... replace",
			existing.Name, existing.Uuid)
	}
	var fields, fieldsErr = systemGroupFieldsFrom(api, args, true)
	if fieldsErr != nil {
		return fieldsErr
	}
	if findErr == nil {
		if err := systemGroupGuard(c, api, existing, fields); err != nil {
			return err
		}
		if err := api.GroupUpdate(existing.Uuid, fields); err != nil {
			return err
		}
		c.Infof("replaced the existing group %q", existing.Name)
		c.Println(existing.Uuid)
		return nil
	}
	var uuid, createErr = api.GroupCreate(fields)
	if createErr != nil {
		return createErr
	}
	c.Println(uuid)
	return nil
}

func systemGroupSet(c *Context, args *Args) error {
	var api, err = systemUserApi(c)
	if err != nil {
		return err
	}
	var group, selectErr = systemGroupSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var fields, fieldsErr = systemGroupFieldsFrom(api, args, false)
	if fieldsErr != nil {
		return fieldsErr
	}
	if err := systemGroupGuard(c, api, group, fields); err != nil {
		return err
	}
	return api.GroupUpdate(group.Uuid, fields)
}

func systemGroupRemove(c *Context, args *Args) error {
	var api, err = systemUserApi(c)
	if err != nil {
		return err
	}
	var group, selectErr = systemGroupSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if systemGroupIsAdmins(group) {
		return fmt.Errorf("refusing to remove the admins group (protected by opn)")
	}
	return api.GroupRemove(group.Uuid)
}
