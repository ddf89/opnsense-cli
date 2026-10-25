package cli

import (
	"errors"
	"fmt"
	"opnsense-cli/opnsense/api/auth"
	"slices"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// /system/privilege: System > Access > Privileges (api/auth/priv). The privileges are fixed by OPNsense and its
// plugins, they are granted to users and groups. Items are selected by the # of print, the id (page-all) or the
// name ("All pages"). opn never revokes privileges from root, the user of the API key in use or the admins group

const systemPrivilegeItemHelp = "the #, id (like page-all) or name of the privilege"

func init() {
	var menu = Root.Menu("system/privilege")
	menu.Help = "privileges and who they are granted to (System > Access > Privileges)"
	var item = Arg{Name: "item", Help: systemPrivilegeItemHelp, Positional: true, Required: true, Complete: systemPrivilegeIds}
	var holders = []Arg{
		{Name: "user", Type: List, Help: "users by name", Complete: systemUserItemNames},
		{Name: "group", Type: List, Help: "groups by name", Complete: systemGroupItemNames},
	}
	menu.Add(
		&Command{Name: "print", Help: "list the privileges and who they are granted to directly",
			Long: `USERS and GROUPS are the users and groups the privilege is granted to directly; users also have the
privileges of their groups. search matches the id, the name and the URL patterns.`,
			Args: []Arg{
				{Name: "detail", Help: "show all fields of every privilege, with its URL patterns", Type: Bool},
				{Name: "json", Help: "one JSON object per line, as the API returns them", Type: Bool},
				{Name: "search", Help: "only privileges whose id, name or URL patterns contain this text (case-insensitive)"},
				{Name: "user", Help: "only privileges granted directly to this user", Complete: systemUserItemNames},
				{Name: "group", Help: "only privileges granted to this group", Complete: systemGroupItemNames},
				{Name: "granted", Type: Bool, Help: "only privileges granted to any user or group"},
			}, Run: systemPrivilegePrint},
		&Command{Name: "show", Help: "show one privilege with its URL patterns", Args: []Arg{item}, Run: systemPrivilegeShow},
		&Command{Name: "grant", Help: "grant a privilege to users and groups, the others keep theirs",
			Long: `  grant page-status-ntp user=alice group=operators`,
			Args: append([]Arg{item}, holders...), Check: systemPrivilegeCheckHolders, Run: systemPrivilegeChange(true)},
		&Command{Name: "revoke", Help: "revoke a privilege from users and groups, the others keep theirs",
			Long: `Only revokes what was granted directly: a user keeps the privileges of its groups. opn refuses to revoke
privileges from root, the user owning the API key it uses and the admins group.`,
			Args: append([]Arg{item}, holders...), Check: systemPrivilegeCheckHolders, Run: systemPrivilegeChange(false)},
	)
}

func systemPrivilegeCheckHolders(args *Args) error {
	if len(args.List("user")) == 0 && len(args.List("group")) == 0 {
		return errors.New("give user= and/or group=")
	}
	return nil
}

// --- lookups

func systemPrivilegeId(privilege auth.Privilege) string {
	return privilege.Id
}

func systemPrivilegeNames(privilege auth.Privilege) []string {
	return []string{privilege.Name}
}

func systemPrivilegeSelect(c *Context, api *auth.AuthApi, selector string) (auth.Privilege, error) {
	var privileges, err = api.PrivilegeList()
	if err != nil {
		return auth.Privilege{}, err
	}
	return Select(c, selector, privileges, systemPrivilegeId, systemPrivilegeNames)
}

func systemPrivilegeIds(c *Context) []string {
	var api, err = systemUserApi(c)
	if err != nil {
		return nil
	}
	var privileges, listErr = api.PrivilegeList()
	if listErr != nil {
		return nil
	}
	var ids = make([]string, 0, len(privileges))
	for _, privilege := range privileges {
		ids = append(ids, privilege.Id)
	}
	return ids
}

// systemPrivilegeMatches tells whether the privilege passes the print filters
func systemPrivilegeMatches(privilege auth.Privilege, args *Args) bool {
	if search := strings.ToLower(args.String("search")); search != "" {
		var text = strings.ToLower(privilege.Id + "\n" + privilege.Name + "\n" + strings.Join(privilege.Match, "\n"))
		if !strings.Contains(text, search) {
			return false
		}
	}
	var contains = func(names []string, name string) bool {
		return slices.ContainsFunc(names, func(candidate string) bool { return strings.EqualFold(candidate, name) })
	}
	if user := args.String("user"); user != "" && !contains(privilege.Users, user) {
		return false
	}
	if group := args.String("group"); group != "" && !contains(privilege.Groups, group) {
		return false
	}
	if args.Bool("granted") && len(privilege.Users) == 0 && len(privilege.Groups) == 0 {
		return false
	}
	return true
}

// --- output

func systemPrivilegeFields(privilege auth.Privilege) [][2]string {
	var fields = [][2]string{
		{"id", privilege.Id},
		{"name", privilege.Name},
		{"users", strings.Join(privilege.Users, ",")},
		{"groups", strings.Join(privilege.Groups, ",")},
	}
	for _, match := range privilege.Match {
		fields = append(fields, [2]string{"match", match})
	}
	return fields
}

func systemPrivilegePrint(c *Context, args *Args) error {
	var api, err = systemUserApi(c)
	if err != nil {
		return err
	}
	var all, listErr = api.PrivilegeList()
	if listErr != nil {
		return listErr
	}
	var privileges []auth.Privilege
	for _, privilege := range all {
		if systemPrivilegeMatches(privilege, args) {
			privileges = append(privileges, privilege)
		}
	}
	var ids = make([]string, len(privileges))
	for i, privilege := range privileges {
		ids[i] = privilege.Id
	}
	switch {
	case args.Bool("json"):
		for _, privilege := range privileges {
			c.Println(string(privilege.Raw))
		}
	case args.Bool("detail"):
		var items = make([][][2]string, len(privileges))
		for i, privilege := range privileges {
			items[i] = systemPrivilegeFields(privilege)
		}
		c.Details(items, ids)
	default:
		var rows = make([][]string, len(privileges))
		for i, privilege := range privileges {
			rows[i] = []string{privilege.Id, privilege.Name, strings.Join(privilege.Users, ","), strings.Join(privilege.Groups, ",")}
		}
		c.Items([]string{"ID", "NAME", "USERS", "GROUPS"}, rows, ids)
	}
	return nil
}

func systemPrivilegeShow(c *Context, args *Args) error {
	var api, err = systemUserApi(c)
	if err != nil {
		return err
	}
	var privilege, selectErr = systemPrivilegeSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	c.Fields(systemPrivilegeFields(privilege))
	return nil
}

// --- changes

func systemPrivilegeChange(grant bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = systemUserApi(c)
		if err != nil {
			return err
		}
		var privilege, selectErr = systemPrivilegeSelect(c, api, args.String("item"))
		if selectErr != nil {
			return selectErr
		}

		var userUuids, groupUuids []string
		if names := args.List("user"); len(names) > 0 {
			var users, listErr = api.UserList()
			if listErr != nil {
				return listErr
			}
			var owner = ""
			if !grant {
				if owner, err = systemUserApiKeyOwner(c, api); err != nil {
					return err
				}
			}
			for _, name := range names {
				var index = slices.IndexFunc(users, func(user auth.User) bool { return strings.EqualFold(user.Name, name) })
				if index < 0 {
					return &coreapi.NotFoundError{Name: fmt.Sprintf("user %q", name)}
				}
				if why := systemUserProtection(users[index], owner); !grant && why != "" {
					return fmt.Errorf("refusing to revoke privileges from %q: it is %s (protected by opn)", users[index].Name, why)
				}
				userUuids = append(userUuids, users[index].Uuid)
			}
		}
		if names := args.List("group"); len(names) > 0 {
			var groups, listErr = api.GroupList()
			if listErr != nil {
				return listErr
			}
			for _, name := range names {
				var index = slices.IndexFunc(groups, func(group auth.Group) bool { return strings.EqualFold(group.Name, name) })
				if index < 0 {
					return &coreapi.NotFoundError{Name: fmt.Sprintf("group %q", name)}
				}
				if !grant && systemGroupIsAdmins(groups[index]) {
					return errors.New("refusing to revoke privileges from the admins group (protected by opn)")
				}
				groupUuids = append(groupUuids, groups[index].Uuid)
			}
		}
		if grant {
			return api.PrivilegeGrant(privilege.Id, userUuids, groupUuids)
		}
		return api.PrivilegeRevoke(privilege.Id, userUuids, groupUuids)
	}
}
