package cli

import (
	"errors"
	"fmt"
	"opnsense-cli/opnsense/api/auth"
	"slices"
	"strconv"
	"strings"
	"time"

	coreapi "opnsense-cli/opnsense/api"
)

// /system/user: System > Access > Users (api/auth/user). Items are selected by the # of print, the uuid or the
// name. Passwords, password hashes, OTP seeds and API secrets are never printed (the search answer of OPNsense
// contains the hashes and the OTP seed in clear text). root (uid 0) and the user of the API key in use are
// protected: they can not be removed, disabled, renamed or lose groups or privileges through opn

const systemUserItemHelp = "the #, uuid or name of the user"

const systemUserProtectedHelp = `root (uid 0) and the user owning the API key opn uses are protected: opn refuses to
remove, disable, rename or expire them, and to take groups or privileges away from them.`

// systemUserFieldArgs are the field arguments of add and set
func systemUserFieldArgs(add bool) []Arg {
	var name = Arg{Name: "name", Help: "the user name (letters, digits, . - _ @; at most 32 characters without @ for users with a shell)",
		Required: add, Validate: auth.UserValidateName}
	if !add {
		name.Help = "rename the user"
	}
	return []Arg{
		name,
		{Name: "password", Help: "the password; it is visible in the shell history, prefer the password command"},
		{Name: "full-name", Help: "the full name"},
		{Name: "email", Help: "the e-mail address"},
		{Name: "comment", Help: "a comment"},
		{Name: "groups", Type: List, Help: "the groups the user is a member of, by name or gid (replaces the list, \"\" for none)",
			Complete: systemGroupItemNames},
		{Name: "privileges", Type: List, Help: "privileges granted to the user directly, by id like page-all (replaces the list, \"\" for none)",
			Complete: systemPrivilegeIds},
		{Name: "shell", Help: `the login shell like /bin/sh, "" for none (the console menu for root)`, Complete: systemUserOptionKeys("shell")},
		{Name: "language", Help: `the GUI language like de_DE, "" for the default`, Complete: systemUserOptionKeys("language")},
		{Name: "landing-page", Help: `the page shown after login like /ui/diagnostics/log/core/system, "" for the dashboard`,
			Validate: auth.UserValidateLandingPage},
		{Name: "expires", Help: `the expiration date as MM/DD/YYYY or YYYY-MM-DD, "" for never`, Validate: auth.UserValidateExpires},
		{Name: "disabled", Type: Bool, Help: "the user can not log in"},
	}
}

func init() {
	var menu = Root.Menu("system/user")
	menu.Help = "users and their API keys (System > Access > Users)"
	var item = Arg{Name: "item", Help: systemUserItemHelp, Positional: true, Required: true, Complete: systemUserItemNames}
	menu.Add(
		&Command{Name: "print", Help: "list the users",
			Long: `ADMIN users have "All pages" (page-all), directly or through a group. Password hashes, API keys and OTP
seeds are never shown, also not in json.`,
			Args: []Arg{
				{Name: "detail", Help: "show all fields of every user", Type: Bool},
				{Name: "json", Help: "one JSON object per line, as the API returns them without the secret fields", Type: Bool},
				{Name: "search", Help: "only users where any field contains this text"},
			}, Run: systemUserPrint},
		&Command{Name: "show", Help: "show all fields of one user", Args: []Arg{item}, Run: systemUserShow},
		&Command{Name: "add", Help: "add a user, prints its uuid",
			Long: `Without password= the user gets a random password nobody knows: it can only use API keys (see
api-key add) until a password is set with the password command. groups= takes group names (or gids).

If a user with this name exists already, add fails unless replace is given: then all its fields are replaced
(fields not given are cleared, the password is only changed when given).

  add name=backup full-name="Backup job" groups=backup-operators
  add name=alice email=alice@example.com shell=/bin/sh

` + systemUserProtectedHelp,
			Args: append(systemUserFieldArgs(true), Arg{Name: "replace", Help: "replace the user with the same name", Type: Bool}),
			Run:  systemUserAdd},
		&Command{Name: "set", Help: "change fields of a user, the others are kept",
			Long: systemUserProtectedHelp,
			Args: append([]Arg{item}, systemUserFieldArgs(false)...), Check: systemUserCheckSet, Run: systemUserSet},
		&Command{Name: "remove", Help: "remove a user with its API keys",
			Long: `The user is taken out of its groups first (OPNsense would keep its uid in their member lists, and the next
new user would get that uid with the memberships). opn refuses to remove root (uid 0) and the user owning the API
key it uses.`,
			Confirm: "This removes the user, its API keys and its shell account.",
			Args:    []Arg{item}, Run: systemUserRemove},
		&Command{Name: "enable", Help: "allow the user to log in again", Args: []Arg{item}, Run: systemUserSetDisabled(false)},
		&Command{Name: "disable", Help: "keep the user from logging in (also with API keys)",
			Long: `opn refuses to disable root (uid 0) and the user owning the API key it uses.`,
			Args: []Arg{item}, Run: systemUserSetDisabled(true)},
		&Command{Name: "password", Help: "set the password of a user, asked twice without echo",
			Long: `The new password is read from the terminal without echo. In scripts use set <user> password=... instead.`,
			Args: []Arg{item}, Run: systemUserPassword},
	)
}

func systemUserApi(c *Context) (*auth.AuthApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &auth.AuthApi{OPNsense: opn}, nil
}

// --- protection of root and the API key's user

// systemUserApiKeyOwner returns the name of the user owning the API key of this connection ("" if not found)
func systemUserApiKeyOwner(c *Context, api *auth.AuthApi) (string, error) {
	var keys, err = api.ApiKeyList()
	if err != nil {
		return "", fmt.Errorf("looking up the user of the API key in use: %w", err)
	}
	for _, key := range keys {
		if key.Key == api.ApiKey {
			return key.Username, nil
		}
	}
	return "", nil
}

// systemUserProtection tells why a user is protected ("" if it is not)
func systemUserProtection(user auth.User, apiKeyOwner string) string {
	switch {
	case user.Uid == "0" || user.Name == "root":
		return "root"
	case apiKeyOwner != "" && user.Name == apiKeyOwner:
		return "the user of the API key opn uses"
	}
	return ""
}

// systemUserGuard refuses changes of fields that could lock out a protected user
func systemUserGuard(c *Context, api *auth.AuthApi, user auth.User, fields auth.UserFields) error {
	var owner, err = systemUserApiKeyOwner(c, api)
	if err != nil {
		return err
	}
	var why = systemUserProtection(user, owner)
	if why == "" {
		return nil
	}
	var refuse = func(what string) error {
		return fmt.Errorf("refusing to %s %q: it is %s (protected by opn)", what, user.Name, why)
	}
	switch {
	case fields.Disabled != nil && *fields.Disabled:
		return refuse("disable")
	case fields.Expires != nil && *fields.Expires != "":
		return refuse("set an expiration date on")
	case fields.Name != nil && *fields.Name != user.Name:
		return refuse("rename")
	case fields.RandomPassword:
		return refuse("set a random password for")
	}
	if fields.Groups != nil {
		for _, gid := range user.Groups {
			if !slices.Contains(*fields.Groups, gid) {
				var name = gid
				if groups, err := api.GroupList(); err == nil {
					name = systemUserGroupNames(groups, []string{gid})[0]
				}
				return refuse(fmt.Sprintf("take group %q away from", name))
			}
		}
	}
	if fields.Privileges != nil {
		for _, privilege := range user.Privileges {
			if !slices.Contains(*fields.Privileges, privilege) {
				return refuse("take privilege " + privilege + " away from")
			}
		}
	}
	return nil
}

// --- lookups

func systemUserUuid(user auth.User) string {
	return user.Uuid
}

func systemUserNames(user auth.User) []string {
	return []string{user.Name}
}

// systemUserSelect loads all users and finds the one selector refers to
func systemUserSelect(c *Context, api *auth.AuthApi, selector string) (auth.User, error) {
	var users, err = api.UserList()
	if err != nil {
		return auth.User{}, err
	}
	return Select(c, selector, users, systemUserUuid, systemUserNames)
}

func systemUserItemNames(c *Context) []string {
	var api, err = systemUserApi(c)
	if err != nil {
		return nil
	}
	var users, listErr = api.UserList()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(users))
	for _, user := range users {
		names = append(names, user.Name)
	}
	return names
}

// systemUserOptionKeys completes the keys of an option field of the user model (shell, language)
func systemUserOptionKeys(field string) func(c *Context) []string {
	return func(c *Context) []string {
		var api, err = systemUserApi(c)
		if err != nil {
			return nil
		}
		var options, optionsErr = api.UserOptions()
		if optionsErr != nil {
			return nil
		}
		var keys []string
		for _, option := range options[field] {
			if option.Key != "" {
				keys = append(keys, option.Key)
			}
		}
		return keys
	}
}

// systemUserGroupGids resolves group names (case-insensitive) or gids to gids
func systemUserGroupGids(groups []auth.Group, selectors []string) ([]string, error) {
	var gids = make([]string, 0, len(selectors))
	for _, selector := range selectors {
		var index = slices.IndexFunc(groups, func(group auth.Group) bool {
			return strings.EqualFold(group.Name, selector) || group.Gid == selector
		})
		if index < 0 {
			return nil, &coreapi.NotFoundError{Name: fmt.Sprintf("group %q", selector)}
		}
		if !slices.Contains(gids, groups[index].Gid) {
			gids = append(gids, groups[index].Gid)
		}
	}
	return gids, nil
}

// systemUserGroupNames renders gids as group names (unknown gids as they are)
func systemUserGroupNames(groups []auth.Group, gids []string) []string {
	var names = make([]string, 0, len(gids))
	for _, gid := range gids {
		var index = slices.IndexFunc(groups, func(group auth.Group) bool { return group.Gid == gid })
		if index < 0 {
			names = append(names, gid)
		} else {
			names = append(names, groups[index].Name)
		}
	}
	return names
}

// systemUserPrivilegeIds checks privilege ids against the privilege list and returns them as OPNsense spells them
func systemUserPrivilegeIds(api *auth.AuthApi, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return []string{}, nil
	}
	var privileges, err = api.PrivilegeList()
	if err != nil {
		return nil, err
	}
	var result = make([]string, 0, len(ids))
	for _, id := range ids {
		var index = slices.IndexFunc(privileges, func(privilege auth.Privilege) bool { return strings.EqualFold(privilege.Id, id) })
		if index < 0 {
			return nil, &coreapi.NotFoundError{Name: fmt.Sprintf("privilege %q, see /system/privilege print", id)}
		}
		if !slices.Contains(result, privileges[index].Id) {
			result = append(result, privileges[index].Id)
		}
	}
	return result, nil
}

// --- output

// systemUserPasswordChanged renders pwd_changed_at (unix time with fractions) as a UTC time
func systemUserPasswordChanged(value string) string {
	var seconds, err = strconv.ParseFloat(value, 64)
	if err != nil || seconds <= 0 {
		return value
	}
	return time.Unix(int64(seconds), 0).UTC().Format("2006-01-02 15:04:05 UTC")
}

func systemUserFields(user auth.User, groups []auth.Group, apiKeys int) [][2]string {
	var keys = 0
	for _, line := range strings.Split(user.AuthorizedKeys, "\n") {
		if strings.TrimSpace(line) != "" {
			keys++
		}
	}
	var fields = [][2]string{
		{"uuid", user.Uuid},
		{"uid", user.Uid},
		{"name", user.Name},
		{"scope", user.Scope},
		{"disabled", YesNo(Flag(user.Disabled))},
		{"full-name", user.Descr},
		{"email", user.Email},
		{"comment", user.Comment},
		{"groups", strings.Join(systemUserGroupNames(groups, user.Groups), ",")},
		{"privileges", strings.Join(user.Privileges, ",")},
		{"admin", YesNo(Flag(user.IsAdmin))},
		{"shell", user.Shell},
		{"language", user.Language},
		{"landing-page", user.LandingPage},
		{"expires", user.Expires},
		{"password-changed", systemUserPasswordChanged(user.PasswordChangedAt)},
		{"otp", YesNo(Flag(user.HasOtpSeed))},
		{"authorized-keys", strconv.Itoa(keys)},
	}
	if apiKeys >= 0 {
		fields = append(fields, [2]string{"api-keys", strconv.Itoa(apiKeys)})
	}
	return fields
}

func systemUserPrint(c *Context, args *Args) error {
	var api, err = systemUserApi(c)
	if err != nil {
		return err
	}
	var users, searchErr = api.UserSearch(args.String("search"))
	if searchErr != nil {
		return searchErr
	}
	var uuids = make([]string, len(users))
	for i, user := range users {
		uuids[i] = user.Uuid
	}
	if args.Bool("json") {
		for _, user := range users {
			if err := c.JSON(user.Raw); err != nil {
				return err
			}
		}
		return nil
	}
	var groups, groupsErr = api.GroupList()
	if groupsErr != nil {
		return groupsErr
	}
	if args.Bool("detail") {
		var keys, keysErr = api.ApiKeyList()
		if keysErr != nil {
			return keysErr
		}
		var items = make([][][2]string, len(users))
		for i, user := range users {
			items[i] = systemUserFields(user, groups, systemUserApiKeyCount(keys, user.Name))
		}
		c.Details(items, uuids)
		return nil
	}
	var rows = make([][]string, len(users))
	for i, user := range users {
		rows[i] = []string{user.Name, user.Uid, YesNo(Flag(user.Disabled)), YesNo(Flag(user.IsAdmin)),
			strings.Join(systemUserGroupNames(groups, user.Groups), ","), user.Descr, user.Expires}
	}
	c.Items([]string{"NAME", "UID", "DISABLED", "ADMIN", "GROUPS", "FULL-NAME", "EXPIRES"}, rows, uuids)
	return nil
}

func systemUserApiKeyCount(keys []auth.ApiKey, username string) int {
	var count = 0
	for _, key := range keys {
		if key.Username == username {
			count++
		}
	}
	return count
}

func systemUserShow(c *Context, args *Args) error {
	var api, err = systemUserApi(c)
	if err != nil {
		return err
	}
	var user, selectErr = systemUserSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var groups, groupsErr = api.GroupList()
	if groupsErr != nil {
		return groupsErr
	}
	var keys, keysErr = api.ApiKeyList()
	if keysErr != nil {
		return keysErr
	}
	c.Fields(systemUserFields(user, groups, systemUserApiKeyCount(keys, user.Name)))
	return nil
}

// --- changes

func systemUserCheckSet(args *Args) error {
	for _, name := range args.Given() {
		if name != "item" {
			return nil
		}
	}
	return errors.New("nothing to change, give the fields to set (type \"set ?\" for help)")
}

// systemUserFieldsFrom builds the fields to send from the arguments; with all every field is set (add), missing
// ones empty
func systemUserFieldsFrom(api *auth.AuthApi, args *Args, all bool) (auth.UserFields, error) {
	var fields auth.UserFields
	var text = func(arg string, target **string) {
		if all || args.Has(arg) {
			var value = args.String(arg)
			*target = &value
		}
	}
	text("name", &fields.Name)
	text("full-name", &fields.Descr)
	text("email", &fields.Email)
	text("comment", &fields.Comment)
	text("shell", &fields.Shell)
	text("language", &fields.Language)
	text("landing-page", &fields.LandingPage)
	text("expires", &fields.Expires)
	if args.Has("password") {
		var password = args.String("password")
		fields.Password = &password
	}
	if all || args.Has("disabled") {
		var disabled = args.Bool("disabled")
		fields.Disabled = &disabled
	}
	if all || args.Has("groups") {
		var gids = []string{}
		if selectors := args.List("groups"); len(selectors) > 0 {
			var groups, err = api.GroupList()
			if err != nil {
				return fields, err
			}
			if gids, err = systemUserGroupGids(groups, selectors); err != nil {
				return fields, err
			}
		}
		fields.Groups = &gids
	}
	if all || args.Has("privileges") {
		var ids, err = systemUserPrivilegeIds(api, args.List("privileges"))
		if err != nil {
			return fields, err
		}
		fields.Privileges = &ids
	}
	return fields, nil
}

func systemUserAdd(c *Context, args *Args) error {
	var api, err = systemUserApi(c)
	if err != nil {
		return err
	}
	var name = args.String("name")
	var existing, findErr = api.UserGetByName(name)
	if findErr != nil && !coreapi.IsNotFound(findErr) {
		return findErr
	}
	if findErr == nil && !args.Bool("replace") {
		return fmt.Errorf("a user named %q exists already (%s), change it with set or replace it with add ... replace",
			existing.Name, existing.Uuid)
	}
	var fields, fieldsErr = systemUserFieldsFrom(api, args, true)
	if fieldsErr != nil {
		return fieldsErr
	}

	if findErr == nil {
		if err := systemUserGuard(c, api, existing, fields); err != nil {
			return err
		}
		if err := api.UserUpdate(existing.Uuid, fields); err != nil {
			return err
		}
		c.Infof("replaced the existing user %q", existing.Name)
		c.Println(existing.Uuid)
		return nil
	}

	if fields.Password == nil {
		fields.RandomPassword = true
	}
	var uuid, createErr = api.UserCreate(fields)
	if createErr != nil {
		return createErr
	}
	if fields.RandomPassword {
		c.Infof("user %q has a random password, set one with: /system/user password %s", name, name)
	}
	c.Println(uuid)
	return nil
}

func systemUserSet(c *Context, args *Args) error {
	var api, err = systemUserApi(c)
	if err != nil {
		return err
	}
	var user, selectErr = systemUserSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var fields, fieldsErr = systemUserFieldsFrom(api, args, false)
	if fieldsErr != nil {
		return fieldsErr
	}
	if err := systemUserGuard(c, api, user, fields); err != nil {
		return err
	}
	return api.UserUpdate(user.Uuid, fields)
}

func systemUserSetDisabled(disabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = systemUserApi(c)
		if err != nil {
			return err
		}
		var user, selectErr = systemUserSelect(c, api, args.String("item"))
		if selectErr != nil {
			return selectErr
		}
		var fields = auth.UserFields{Disabled: &disabled}
		if err := systemUserGuard(c, api, user, fields); err != nil {
			return err
		}
		if user.Disabled == disabled {
			c.Infof("the user %q is already %s", user.Name, EnabledWord(!disabled))
			return nil
		}
		return api.UserUpdate(user.Uuid, fields)
	}
}

func systemUserRemove(c *Context, args *Args) error {
	var api, err = systemUserApi(c)
	if err != nil {
		return err
	}
	var user, selectErr = systemUserSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var owner, ownerErr = systemUserApiKeyOwner(c, api)
	if ownerErr != nil {
		return ownerErr
	}
	if why := systemUserProtection(user, owner); why != "" {
		return fmt.Errorf("refusing to remove %q: it is %s (protected by opn)", user.Name, why)
	}
	return api.UserRemove(user.Uuid)
}

func systemUserPassword(c *Context, args *Args) error {
	var api, err = systemUserApi(c)
	if err != nil {
		return err
	}
	var user, selectErr = systemUserSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var password, askErr = systemUserAskPassword(c, user.Name)
	if askErr != nil {
		return askErr
	}
	return api.UserUpdate(user.Uuid, auth.UserFields{Password: &password})
}
