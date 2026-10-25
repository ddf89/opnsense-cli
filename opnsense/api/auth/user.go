package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	coreapi "opnsense-cli/opnsense/api"
)

// User is a user of System > Access > Users (api/auth/user). The search answer of OPNsense contains the password
// hash, the API keys (key and hashed secret) and the OTP seed in clear text: they are never kept, Raw is the row
// without them
type User struct {
	Uuid string
	// Uid is the numeric user id, 0 for root, new users get the next free id from 2000
	Uid  string
	Name string
	// Scope is "system" for the built-in root user (can not be removed or renamed), "user" for the others
	Scope    string
	Disabled bool
	// Descr is the full name
	Descr       string
	Email       string
	Comment     string
	LandingPage string
	Language    string
	// Shell is the login shell, "" for none (no shell login, except root)
	Shell string
	// Expires is the expiration date as MM/DD/YYYY, "" for never
	Expires string
	// Groups are the gids of the groups the user is a member of
	Groups []string
	// Privileges are the ids of the privileges granted to the user directly (not via a group)
	Privileges []string
	// IsAdmin tells whether the user has "All pages" (page-all) directly or via a group
	IsAdmin bool
	// PasswordChangedAt is the unix time (with fractions) of the last password change, "" if unknown
	PasswordChangedAt string
	// HasOtpSeed tells whether an OTP seed (two factor authentication) is set, the seed itself is not kept
	HasOtpSeed bool
	// AuthorizedKeys are the SSH public keys, one per line
	AuthorizedKeys string
	// Raw is the search row as OPNsense returned it, without the secret fields (see UserSecretFields)
	Raw map[string]any
}

// UserSecretFields are the fields of a user record (search or get) that hold secrets or would reveal them
var UserSecretFields = []string{"password", "%password", "apikeys", "%apikeys", "otp_seed", "%otp_seed", "otp_uri"}

// UserFields holds the user fields to set, nil fields are not sent (kept on update)
type UserFields struct {
	Name        *string
	Disabled    *bool
	Descr       *string
	Email       *string
	Comment     *string
	LandingPage *string
	Language    *string
	Shell       *string
	// Expires is MM/DD/YYYY (OPNsense also converts anything PHP's DateTime understands, like 2030-12-31), "" for never
	Expires *string
	// Groups are gids, the user is added to or removed from the groups accordingly
	Groups *[]string
	// Privileges are privilege ids (see PrivilegeList)
	Privileges *[]string
	// Password is the new password in clear text, OPNsense stores a hash
	Password *string
	// RandomPassword sets a random password nobody knows (scrambled_password), for users that only use API keys
	// or another authentication server
	RandomPassword bool
}

var userLandingPagePattern = regexp.MustCompile(`^/[a-zA-Z0-9_\-.~/?=&#+,@!;]*$`)
var userExpiresPattern = regexp.MustCompile(`^(\d{2}/\d{2}/\d{4}|\d{4}-\d{2}-\d{2})$`)

// UserValidateName checks a user name roughly like OPNsense: 1-320 letters, digits, . - _ @ (an e-mail address
// is allowed; users with a login shell are limited to 32 characters without @, which OPNsense checks)
func UserValidateName(name string) error {
	if name == "" {
		return errors.New("a user name must not be empty")
	}
	if len(name) > 320 {
		return fmt.Errorf("invalid user name %q: at most 320 characters", name)
	}
	for _, char := range name {
		var allowed = unicode.IsLetter(char) || unicode.IsDigit(char) || strings.ContainsRune(".-_@", char)
		if char > unicode.MaxASCII || !allowed {
			return fmt.Errorf("invalid user name %q: only letters, digits, . - _ and @ are allowed", name)
		}
	}
	return nil
}

// UserValidateExpires checks an expiration date: MM/DD/YYYY, YYYY-MM-DD or "" for never
func UserValidateExpires(expires string) error {
	if expires != "" && !userExpiresPattern.MatchString(expires) {
		return fmt.Errorf("invalid expiration date %q: use MM/DD/YYYY or YYYY-MM-DD", expires)
	}
	return nil
}

// UserValidateLandingPage checks a landing page: a relative path like /ui/diagnostics/log/core/system or ""
func UserValidateLandingPage(page string) error {
	if page != "" && !userLandingPagePattern.MatchString(page) {
		return fmt.Errorf("invalid landing page %q: a relative path like /ui/core/dashboard", page)
	}
	return nil
}

func (u *User) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var text = func(name string) string {
		var value, _ = raw[name].(string)
		return value
	}
	*u = User{
		Uuid: text("uuid"), Uid: text("uid"), Name: text("name"), Scope: text("scope"), Disabled: text("disabled") == "1",
		Descr: text("descr"), Email: text("email"), Comment: text("comment"), LandingPage: text("landing_page"),
		Language: text("language"), Shell: text("shell"), Expires: text("expires"),
		Groups: splitList(text("group_memberships")), Privileges: splitList(text("priv")), IsAdmin: text("is_admin") == "1",
		PasswordChangedAt: text("pwd_changed_at"), HasOtpSeed: text("otp_seed") != "", AuthorizedKeys: text("authorizedkeys"),
	}
	for _, secret := range UserSecretFields {
		delete(raw, secret)
	}
	u.Raw = raw
	return nil
}

func (fields UserFields) validate() error {
	if fields.Name != nil {
		if err := UserValidateName(*fields.Name); err != nil {
			return err
		}
	}
	if fields.Expires != nil {
		if err := UserValidateExpires(*fields.Expires); err != nil {
			return err
		}
	}
	if fields.LandingPage != nil {
		if err := UserValidateLandingPage(*fields.LandingPage); err != nil {
			return err
		}
	}
	if fields.Password != nil && *fields.Password == "" {
		return errors.New("the password must not be empty")
	}
	if fields.Password != nil && fields.RandomPassword {
		return errors.New("give either a password or a random password, not both")
	}
	return nil
}

func (fields UserFields) body() map[string]string {
	var body = map[string]string{}
	var set = func(name string, value *string) {
		if value != nil {
			body[name] = *value
		}
	}
	set("name", fields.Name)
	set("descr", fields.Descr)
	set("email", fields.Email)
	set("comment", fields.Comment)
	set("landing_page", fields.LandingPage)
	set("language", fields.Language)
	set("shell", fields.Shell)
	set("expires", fields.Expires)
	set("password", fields.Password)
	if fields.Disabled != nil {
		body["disabled"] = map[bool]string{true: "1", false: "0"}[*fields.Disabled]
	}
	if fields.Groups != nil {
		body["group_memberships"] = strings.Join(*fields.Groups, ",")
	}
	if fields.Privileges != nil {
		body["priv"] = strings.Join(*fields.Privileges, ",")
	}
	if fields.RandomPassword {
		body["scrambled_password"] = "1"
	}
	return body
}

// UserSearch returns the users where any field contains searchPhrase ("" for all), in the order of the config
func (opn *AuthApi) UserSearch(searchPhrase string) ([]User, error) {
	return coreapi.Search[User](opn.OPNsense, opn.endpoint("user", "search"), searchPhrase)
}

func (opn *AuthApi) UserList() ([]User, error) {
	return opn.UserSearch("")
}

// UserGet returns the user with the given uuid or a *NotFoundError (looked up by search, get answers unknown
// uuids with an empty record)
func (opn *AuthApi) UserGet(uuid string) (User, error) {
	if uuid == "" {
		return User{}, errors.New("cannot look up a user without uuid")
	}
	var users, err = opn.UserList()
	if err != nil {
		return User{}, err
	}
	for _, user := range users {
		if user.Uuid == uuid {
			return user, nil
		}
	}
	return User{}, &coreapi.NotFoundError{Name: "user " + uuid}
}

// UserGetByName returns the user with exactly this name (case-sensitive like OPNsense) or a *NotFoundError
func (opn *AuthApi) UserGetByName(name string) (User, error) {
	if name == "" {
		return User{}, errors.New("cannot look up a user by an empty name")
	}
	var users, err = opn.UserSearch(name)
	if err != nil {
		return User{}, err
	}
	for _, user := range users {
		if user.Name == name {
			return user, nil
		}
	}
	return User{}, &coreapi.NotFoundError{Name: fmt.Sprintf("user %q", name)}
}

// UserOptions returns the choices of the option fields of a new user by API field name: shell, language,
// group_memberships (gid → group name) and priv (privilege id → name)
func (opn *AuthApi) UserOptions() (map[string][]Option, error) {
	return opn.options("user", "get", "user", "shell", "language", "group_memberships", "priv")
}

// options reads the option maps of fields from a get answer {"<container>":{...}}
func (opn *AuthApi) options(controller string, method string, container string, fields ...string) (map[string][]Option, error) {
	var answer map[string]map[string]json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint(controller, method), nil, &answer); err != nil {
		return nil, err
	}
	var record, found = answer[container]
	if !found {
		return nil, fmt.Errorf("unexpected answer from %s/%s: no %s", controller, method, container)
	}
	var result = map[string][]Option{}
	for _, field := range fields {
		if raw, given := record[field]; given {
			var options, err = decodeOptions(raw)
			if err != nil {
				return nil, fmt.Errorf("unexpected %s options from %s/%s: %w", field, controller, method, err)
			}
			result[field] = options
		}
	}
	return result, nil
}

// UserCreate adds a user and returns its uuid. Name is required, and a Password or RandomPassword (OPNsense
// requires a password)
func (opn *AuthApi) UserCreate(fields UserFields) (string, error) {
	if fields.Name == nil {
		return "", errors.New("a new user needs a name")
	}
	if fields.Password == nil && !fields.RandomPassword {
		return "", errors.New("a new user needs a password or a random password")
	}
	if err := fields.validate(); err != nil {
		return "", err
	}
	return opn.Mutate(opn.endpoint("user", "add"), map[string]any{"user": fields.body()})
}

// UserUpdate changes the non nil fields of the user with the given uuid, the others are kept. Returns
// *NotFoundError for an unknown uuid (checked first: set with a name and password would create a user). The
// current name is always sent: OPNsense only updates the system account (shell, password, disabled) when the
// request contains the name
func (opn *AuthApi) UserUpdate(uuid string, fields UserFields) error {
	if uuid == "" {
		return errors.New("cannot update a user without uuid")
	}
	if err := fields.validate(); err != nil {
		return err
	}
	var existing, err = opn.UserGet(uuid)
	if err != nil {
		return err
	}
	if fields.Name == nil {
		fields.Name = &existing.Name
	}
	_, err = opn.mutate(opn.endpoint("user", "set")+"/"+uuid, "user "+uuid, map[string]any{"user": fields.body()})
	return err
}

// UserRemove deletes the user with the given uuid. OPNsense refuses to remove the system user root and the user
// of the API key in use. The user is taken out of its groups first: OPNsense leaves the uid of a removed user in
// the member lists of its groups, and the next new user gets that uid again (and with it the memberships)
func (opn *AuthApi) UserRemove(uuid string) error {
	if uuid == "" || strings.ContainsAny(uuid, ",/") {
		return fmt.Errorf("cannot remove a user by uuid %q", uuid)
	}
	var existing, err = opn.UserGet(uuid)
	if err != nil {
		return err
	}
	if existing.Scope == "system" {
		return fmt.Errorf("the system user %q can not be removed", existing.Name)
	}
	if len(existing.Groups) > 0 {
		var none = []string{}
		if err := opn.UserUpdate(uuid, UserFields{Groups: &none}); err != nil {
			return fmt.Errorf("taking user %q out of its groups before removing it: %w", existing.Name, err)
		}
	}
	_, err = opn.mutate(opn.endpoint("user", "del")+"/"+uuid, "user "+uuid, nil)
	return err
}
