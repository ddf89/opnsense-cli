package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// AdminsGid is the gid of the built-in admins group (All pages)
const AdminsGid = "1999"

// Group is a group of System > Access > Groups (api/auth/group)
type Group struct {
	Uuid string
	// Gid is the numeric group id, 1999 for admins, new groups get the next free id from 2000
	Gid  string
	Name string
	// Scope is "system" for the built-in admins group (can not be removed), "user" for the others
	Scope       string
	Description string
	// Members are the uids of the member users
	Members []string
	// Privileges are the ids of the privileges granted to the members
	Privileges []string
	// SourceNetworks restrict where members may log in from (empty: anywhere)
	SourceNetworks []string
	// Raw is the search row as OPNsense returned it
	Raw map[string]any
}

// GroupFields holds the group fields to set, nil fields are not sent (kept on update)
type GroupFields struct {
	Name        *string
	Description *string
	// Members are uids
	Members *[]string
	// Privileges are privilege ids
	Privileges     *[]string
	SourceNetworks *[]string
}

var groupNamePattern = regexp.MustCompile(`^[a-zA-Z0-9.\-_]{1,32}$`)

// GroupValidateName checks a group name like OPNsense: 1-32 letters, digits, . - _
func GroupValidateName(name string) error {
	if !groupNamePattern.MatchString(name) {
		return fmt.Errorf("invalid group name %q: 1-32 letters, digits, . - and _", name)
	}
	return nil
}

func (g *Group) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var text = func(name string) string {
		var value, _ = raw[name].(string)
		return value
	}
	*g = Group{
		Uuid: text("uuid"), Gid: text("gid"), Name: text("name"), Scope: text("scope"), Description: text("description"),
		Members: splitList(text("member")), Privileges: splitList(text("priv")), SourceNetworks: splitList(text("source_networks")),
		Raw: raw,
	}
	return nil
}

func (fields GroupFields) validate() error {
	if fields.Name != nil {
		return GroupValidateName(*fields.Name)
	}
	return nil
}

func (fields GroupFields) body() map[string]string {
	var body = map[string]string{}
	if fields.Name != nil {
		body["name"] = *fields.Name
	}
	if fields.Description != nil {
		body["description"] = *fields.Description
	}
	var list = func(name string, value *[]string) {
		if value != nil {
			body[name] = strings.Join(*value, ",")
		}
	}
	list("member", fields.Members)
	list("priv", fields.Privileges)
	list("source_networks", fields.SourceNetworks)
	return body
}

// GroupSearch returns the groups where any field contains searchPhrase ("" for all), in the order of the config
func (opn *AuthApi) GroupSearch(searchPhrase string) ([]Group, error) {
	return coreapi.Search[Group](opn.OPNsense, opn.endpoint("group", "search"), searchPhrase)
}

func (opn *AuthApi) GroupList() ([]Group, error) {
	return opn.GroupSearch("")
}

// GroupGet returns the group with the given uuid or a *NotFoundError
func (opn *AuthApi) GroupGet(uuid string) (Group, error) {
	if uuid == "" {
		return Group{}, errors.New("cannot look up a group without uuid")
	}
	var groups, err = opn.GroupList()
	if err != nil {
		return Group{}, err
	}
	for _, group := range groups {
		if group.Uuid == uuid {
			return group, nil
		}
	}
	return Group{}, &coreapi.NotFoundError{Name: "group " + uuid}
}

// GroupGetByName returns the group with exactly this name (case-sensitive like OPNsense) or a *NotFoundError
func (opn *AuthApi) GroupGetByName(name string) (Group, error) {
	if name == "" {
		return Group{}, errors.New("cannot look up a group by an empty name")
	}
	var groups, err = opn.GroupSearch(name)
	if err != nil {
		return Group{}, err
	}
	for _, group := range groups {
		if group.Name == name {
			return group, nil
		}
	}
	return Group{}, &coreapi.NotFoundError{Name: fmt.Sprintf("group %q", name)}
}

// GroupCreate adds a group and returns its uuid, Name is required
func (opn *AuthApi) GroupCreate(fields GroupFields) (string, error) {
	if fields.Name == nil {
		return "", errors.New("a new group needs a name")
	}
	if err := fields.validate(); err != nil {
		return "", err
	}
	return opn.Mutate(opn.endpoint("group", "add"), map[string]any{"group": fields.body()})
}

// GroupUpdate changes the non nil fields of the group with the given uuid, the others are kept. Returns
// *NotFoundError for an unknown uuid (checked first: set with a name would create a group). The current name is
// always sent: OPNsense only updates the system group when the request contains the name
func (opn *AuthApi) GroupUpdate(uuid string, fields GroupFields) error {
	if uuid == "" {
		return errors.New("cannot update a group without uuid")
	}
	if err := fields.validate(); err != nil {
		return err
	}
	var existing, err = opn.GroupGet(uuid)
	if err != nil {
		return err
	}
	if fields.Name == nil {
		fields.Name = &existing.Name
	}
	_, err = opn.mutate(opn.endpoint("group", "set")+"/"+uuid, "group "+uuid, map[string]any{"group": fields.body()})
	return err
}

// GroupRemove deletes the group with the given uuid (OPNsense refuses the system group admins)
func (opn *AuthApi) GroupRemove(uuid string) error {
	if uuid == "" || strings.ContainsAny(uuid, ",/") {
		return fmt.Errorf("cannot remove a group by uuid %q", uuid)
	}
	var existing, err = opn.GroupGet(uuid)
	if err != nil {
		return err
	}
	if existing.Scope == "system" || existing.Gid == AdminsGid {
		return fmt.Errorf("the system group %q can not be removed", existing.Name)
	}
	_, err = opn.mutate(opn.endpoint("group", "del")+"/"+uuid, "group "+uuid, nil)
	return err
}
